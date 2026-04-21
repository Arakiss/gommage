//! gommage-mcp — thin adapter that bridges Claude Code's `PreToolUse` hook to
//! the running Gommage daemon.
//!
//! Reads a single hook JSON from stdin, forwards a `decide` op to the daemon,
//! and prints the hook response JSON on stdout. If the daemon is not running,
//! falls back to `gommage decide` in-process (same crate).
//!
//! This binary stays thin on purpose: every feature worth reviewing lives in
//! `gommage-core`.

use anyhow::{Context, Result};
use gommage_core::{
    Decision, ToolCall, evaluate,
    runtime::{HomeLayout, Runtime},
};
use serde::Deserialize;
use std::io::{self, Read, Write};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[derive(Debug, Deserialize)]
struct HookInput {
    #[allow(dead_code)]
    #[serde(default)]
    session_id: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    hook_event_name: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;
    let input: HookInput = serde_json::from_str(&buf).context("parsing hook JSON")?;
    let call = ToolCall {
        tool: input.tool_name,
        input: input.tool_input,
    };

    let layout = HomeLayout::default();
    layout.ensure()?;

    let eval = match forward_to_daemon(&layout, &call).await {
        Ok(e) => e,
        Err(_) => decide_in_process(&layout, &call)?,
    };

    let (decision_str, reason) = match &eval.decision {
        Decision::Allow => ("allow", "gommage allowed".to_string()),
        Decision::Gommage { reason, hard_stop } => {
            let prefix = if *hard_stop {
                "gommaged (hard-stop): "
            } else {
                "gommaged: "
            };
            ("deny", format!("{prefix}{reason}"))
        }
        Decision::AskPicto {
            reason,
            required_scope,
        } => (
            "ask",
            format!("gommage: requires picto scope {required_scope:?} — {reason}"),
        ),
    };
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision_str,
            "permissionDecisionReason": reason,
        }
    });
    let s = serde_json::to_string(&out)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(s.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(())
}

async fn forward_to_daemon(
    layout: &HomeLayout,
    call: &ToolCall,
) -> Result<gommage_core::EvalResult> {
    let stream = UnixStream::connect(&layout.socket).await?;
    let (r, mut w) = stream.into_split();
    let req = serde_json::json!({ "op": "decide", "call": call });
    w.write_all(serde_json::to_string(&req)?.as_bytes()).await?;
    w.write_all(b"\n").await?;
    let mut lines = BufReader::new(r).lines();
    let line = lines
        .next_line()
        .await?
        .context("daemon closed without response")?;
    let resp: serde_json::Value = serde_json::from_str(&line)?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let result = resp.get("result").cloned().context("missing result")?;
        let eval: gommage_core::EvalResult = serde_json::from_value(result)?;
        Ok(eval)
    } else {
        anyhow::bail!(
            "daemon returned error: {}",
            resp.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
        );
    }
}

fn decide_in_process(layout: &HomeLayout, call: &ToolCall) -> Result<gommage_core::EvalResult> {
    let rt = Runtime::open(HomeLayout::at(&layout.root))?;
    let caps = rt.mapper.map(call);
    let mut eval = evaluate(&caps, &rt.policy);
    if let Decision::AskPicto { required_scope, .. } = eval.decision.clone()
        && let Some(p) = rt.pictos.find_match(&required_scope, time::OffsetDateTime::now_utc())?
        && rt.pictos.consume(&p.id)?
    {
        eval.decision = Decision::Allow;
    }
    Ok(eval)
}
