//! gommage-mcp — legacy compatibility adapter and optional stdio MCP gateway.
//!
//! New agent hooks should call `gommage hook`. This binary remains for older
//! hooks and for explicitly wrapped MCP gateway use.
//!
//! Reads a single hook JSON from stdin, forwards a `decide` op to the daemon,
//! and prints the hook response JSON on stdout. If the daemon is not running,
//! falls back to `gommage decide` in-process (same crate).
//!
//! This binary stays thin on purpose: every feature worth reviewing lives in
//! `gommage-core`.

use anyhow::{Context, Result};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalRequest, ApprovalWebhookDeliveryKind, ApprovalWebhookDeliverySettings,
    ApprovalWebhookSource, AuthorizationEvidence, Capability, CapabilityMapper, Decision,
    EvalResult, PictoConsume, PictoLookup, ToolCall, approval_webhook_generic_payload,
    deliver_prepared_approval_webhook, evaluate, evaluate_bypass, prepare_approval_webhook,
    runtime::{HomeLayout, Runtime},
    webhook_signature::WebhookSignatureReport,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    env,
    io::{self, BufRead, BufReader as StdBufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader},
    net::UnixStream,
};

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    session_id: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    hook_event_name: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

const MAX_APPLY_PATCH_PATHS: usize = 16;
const MAX_GIT_WRITE_CONTEXTS: usize = 16;

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args()? {
        Mode::InfoPrinted => return Ok(()),
        Mode::Gateway(options) => return run_gateway(options).await,
        Mode::Hook => {}
    }

    run_hook().await
}

async fn run_hook() -> Result<()> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;
    if bypass_enabled() {
        // STDERR ONLY: stdout must stay the single hook-decision JSON object.
        // Warn loudly that GOMMAGE_BYPASS=1 skipped normal policy evaluation
        // (hard-stops still apply; see handle_bypass).
        eprintln!(
            "gommage-mcp: WARNING: GOMMAGE_BYPASS=1 is set; skipping policy evaluation (compiled hard-stops still apply)"
        );
        return handle_bypass(&buf);
    }

    let call = match parse_hook_tool_call(&buf) {
        Ok(call) => call,
        Err(error) => {
            write_hook_response("deny", &format!("gommage hook failed closed: {error:#}"))?;
            return Ok(());
        }
    };

    let layout = HomeLayout::default();
    if let Err(error) = layout.ensure().context("initializing Gommage home") {
        write_hook_response("deny", &format!("gommage hook failed closed: {error:#}"))?;
        return Ok(());
    }

    let eval = match decide_call(&layout, &call)
        .await
        .context("evaluating policy")
    {
        Ok(eval) => eval,
        Err(error) => {
            write_hook_response("deny", &format!("gommage hook failed closed: {error:#}"))?;
            return Ok(());
        }
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
            bind_input,
        } => (
            "ask",
            format!(
                "gommage: requires {} for scope {required_scope:?} — {reason}",
                picto_requirement(*bind_input)
            ),
        ),
    };
    write_hook_response(decision_str, &reason)?;
    Ok(())
}

async fn decide_call(layout: &HomeLayout, call: &ToolCall) -> Result<gommage_core::EvalResult> {
    match forward_to_daemon(layout, call).await {
        Ok(e) => Ok(e),
        Err(e) if is_missing_daemon(&e) => {
            // STDERR ONLY: stdout carries the hook decision JSON and must stay a
            // single JSON object. This line just tells the operator the daemon
            // socket was unreachable and Gommage decided + audited in-process.
            eprintln!(
                "gommage-mcp: daemon socket unavailable; evaluating policy in-process and writing the audit entry directly"
            );
            decide_in_process_and_audit(layout, call)
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
enum Mode {
    Hook,
    Gateway(GatewayOptions),
    InfoPrinted,
}

#[derive(Debug)]
struct GatewayOptions {
    server_name: String,
    command: Vec<String>,
}

fn parse_args() -> Result<Mode> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Ok(Mode::Hook);
    }
    if args == ["-V"] || args == ["--version"] {
        println!("gommage-mcp {}", env!("CARGO_PKG_VERSION"));
        return Ok(Mode::InfoPrinted);
    }
    if args == ["-h"] || args == ["--help"] {
        print_help();
        return Ok(Mode::InfoPrinted);
    }
    if args.first().map(String::as_str) != Some("--gateway") {
        anyhow::bail!("unexpected argument {:?}; try --help", args[0]);
    }

    let mut server_name = "upstream".to_string();
    let mut command_start = None;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--server-name" => {
                let Some(value) = args.get(i + 1) else {
                    anyhow::bail!("--server-name requires a value");
                };
                server_name = value.clone();
                i += 2;
            }
            "--" => {
                command_start = Some(i + 1);
                break;
            }
            other => anyhow::bail!("unexpected gateway argument {other:?}; try --help"),
        }
    }
    let Some(start) = command_start else {
        anyhow::bail!("--gateway requires `-- <upstream-command> [args...]`");
    };
    let command = args[start..].to_vec();
    if command.is_empty() {
        anyhow::bail!("--gateway requires an upstream command after `--`");
    }
    Ok(Mode::Gateway(GatewayOptions {
        server_name,
        command,
    }))
}

async fn run_gateway(options: GatewayOptions) -> Result<()> {
    let layout = HomeLayout::default();
    layout.ensure()?;
    let mut child = Command::new(&options.command[0])
        .args(&options.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting upstream MCP server {:?}", options.command))?;
    let mut upstream_stdin = child.stdin.take().context("missing upstream stdin")?;
    let upstream_stdout = child.stdout.take().context("missing upstream stdout")?;
    let mut upstream_stdout = StdBufReader::new(upstream_stdout);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line.context("reading gateway stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = serde_json::from_str(&line).context("parsing MCP JSON-RPC line")?;
        if let Some(response) = gate_mcp_tool_call(&layout, &options.server_name, &message).await? {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
            continue;
        }

        upstream_stdin.write_all(line.as_bytes())?;
        upstream_stdin.write_all(b"\n")?;
        upstream_stdin.flush()?;
        if message.get("id").is_none() {
            continue;
        }
        let mut response = String::new();
        upstream_stdout
            .read_line(&mut response)
            .context("reading upstream MCP response")?;
        if response.is_empty() {
            anyhow::bail!("upstream MCP server closed without response");
        }
        stdout.write_all(response.as_bytes())?;
        stdout.flush()?;
    }

    drop(upstream_stdin);
    let status = child.wait().context("waiting for upstream MCP server")?;
    if !status.success() {
        anyhow::bail!("upstream MCP server exited with {status}");
    }
    Ok(())
}

async fn gate_mcp_tool_call(
    layout: &HomeLayout,
    server_name: &str,
    message: &Value,
) -> Result<Option<Value>> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(None);
    }
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let Some(params) = message.get("params").and_then(Value::as_object) else {
        return Ok(Some(jsonrpc_error(
            id,
            -32602,
            "Malformed tools/call: missing params",
        )));
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return Ok(Some(jsonrpc_error(
            id,
            -32602,
            "Malformed tools/call: missing params.name",
        )));
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let call = ToolCall {
        tool: gateway_tool_name(server_name, tool_name),
        input: arguments,
    };
    let eval = decide_call(layout, &call).await?;
    match &eval.decision {
        Decision::Allow => Ok(None),
        Decision::Gommage { reason, hard_stop } => Ok(Some(gateway_denied_response(
            id, &call.tool, reason, *hard_stop, &eval,
        ))),
        Decision::AskPicto {
            reason,
            required_scope,
            bind_input,
        } => Ok(Some(gateway_ask_response(
            id,
            &call.tool,
            reason,
            required_scope,
            *bind_input,
            &eval,
        ))),
    }
}

fn gateway_tool_name(server_name: &str, tool_name: &str) -> String {
    format!(
        "mcp__{}__{}",
        sanitize_mcp_segment(server_name),
        sanitize_mcp_segment(tool_name)
    )
}

fn sanitize_mcp_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unnamed".to_string()
    } else {
        sanitized
    }
}

fn gateway_denied_response(
    id: Value,
    tool: &str,
    reason: &str,
    hard_stop: bool,
    eval: &EvalResult,
) -> Value {
    let prefix = if hard_stop {
        "gommage denied MCP tool call (hard-stop)"
    } else {
        "gommage denied MCP tool call"
    };
    mcp_tool_error_response(id, format!("{prefix}: {reason}"), tool, eval)
}

fn gateway_ask_response(
    id: Value,
    tool: &str,
    reason: &str,
    required_scope: &str,
    bind_input: bool,
    eval: &EvalResult,
) -> Value {
    mcp_tool_error_response(
        id,
        format!(
            "gommage requires {} for scope {required_scope:?}: {reason}",
            picto_requirement(bind_input)
        ),
        tool,
        eval,
    )
}

fn picto_requirement(bind_input: bool) -> &'static str {
    if bind_input {
        "an exact-input picto"
    } else {
        "a picto"
    }
}

fn mcp_tool_error_response(id: Value, text: String, tool: &str, eval: &EvalResult) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": true,
            "_meta": {
                "com.gommage/decision": {
                "gateway_tool": tool,
                "policy_version": eval.policy_version,
                    "matched_rule": &eval.matched_rule,
                    "capabilities": &eval.capabilities,
                }
            }
        }
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn bypass_enabled() -> bool {
    env::var("GOMMAGE_BYPASS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn parse_hook_tool_call(buf: &str) -> Result<ToolCall> {
    let raw: Value = serde_json::from_str(buf).context("parsing hook JSON")?;
    validate_hook_session_id(&raw)?;
    let input: HookInput = serde_json::from_value(raw).context("parsing hook JSON")?;
    let tool = input.tool_name;
    let tool_input = enrich_tool_input(
        &tool,
        input.tool_input,
        input.cwd.as_deref(),
        input.session_id.as_deref(),
    )?;
    Ok(ToolCall {
        tool,
        input: tool_input,
    })
}

fn validate_hook_session_id(input: &Value) -> Result<()> {
    match input.get("session_id") {
        None => Ok(()),
        Some(Value::String(session_id)) if !session_id.is_empty() => Ok(()),
        Some(Value::String(_)) => anyhow::bail!("hook session_id must not be empty"),
        Some(_) => anyhow::bail!("hook session_id must be a string"),
    }
}

fn handle_bypass(buf: &str) -> Result<()> {
    let Ok(call) = parse_hook_tool_call(buf) else {
        write_hook_response(
            "allow",
            "gommage bypass: GOMMAGE_BYPASS=1 was set, but the hook payload could not be parsed; policy evaluation skipped for hook recovery",
        )?;
        return Ok(());
    };

    let layout = HomeLayout::default();
    // Map from the bundled stdlib (not on-disk policy — the kill-switch must
    // work when that is broken), then apply the shared core decision: compiled
    // hard-stops still deny, everything else is allowed with policy skipped.
    let eval = evaluate_bypass(bypass_capabilities(&call));
    match &eval.decision {
        Decision::Gommage { reason, .. } => {
            gommage_audit::append_bypass_event_best_effort(&layout, &call, &eval, "deny");
            write_hook_response(
                "deny",
                &format!("gommage bypass refused: {reason}; hard-stops cannot be bypassed"),
            )?;
        }
        _ => {
            gommage_audit::append_bypass_event_best_effort(&layout, &call, &eval, "allow");
            write_hook_response(
                "allow",
                "gommage bypass: GOMMAGE_BYPASS=1 was set by the host environment; policy evaluation skipped after hard-stop check",
            )?;
        }
    }
    Ok(())
}

/// Map a tool call to capabilities using the compiled-in stdlib mappers for the
/// bypass path. Falls back to a bare `proc.exec:<command>` for a Bash call if
/// the bundled mappers fail to compile, so a compiled hard-stop on the raw
/// command is still surfaced. Kept here (and mirrored in the `gommage hook` CLI
/// adapter) rather than in `gommage-stdlib` so the crate graph stays acyclic.
fn bypass_capabilities(call: &ToolCall) -> Vec<Capability> {
    let yaml = gommage_stdlib::CAPABILITIES
        .iter()
        .map(|file| file.contents)
        .collect::<Vec<_>>()
        .join("\n");
    match CapabilityMapper::from_yaml_string(&yaml, "<compiled-stdlib-capabilities>") {
        Ok(mapper) => mapper.map(call),
        Err(_) => {
            if call.tool == "Bash"
                && let Some(command) = call.input.get("command").and_then(Value::as_str)
            {
                return vec![Capability::new(format!("proc.exec:{command}"))];
            }
            Vec::new()
        }
    }
}

fn write_hook_response(decision: &str, reason: &str) -> Result<()> {
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    let s = serde_json::to_string(&out)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(s.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn print_help() {
    println!(
        "gommage-mcp {}\n\nUSAGE:\n    gommage-mcp < hook.json\n    gommage-mcp --gateway [--server-name NAME] -- <upstream-command> [args...]\n\nLegacy compatibility adapter for older PreToolUse hooks. New hooks should call `gommage hook`. Gateway mode proxies line-delimited MCP JSON-RPC over stdio, gates tools/call requests through Gommage, and returns MCP tool errors for denied calls without forwarding them upstream.\n\nOPTIONS:\n    --gateway             Run stdio MCP gateway mode\n    --server-name NAME    Server segment used for mcp__NAME__tool capability mapping\n    -h, --help            Print help\n    -V, --version         Print version",
        env!("CARGO_PKG_VERSION")
    );
}

#[path = "mcp/decision.rs"]
mod decision;
#[path = "mcp/enrichment.rs"]
mod enrichment;

use decision::*;
use enrichment::*;

#[cfg(test)]
#[path = "mcp/tests.rs"]
mod tests;
