use anyhow::{Context, Result};
use clap::ValueEnum;
use ed25519_dalek::SigningKey;
use gommage_audit::AuditWriter;
use gommage_core::{Capability, CapabilityMapper, Decision, evaluate_bypass, runtime::HomeLayout};
use std::process::ExitCode;

use crate::{decide_with_pictos, input::tool_call_from_hook_payload};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum HookAgent {
    Auto,
    Claude,
    Codex,
}

impl std::fmt::Display for HookAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Claude => "claude",
            Self::Codex => "codex",
        })
    }
}

/// True when the kill-switch env var is set. Mirrors the standalone
/// `gommage-mcp` binary so a legacy install whose hook command is
/// `gommage mcp` honours `GOMMAGE_BYPASS=1` identically.
fn bypass_enabled() -> bool {
    std::env::var("GOMMAGE_BYPASS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn write_hook_decision(decision: &str, reason: &str) -> Result<ExitCode> {
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(ExitCode::SUCCESS)
}

/// Handle a hook call under `GOMMAGE_BYPASS=1`: skip policy evaluation but keep
/// the compiled hard-stops and the signed audit trail. Checked before opening
/// the runtime so the kill-switch still works when the on-disk policy is broken.
fn run_mcp_bypass(layout: &HomeLayout, buf: &str, agent: HookAgent) -> Result<ExitCode> {
    eprintln!(
        "gommage: WARNING: GOMMAGE_BYPASS=1 is set; skipping policy evaluation (compiled hard-stops still apply)"
    );
    let call = match serde_json::from_str(buf)
        .ok()
        .and_then(|input| tool_call_from_hook_payload(input).ok())
    {
        Some(call) => call,
        None => {
            return write_allow_decision(
                agent,
                "allow",
                "gommage bypass: GOMMAGE_BYPASS=1 was set, but the hook payload could not be parsed; policy evaluation skipped for hook recovery",
            );
        }
    };
    let eval = evaluate_bypass(bypass_capabilities(&call));
    match &eval.decision {
        Decision::Gommage { reason, .. } => {
            gommage_audit::append_bypass_event_best_effort(layout, &call, &eval, "deny");
            write_hook_decision(
                "deny",
                &format!("gommage bypass refused: {reason}; hard-stops cannot be bypassed"),
            )
        }
        _ => {
            gommage_audit::append_bypass_event_best_effort(layout, &call, &eval, "allow");
            write_allow_decision(
                agent,
                "allow",
                "gommage bypass: GOMMAGE_BYPASS=1 was set by the host environment; policy evaluation skipped after hard-stop check",
            )
        }
    }
}

/// Map a tool call to capabilities using the compiled-in stdlib mappers for the
/// bypass path (mirrors the standalone `gommage-mcp` binary). Kept local rather
/// than in `gommage-stdlib` so the crate graph stays acyclic for the release
/// tooling. Falls back to a bare `proc.exec:<command>` if the bundled mappers
/// fail to compile, so a compiled hard-stop on the raw command still fires.
fn bypass_capabilities(call: &gommage_core::ToolCall) -> Vec<Capability> {
    let yaml = gommage_stdlib::CAPABILITIES
        .iter()
        .map(|file| file.contents)
        .collect::<Vec<_>>()
        .join("\n");
    match CapabilityMapper::from_yaml_string(&yaml, "<compiled-stdlib-capabilities>") {
        Ok(mapper) => mapper.map(call),
        Err(_) => {
            if call.tool == "Bash"
                && let Some(command) = call.input.get("command").and_then(|value| value.as_str())
            {
                return vec![Capability::new(format!("proc.exec:{command}"))];
            }
            Vec::new()
        }
    }
}

/// Legacy MCP-named entrypoint for older hooks whose command is `gommage mcp`.
pub(crate) fn run_mcp(layout: HomeLayout) -> Result<ExitCode> {
    run_hook(layout, HookAgent::Auto)
}

/// PreToolUse hook adapter. Reads one Claude Code/Codex hook JSON object from
/// stdin and writes one hook response JSON object to stdout.
///
/// Input shape (Claude Code):
/// ```json
/// { "session_id": "...", "hook_event_name": "PreToolUse",
///   "tool_name": "Bash", "tool_input": { "command": "git push origin main" } }
/// ```
/// Output shape:
/// ```json
/// { "hookSpecificOutput": { "hookEventName": "PreToolUse",
///   "permissionDecision": "allow" | "deny" | "ask",
///   "permissionDecisionReason": "..." } }
/// ```
pub(crate) fn run_hook(layout: HomeLayout, agent: HookAgent) -> Result<ExitCode> {
    use std::io::Read;

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;

    if bypass_enabled() {
        return run_mcp_bypass(&layout, &buf, agent);
    }

    let input: serde_json::Value = match serde_json::from_str(&buf).context("parsing hook input") {
        Ok(input) => input,
        Err(error) => {
            return write_hook_decision("deny", &format!("gommage hook failed closed: {error:#}"));
        }
    };
    let call = match tool_call_from_hook_payload(input).context("normalizing hook input") {
        Ok(call) => call,
        Err(error) => {
            return write_hook_decision("deny", &format!("gommage hook failed closed: {error:#}"));
        }
    };

    let eval = match decide_call(&layout, &call).context("evaluating policy") {
        Ok(eval) => eval,
        Err(error) => {
            return write_hook_decision("deny", &format!("gommage hook failed closed: {error:#}"));
        }
    };

    write_eval_decision(&eval, agent)
}

fn decide_call(
    layout: &HomeLayout,
    call: &gommage_core::ToolCall,
) -> Result<gommage_core::EvalResult> {
    match forward_to_daemon(layout, call) {
        Ok(eval) => Ok(eval),
        Err(error) if is_missing_daemon(&error) => {
            eprintln!(
                "gommage hook: daemon socket unavailable; evaluating policy in-process and writing the audit entry directly"
            );
            decide_in_process_and_audit(layout, call)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn forward_to_daemon(
    layout: &HomeLayout,
    call: &gommage_core::ToolCall,
) -> Result<gommage_core::EvalResult> {
    use std::{
        io::{BufRead, BufReader, Write as _},
        os::unix::net::UnixStream,
    };

    let mut stream = UnixStream::connect(&layout.socket)?;
    let req = serde_json::json!({ "op": "decide", "call": call });
    writeln!(stream, "{}", serde_json::to_string(&req)?)?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let resp: serde_json::Value = serde_json::from_str(&line)?;
    if resp.get("ok").and_then(|value| value.as_bool()) == Some(true) {
        let result = resp.get("result").cloned().context("missing result")?;
        return serde_json::from_value(result).context("parsing daemon decision");
    }
    anyhow::bail!(
        "daemon returned error: {}",
        resp.get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("<none>")
    );
}

#[cfg(not(unix))]
fn forward_to_daemon(
    _layout: &HomeLayout,
    _call: &gommage_core::ToolCall,
) -> Result<gommage_core::EvalResult> {
    anyhow::bail!("daemon IPC is unavailable on this platform")
}

fn is_missing_daemon(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        )
    })
}

fn decide_in_process_and_audit(
    layout: &HomeLayout,
    call: &gommage_core::ToolCall,
) -> Result<gommage_core::EvalResult> {
    let sk: SigningKey = layout.load_key().context("loading Gommage signing key")?;
    let vk = sk.verifying_key();
    let mut rt = gommage_core::runtime::Runtime::open(layout.clone_layout())
        .context("opening Gommage runtime")?;
    let (eval, events) = decide_with_pictos(&rt, call, &vk).context("evaluating policy")?;
    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer =
        AuditWriter::open(&rt.layout.audit_log, sk).context("opening Gommage audit writer")?;
    for event in events {
        writer
            .append_event(event)
            .context("writing hook audit event")?;
    }
    writer
        .append(call, &eval, expedition_name.as_deref())
        .context("writing hook audit decision")?;

    drop(writer);
    let _ = &mut rt;
    Ok(eval)
}

fn write_eval_decision(eval: &gommage_core::EvalResult, agent: HookAgent) -> Result<ExitCode> {
    let (decision_str, reason) = match &eval.decision {
        Decision::Allow => return write_allow_decision(agent, "allow", "gommage allowed"),
        Decision::Gommage { reason, hard_stop } => (
            "deny",
            if *hard_stop {
                format!("gommaged (hard-stop): {reason}")
            } else {
                format!("gommaged: {reason}")
            },
        ),
        Decision::AskPicto {
            reason,
            required_scope,
            bind_input,
        } if agent == HookAgent::Codex => (
            "deny",
            format!(
                "gommage: requires {} for scope {required_scope:?} — {reason} (Codex PreToolUse does not support ask yet; denied instead.)",
                picto_requirement(*bind_input)
            ),
        ),
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
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision_str,
            "permissionDecisionReason": reason,
        }
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(ExitCode::SUCCESS)
}

fn picto_requirement(bind_input: bool) -> &'static str {
    if bind_input {
        "an exact-input picto"
    } else {
        "a picto"
    }
}

fn write_allow_decision(agent: HookAgent, decision: &str, reason: &str) -> Result<ExitCode> {
    if agent == HookAgent::Codex {
        return Ok(ExitCode::SUCCESS);
    }
    write_hook_decision(decision, reason)
}

trait CloneLayout {
    fn clone_layout(&self) -> HomeLayout;
}

impl CloneLayout for HomeLayout {
    fn clone_layout(&self) -> HomeLayout {
        HomeLayout::at(&self.root)
    }
}
