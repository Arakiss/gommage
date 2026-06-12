use anyhow::Result;
use ed25519_dalek::SigningKey;
use gommage_audit::AuditWriter;
use gommage_core::{Capability, CapabilityMapper, Decision, evaluate_bypass, runtime::HomeLayout};
use std::process::ExitCode;

use crate::{decide_with_pictos, input::tool_call_from_hook_payload};

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
fn run_mcp_bypass(layout: &HomeLayout, buf: &str) -> Result<ExitCode> {
    eprintln!(
        "gommage: WARNING: GOMMAGE_BYPASS=1 is set; skipping policy evaluation (compiled hard-stops still apply)"
    );
    let call = match serde_json::from_str(buf)
        .ok()
        .and_then(|input| tool_call_from_hook_payload(input).ok())
    {
        Some(call) => call,
        None => {
            return write_hook_decision(
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
            write_hook_decision(
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

/// MCP / PreToolUse hook adapter. Reads one Claude Code hook JSON object from
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
pub(crate) fn run_mcp(layout: HomeLayout) -> Result<ExitCode> {
    use anyhow::Context;
    use std::io::Read;

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;

    if bypass_enabled() {
        return run_mcp_bypass(&layout, &buf);
    }

    let input: serde_json::Value = serde_json::from_str(&buf).context("parsing hook input")?;
    let call = tool_call_from_hook_payload(input)?;

    let sk: SigningKey = layout.load_key()?;
    let vk = sk.verifying_key();
    let mut rt = gommage_core::runtime::Runtime::open(layout.clone_layout())?;
    let (eval, events) = decide_with_pictos(&rt, &call, &vk)?;

    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
    for event in events {
        writer.append_event(event)?;
    }
    writer.append(&call, &eval, expedition_name.as_deref())?;

    drop(writer);
    let _ = &mut rt;

    let (decision_str, reason) = match &eval.decision {
        Decision::Allow => ("allow", "gommage allowed".to_string()),
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
    println!("{}", serde_json::to_string(&out)?);
    Ok(ExitCode::SUCCESS)
}

trait CloneLayout {
    fn clone_layout(&self) -> HomeLayout;
}

impl CloneLayout for HomeLayout {
    fn clone_layout(&self) -> HomeLayout {
        HomeLayout::at(&self.root)
    }
}
