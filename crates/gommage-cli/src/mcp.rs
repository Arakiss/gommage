use anyhow::Result;
use ed25519_dalek::SigningKey;
use gommage_audit::AuditWriter;
use gommage_core::{Decision, runtime::HomeLayout};
use std::process::ExitCode;

use crate::{decide_with_pictos, input::tool_call_from_hook_payload};

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
