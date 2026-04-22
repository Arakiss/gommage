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
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalRequest, Capability, CapabilityMapper, Decision, EvalResult, MatchedRule, PictoConsume,
    PictoLookup, ToolCall, evaluate, hardstop,
    runtime::{HomeLayout, Runtime},
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    env,
    io::{self, Read, Write},
    process::{Command, Stdio},
};
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
    #[serde(default)]
    cwd: Option<String>,
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    if handle_info_flag()? {
        return Ok(());
    }

    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;
    if bypass_enabled() {
        return handle_bypass(&buf);
    }

    let call = parse_hook_tool_call(&buf)?;

    let layout = HomeLayout::default();
    layout.ensure()?;

    let eval = match forward_to_daemon(&layout, &call).await {
        Ok(e) => e,
        Err(e) if is_missing_daemon(&e) => decide_in_process_and_audit(&layout, &call)?,
        Err(e) => return Err(e),
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
    write_hook_response(decision_str, &reason)?;
    Ok(())
}

fn bypass_enabled() -> bool {
    env::var("GOMMAGE_BYPASS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn parse_hook_tool_call(buf: &str) -> Result<ToolCall> {
    let input: HookInput = serde_json::from_str(buf).context("parsing hook JSON")?;
    let tool = input.tool_name;
    let tool_input = enrich_tool_input(&tool, input.tool_input, input.cwd.as_deref());
    Ok(ToolCall {
        tool,
        input: tool_input,
    })
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
    let caps = bypass_capabilities(&call);
    if let Some(hit) = hardstop::check(&caps) {
        let reason = format!(
            "hard-stop {}: pattern {:?} matched {}",
            hit.name, hit.pattern, hit.capability
        );
        let eval = EvalResult {
            decision: Decision::Gommage {
                reason: reason.clone(),
                hard_stop: true,
            },
            matched_rule: Some(MatchedRule {
                name: format!("<hardcoded:{}>", hit.name),
                file: "<compiled-in>".to_string(),
                index: 0,
            }),
            capabilities: caps,
            policy_version: "bypass:compiled-hardstop".to_string(),
        };
        append_bypass_event_best_effort(&layout, &call, &eval, "deny");
        write_hook_response(
            "deny",
            &format!("gommage bypass refused: {reason}; hard-stops cannot be bypassed"),
        )?;
        return Ok(());
    }

    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: caps,
        policy_version: "bypass:policy-skipped".to_string(),
    };
    append_bypass_event_best_effort(&layout, &call, &eval, "allow");
    write_hook_response(
        "allow",
        "gommage bypass: GOMMAGE_BYPASS=1 was set by the host environment; policy evaluation skipped after hard-stop check",
    )?;
    Ok(())
}

fn bypass_capabilities(call: &ToolCall) -> Vec<Capability> {
    let yaml = gommage_stdlib::CAPABILITIES
        .iter()
        .map(|file| file.contents)
        .collect::<Vec<_>>()
        .join("\n");
    match CapabilityMapper::from_yaml_string(&yaml, "<compiled-stdlib-capabilities>") {
        Ok(mapper) => mapper.map(call),
        Err(_) => fallback_capabilities(call),
    }
}

fn fallback_capabilities(call: &ToolCall) -> Vec<Capability> {
    if call.tool == "Bash"
        && let Some(command) = call.input.get("command").and_then(Value::as_str)
    {
        return vec![Capability::new(format!("proc.exec:{command}"))];
    }
    Vec::new()
}

fn append_bypass_event_best_effort(
    layout: &HomeLayout,
    call: &ToolCall,
    eval: &EvalResult,
    bypass_decision: &str,
) {
    let Ok(sk) = layout.load_key() else {
        return;
    };
    let Ok(mut writer) = AuditWriter::open(&layout.audit_log, sk) else {
        return;
    };
    let (original_decision, original_reason, hard_stop) = match &eval.decision {
        Decision::Allow => (
            "allow".to_string(),
            "policy evaluation skipped".to_string(),
            false,
        ),
        Decision::Gommage { reason, hard_stop } => ("deny".to_string(), reason.clone(), *hard_stop),
        Decision::AskPicto { reason, .. } => ("ask".to_string(), reason.clone(), false),
    };
    let _ = writer.append_event(AuditEvent::BypassActivated {
        tool: call.tool.clone(),
        input_hash: call.input_hash(),
        capabilities: eval.capabilities.clone(),
        original_decision,
        original_reason,
        hard_stop,
        bypass_decision: bypass_decision.to_string(),
    });
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

fn handle_info_flag() -> Result<bool> {
    let mut args = env::args().skip(1);
    let Some(arg) = args.next() else {
        return Ok(false);
    };

    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected argument {extra:?}; try --help");
    }

    match arg.as_str() {
        "-V" | "--version" => {
            println!("gommage-mcp {}", env!("CARGO_PKG_VERSION"));
            Ok(true)
        }
        "-h" | "--help" => {
            print_help();
            Ok(true)
        }
        _ => anyhow::bail!("unexpected argument {arg:?}; try --help"),
    }
}

fn print_help() {
    println!(
        "gommage-mcp {}\n\nUSAGE:\n    gommage-mcp < hook.json\n\nReads one Claude Code PreToolUse hook payload from stdin and writes one permission response JSON object to stdout.\n\nOPTIONS:\n    -h, --help       Print help\n    -V, --version    Print version",
        env!("CARGO_PKG_VERSION")
    );
}

fn enrich_tool_input(tool: &str, mut input: Value, cwd: Option<&str>) -> Value {
    let Some(cwd) = cwd else {
        return input;
    };
    let Value::Object(map) = &mut input else {
        return input;
    };

    match tool {
        "Grep" => {
            let base = map
                .get("path")
                .and_then(Value::as_str)
                .map(|path| resolve_hook_path(cwd, path))
                .unwrap_or_else(|| cwd.to_string());
            map.entry("__gommage_path".to_string())
                .or_insert_with(|| Value::String(base.clone()));
            if let Some(glob) = map.get("glob").and_then(Value::as_str) {
                let glob_path = resolve_hook_path(&base, glob);
                map.entry("__gommage_glob_path".to_string())
                    .or_insert_with(|| Value::String(glob_path));
            }
        }
        "Glob" => {
            if let Some(pattern) = map.get("pattern").and_then(Value::as_str) {
                let pattern_path = resolve_hook_path(cwd, pattern);
                map.entry("__gommage_pattern".to_string())
                    .or_insert_with(|| Value::String(pattern_path));
            }
        }
        _ => {}
    }

    input
}

fn resolve_hook_path(base: &str, path: &str) -> String {
    if path.starts_with('/') || path.starts_with('~') {
        return path.to_string();
    }
    if path == "." || path.is_empty() {
        return base.to_string();
    }
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches("./")
    )
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
    call: &ToolCall,
) -> Result<gommage_core::EvalResult> {
    let sk = layout.load_key()?;
    let vk = sk.verifying_key();
    let rt = Runtime::open(HomeLayout::at(&layout.root))?;
    let caps = rt.mapper.map(call);
    let mut eval = evaluate(&caps, &rt.policy);
    let mut events = Vec::new();
    if let Decision::AskPicto {
        required_scope,
        reason,
    } = eval.decision.clone()
    {
        let now = time::OffsetDateTime::now_utc();
        match rt.pictos.find_verified_match(&required_scope, now, &vk)? {
            PictoLookup::None => {
                let request =
                    rt.approvals
                        .request_for_ask(call, &eval, &required_scope, &reason)?;
                events.push(AuditEvent::ApprovalRequested {
                    id: request.id.clone(),
                    tool: request.tool.clone(),
                    input_hash: request.input_hash.clone(),
                    required_scope: request.required_scope.clone(),
                    reason: request.reason.clone(),
                    policy_version: request.policy_version.clone(),
                });
                if let Some(event) = notify_approval_webhook_best_effort(&request) {
                    events.push(event);
                }
                eval.decision = Decision::AskPicto {
                    required_scope,
                    reason: approval_reason(&reason, &request.id),
                };
            }
            PictoLookup::BadSignature { id, scope } => {
                events.push(AuditEvent::PictoRejected {
                    id,
                    scope,
                    reason: "bad signature".to_string(),
                });
            }
            PictoLookup::Verified { picto } => {
                match rt.pictos.consume_verified(&picto.id, now, &vk)? {
                    PictoConsume::Consumed { picto } => {
                        events.push(AuditEvent::PictoConsumed {
                            id: picto.id,
                            scope: picto.scope,
                            uses: picto.uses,
                            max_uses: picto.max_uses,
                            status: picto.status.as_str().to_string(),
                        });
                        eval.decision = Decision::Allow;
                    }
                    PictoConsume::NotUsable => {}
                    PictoConsume::BadSignature { id, scope } => {
                        events.push(AuditEvent::PictoRejected {
                            id,
                            scope,
                            reason: "bad signature".to_string(),
                        });
                    }
                }
            }
        }
    }
    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
    for event in events {
        writer.append_event(event)?;
    }
    writer.append(call, &eval, expedition_name.as_deref())?;
    Ok(eval)
}

fn approval_reason(reason: &str, request_id: &str) -> String {
    format!(
        "{reason}; approval request {request_id} pending; run `gommage approval approve {request_id}`"
    )
}

fn notify_approval_webhook_best_effort(request: &ApprovalRequest) -> Option<AuditEvent> {
    let Ok(url) = env::var("GOMMAGE_APPROVAL_WEBHOOK_URL") else {
        return None;
    };
    if url.trim().is_empty() {
        return None;
    }
    Some(match post_approval_json(&url, request) {
        Ok(status) => AuditEvent::ApprovalWebhookDelivered {
            id: request.id.clone(),
            url,
            status: Some(status),
        },
        Err(error) => AuditEvent::ApprovalWebhookFailed {
            id: request.id.clone(),
            url,
            error: error.to_string(),
        },
    })
}

fn post_approval_json(url: &str, request: &ApprovalRequest) -> Result<i32> {
    let payload = serde_json::json!({
        "kind": "gommage_approval_request",
        "id": request.id,
        "created_at": request.created_at,
        "tool": request.tool,
        "input_hash": request.input_hash,
        "required_scope": request.required_scope,
        "reason": request.reason,
        "capabilities": request.capabilities,
        "matched_rule": request.matched_rule,
        "policy_version": request.policy_version,
        "commands": {
            "approve": format!("gommage approval approve {}", request.id),
            "deny": format!("gommage approval deny {}", request.id)
        }
    });
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--header",
            "content-type: application/json",
            "--request",
            "POST",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting curl for approval webhook delivery")?;
    child
        .stdin
        .take()
        .context("opening curl stdin")?
        .write_all(serde_json::to_string(&payload)?.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enriches_grep_with_hook_cwd_when_path_is_implicit() {
        let input = enrich_tool_input(
            "Grep",
            json!({"pattern": "fn main", "glob": "*.rs"}),
            Some("/tmp/proj"),
        );
        assert_eq!(input["__gommage_path"], "/tmp/proj");
        assert_eq!(input["__gommage_glob_path"], "/tmp/proj/*.rs");
    }

    #[test]
    fn enriches_grep_relative_path_against_hook_cwd() {
        let input = enrich_tool_input(
            "Grep",
            json!({"pattern": "todo", "path": "src"}),
            Some("/tmp/proj"),
        );
        assert_eq!(input["__gommage_path"], "/tmp/proj/src");
    }

    #[test]
    fn leaves_existing_reserved_fields_untouched() {
        let input = enrich_tool_input(
            "Grep",
            json!({"pattern": "todo", "__gommage_path": "/already"}),
            Some("/tmp/proj"),
        );
        assert_eq!(input["__gommage_path"], "/already");
    }
}
