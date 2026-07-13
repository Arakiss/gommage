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
    ApprovalWebhookSource, Capability, CapabilityMapper, Decision, EvalResult, PictoConsume,
    PictoLookup, ToolCall, approval_webhook_generic_payload, deliver_prepared_approval_webhook,
    evaluate, evaluate_bypass, prepare_approval_webhook,
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

fn enrich_tool_input(tool: &str, mut input: Value, cwd: Option<&str>) -> Value {
    let Value::Object(map) = &mut input else {
        return input;
    };

    strip_internal_fields(map);

    let Some(cwd) = cwd else {
        return input;
    };

    match tool {
        "Read" => {
            enrich_resolved_path(map, cwd, "file_path", "__gommage_file_path");
        }
        "Write" | "Edit" | "MultiEdit" => {
            if let Some(path) = enrich_resolved_path(map, cwd, "file_path", "__gommage_file_path") {
                add_git_write_contexts(map, [path]);
            }
        }
        "NotebookEdit" => {
            if let Some(path) =
                enrich_resolved_path(map, cwd, "notebook_path", "__gommage_notebook_path")
            {
                add_git_write_contexts(map, [path]);
            }
        }
        "apply_patch" => {
            let paths = enrich_apply_patch_input(map, cwd);
            add_git_write_contexts(map, paths);
        }
        "Bash" => enrich_bash_input(map, cwd),
        "Grep" => {
            let base = map
                .get("path")
                .and_then(Value::as_str)
                .map(|path| resolve_hook_path(cwd, path))
                .unwrap_or_else(|| cwd.to_string());
            map.insert("__gommage_path".to_string(), Value::String(base.clone()));
            if let Some(glob) = map.get("glob").and_then(Value::as_str) {
                let glob_path = resolve_hook_path(&base, glob);
                map.insert("__gommage_glob_path".to_string(), Value::String(glob_path));
            }
        }
        "Glob" => {
            if let Some(pattern) = map.get("pattern").and_then(Value::as_str) {
                let pattern_path = resolve_hook_path(cwd, pattern);
                map.insert("__gommage_pattern".to_string(), Value::String(pattern_path));
            }
        }
        _ => {}
    }

    input
}

fn strip_internal_fields(map: &mut serde_json::Map<String, Value>) {
    map.retain(|key, _| !key.starts_with("__gommage_"));
}

fn enrich_resolved_path(
    map: &mut serde_json::Map<String, Value>,
    cwd: &str,
    source_key: &str,
    target_key: &str,
) -> Option<String> {
    let path = map.get(source_key).and_then(Value::as_str)?;
    let resolved = resolve_hook_path(cwd, path);
    map.insert(target_key.to_string(), Value::String(resolved.clone()));
    Some(resolved)
}

fn enrich_bash_input(map: &mut serde_json::Map<String, Value>, cwd: &str) {
    map.insert("__gommage_cwd".to_string(), Value::String(cwd.to_string()));
    if let Some(branch) = git_branch_for_path(cwd) {
        map.insert(
            "__gommage_cwd_git_branch".to_string(),
            Value::String(branch),
        );
    }
    let Some(command) = map.get("command").and_then(Value::as_str) else {
        return;
    };
    let paths = gommage_core::shell_write_targets(command)
        .into_iter()
        .map(|path| resolve_hook_path(cwd, &path))
        .collect::<Vec<_>>();
    add_git_write_contexts(map, paths);
}

fn enrich_apply_patch_input(map: &mut serde_json::Map<String, Value>, cwd: &str) -> Vec<String> {
    let Some(command) = map.get("command").and_then(Value::as_str) else {
        map.insert("__gommage_patch_unparsed".to_string(), Value::Bool(true));
        return Vec::new();
    };

    let paths = apply_patch_paths(command);
    if paths.is_empty() {
        map.insert("__gommage_patch_unparsed".to_string(), Value::Bool(true));
        return Vec::new();
    }
    if paths.len() > MAX_APPLY_PATCH_PATHS {
        map.insert("__gommage_patch_overflow".to_string(), Value::Bool(true));
        return Vec::new();
    }

    let mut resolved_paths = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        if path.starts_with('/') {
            map.insert("__gommage_patch_absolute".to_string(), Value::Bool(true));
        }
        let resolved = resolve_hook_path(cwd, path);
        map.insert(
            format!("__gommage_patch_path_{index}"),
            Value::String(resolved.clone()),
        );
        resolved_paths.push(resolved);
    }
    resolved_paths
}

fn apply_patch_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in command.lines() {
        for prefix in [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            let Some(path) = line.strip_prefix(prefix) else {
                continue;
            };
            let path = path.trim();
            if !path.is_empty() && !paths.iter().any(|existing| existing == path) {
                paths.push(path.to_string());
            }
        }
    }
    paths
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

fn add_git_write_contexts<I>(map: &mut serde_json::Map<String, Value>, paths: I)
where
    I: IntoIterator<Item = String>,
{
    let mut seen = std::collections::HashSet::new();
    let mut index = 0usize;
    for path in paths {
        if index >= MAX_GIT_WRITE_CONTEXTS {
            break;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        let Some(branch) = git_branch_for_path(&path) else {
            continue;
        };
        map.insert(
            format!("__gommage_git_write_path_{index}"),
            Value::String(path),
        );
        map.insert(
            format!("__gommage_git_write_branch_{index}"),
            Value::String(branch),
        );
        index += 1;
    }
}

fn git_branch_for_path(path: &str) -> Option<String> {
    let anchor = nearest_existing_anchor(Path::new(path))?;
    let output = Command::new("git")
        .arg("-C")
        .arg(anchor)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let branch = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!branch.is_empty()).then_some(branch)
}

fn nearest_existing_anchor(path: &Path) -> Option<PathBuf> {
    let mut current = if path.exists() {
        if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()?.to_path_buf()
        }
    } else {
        path.parent()?.to_path_buf()
    };
    loop {
        if current.exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
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
    let mut lines = TokioBufReader::new(r).lines();
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
        bind_input,
    } = eval.decision.clone()
    {
        let now = time::OffsetDateTime::now_utc();
        let input_hash = call.input_hash();
        let lookup = if bind_input {
            rt.pictos
                .find_verified_match_for_input(&required_scope, &input_hash, now, &vk)?
        } else {
            rt.pictos.find_verified_match(&required_scope, now, &vk)?
        };
        match lookup {
            PictoLookup::None => {
                let request = rt.approvals.request_for_ask(
                    call,
                    &eval,
                    &required_scope,
                    bind_input,
                    &reason,
                )?;
                events.push(AuditEvent::ApprovalRequested {
                    id: request.id.clone(),
                    tool: request.tool.clone(),
                    input_hash: request.input_hash.clone(),
                    required_scope: request.required_scope.clone(),
                    reason: request.reason.clone(),
                    policy_version: request.policy_version.clone(),
                });
                for event in notify_approval_webhook_best_effort(&request) {
                    events.push(event);
                }
                eval.decision = Decision::AskPicto {
                    required_scope,
                    reason: approval_reason(&reason, &request.id),
                    bind_input,
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
                let consume = if bind_input {
                    rt.pictos
                        .consume_verified_for_input(&picto.id, &input_hash, now, &vk)?
                } else {
                    rt.pictos.consume_verified(&picto.id, now, &vk)?
                };
                match consume {
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

fn notify_approval_webhook_best_effort(request: &ApprovalRequest) -> Vec<AuditEvent> {
    let Ok(url) = env::var("GOMMAGE_APPROVAL_WEBHOOK_URL") else {
        return Vec::new();
    };
    if url.trim().is_empty() {
        return Vec::new();
    }
    let payload = approval_webhook_generic_payload(request);
    let Ok(prepared) = prepare_approval_webhook(
        payload,
        env::var("GOMMAGE_APPROVAL_WEBHOOK_SECRET").ok().as_deref(),
        env::var("GOMMAGE_APPROVAL_WEBHOOK_SECRET_ID")
            .ok()
            .as_deref(),
    ) else {
        return Vec::new();
    };
    let layout = HomeLayout::default();
    let settings = ApprovalWebhookDeliverySettings::from_env();
    match deliver_prepared_approval_webhook(
        &layout,
        request,
        ApprovalWebhookSource::McpFallback,
        "generic",
        &url,
        &prepared,
        &settings,
    ) {
        Ok(outcome) if outcome.kind == ApprovalWebhookDeliveryKind::Delivered => {
            vec![AuditEvent::ApprovalWebhookDelivered {
                id: request.id.clone(),
                url,
                status: outcome.http_status,
                attempts: outcome.attempts,
                source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                signature: outcome.signature.as_ref().map(signature_audit_summary),
            }]
        }
        Ok(outcome) => {
            let error = outcome
                .error
                .clone()
                .unwrap_or_else(|| "webhook delivery failed".to_string());
            vec![
                AuditEvent::ApprovalWebhookFailed {
                    id: request.id.clone(),
                    url: url.clone(),
                    error: error.clone(),
                    attempts: outcome.attempts,
                    source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                    signature: outcome.signature.as_ref().map(signature_audit_summary),
                },
                AuditEvent::ApprovalWebhookDeadLettered {
                    id: request.id.clone(),
                    url,
                    dead_letter_id: outcome
                        .dead_letter_id
                        .clone()
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    provider: "generic".to_string(),
                    attempts: outcome.attempts,
                    source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
                    error,
                    signature: outcome.signature.as_ref().map(signature_audit_summary),
                },
            ]
        }
        Err(error) => vec![AuditEvent::ApprovalWebhookFailed {
            id: request.id.clone(),
            url,
            error: error.to_string(),
            attempts: settings.attempts,
            source: ApprovalWebhookSource::McpFallback.as_str().to_string(),
            signature: prepared.signature.as_ref().map(signature_audit_summary),
        }],
    }
}

fn signature_audit_summary(
    signature: &WebhookSignatureReport,
) -> gommage_audit::WebhookSignatureAudit {
    gommage_audit::WebhookSignatureAudit {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        timestamp: signature.timestamp.clone(),
        body_sha256: signature.body_sha256.clone(),
        signature_prefix: signature.signature.chars().take(18).collect(),
    }
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
    fn strips_and_recomputes_existing_reserved_fields() {
        let input = enrich_tool_input(
            "Grep",
            json!({"pattern": "todo", "__gommage_path": "/already"}),
            Some("/tmp/proj"),
        );
        assert_eq!(input["__gommage_path"], "/tmp/proj");
    }

    #[test]
    fn strips_reserved_fields_even_without_cwd() {
        let input = enrich_tool_input(
            "Write",
            json!({"file_path": "src/lib.rs", "__gommage_file_path": "/spoofed"}),
            None,
        );
        assert!(input.get("__gommage_file_path").is_none());
    }

    #[test]
    fn enriches_apply_patch_with_resolved_patch_paths() {
        let input = enrich_tool_input(
            "apply_patch",
            json!({
                "command": "*** Begin Patch\n*** Update File: src/lib.rs\n*** Delete File: old.rs\n*** End Patch\n"
            }),
            Some("/tmp/proj"),
        );
        assert_eq!(input["__gommage_patch_path_0"], "/tmp/proj/src/lib.rs");
        assert_eq!(input["__gommage_patch_path_1"], "/tmp/proj/old.rs");
    }

    #[test]
    fn enriches_apply_patch_unparsed_when_command_is_missing() {
        let input = enrich_tool_input("apply_patch", json!({}), Some("/tmp/proj"));
        assert_eq!(input["__gommage_patch_unparsed"], true);
    }
}
