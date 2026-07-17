use anyhow::{Context, Result};
use gommage_core::{CapabilityMapper, Policy, ToolCall, evaluate};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

const MAX_APPLY_PATCH_PATHS: usize = 16;
const MAX_GIT_WRITE_CONTEXTS: usize = 16;

pub(crate) fn evaluate_only(
    mapper: &CapabilityMapper,
    policy: &Policy,
    call: &ToolCall,
) -> gommage_core::EvalResult {
    let caps = mapper.map(call);
    evaluate(&caps, policy)
}

pub(crate) fn read_tool_call_from_stdin(hook: bool) -> Result<ToolCall> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    if hook {
        let input: serde_json::Value =
            serde_json::from_str(&buf).context("parsing stdin as hook payload")?;
        tool_call_from_hook_payload(input)
    } else {
        let input: serde_json::Value =
            serde_json::from_str(&buf).context("parsing stdin as ToolCall")?;
        if looks_like_hook_payload(&input) {
            anyhow::bail!(
                "parsing stdin as ToolCall: received a PreToolUse hook payload; use --hook when passing tool_name/tool_input JSON"
            );
        }
        serde_json::from_value(input).context("parsing stdin as ToolCall")
    }
}

fn looks_like_hook_payload(input: &serde_json::Value) -> bool {
    input.get("tool_name").is_some()
        || input.get("tool_input").is_some()
        || input
            .get("hook_event_name")
            .and_then(|value| value.as_str())
            .is_some_and(|name| name == "PreToolUse")
}

pub(crate) fn tool_call_from_hook_payload(input: serde_json::Value) -> Result<ToolCall> {
    let tool_name = input
        .get("tool_name")
        .and_then(|v| v.as_str())
        .context("missing tool_name")?;
    let tool_input = input
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cwd = input.get("cwd").and_then(|v| v.as_str());
    let session_id = hook_session_id(&input)?;
    Ok(ToolCall {
        tool: tool_name.to_string(),
        input: enrich_hook_tool_input(tool_name, tool_input, cwd, session_id)?,
    })
}

fn hook_session_id(input: &serde_json::Value) -> Result<Option<&str>> {
    match input.get("session_id") {
        None => Ok(None),
        Some(serde_json::Value::String(session_id)) if !session_id.is_empty() => {
            Ok(Some(session_id))
        }
        Some(serde_json::Value::String(_)) => anyhow::bail!("hook session_id must not be empty"),
        Some(_) => anyhow::bail!("hook session_id must be a string"),
    }
}

pub(crate) fn bash_call(command: &str) -> ToolCall {
    ToolCall {
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": command }),
    }
}

pub(crate) fn enrich_hook_tool_input(
    tool: &str,
    mut input: serde_json::Value,
    cwd: Option<&str>,
    session_id: Option<&str>,
) -> Result<serde_json::Value> {
    let serde_json::Value::Object(map) = &mut input else {
        if session_id.is_some() {
            anyhow::bail!("hook tool_input must be an object when session_id is present");
        }
        return Ok(input);
    };

    strip_internal_fields(map);

    if let Some(session_id) = session_id {
        map.insert(
            "__gommage_session_hash".to_string(),
            serde_json::Value::String(ToolCall::host_session_hash(session_id)),
        );
    }

    let Some(cwd) = cwd else {
        return Ok(input);
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
                .and_then(|v| v.as_str())
                .map(|path| resolve_hook_path(cwd, path))
                .unwrap_or_else(|| cwd.to_string());
            map.insert(
                "__gommage_path".to_string(),
                serde_json::Value::String(base.clone()),
            );
            if let Some(glob) = map.get("glob").and_then(|v| v.as_str()) {
                let glob_path = resolve_hook_path(&base, glob);
                map.insert(
                    "__gommage_glob_path".to_string(),
                    serde_json::Value::String(glob_path),
                );
            }
        }
        "Glob" => {
            if let Some(pattern) = map.get("pattern").and_then(|v| v.as_str()) {
                let pattern_path = resolve_hook_path(cwd, pattern);
                map.insert(
                    "__gommage_pattern".to_string(),
                    serde_json::Value::String(pattern_path),
                );
            }
        }
        _ => {}
    }

    Ok(input)
}

fn strip_internal_fields(map: &mut serde_json::Map<String, serde_json::Value>) {
    map.retain(|key, _| !key.starts_with("__gommage_"));
}

fn enrich_resolved_path(
    map: &mut serde_json::Map<String, serde_json::Value>,
    cwd: &str,
    source_key: &str,
    target_key: &str,
) -> Option<String> {
    let path = map.get(source_key).and_then(|v| v.as_str())?;
    let resolved = resolve_hook_path(cwd, path);
    map.insert(
        target_key.to_string(),
        serde_json::Value::String(resolved.clone()),
    );
    Some(resolved)
}

fn enrich_bash_input(map: &mut serde_json::Map<String, serde_json::Value>, cwd: &str) {
    map.insert(
        "__gommage_cwd".to_string(),
        serde_json::Value::String(cwd.to_string()),
    );
    if let Some(branch) = git_branch_for_path(cwd) {
        map.insert(
            "__gommage_cwd_git_branch".to_string(),
            serde_json::Value::String(branch),
        );
    }
    let Some(command) = map.get("command").and_then(|v| v.as_str()) else {
        return;
    };
    let paths = gommage_core::shell_write_targets(command)
        .into_iter()
        .map(|path| resolve_hook_path(cwd, &path))
        .collect::<Vec<_>>();
    add_git_write_contexts(map, paths);
}

fn enrich_apply_patch_input(
    map: &mut serde_json::Map<String, serde_json::Value>,
    cwd: &str,
) -> Vec<String> {
    let Some(command) = map.get("command").and_then(|v| v.as_str()) else {
        map.insert(
            "__gommage_patch_unparsed".to_string(),
            serde_json::Value::Bool(true),
        );
        return Vec::new();
    };

    let paths = apply_patch_paths(command);
    if paths.is_empty() {
        map.insert(
            "__gommage_patch_unparsed".to_string(),
            serde_json::Value::Bool(true),
        );
        return Vec::new();
    }
    if paths.len() > MAX_APPLY_PATCH_PATHS {
        map.insert(
            "__gommage_patch_overflow".to_string(),
            serde_json::Value::Bool(true),
        );
        return Vec::new();
    }

    let mut resolved_paths = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        if path.starts_with('/') {
            map.insert(
                "__gommage_patch_absolute".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        let resolved = resolve_hook_path(cwd, path);
        map.insert(
            format!("__gommage_patch_path_{index}"),
            serde_json::Value::String(resolved.clone()),
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

fn add_git_write_contexts<I>(map: &mut serde_json::Map<String, serde_json::Value>, paths: I)
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
            serde_json::Value::String(path),
        );
        map.insert(
            format!("__gommage_git_write_branch_{index}"),
            serde_json::Value::String(branch),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enriches_apply_patch_with_resolved_patch_paths() {
        let input = enrich_hook_tool_input(
            "apply_patch",
            json!({
                "command": "*** Begin Patch\n*** Update File: src/lib.rs\n*** Move to: src/main.rs\n*** End Patch\n"
            }),
            Some("/tmp/proj"),
            None,
        )
        .unwrap();

        assert_eq!(input["__gommage_patch_path_0"], "/tmp/proj/src/lib.rs");
        assert_eq!(input["__gommage_patch_path_1"], "/tmp/proj/src/main.rs");
        assert!(input.get("__gommage_patch_unparsed").is_none());
    }

    #[test]
    fn enriches_apply_patch_unparsed_when_command_is_missing() {
        let input =
            enrich_hook_tool_input("apply_patch", json!({}), Some("/tmp/proj"), None).unwrap();

        assert_eq!(input["__gommage_patch_unparsed"], true);
    }

    #[test]
    fn enriches_relative_write_paths_against_cwd() {
        let input = enrich_hook_tool_input(
            "Write",
            json!({"file_path": "src/lib.rs", "__gommage_file_path": "/spoofed"}),
            Some("/tmp/proj"),
            None,
        )
        .unwrap();

        assert_eq!(input["__gommage_file_path"], "/tmp/proj/src/lib.rs");
    }

    #[test]
    fn enriches_bash_with_cwd_and_write_targets() {
        let input = enrich_hook_tool_input(
            "Bash",
            json!({"command": "cat > src/lib.rs <<EOF\nx\nEOF"}),
            Some("/tmp/proj"),
            None,
        )
        .unwrap();

        assert_eq!(input["__gommage_cwd"], "/tmp/proj");
    }

    #[test]
    fn strips_reserved_fields_even_without_cwd() {
        let input = enrich_hook_tool_input(
            "Write",
            json!({"file_path": "src/lib.rs", "__gommage_file_path": "/spoofed"}),
            None,
            None,
        )
        .unwrap();

        assert!(input.get("__gommage_file_path").is_none());
    }

    #[test]
    fn hook_session_hash_is_domain_separated_and_spoof_resistant() {
        let payload = json!({
            "session_id": "session-a",
            "tool_name": "mcp__node_repl__js",
            "tool_input": {
                "code": "1 + 1",
                "__gommage_session_hash": "sha256:spoofed"
            }
        });

        let call = tool_call_from_hook_payload(payload).unwrap();
        assert_eq!(
            call.input["__gommage_session_hash"],
            ToolCall::host_session_hash("session-a")
        );
        assert_ne!(
            call.input["__gommage_session_hash"],
            serde_json::Value::String("sha256:spoofed".to_string())
        );
        assert_eq!(
            call.input_hash(),
            "sha256:caf2b377b4cd0bcce801a72468fd232cf08a2bc2b1141990a3fceeaafa6a11c9"
        );
        assert!(
            !serde_json::to_string(&call.input)
                .unwrap()
                .contains("session-a")
        );
    }

    #[test]
    fn hook_session_changes_hash_but_absence_is_stable() {
        let payload = |session_id: Option<&str>| {
            let mut value = json!({
                "tool_name": "mcp__node_repl__js",
                "tool_input": {"code": "1 + 1"}
            });
            if let Some(session_id) = session_id {
                value["session_id"] = json!(session_id);
            }
            tool_call_from_hook_payload(value).unwrap()
        };

        assert_ne!(
            payload(Some("session-a")).input_hash(),
            payload(Some("session-b")).input_hash()
        );
        let without_session = payload(None);
        assert_eq!(without_session.input_hash(), payload(None).input_hash());
        assert!(
            without_session
                .input
                .get("__gommage_session_hash")
                .is_none()
        );
    }

    #[test]
    fn hook_session_rejects_non_object_tool_input() {
        let error = tool_call_from_hook_payload(json!({
            "session_id": "session-a",
            "tool_name": "mcp__node_repl__js",
            "tool_input": "1 + 1"
        }))
        .unwrap_err();

        assert!(error.to_string().contains("tool_input must be an object"));
    }

    #[test]
    fn hook_session_rejects_empty_or_non_string_identifiers() {
        for session_id in [json!(""), json!(null), json!(42)] {
            let error = tool_call_from_hook_payload(json!({
                "session_id": session_id,
                "tool_name": "mcp__node_repl__js",
                "tool_input": {"code": "1 + 1"}
            }))
            .unwrap_err();

            assert!(error.to_string().contains("hook session_id must"));
        }
    }
}
