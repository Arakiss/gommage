use anyhow::{Context, Result};
use gommage_core::{ToolCall, evaluate, runtime::Runtime};
use std::io::{self, Read};

const MAX_APPLY_PATCH_PATHS: usize = 16;

pub(crate) fn evaluate_only(rt: &Runtime, call: &ToolCall) -> gommage_core::EvalResult {
    let caps = rt.mapper.map(call);
    evaluate(&caps, &rt.policy)
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
    Ok(ToolCall {
        tool: tool_name.to_string(),
        input: enrich_hook_tool_input(tool_name, tool_input, cwd),
    })
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
) -> serde_json::Value {
    let Some(cwd) = cwd else {
        return input;
    };
    let serde_json::Value::Object(map) = &mut input else {
        return input;
    };

    match tool {
        "apply_patch" => enrich_apply_patch_input(map, cwd),
        "Grep" => {
            let base = map
                .get("path")
                .and_then(|v| v.as_str())
                .map(|path| resolve_hook_path(cwd, path))
                .unwrap_or_else(|| cwd.to_string());
            map.entry("__gommage_path".to_string())
                .or_insert_with(|| serde_json::Value::String(base.clone()));
            if let Some(glob) = map.get("glob").and_then(|v| v.as_str()) {
                let glob_path = resolve_hook_path(&base, glob);
                map.entry("__gommage_glob_path".to_string())
                    .or_insert_with(|| serde_json::Value::String(glob_path));
            }
        }
        "Glob" => {
            if let Some(pattern) = map.get("pattern").and_then(|v| v.as_str()) {
                let pattern_path = resolve_hook_path(cwd, pattern);
                map.entry("__gommage_pattern".to_string())
                    .or_insert_with(|| serde_json::Value::String(pattern_path));
            }
        }
        _ => {}
    }

    input
}

fn enrich_apply_patch_input(map: &mut serde_json::Map<String, serde_json::Value>, cwd: &str) {
    map.retain(|key, _| !key.starts_with("__gommage_patch_"));

    let Some(command) = map.get("command").and_then(|v| v.as_str()) else {
        map.insert(
            "__gommage_patch_unparsed".to_string(),
            serde_json::Value::Bool(true),
        );
        return;
    };

    let paths = apply_patch_paths(command);
    if paths.is_empty() {
        map.insert(
            "__gommage_patch_unparsed".to_string(),
            serde_json::Value::Bool(true),
        );
        return;
    }
    if paths.len() > MAX_APPLY_PATCH_PATHS {
        map.insert(
            "__gommage_patch_overflow".to_string(),
            serde_json::Value::Bool(true),
        );
        return;
    }

    for (index, path) in paths.iter().enumerate() {
        if path.starts_with('/') {
            map.insert(
                "__gommage_patch_absolute".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        map.insert(
            format!("__gommage_patch_path_{index}"),
            serde_json::Value::String(resolve_hook_path(cwd, path)),
        );
    }
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
        );

        assert_eq!(input["__gommage_patch_path_0"], "/tmp/proj/src/lib.rs");
        assert_eq!(input["__gommage_patch_path_1"], "/tmp/proj/src/main.rs");
        assert!(input.get("__gommage_patch_unparsed").is_none());
    }

    #[test]
    fn enriches_apply_patch_unparsed_when_command_is_missing() {
        let input = enrich_hook_tool_input("apply_patch", json!({}), Some("/tmp/proj"));

        assert_eq!(input["__gommage_patch_unparsed"], true);
    }
}
