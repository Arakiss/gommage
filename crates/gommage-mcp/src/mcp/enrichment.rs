use super::*;

pub(super) fn enrich_tool_input(
    tool: &str,
    mut input: Value,
    cwd: Option<&str>,
    session_id: Option<&str>,
) -> Result<Value> {
    let Value::Object(map) = &mut input else {
        if session_id.is_some() {
            anyhow::bail!("hook tool_input must be an object when session_id is present");
        }
        return Ok(input);
    };

    strip_internal_fields(map);

    if let Some(session_id) = session_id {
        map.insert(
            "__gommage_session_hash".to_string(),
            Value::String(ToolCall::host_session_hash(session_id)),
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

    Ok(input)
}

pub(super) fn strip_internal_fields(map: &mut serde_json::Map<String, Value>) {
    map.retain(|key, _| !key.starts_with("__gommage_"));
}

pub(super) fn enrich_resolved_path(
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

pub(super) fn enrich_bash_input(map: &mut serde_json::Map<String, Value>, cwd: &str) {
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

pub(super) fn enrich_apply_patch_input(
    map: &mut serde_json::Map<String, Value>,
    cwd: &str,
) -> Vec<String> {
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

pub(super) fn apply_patch_paths(command: &str) -> Vec<String> {
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

pub(super) fn resolve_hook_path(base: &str, path: &str) -> String {
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

pub(super) fn add_git_write_contexts<I>(map: &mut serde_json::Map<String, Value>, paths: I)
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

pub(super) fn git_branch_for_path(path: &str) -> Option<String> {
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

pub(super) fn nearest_existing_anchor(path: &Path) -> Option<PathBuf> {
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
