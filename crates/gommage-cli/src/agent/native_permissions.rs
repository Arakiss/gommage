use super::*;

pub(super) struct NativePermissionImportGroup {
    pub(super) capability: String,
    pub(super) raws: Vec<String>,
}

pub(super) fn group_native_permission_imports(
    translated: &[NativePermissionImport],
) -> Vec<NativePermissionImportGroup> {
    let mut groups: Vec<NativePermissionImportGroup> = Vec::new();
    for imported in translated {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.capability == imported.capability)
        {
            group.raws.push(imported.raw.clone());
        } else {
            groups.push(NativePermissionImportGroup {
                capability: imported.capability.clone(),
                raws: vec![imported.raw.clone()],
            });
        }
    }
    groups
}

pub(crate) fn translate_claude_permission_deny(raw: &str) -> Option<String> {
    translate_claude_permission_specifier(raw)
}

pub(crate) fn translate_claude_permission_allow(raw: &str) -> Option<String> {
    translate_claude_permission_specifier(raw)
}

pub(super) fn translate_claude_permission_specifier(raw: &str) -> Option<String> {
    if let Some((tool, value)) = raw.split_once('(') {
        let value = value.strip_suffix(')')?;
        let capability = match tool {
            "Read" | "Glob" => format!("fs.read:{}", normalize_native_path_pattern(value)),
            "Grep" => format!("fs.search:{}", normalize_native_path_pattern(value)),
            "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
                format!("fs.write:{}", normalize_native_path_pattern(value))
            }
            "Bash" => format!("proc.exec:{}", normalize_bash_permission_pattern(value)),
            "WebFetch" => format!(
                "net.fetch:{}",
                value.strip_prefix("domain:").unwrap_or(value)
            ),
            tool if tool.starts_with("mcp__") => format!("mcp.call:{tool}"),
            _ => return None,
        };
        return Some(capability);
    }

    let capability = match raw {
        "*" => "**".to_string(),
        "Read" | "Glob" => "fs.read:**".to_string(),
        "Grep" => "fs.search:**".to_string(),
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "fs.write:**".to_string(),
        "Bash" => "proc.exec:*".to_string(),
        "WebFetch" => "net.fetch:*".to_string(),
        "WebSearch" => "net.search:web".to_string(),
        tool if tool.starts_with("mcp__") && tool.matches("__").count() >= 2 => {
            format!("mcp.call:{tool}")
        }
        _ => return None,
    };
    Some(capability)
}

pub(super) fn normalize_native_path_pattern(raw: &str) -> String {
    if raw == "*" || raw == "**" {
        "**".to_string()
    } else if raw == "~" {
        "${HOME}".to_string()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        format!("${{HOME}}/{rest}")
    } else if raw == "." || raw == "./" {
        "${EXPEDITION_ROOT}/**".to_string()
    } else if let Some(rest) = raw.strip_prefix("./") {
        format!("${{EXPEDITION_ROOT}}/{rest}")
    } else {
        raw.to_string()
    }
}

pub(super) fn normalize_bash_permission_pattern(raw: &str) -> String {
    raw.replace(":*", "*")
}

pub(crate) fn claude_gommage_matcher(_settings: &serde_json::Value) -> String {
    "*".to_string()
}

pub(super) fn install_json_hook_group(
    root: &mut serde_json::Value,
    path: &[&str],
    group: serde_json::Value,
    replace_hooks: bool,
    agent: AgentKind,
) -> Result<()> {
    let canonical_command = group
        .pointer("/hooks/0/command")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let pre_tool_use = ensure_array_path(root, path)?;
    if replace_hooks {
        pre_tool_use.clear();
    } else {
        remove_owned_hook_commands(pre_tool_use, agent, canonical_command.as_deref());
        if !pre_tool_use.is_empty() {
            println!(
                "warn {}: preserving existing PreToolUse hook group(s); use --replace-hooks to let Gommage own the hook surface",
                agent.as_str()
            );
        }
    }
    pre_tool_use.push(group);
    Ok(())
}

pub(super) fn ensure_array_path<'a>(
    root: &'a mut serde_json::Value,
    path: &[&str],
) -> Result<&'a mut Vec<serde_json::Value>> {
    let mut current = root;
    for key in &path[..path.len() - 1] {
        if !current.is_object() {
            anyhow::bail!("expected JSON object while creating {key}");
        }
        let object = current.as_object_mut().expect("checked object");
        current = object
            .entry((*key).to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let key = path[path.len() - 1];
    if !current.is_object() {
        anyhow::bail!("expected JSON object while creating {key}");
    }
    let value = current
        .as_object_mut()
        .expect("checked object")
        .entry(key.to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !value.is_array() {
        anyhow::bail!("{key} exists but is not an array");
    }
    Ok(value.as_array_mut().expect("checked array"))
}

pub(super) fn remove_owned_hook_commands(
    groups: &mut Vec<serde_json::Value>,
    agent: AgentKind,
    canonical_command: Option<&str>,
) {
    groups.retain_mut(|entry| {
        let Some(hooks) = entry
            .get_mut("hooks")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return true;
        };
        hooks.retain(|hook| {
            !hook
                .get("command")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|command| {
                    hook_command_is_owned_by_gommage(command, agent, canonical_command)
                })
        });
        !hooks.is_empty()
    });
}

pub(crate) fn hook_command_is_owned_by_gommage(
    command: &str,
    agent: AgentKind,
    canonical_command: Option<&str>,
) -> bool {
    let command = command.trim();
    if canonical_command.is_some_and(|expected| command == expected.trim())
        || command == legacy_agent_hook_command(agent)
    {
        return true;
    }

    let Some(words) = simple_shell_command_words(command) else {
        return false;
    };
    let mut command_index = 0;
    while words
        .get(command_index)
        .is_some_and(|word| is_shell_assignment(word))
    {
        command_index += 1;
    }
    let Some(executable) = words.get(command_index) else {
        return false;
    };
    let executable_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    if executable_name == "gommage-mcp" {
        return true;
    }
    if agent == AgentKind::Codex && executable_name == "gommage-codex-pretooluse.sh" {
        return true;
    }
    if executable_name != "gommage" {
        return false;
    }

    let mut args = &words[command_index + 1..];
    if matches!(args, [home, ..] if home.starts_with("--home=")) {
        args = &args[1..];
    } else if args.len() >= 2 && args.first().is_some_and(|arg| arg == "--home") {
        args = &args[2..];
    }
    match args.first().map(String::as_str) {
        Some("mcp") => true,
        Some("hook") => {
            args.windows(2).any(|pair| {
                pair.first().map(String::as_str) == Some("--agent")
                    && pair.get(1).map(String::as_str) == Some(agent.as_str())
            }) || args
                .iter()
                .any(|arg| arg == &format!("--agent={}", agent.as_str()))
        }
        _ => false,
    }
}

pub(super) fn is_shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub(super) fn simple_shell_command_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                _ => current.push(ch),
            },
            Some(_) => unreachable!(),
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => escaped = true,
                // A compound shell expression is not wholly owned by Gommage,
                // even when its first command is. Preserve the hook rather
                // than deleting operator-provided work after a separator.
                ';' | '|' | '&' | '\n' | '\r' => return None,
                _ if ch.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    Some(words)
}
