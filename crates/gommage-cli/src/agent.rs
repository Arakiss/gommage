use crate::{
    agent_status::cmd_agent_status,
    agent_uninstall::{AgentUninstallTarget, cmd_agent_uninstall},
    util::{env_path_or_home, read_json_object, read_toml_document, write_json, write_text},
};
use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{path::Path, process::ExitCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Claude,
    Codex,
}

impl AgentKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Install a PreToolUse hook for a supported agent.
    Install {
        #[arg(value_enum)]
        agent: AgentKind,
        /// Replace existing PreToolUse hook groups instead of preserving them.
        #[arg(long)]
        replace_hooks: bool,
        /// Skip importing native agent permission rules into Gommage policy.
        #[arg(long)]
        no_import_native_permissions: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a supported agent integration.
    Uninstall {
        #[arg(value_enum)]
        agent: AgentUninstallTarget,
        /// Restore the newest validated .gommage-bak-* backup instead of only removing the hook.
        #[arg(long)]
        restore_backup: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect whether a supported agent integration is wired correctly.
    Status {
        #[arg(value_enum)]
        agent: AgentKind,
        /// Emit a stable machine-readable status report.
        #[arg(long)]
        json: bool,
    },
}

pub fn cmd_agent(sub: AgentCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        AgentCmd::Install {
            agent,
            replace_hooks,
            no_import_native_permissions,
            dry_run,
        } => {
            install_agent(
                agent,
                &layout,
                replace_hooks,
                !no_import_native_permissions,
                dry_run,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        AgentCmd::Uninstall {
            agent,
            restore_backup,
            dry_run,
        } => cmd_agent_uninstall(agent, restore_backup, dry_run),
        AgentCmd::Status { agent, json } => cmd_agent_status(agent, &layout, json),
    }
}

pub fn install_agent(
    agent: AgentKind,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    dry_run: bool,
) -> Result<()> {
    if !dry_run {
        layout.ensure().context("initializing home")?;
    }
    match agent {
        AgentKind::Claude => {
            let path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
            install_claude(
                &path,
                layout,
                replace_hooks,
                import_native_permissions,
                dry_run,
            )
        }
        AgentKind::Codex => {
            let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
            let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
            install_codex(&hooks_path, &config_path, replace_hooks, dry_run)
        }
    }
}

fn install_claude(
    settings_path: &Path,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    dry_run: bool,
) -> Result<()> {
    let mut settings = read_json_object(settings_path)?;
    if import_native_permissions {
        import_claude_permissions(&settings, layout, replace_hooks, dry_run)?;
    }

    let matcher = claude_gommage_matcher(&settings);
    if matcher.is_empty() {
        println!("warn claude: no currently allowed Claude tools have Gommage capability mappers");
        return Ok(());
    }

    let group = serde_json::json!({
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": "gommage-mcp",
                "timeout": 10
            }
        ]
    });
    install_json_hook_group(
        &mut settings,
        &["hooks", "PreToolUse"],
        group,
        replace_hooks,
        "claude",
    )?;

    write_json(settings_path, &settings, dry_run)?;
    println!(
        "ok claude: PreToolUse hook installed at {}",
        settings_path.display()
    );
    Ok(())
}

fn install_codex(
    hooks_path: &Path,
    config_path: &Path,
    replace_hooks: bool,
    dry_run: bool,
) -> Result<()> {
    let mut hooks = read_json_object(hooks_path)?;
    let group = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "gommage-mcp"
            }
        ]
    });
    install_json_hook_group(&mut hooks, &["PreToolUse"], group, replace_hooks, "codex")?;
    write_json(hooks_path, &hooks, dry_run)?;
    println!(
        "ok codex: PreToolUse hook installed at {}",
        hooks_path.display()
    );

    let mut config = read_toml_document(config_path)?;
    let sandbox_mode = config
        .get("sandbox_mode")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    config["features"]["codex_hooks"] = toml_edit::value(true);
    write_text(config_path, &config.to_string(), dry_run)?;
    println!(
        "ok codex: features.codex_hooks enabled at {}",
        config_path.display()
    );
    if sandbox_mode.as_deref() == Some("danger-full-access") {
        println!(
            "warn codex: sandbox_mode is danger-full-access; Gommage can govern Bash, but Codex file/MCP tools are still outside Gommage's hook coverage"
        );
    }
    println!(
        "warn codex: native sandbox/approval config remains authoritative and is not converted to Gommage YAML"
    );
    Ok(())
}

fn import_claude_permissions(
    settings: &serde_json::Value,
    layout: &HomeLayout,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let deny_path = layout.policy_dir.join("05-claude-import.yaml");
    let deny_rules = native_permission_rules(settings, "/permissions/deny");
    let (translated_denies, skipped_denies) =
        translate_claude_native_rules(&deny_rules, translate_claude_permission_deny);
    write_claude_permission_import(
        &deny_path,
        "Claude Code permissions.deny",
        "Deny imports live before stdlib allow rules so native blocks remain fail-closed.",
        "claude-import-deny",
        "gommage",
        &translated_denies,
        force,
        dry_run,
    )?;
    if translated_denies.is_empty() {
        println!("warn claude: no importable native deny rules found");
    }
    if !skipped_denies.is_empty() {
        println!(
            "warn claude: skipped {} native deny rule(s) that need manual policy review",
            skipped_denies.len()
        );
    }

    let allow_rules = native_permission_rules(settings, "/permissions/allow");
    let (translated_allows, skipped_allows) =
        translate_claude_native_rules(&allow_rules, translate_claude_permission_allow);
    if !allow_rules.is_empty() {
        let allow_path = layout.policy_dir.join("90-claude-allow-import.yaml");
        write_claude_permission_import(
            &allow_path,
            "Claude Code permissions.allow",
            "Allow imports load late so Gommage hard-stop, deny, and ask rules win first.",
            "claude-import-allow",
            "allow",
            &translated_allows,
            force,
            dry_run,
        )?;
        if translated_allows.is_empty() {
            println!("warn claude: no narrow native allow rules were imported");
        }
        if !skipped_allows.is_empty() {
            println!(
                "warn claude: skipped {} native allow rule(s) that need manual policy review",
                skipped_allows.len()
            );
        }
    }
    Ok(())
}

pub(crate) struct NativePermissionImport {
    raw: String,
    capability: String,
}

pub(crate) fn native_permission_rules(settings: &serde_json::Value, pointer: &str) -> Vec<String> {
    settings
        .pointer(pointer)
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

pub(crate) fn translate_claude_native_rules(
    rules: &[String],
    translate: fn(&str) -> Option<String>,
) -> (Vec<NativePermissionImport>, Vec<String>) {
    let mut translated = Vec::new();
    let mut skipped = Vec::new();
    for raw in rules {
        match translate(raw) {
            Some(capability) => translated.push(NativePermissionImport {
                raw: raw.clone(),
                capability,
            }),
            None => skipped.push(raw.clone()),
        }
    }
    (translated, skipped)
}

#[allow(clippy::too_many_arguments)]
fn write_claude_permission_import(
    import_path: &Path,
    source_label: &str,
    ordering_note: &str,
    name_prefix: &str,
    decision: &str,
    translated: &[NativePermissionImport],
    force: bool,
    dry_run: bool,
) -> Result<()> {
    if translated.is_empty() {
        return Ok(());
    }

    let grouped = group_native_permission_imports(translated);
    let mut yaml = String::new();
    yaml.push_str(&format!(
        "# Generated by `gommage quickstart` from {source_label}.\n"
    ));
    yaml.push_str(
        "# Review before sharing; native permission syntax is broader than Gommage capabilities.\n",
    );
    yaml.push_str(&format!("# {ordering_note}\n\n"));
    for (index, imported) in grouped.iter().enumerate() {
        yaml.push_str(&format!("- name: {name_prefix}-{:02}\n", index + 1));
        yaml.push_str(&format!("  decision: {decision}\n"));
        yaml.push_str("  match:\n");
        yaml.push_str("    any_capability:\n");
        yaml.push_str(&format!(
            "      - {}\n",
            serde_json::to_string(&imported.capability)?
        ));
        yaml.push_str(&format!(
            "  reason: {}\n\n",
            serde_json::to_string(&format!(
                "imported from {source_label}: {}",
                imported.raws.join(", ")
            ))?
        ));
    }

    if import_path.exists() && !force {
        let current = std::fs::read_to_string(import_path)?;
        if current == yaml {
            println!(
                "ok claude: native permission import already current at {}",
                import_path.display()
            );
        } else {
            println!(
                "warn claude: {} exists; use --replace-hooks to refresh imported native permissions",
                import_path.display()
            );
        }
    } else {
        write_text(import_path, &yaml, dry_run)?;
        println!(
            "ok claude: imported {} native rule(s) as {} capability rule(s) into {}",
            translated.len(),
            grouped.len(),
            import_path.display()
        );
    }
    Ok(())
}

struct NativePermissionImportGroup {
    capability: String,
    raws: Vec<String>,
}

fn group_native_permission_imports(
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

fn translate_claude_permission_specifier(raw: &str) -> Option<String> {
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

fn normalize_native_path_pattern(raw: &str) -> String {
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

fn normalize_bash_permission_pattern(raw: &str) -> String {
    raw.replace(":*", "*")
}

pub(crate) fn claude_gommage_matcher(settings: &serde_json::Value) -> String {
    const MAPPED: &[&str] = &[
        "Bash",
        "Read",
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Glob",
        "Grep",
        "WebFetch",
        "WebSearch",
        "mcp__.*",
    ];
    let allow = settings
        .pointer("/permissions/allow")
        .and_then(|v| v.as_array());
    let mut tools = Vec::new();
    for tool in MAPPED {
        let allowed = allow.is_none_or(|rules| claude_allow_covers_tool(rules, tool));
        if allowed {
            tools.push(*tool);
        }
    }
    tools.join("|")
}

fn claude_allow_covers_tool(rules: &[serde_json::Value], tool: &str) -> bool {
    rules.iter().filter_map(|v| v.as_str()).any(|rule| {
        rule == "*"
            || rule == tool
            || rule
                .strip_prefix(tool)
                .is_some_and(|rest| rest.starts_with('('))
            || (tool == "mcp__.*" && rule.starts_with("mcp__"))
    })
}

fn install_json_hook_group(
    root: &mut serde_json::Value,
    path: &[&str],
    group: serde_json::Value,
    replace_hooks: bool,
    agent_name: &str,
) -> Result<()> {
    let pre_tool_use = ensure_array_path(root, path)?;
    if replace_hooks {
        pre_tool_use.clear();
    } else {
        pre_tool_use.retain(|entry| !json_hook_entry_contains_command(entry, "gommage-mcp"));
        if !pre_tool_use.is_empty() {
            println!(
                "warn {agent_name}: preserving existing PreToolUse hook group(s); use --replace-hooks to let Gommage own the hook surface"
            );
        }
    }
    pre_tool_use.push(group);
    Ok(())
}

fn ensure_array_path<'a>(
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

fn json_hook_entry_contains_command(entry: &serde_json::Value, needle: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|command| command.contains(needle))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_write_native_permissions_collapse_to_one_capability() {
        let rules = vec![
            "Write".to_string(),
            "Edit".to_string(),
            "NotebookEdit(*)".to_string(),
            "MultiEdit(**)".to_string(),
        ];

        let (translated, skipped) =
            translate_claude_native_rules(&rules, translate_claude_permission_allow);
        let grouped = group_native_permission_imports(&translated);

        assert!(skipped.is_empty());
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].capability, "fs.write:**");
        assert_eq!(
            grouped[0].raws,
            vec!["Write", "Edit", "NotebookEdit(*)", "MultiEdit(**)"]
        );
    }

    #[test]
    fn native_star_path_is_normalized_to_recursive_glob() {
        assert_eq!(
            translate_claude_permission_allow("Read(*)").as_deref(),
            Some("fs.read:**")
        );
        assert_eq!(
            translate_claude_permission_allow("Write(*)").as_deref(),
            Some("fs.write:**")
        );
    }
}
