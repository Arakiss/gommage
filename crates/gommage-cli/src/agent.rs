use crate::util::{
    env_path_or_home, path_details, path_display, read_json_object, read_toml_document, write_json,
    write_text,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentStatus {
    Ok,
    Warn,
    Fail,
}

impl AgentStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct AgentStatusSummary {
    failures: usize,
    warnings: usize,
}

#[derive(Debug, Serialize)]
struct AgentStatusCheck {
    name: String,
    status: AgentStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct AgentStatusReport {
    agent: AgentKind,
    status: AgentStatus,
    summary: AgentStatusSummary,
    checks: Vec<AgentStatusCheck>,
}

impl AgentStatusReport {
    fn new(agent: AgentKind) -> Self {
        Self {
            agent,
            status: AgentStatus::Ok,
            summary: AgentStatusSummary::default(),
            checks: Vec::new(),
        }
    }

    fn push(
        &mut self,
        name: impl Into<String>,
        status: AgentStatus,
        message: impl Into<String>,
        details: Option<serde_json::Value>,
    ) {
        match status {
            AgentStatus::Ok => {}
            AgentStatus::Warn => self.summary.warnings += 1,
            AgentStatus::Fail => self.summary.failures += 1,
        }
        self.checks.push(AgentStatusCheck {
            name: name.into(),
            status,
            message: message.into(),
            details,
        });
        self.status = if self.summary.failures > 0 {
            AgentStatus::Fail
        } else if self.summary.warnings > 0 {
            AgentStatus::Warn
        } else {
            AgentStatus::Ok
        };
    }

    fn exit_code(&self) -> ExitCode {
        if self.summary.failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

fn cmd_agent_status(agent: AgentKind, layout: &HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_agent_status_report(agent, layout);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_status_report(&report);
    }
    Ok(report.exit_code())
}

fn build_agent_status_report(agent: AgentKind, layout: &HomeLayout) -> AgentStatusReport {
    match agent {
        AgentKind::Claude => build_claude_status_report(layout),
        AgentKind::Codex => build_codex_status_report(),
    }
}

fn build_claude_status_report(layout: &HomeLayout) -> AgentStatusReport {
    let mut report = AgentStatusReport::new(AgentKind::Claude);
    let settings_path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
    push_agent_path_check(&mut report, "settings_file", &settings_path);

    let settings = match read_json_object(&settings_path) {
        Ok(settings) => settings,
        Err(error) => {
            report.push(
                "settings_json",
                AgentStatus::Fail,
                format!("could not read Claude settings: {error}"),
                Some(path_details(&settings_path)),
            );
            return report;
        }
    };

    let matchers = gommage_hook_matchers(&settings, "/hooks/PreToolUse");
    if matchers.is_empty() {
        report.push(
            "pre_tool_use",
            AgentStatus::Fail,
            "no Claude PreToolUse hook invoking gommage-mcp",
            Some(serde_json::json!({
                "path": path_display(&settings_path),
                "pointer": "/hooks/PreToolUse",
            })),
        );
    } else {
        report.push(
            "pre_tool_use",
            AgentStatus::Ok,
            format!("{} Gommage hook group(s) installed", matchers.len()),
            Some(serde_json::json!({
                "path": path_display(&settings_path),
                "matchers": matchers,
            })),
        );
    }

    push_claude_import_status(
        &mut report,
        &settings,
        layout,
        "/permissions/deny",
        "deny_import",
        "05-claude-import.yaml",
        translate_claude_permission_deny,
    );
    push_claude_import_status(
        &mut report,
        &settings,
        layout,
        "/permissions/allow",
        "allow_import",
        "90-claude-allow-import.yaml",
        translate_claude_permission_allow,
    );

    report
}

fn build_codex_status_report() -> AgentStatusReport {
    let mut report = AgentStatusReport::new(AgentKind::Codex);
    let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
    let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
    push_agent_path_check(&mut report, "hooks_file", &hooks_path);
    push_agent_path_check(&mut report, "config_file", &config_path);

    let hooks = match read_json_object(&hooks_path) {
        Ok(hooks) => hooks,
        Err(error) => {
            report.push(
                "hooks_json",
                AgentStatus::Fail,
                format!("could not read Codex hooks: {error}"),
                Some(path_details(&hooks_path)),
            );
            return report;
        }
    };
    let matchers = gommage_hook_matchers(&hooks, "/PreToolUse");
    if matchers.is_empty() {
        report.push(
            "pre_tool_use",
            AgentStatus::Fail,
            "no Codex PreToolUse hook invoking gommage-mcp",
            Some(serde_json::json!({
                "path": path_display(&hooks_path),
                "pointer": "/PreToolUse",
            })),
        );
    } else {
        report.push(
            "pre_tool_use",
            AgentStatus::Ok,
            format!("{} Gommage hook group(s) installed", matchers.len()),
            Some(serde_json::json!({
                "path": path_display(&hooks_path),
                "matchers": matchers,
            })),
        );
    }

    let config = match read_toml_document(&config_path) {
        Ok(config) => config,
        Err(error) => {
            report.push(
                "config_toml",
                AgentStatus::Fail,
                format!("could not read Codex config: {error}"),
                Some(path_details(&config_path)),
            );
            return report;
        }
    };
    let codex_hooks_enabled = config
        .get("features")
        .and_then(|features| features.get("codex_hooks"))
        .and_then(|value| value.as_bool())
        == Some(true);
    if codex_hooks_enabled {
        report.push(
            "codex_hooks",
            AgentStatus::Ok,
            "features.codex_hooks is enabled",
            Some(path_details(&config_path)),
        );
    } else {
        report.push(
            "codex_hooks",
            AgentStatus::Fail,
            "features.codex_hooks is not enabled",
            Some(path_details(&config_path)),
        );
    }

    let sandbox_mode = config
        .get("sandbox_mode")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    match sandbox_mode.as_deref() {
        Some("danger-full-access") => report.push(
            "sandbox",
            AgentStatus::Warn,
            "Codex sandbox_mode is danger-full-access; file and MCP tools remain outside Gommage hook coverage",
            Some(serde_json::json!({
                "path": path_display(&config_path),
                "sandbox_mode": sandbox_mode,
            })),
        ),
        Some(mode) => report.push(
            "sandbox",
            AgentStatus::Ok,
            format!("Codex sandbox_mode is {mode}"),
            Some(serde_json::json!({
                "path": path_display(&config_path),
                "sandbox_mode": mode,
            })),
        ),
        None => report.push(
            "sandbox",
            AgentStatus::Ok,
            "Codex sandbox_mode is not set; Codex default remains authoritative",
            Some(path_details(&config_path)),
        ),
    }

    report
}

fn push_agent_path_check(report: &mut AgentStatusReport, name: &str, path: &Path) {
    if path.exists() {
        report.push(
            name,
            AgentStatus::Ok,
            format!("{} exists", path.display()),
            Some(path_details(path)),
        );
    } else {
        report.push(name, AgentStatus::Fail, "missing", Some(path_details(path)));
    }
}

fn push_claude_import_status(
    report: &mut AgentStatusReport,
    settings: &serde_json::Value,
    layout: &HomeLayout,
    pointer: &str,
    check_name: &str,
    file_name: &str,
    translate: fn(&str) -> Option<String>,
) {
    let rules = native_permission_rules(settings, pointer);
    let (translated, skipped) = translate_claude_native_rules(&rules, translate);
    let path = layout.policy_dir.join(file_name);
    if translated.is_empty() {
        report.push(
            check_name,
            AgentStatus::Ok,
            format!("no importable native rules at {pointer}"),
            Some(serde_json::json!({
                "path": path_display(&path),
                "native_rules": rules.len(),
                "importable_rules": translated.len(),
                "skipped_rules": skipped.len(),
            })),
        );
    } else if path.exists() {
        report.push(
            check_name,
            AgentStatus::Ok,
            format!(
                "{} importable native rule(s) have a generated policy file",
                translated.len()
            ),
            Some(serde_json::json!({
                "path": path_display(&path),
                "native_rules": rules.len(),
                "importable_rules": translated.len(),
                "skipped_rules": skipped.len(),
            })),
        );
    } else {
        report.push(
            check_name,
            AgentStatus::Warn,
            format!(
                "{} importable native rule(s) have not been converted into Gommage policy",
                translated.len()
            ),
            Some(serde_json::json!({
                "path": path_display(&path),
                "native_rules": rules.len(),
                "importable_rules": translated.len(),
                "skipped_rules": skipped.len(),
            })),
        );
    }
}

fn gommage_hook_matchers(root: &serde_json::Value, pointer: &str) -> Vec<String> {
    root.pointer(pointer)
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter(|entry| json_hook_entry_contains_command(entry, "gommage-mcp"))
        .map(|entry| {
            entry
                .get("matcher")
                .and_then(|value| value.as_str())
                .unwrap_or("<missing matcher>")
                .to_string()
        })
        .collect()
}

fn print_agent_status_report(report: &AgentStatusReport) {
    println!("agent: {}", agent_kind_name(report.agent));
    for check in &report.checks {
        println!(
            "{} {}: {}",
            check.status.as_str(),
            check.name,
            check.message
        );
    }
    println!(
        "summary: {} failure(s), {} warning(s)",
        report.summary.failures, report.summary.warnings
    );
}

fn agent_kind_name(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Claude => "claude",
        AgentKind::Codex => "codex",
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
                "warn claude: skipped {} broad native allow rule(s); keep them as hook matcher input or review manually",
                skipped_allows.len()
            );
        }
    }
    Ok(())
}

struct NativePermissionImport {
    raw: String,
    capability: String,
}

fn native_permission_rules(settings: &serde_json::Value, pointer: &str) -> Vec<String> {
    settings
        .pointer(pointer)
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn translate_claude_native_rules(
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

    let mut yaml = String::new();
    yaml.push_str(&format!(
        "# Generated by `gommage quickstart` from {source_label}.\n"
    ));
    yaml.push_str(
        "# Review before sharing; native permission syntax is broader than Gommage capabilities.\n",
    );
    yaml.push_str(&format!("# {ordering_note}\n\n"));
    for (index, imported) in translated.iter().enumerate() {
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
            serde_json::to_string(&format!("imported from {source_label}: {}", imported.raw))?
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
            "ok claude: imported {} native rule(s) into {}",
            translated.len(),
            import_path.display()
        );
    }
    Ok(())
}

fn translate_claude_permission_deny(raw: &str) -> Option<String> {
    translate_claude_permission_specifier(raw)
}

fn translate_claude_permission_allow(raw: &str) -> Option<String> {
    if !raw.contains('(') {
        return None;
    }
    translate_claude_permission_specifier(raw)
}

fn translate_claude_permission_specifier(raw: &str) -> Option<String> {
    let (tool, value) = raw.split_once('(')?;
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
    Some(capability)
}

fn normalize_native_path_pattern(raw: &str) -> String {
    if raw == "~" {
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

fn claude_gommage_matcher(settings: &serde_json::Value) -> String {
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
