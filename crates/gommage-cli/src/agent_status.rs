use anyhow::Result;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{path::Path, process::ExitCode};

use crate::{
    agent::{
        AgentKind, native_permission_rules, translate_claude_native_rules,
        translate_claude_permission_allow, translate_claude_permission_deny,
    },
    util::{env_path_or_home, path_details, path_display, read_json_object, read_toml_document},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentStatus {
    Ok,
    Warn,
    Fail,
}

impl AgentStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct AgentStatusSummary {
    failures: usize,
    warnings: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentStatusCheck {
    name: String,
    status: AgentStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentStatusReport {
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

    pub(crate) fn status(&self) -> AgentStatus {
        self.status
    }

    pub(crate) fn failures(&self) -> usize {
        self.summary.failures
    }

    pub(crate) fn warnings(&self) -> usize {
        self.summary.warnings
    }
}

pub(crate) fn cmd_agent_status(
    agent: AgentKind,
    layout: &HomeLayout,
    json: bool,
) -> Result<ExitCode> {
    let report = build_agent_status_report(agent, layout);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_status_report(&report);
    }
    Ok(report.exit_code())
}

pub(crate) fn build_agent_status_report(
    agent: AgentKind,
    layout: &HomeLayout,
) -> AgentStatusReport {
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

fn json_hook_entry_contains_command(entry: &serde_json::Value, needle: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .any(|hook| {
            hook.get("command")
                .and_then(|command| command.as_str())
                .is_some_and(|command| command.contains(needle))
        })
}
