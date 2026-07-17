use anyhow::Result;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{path::Path, process::ExitCode};

use crate::{
    agent::{
        AgentKind, CODEX_GOMMAGE_MATCHER, ClaudeImportKind, claude_gommage_matcher,
        is_generated_claude_permission_import, is_generated_relaxation_layer,
        legacy_agent_hook_command, native_permission_rules, render_agent_hook_command,
        render_claude_permission_import, translate_claude_native_rules,
        translate_claude_permission_allow, translate_claude_permission_deny,
    },
    codex_config::codex_hooks_feature_state,
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
        AgentKind::Codex => build_codex_status_report(layout),
    }
}

fn build_claude_status_report(layout: &HomeLayout) -> AgentStatusReport {
    let settings_path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
    build_claude_status_report_at(layout, &settings_path)
}

pub(crate) fn build_claude_status_report_at(
    layout: &HomeLayout,
    settings_path: &Path,
) -> AgentStatusReport {
    let mut report = AgentStatusReport::new(AgentKind::Claude);
    push_agent_path_check(&mut report, "settings_file", settings_path);

    let settings = match read_json_object(settings_path) {
        Ok(settings) => settings,
        Err(error) => {
            report.push(
                "settings_json",
                AgentStatus::Fail,
                format!("could not read Claude settings: {error}"),
                Some(path_details(settings_path)),
            );
            return report;
        }
    };

    let matchers = gommage_hook_matchers(&settings, "/hooks/PreToolUse");
    if matchers.is_empty() {
        report.push(
            "pre_tool_use",
            AgentStatus::Fail,
            "no Claude PreToolUse hook invoking the Gommage hook adapter",
            Some(serde_json::json!({
                "path": path_display(settings_path),
                "pointer": "/hooks/PreToolUse",
            })),
        );
    } else {
        report.push(
            "pre_tool_use",
            AgentStatus::Ok,
            format!("{} Gommage hook group(s) installed", matchers.len()),
            Some(serde_json::json!({
                "path": path_display(settings_path),
                "matchers": matchers,
            })),
        );
        let expected = claude_gommage_matcher(&settings);
        push_hook_coverage_report(
            &mut report,
            AgentKind::Claude,
            settings_path,
            &matchers,
            &expected,
        );
    }
    push_hook_hygiene_report(
        &mut report,
        AgentKind::Claude,
        layout,
        settings_path,
        &settings,
        "/hooks/PreToolUse",
    );

    push_claude_import_status(
        &mut report,
        &settings,
        layout,
        ClaudeImportStatusSpec {
            pointer: "/permissions/deny",
            check_name: "deny_import",
            file_name: "05-claude-import.yaml",
            translate: translate_claude_permission_deny,
            kind: ClaudeImportKind::Deny,
            required_in_strict_mode: true,
        },
    );
    push_claude_import_status(
        &mut report,
        &settings,
        layout,
        ClaudeImportStatusSpec {
            pointer: "/permissions/allow",
            check_name: "allow_import",
            file_name: "90-claude-allow-import.yaml",
            translate: translate_claude_permission_allow,
            kind: ClaudeImportKind::Allow,
            required_in_strict_mode: false,
        },
    );
    push_generated_policy_posture_status(&mut report, layout);

    report
}

fn build_codex_status_report(layout: &HomeLayout) -> AgentStatusReport {
    let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
    let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
    let mut report = build_codex_status_report_at(layout, &hooks_path, &config_path);
    push_generated_policy_posture_status(&mut report, layout);
    report
}

pub(crate) fn build_codex_status_report_at(
    layout: &HomeLayout,
    hooks_path: &Path,
    config_path: &Path,
) -> AgentStatusReport {
    let mut report = AgentStatusReport::new(AgentKind::Codex);
    push_agent_path_check(&mut report, "hooks_file", hooks_path);
    push_agent_path_check(&mut report, "config_file", config_path);

    let hooks = match read_json_object(hooks_path) {
        Ok(hooks) => hooks,
        Err(error) => {
            report.push(
                "hooks_json",
                AgentStatus::Fail,
                format!("could not read Codex hooks: {error}"),
                Some(path_details(hooks_path)),
            );
            return report;
        }
    };
    let pre_tool_use_pointer = codex_pre_tool_use_pointer(&hooks);
    let matchers = gommage_hook_matchers(&hooks, pre_tool_use_pointer);
    if matchers.is_empty() {
        report.push(
            "pre_tool_use",
            AgentStatus::Fail,
            "no Codex PreToolUse hook invoking the Gommage hook adapter",
            Some(serde_json::json!({
                "path": path_display(hooks_path),
                "pointer": pre_tool_use_pointer,
            })),
        );
    } else {
        report.push(
            "pre_tool_use",
            AgentStatus::Ok,
            format!("{} Gommage hook group(s) installed", matchers.len()),
            Some(serde_json::json!({
                "path": path_display(hooks_path),
                "matchers": matchers,
            })),
        );
        push_hook_coverage_report(
            &mut report,
            AgentKind::Codex,
            hooks_path,
            &matchers,
            CODEX_GOMMAGE_MATCHER,
        );
    }
    push_hook_hygiene_report(
        &mut report,
        AgentKind::Codex,
        layout,
        hooks_path,
        &hooks,
        pre_tool_use_pointer,
    );

    let config = match read_toml_document(config_path) {
        Ok(config) => config,
        Err(error) => {
            report.push(
                "config_toml",
                AgentStatus::Fail,
                format!("could not read Codex config: {error}"),
                Some(path_details(config_path)),
            );
            return report;
        }
    };
    let hooks_feature = codex_hooks_feature_state(&config);
    if hooks_feature.canonical_enabled() {
        report.push(
            "codex_hooks",
            AgentStatus::Ok,
            "features.hooks is enabled",
            Some(serde_json::json!({
                "path": path_display(config_path),
                "feature": "features.hooks",
                "legacy_codex_hooks": hooks_feature.legacy_codex_hooks,
            })),
        );
    } else if hooks_feature.legacy_only_enabled() {
        report.push(
            "codex_hooks",
            AgentStatus::Warn,
            "legacy features.codex_hooks is enabled; rerun install to write canonical features.hooks",
            Some(serde_json::json!({
                "path": path_display(config_path),
                "feature": "features.hooks",
                "legacy_feature": "features.codex_hooks",
            })),
        );
    } else {
        report.push(
            "codex_hooks",
            AgentStatus::Fail,
            "features.hooks is not enabled",
            Some(serde_json::json!({
                "path": path_display(config_path),
                "feature": "features.hooks",
                "legacy_codex_hooks": hooks_feature.legacy_codex_hooks,
            })),
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
            "Codex sandbox_mode is danger-full-access; Gommage governs matched hook events only, so sandboxing remains the boundary for other Codex tool paths",
            Some(serde_json::json!({
                "path": path_display(config_path),
                "sandbox_mode": sandbox_mode,
            })),
        ),
        Some(mode) => report.push(
            "sandbox",
            AgentStatus::Ok,
            format!("Codex sandbox_mode is {mode}"),
            Some(serde_json::json!({
                "path": path_display(config_path),
                "sandbox_mode": mode,
            })),
        ),
        None => report.push(
            "sandbox",
            AgentStatus::Ok,
            "Codex sandbox_mode is not set; Codex default remains authoritative",
            Some(path_details(config_path)),
        ),
    }

    report
}

fn codex_pre_tool_use_pointer(root: &serde_json::Value) -> &'static str {
    if root.pointer("/hooks/PreToolUse").is_some() {
        "/hooks/PreToolUse"
    } else {
        "/PreToolUse"
    }
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

struct ClaudeImportStatusSpec {
    pointer: &'static str,
    check_name: &'static str,
    file_name: &'static str,
    translate: fn(&str) -> Option<String>,
    kind: ClaudeImportKind,
    required_in_strict_mode: bool,
}

fn push_claude_import_status(
    report: &mut AgentStatusReport,
    settings: &serde_json::Value,
    layout: &HomeLayout,
    spec: ClaudeImportStatusSpec,
) {
    let ClaudeImportStatusSpec {
        pointer,
        check_name,
        file_name,
        translate,
        kind,
        required_in_strict_mode,
    } = spec;
    let rules = native_permission_rules(settings, pointer);
    let (translated, skipped) = translate_claude_native_rules(&rules, translate);
    let path = layout.policy_dir.join(file_name);
    let expected = match render_claude_permission_import(kind, &translated) {
        Ok(expected) => expected,
        Err(error) => {
            report.push(
                check_name,
                AgentStatus::Fail,
                format!("could not render expected native permission import: {error}"),
                None,
            );
            return;
        }
    };
    let current = if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(current) => Some(current),
            Err(error) => {
                report.push(
                    check_name,
                    AgentStatus::Fail,
                    format!("could not read {}: {error}", path.display()),
                    Some(path_details(&path)),
                );
                return;
            }
        }
    } else {
        None
    };
    let generated = current
        .as_ref()
        .is_some_and(|_| is_generated_claude_permission_import(&path, kind).unwrap_or(false));
    let details = |content_state: &str| {
        Some(serde_json::json!({
            "path": path_display(&path),
            "native_rules": rules.len(),
            "importable_rules": translated.len(),
            "skipped_rules": skipped.len(),
            "content_state": content_state,
            "policy_posture": if required_in_strict_mode { "strict" } else { "relaxed_or_custom" },
        }))
    };

    match (required_in_strict_mode, expected.as_deref(), current.as_deref()) {
        (true, None, None) => report.push(
            check_name,
            AgentStatus::Ok,
            format!("no importable native rules at {pointer}"),
            details("absent_as_expected"),
        ),
        (true, Some(expected), Some(current)) if expected == current => report.push(
            check_name,
            AgentStatus::Ok,
            format!("{} native deny rule(s) are synchronized", translated.len()),
            details("current"),
        ),
        (true, Some(_), None) => report.push(
            check_name,
            AgentStatus::Fail,
            format!(
                "{} importable native deny rule(s) are missing from Gommage policy",
                translated.len()
            ),
            details("missing"),
        ),
        (true, _, Some(_)) if generated => report.push(
            check_name,
            AgentStatus::Fail,
            "generated native deny import is stale; rerun agent install",
            details("stale_generated"),
        ),
        (true, _, Some(_)) => report.push(
            check_name,
            AgentStatus::Fail,
            "custom or modified policy occupies the reserved native deny import path",
            details("custom_reserved"),
        ),
        (false, _, None) => report.push(
            check_name,
            AgentStatus::Ok,
            format!(
                "{} importable native allow rule(s) intentionally remain outside strict Gommage policy",
                translated.len()
            ),
            details("absent_strict"),
        ),
        (false, Some(expected), Some(current)) if generated && expected == current => report.push(
            check_name,
            AgentStatus::Warn,
            "current generated native allow import is active in relaxed posture",
            details("current_generated_relaxation"),
        ),
        (false, _, Some(_)) if generated => report.push(
            check_name,
            AgentStatus::Warn,
            "generated native allow import is active but stale",
            details("stale_generated_relaxation"),
        ),
        (false, _, Some(_)) => report.push(
            check_name,
            AgentStatus::Fail,
            "custom or modified policy occupies the reserved native allow import path",
            details("custom_reserved"),
        ),
    }
}

fn push_generated_policy_posture_status(report: &mut AgentStatusReport, layout: &HomeLayout) {
    let mut active = Vec::new();
    let mut modified = Vec::new();
    for name in ["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"] {
        let path = layout.policy_dir.join(name);
        if !path.exists() {
            continue;
        }
        if is_generated_relaxation_layer(&path, name).unwrap_or(false) {
            active.push(path_display(&path));
        } else {
            modified.push(path_display(&path));
        }
    }
    if !modified.is_empty() {
        report.push(
            "policy_posture",
            AgentStatus::Fail,
            "custom or modified policy occupies a reserved broad-agent policy path",
            Some(serde_json::json!({
                "policy_posture": "custom_reserved",
                "modified_layers": modified,
                "active_generated_layers": active,
            })),
        );
        return;
    }
    if active.is_empty() {
        report.push(
            "policy_posture",
            AgentStatus::Ok,
            "no generated broad agent policy layers are active",
            Some(serde_json::json!({ "policy_posture": "strict" })),
        );
    } else {
        report.push(
            "policy_posture",
            AgentStatus::Warn,
            "generated broad agent policy layers are active; run `gommage posture --json`",
            Some(serde_json::json!({
                "policy_posture": "relaxed",
                "active_layers": active,
            })),
        );
    }
}

fn gommage_hook_matchers(root: &serde_json::Value, pointer: &str) -> Vec<String> {
    gommage_hook_entries(root, pointer)
        .into_iter()
        .filter(|entry| is_gommage_hook_command(&entry.command))
        .map(|entry| entry.matcher)
        .collect()
}

#[derive(Debug)]
struct HookEntry {
    matcher: String,
    command: String,
}

fn push_hook_hygiene_report(
    report: &mut AgentStatusReport,
    agent: AgentKind,
    layout: &HomeLayout,
    path: &Path,
    root: &serde_json::Value,
    pointer: &str,
) {
    let entries = gommage_hook_entries(root, pointer);
    let expected = match render_agent_hook_command(agent, layout) {
        Ok(expected) => expected,
        Err(error) => {
            report.push(
                "hook_home",
                AgentStatus::Fail,
                format!(
                    "could not resolve the canonical Gommage home for hook validation: {error}"
                ),
                Some(path_details(path)),
            );
            legacy_agent_hook_command(agent).to_string()
        }
    };
    let legacy = entries
        .iter()
        .filter(|entry| is_gommage_hook_command(&entry.command))
        .filter(|entry| !is_canonical_hook_command(&entry.command, &expected))
        .map(hook_entry_json)
        .collect::<Vec<_>>();
    if !legacy.is_empty() {
        report.push(
            "legacy_hooks",
            AgentStatus::Warn,
            format!(
                "legacy Gommage hook command(s) found; new installs use `{}`; run `gommage repair agent {} --dry-run`",
                expected,
                agent.as_str(),
            ),
            Some(serde_json::json!({
                "path": path_display(path),
                "pointer": pointer,
                "hooks": legacy,
                "repair": format!("gommage repair agent {} --dry-run", agent.as_str()),
            })),
        );
    }

    let misbound = entries
        .iter()
        .filter(|entry| is_agent_hook_adapter(&entry.command, agent))
        .filter(|entry| !is_canonical_hook_command(&entry.command, &expected))
        .map(hook_entry_json)
        .collect::<Vec<_>>();
    if !misbound.is_empty() {
        report.push(
            "hook_home",
            AgentStatus::Fail,
            format!("Gommage hook is not bound to this installation home; expected `{expected}`"),
            Some(serde_json::json!({
                "path": path_display(path),
                "expected_command": expected,
                "hooks": misbound,
                "repair": format!("gommage repair agent {} --dry-run", agent.as_str()),
            })),
        );
    } else if entries
        .iter()
        .any(|entry| is_canonical_hook_command(&entry.command, &expected))
    {
        report.push(
            "hook_home",
            AgentStatus::Ok,
            "Gommage hook is bound to the canonical installation home",
            Some(serde_json::json!({ "expected_command": expected })),
        );
    }
}

fn push_hook_coverage_report(
    report: &mut AgentStatusReport,
    agent: AgentKind,
    path: &Path,
    installed_matchers: &[String],
    expected_matcher: &str,
) {
    let required = matcher_alternatives(expected_matcher);
    if required.is_empty() {
        return;
    }
    let missing = required
        .into_iter()
        .filter(|required| {
            !installed_matchers
                .iter()
                .any(|matcher| matcher_covers_required(matcher, required))
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        report.push(
            "hook_coverage",
            AgentStatus::Ok,
            "Gommage hook matcher covers the current mapped tool surface",
            Some(serde_json::json!({
                "path": path_display(path),
                "installed_matchers": installed_matchers,
                "expected_matcher": expected_matcher,
            })),
        );
        return;
    }

    report.push(
        "hook_coverage",
        AgentStatus::Warn,
        format!(
            "Gommage hook matcher is missing current mapped tool coverage: {}",
            missing.join(", ")
        ),
        Some(serde_json::json!({
            "path": path_display(path),
            "installed_matchers": installed_matchers,
            "expected_matcher": expected_matcher,
            "missing": missing,
            "repair": format!("gommage repair agent {} --dry-run", agent.as_str()),
        })),
    );
}

fn matcher_covers_required(matcher: &str, required: &str) -> bool {
    if matcher_is_global(matcher) {
        return true;
    }
    matcher_alternatives(matcher)
        .iter()
        .any(|alternative| alternative == required)
}

fn matcher_alternatives(matcher: &str) -> Vec<String> {
    matcher
        .split('|')
        .map(normalize_matcher_alternative)
        .filter(|alternative| !alternative.is_empty())
        .collect()
}

fn normalize_matcher_alternative(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('^')
        .trim_end_matches('$')
        .to_string()
}

fn gommage_hook_entries(root: &serde_json::Value, pointer: &str) -> Vec<HookEntry> {
    root.pointer(pointer)
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let matcher = entry
                .get("matcher")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let command = first_gommage_command(entry)?;
            Some(HookEntry { matcher, command })
        })
        .collect()
}

fn first_gommage_command(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("hooks")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|hook| hook.get("command").and_then(|command| command.as_str()))
        .find(|command| command.to_ascii_lowercase().contains("gommage"))
        .map(str::to_string)
}

fn is_gommage_hook_command(command: &str) -> bool {
    let command = command.to_ascii_lowercase();
    command.contains("gommage-mcp")
        || command_contains_gommage_subcommand(&command, "hook")
        || command_contains_gommage_subcommand(&command, "mcp")
}

fn is_agent_hook_adapter(command: &str, agent: AgentKind) -> bool {
    let command = command.to_ascii_lowercase();
    command_contains_gommage_subcommand(&command, "hook")
        && command_has_agent_arg(&command, agent.as_str())
}

fn is_canonical_hook_command(command: &str, expected: &str) -> bool {
    command.trim() == expected
}

fn command_contains_gommage_subcommand(command: &str, subcommand: &str) -> bool {
    let tokens = command_tokens(command);
    tokens.iter().enumerate().any(|(index, binary)| {
        if !binary.ends_with("gommage") {
            return false;
        }
        let args = &tokens[index + 1..];
        args.first().is_some_and(|arg| *arg == subcommand)
            || matches!(args, ["--home", _, command, ..] if *command == subcommand)
            || matches!(args, [home, command, ..] if home.starts_with("--home=") && *command == subcommand)
    })
}

fn command_has_agent_arg(command: &str, agent: &str) -> bool {
    let agent_equals = format!("--agent={agent}");
    let tokens = command_tokens(command);
    tokens
        .windows(2)
        .any(|pair| pair.first() == Some(&"--agent") && pair.get(1) == Some(&agent))
        || tokens.contains(&agent_equals.as_str())
}

fn command_tokens(command: &str) -> Vec<&str> {
    command
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | ';' | '&' | '|' | '(' | ')')
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn matcher_is_global(matcher: &str) -> bool {
    let matcher = matcher.trim();
    matcher.is_empty() || matches!(matcher, "*" | ".*" | "all" | "All" | "ALL")
}

fn hook_entry_json(entry: &HookEntry) -> serde_json::Value {
    serde_json::json!({
        "matcher": if entry.matcher.is_empty() { "<missing>" } else { &entry.matcher },
        "command": entry.command,
    })
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
