use anyhow::Result;
use clap::Subcommand;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::process::ExitCode;

use crate::{
    agent::{
        AgentKind, native_permission_rules, translate_claude_native_rules,
        translate_claude_permission_allow, translate_claude_permission_deny,
    },
    agent_status::{AgentStatus, build_agent_status_report},
    util::{env_path_or_home, path_display, read_json_object, read_toml_document, write_text},
};

#[derive(Subcommand)]
pub(crate) enum HarnessCmd {
    /// Diagnose local host-agent harness state without installing anything.
    Diagnose {
        /// Agent integration to inspect. Defaults to claude and codex.
        #[arg(long = "agent", value_enum)]
        agents: Vec<AgentKind>,
        /// Emit a stable machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Explain the effective Gommage setup in agent-readable language.
    Explain {
        /// Agent integration to explain. Defaults to claude and codex.
        #[arg(long = "agent", value_enum)]
        agents: Vec<AgentKind>,
        /// Emit the same setup report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write AGENT_CONTEXT.md and integration-report.json into GOMMAGE_HOME.
    #[command(name = "write-context")]
    WriteContext {
        /// Agent integration to include. Defaults to claude and codex.
        #[arg(long = "agent", value_enum)]
        agents: Vec<AgentKind>,
        /// Show planned writes without mutating GOMMAGE_HOME.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HarnessStatus {
    Ok,
    Warn,
}

impl HarnessStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct HarnessReport {
    status: HarnessStatus,
    home: String,
    mode: &'static str,
    agents: Vec<HarnessAgentReport>,
    guidance: Vec<String>,
    next_commands: Vec<String>,
    context_files: ContextFiles,
}

#[derive(Debug, Serialize)]
struct ContextFiles {
    markdown: String,
    json: String,
}

#[derive(Debug, Serialize)]
struct HarnessAgentReport {
    agent: AgentKind,
    integration_status: AgentStatus,
    config_paths: Vec<String>,
    existing_hooks_detected: bool,
    gommage_hook_installed: bool,
    default_install_mode: &'static str,
    replace_hooks_available: bool,
    native_permissions: NativePermissionSummary,
    coverage: Vec<CoverageSurface>,
    guidance: Vec<String>,
    status_report: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct NativePermissionSummary {
    supported: bool,
    deny_import_enabled_by_default: bool,
    allow_import_enabled_by_default: bool,
    allow_import_active: bool,
    deny: Option<PermissionImportSummary>,
    allow: Option<PermissionImportSummary>,
}

#[derive(Debug, Serialize)]
struct PermissionImportSummary {
    source_pointer: &'static str,
    native_rules: usize,
    importable_rules: usize,
    skipped_rules: usize,
    output_path: String,
    layer_order: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    broad_allow_entries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CoverageSurface {
    surface: &'static str,
    default_coverage: &'static str,
    boundary: &'static str,
}

pub(crate) fn cmd_harness(sub: HarnessCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        HarnessCmd::Diagnose { agents, json } => {
            let report = build_harness_report(&layout, agents)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_harness_report(&report);
            }
            Ok(ExitCode::SUCCESS)
        }
        HarnessCmd::Explain { agents, json } => {
            let report = build_harness_report(&layout, agents)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_agent_context_markdown(&report));
            }
            Ok(ExitCode::SUCCESS)
        }
        HarnessCmd::WriteContext { agents, dry_run } => {
            let report = build_harness_report(&layout, agents)?;
            write_harness_context_files(&layout, &report, dry_run)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub(crate) fn write_harness_context(layout: &HomeLayout, agents: Vec<AgentKind>) -> Result<()> {
    let report = build_harness_report(layout, agents)?;
    write_harness_context_files(layout, &report, false)
}

pub(crate) fn build_harness_report(
    layout: &HomeLayout,
    agents: Vec<AgentKind>,
) -> Result<HarnessReport> {
    let agents = normalize_agents(agents);
    let mut reports = Vec::new();
    for agent in agents {
        reports.push(build_agent_harness_report(agent, layout)?);
    }
    let status = if reports
        .iter()
        .any(|report| report.integration_status != AgentStatus::Ok)
    {
        HarnessStatus::Warn
    } else {
        HarnessStatus::Ok
    };
    let next_commands = next_commands(&reports);
    Ok(HarnessReport {
        status,
        home: path_display(&layout.root),
        mode: "diagnose",
        agents: reports,
        guidance: vec![
            "Gommage is a policy and audit layer, not an OS sandbox.".to_string(),
            "Native agent sandboxing and approval policy remain authoritative below the hook layer."
                .to_string(),
            "Quickstart defaults to coexistence: preserve unrelated host hooks, install Gommage, then verify."
                .to_string(),
            "A denied inner executor call in a dual-agent flow is an executor failure, not trustworthy partial output."
                .to_string(),
        ],
        next_commands,
        context_files: ContextFiles {
            markdown: path_display(&layout.root.join("AGENT_CONTEXT.md")),
            json: path_display(&layout.root.join("integration-report.json")),
        },
    })
}

fn normalize_agents(agents: Vec<AgentKind>) -> Vec<AgentKind> {
    if agents.is_empty() {
        vec![AgentKind::Claude, AgentKind::Codex]
    } else {
        agents
    }
}

fn build_agent_harness_report(agent: AgentKind, layout: &HomeLayout) -> Result<HarnessAgentReport> {
    let status_report = build_agent_status_report(agent, layout);
    let integration_status = status_report.status();
    let status_report_json = serde_json::to_value(&status_report)?;
    match agent {
        AgentKind::Claude => {
            let settings_path =
                env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
            let settings = read_json_object(&settings_path)?;
            let hooks = hook_groups(&settings, "/hooks/PreToolUse");
            Ok(HarnessAgentReport {
                agent,
                integration_status,
                config_paths: vec![path_display(&settings_path)],
                existing_hooks_detected: hooks.iter().any(|hook| !hook.contains_gommage),
                gommage_hook_installed: hooks.iter().any(|hook| hook.contains_gommage),
                default_install_mode: "coexistence",
                replace_hooks_available: true,
                native_permissions: claude_native_permission_summary(&settings, layout),
                coverage: claude_coverage(),
                guidance: vec![
                    "quickstart preserves unrelated Claude PreToolUse hook groups unless --replace-hooks is passed.".to_string(),
                    "If another hook blocks before Gommage, Gommage cannot audit that decision.".to_string(),
                    "Supported permissions.deny entries are synchronized by default; permissions.allow stays outside strict policy unless --relaxed is explicit.".to_string(),
                ],
                status_report: status_report_json,
            })
        }
        AgentKind::Codex => {
            let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
            let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
            let hooks = read_json_object(&hooks_path)?;
            let hook_groups = hook_groups(&hooks, "/PreToolUse");
            let config = read_toml_document(&config_path)?;
            let sandbox_mode = config
                .get("sandbox_mode")
                .and_then(|value| value.as_str())
                .unwrap_or("<codex-default>");
            Ok(HarnessAgentReport {
                agent,
                integration_status,
                config_paths: vec![path_display(&hooks_path), path_display(&config_path)],
                existing_hooks_detected: hook_groups.iter().any(|hook| !hook.contains_gommage),
                gommage_hook_installed: hook_groups.iter().any(|hook| hook.contains_gommage),
                default_install_mode: "coexistence",
                replace_hooks_available: true,
                native_permissions: NativePermissionSummary {
                    supported: false,
                    deny_import_enabled_by_default: false,
                    allow_import_enabled_by_default: false,
                    allow_import_active: false,
                    deny: None,
                    allow: None,
                },
                coverage: codex_coverage(),
                guidance: vec![
                    "quickstart enables Codex hooks and installs Gommage's Bash/apply_patch/MCP matcher by default.".to_string(),
                    format!("Codex sandbox remains authoritative outside mapped hook events; current sandbox_mode is {sandbox_mode}."),
                    "Codex hooks still do not intercept every shell path or non-shell, non-MCP tool call.".to_string(),
                ],
                status_report: status_report_json,
            })
        }
    }
}

fn claude_native_permission_summary(
    settings: &serde_json::Value,
    layout: &HomeLayout,
) -> NativePermissionSummary {
    let deny_rules = native_permission_rules(settings, "/permissions/deny");
    let allow_rules = native_permission_rules(settings, "/permissions/allow");
    let (deny_translated, deny_skipped) =
        translate_claude_native_rules(&deny_rules, translate_claude_permission_deny);
    let (allow_translated, allow_skipped) =
        translate_claude_native_rules(&allow_rules, translate_claude_permission_allow);
    NativePermissionSummary {
        supported: true,
        deny_import_enabled_by_default: true,
        allow_import_enabled_by_default: false,
        allow_import_active: layout
            .policy_dir
            .join("90-claude-allow-import.yaml")
            .exists(),
        deny: Some(PermissionImportSummary {
            source_pointer: "/permissions/deny",
            native_rules: deny_rules.len(),
            importable_rules: deny_translated.len(),
            skipped_rules: deny_skipped.len(),
            output_path: path_display(&layout.policy_dir.join("05-claude-import.yaml")),
            layer_order: "early deny import before bundled allow rules",
            broad_allow_entries: Vec::new(),
        }),
        allow: Some(PermissionImportSummary {
            source_pointer: "/permissions/allow",
            native_rules: allow_rules.len(),
            importable_rules: allow_translated.len(),
            skipped_rules: allow_skipped.len(),
            output_path: path_display(&layout.policy_dir.join("90-claude-allow-import.yaml")),
            layer_order: "late allow import after hard-stops, denies, and asks",
            broad_allow_entries: allow_rules
                .into_iter()
                .filter(|rule| matches!(rule.as_str(), "*" | "Bash" | "Read" | "Write" | "Edit"))
                .collect(),
        }),
    }
}

fn claude_coverage() -> Vec<CoverageSurface> {
    vec![
        CoverageSurface {
            surface: "bash",
            default_coverage: "mapped",
            boundary: "Claude Bash tool calls emitted through PreToolUse",
        },
        CoverageSurface {
            surface: "filesystem",
            default_coverage: "mapped",
            boundary: "Claude Read/Write/Edit/MultiEdit/NotebookEdit/Glob/Grep hook calls",
        },
        CoverageSurface {
            surface: "web",
            default_coverage: "mapped",
            boundary: "Claude WebFetch/WebSearch hook calls",
        },
        CoverageSurface {
            surface: "mcp",
            default_coverage: "mapped when Claude emits mcp__server__tool names",
            boundary: "does not wrap unrelated MCP servers automatically",
        },
    ]
}

fn codex_coverage() -> Vec<CoverageSurface> {
    vec![
        CoverageSurface {
            surface: "bash",
            default_coverage: "mapped",
            boundary: "Gommage quickstart installs a Bash matcher for Codex hook events",
        },
        CoverageSurface {
            surface: "apply_patch",
            default_coverage: "mapped",
            boundary: "Codex apply_patch hook payloads are mapped to parsed filesystem write paths and fail closed when unparsed",
        },
        CoverageSurface {
            surface: "mcp",
            default_coverage: "mapped when Codex emits mcp__server__tool names",
            boundary: "use optional gommage-mcp --gateway only for intentionally wrapped stdio MCP servers when native hooks are not enough",
        },
        CoverageSurface {
            surface: "filesystem",
            default_coverage: "sandbox boundary",
            boundary: "Codex sandbox remains authoritative for file access outside mapped hook events",
        },
    ]
}

#[derive(Debug)]
struct HookGroup {
    contains_gommage: bool,
}

fn hook_groups(root: &serde_json::Value, pointer: &str) -> Vec<HookGroup> {
    root.pointer(pointer)
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .map(|entry| HookGroup {
            contains_gommage: entry
                .get("hooks")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .any(|hook| {
                    hook.get("command")
                        .and_then(|value| value.as_str())
                        .is_some_and(|command| command.to_ascii_lowercase().contains("gommage"))
                }),
        })
        .collect()
}

fn next_commands(reports: &[HarnessAgentReport]) -> Vec<String> {
    let mut commands = vec![
        "gommage verify --json".to_string(),
        "gommage policy layers --json".to_string(),
    ];
    for report in reports {
        commands.push(format!(
            "gommage agent status {} --json",
            report.agent.as_str()
        ));
    }
    commands.push("gommage uninstall --all --dry-run".to_string());
    commands
}

fn write_harness_context_files(
    layout: &HomeLayout,
    report: &HarnessReport,
    dry_run: bool,
) -> Result<()> {
    let markdown_path = layout.root.join("AGENT_CONTEXT.md");
    let json_path = layout.root.join("integration-report.json");
    write_text(
        &markdown_path,
        &render_agent_context_markdown(report),
        dry_run,
    )?;
    let mut json = serde_json::to_string_pretty(report)?;
    json.push('\n');
    write_text(&json_path, &json, dry_run)?;
    println!(
        "{} harness context: {}, {}",
        if dry_run { "plan" } else { "ok" },
        markdown_path.display(),
        json_path.display()
    );
    Ok(())
}

fn print_harness_report(report: &HarnessReport) {
    println!("harness: {}", report.status.as_str());
    println!("home: {}", report.home);
    for agent in &report.agents {
        println!(
            "{}: {} (mode: {})",
            agent.agent.as_str(),
            agent.integration_status.as_str(),
            agent.default_install_mode
        );
        println!(
            "  hooks: existing={}, gommage={}",
            agent.existing_hooks_detected, agent.gommage_hook_installed
        );
        for note in &agent.guidance {
            println!("  note: {note}");
        }
    }
    for command in &report.next_commands {
        println!("next: {command}");
    }
}

fn render_agent_context_markdown(report: &HarnessReport) -> String {
    let mut out = String::new();
    out.push_str("# Gommage Local Integration Context\n\n");
    out.push_str(
        "This file is generated by `gommage harness write-context` or `gommage quickstart`.\n\n",
    );
    out.push_str(&format!("- GOMMAGE_HOME: `{}`\n", report.home));
    out.push_str(&format!("- Harness status: `{}`\n", report.status.as_str()));
    out.push_str("- Gommage is a policy and audit layer, not an OS sandbox.\n");
    out.push_str("- Keep native sandboxing and approval policy enabled unless an operator explicitly changes them.\n");
    out.push_str("- Gommage audits only tool calls received through installed hooks or an explicitly wrapped MCP gateway.\n\n");

    out.push_str("## How to work with the gate\n\n");
    out.push_str("- `gommage agent install` is strict by default: unmatched shell, file, and outbound capabilities remain fail-closed. Run `gommage posture --json` to inspect the active result.\n");
    out.push_str("- `gommage agent install --relaxed` is an explicit legacy convenience mode. It generates `06-agent-config-writable.yaml` and `95-agent-catch-all.yaml`, permits broad routine work, and gives up complete mediation for opaque scripts and interpreters. Rerun without `--relaxed` to back up and remove those generated relaxations.\n");
    out.push_str("- Web fetch/search and MCP write stay gated by `15-agent-tools` (they cross the local trust boundary); approve per call with a picto, or add a local allow layer if your operator wants them frictionless.\n");
    out.push_str("- An `ask` decision needs a signed picto: request one with `gommage grant --scope <scope> --reason <why>` then `gommage confirm <id>`, and retry. Typical gates: push to `main`/`release`, force-push, `git reset --hard`, cloud prod deploy/destroy, repo delete.\n");
    out.push_str("- A `deny` decision is final for that call (secret reads, dotfile/credential writes, `rm -rf` of any absolute path — not just `/`, but `/tmp/scratch`, `/home/me/build`, … — `curl|sh`). Hard-stops cannot be bypassed by a picto — change the action (a relative path like `./build` is out of hard-stop scope), not the gate.\n");
    out.push_str("- Kill-switch if the gate ever blocks real work: set `GOMMAGE_BYPASS=1` in the hook environment (hard-stops still apply), restore the newest `settings.json.gommage-bak-*` backup, or run `gommage agent uninstall <agent>`.\n\n");

    for agent in &report.agents {
        out.push_str(&format!("## {}\n\n", agent.agent.as_str()));
        out.push_str(&format!(
            "- Integration status: `{}`\n",
            agent.integration_status.as_str()
        ));
        out.push_str(&format!(
            "- Default install mode: `{}`\n",
            agent.default_install_mode
        ));
        out.push_str(&format!(
            "- Existing non-Gommage hooks detected: `{}`\n",
            agent.existing_hooks_detected
        ));
        out.push_str(&format!(
            "- Gommage hook installed: `{}`\n",
            agent.gommage_hook_installed
        ));
        for path in &agent.config_paths {
            out.push_str(&format!("- Config path: `{path}`\n"));
        }
        if let Some(allow) = &agent.native_permissions.allow {
            out.push_str(&format!(
                "- Native allow import (relaxed only; active=`{}`): `{}` importable rule(s), layer `{}`\n",
                agent.native_permissions.allow_import_active,
                allow.importable_rules,
                allow.output_path
            ));
            if !allow.broad_allow_entries.is_empty() {
                out.push_str(&format!(
                    "- Broad native allow entries eligible for late relaxed import: `{}`\n",
                    allow.broad_allow_entries.join("`, `")
                ));
            }
        }
        if let Some(deny) = &agent.native_permissions.deny {
            out.push_str(&format!(
                "- Native deny import: `{}` importable rule(s), layer `{}`\n",
                deny.importable_rules, deny.output_path
            ));
        }
        out.push_str("\nCoverage:\n\n");
        for surface in &agent.coverage {
            out.push_str(&format!(
                "- `{}`: {}. Boundary: {}.\n",
                surface.surface, surface.default_coverage, surface.boundary
            ));
        }
        out.push_str("\nGuidance:\n\n");
        for note in &agent.guidance {
            out.push_str(&format!("- {note}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Commands\n\n");
    for command in &report.next_commands {
        out.push_str(&format!("- `{command}`\n"));
    }
    out
}
