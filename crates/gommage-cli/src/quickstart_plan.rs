use anyhow::Result;
use gommage_core::runtime::HomeLayout;
use gommage_stdlib::{CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES};
use serde::Serialize;
use std::path::Path;

use crate::{
    agent::{
        AgentKind, CLAUDE_GOMMAGE_HOOK_COMMAND, CODEX_GOMMAGE_HOOK_COMMAND, CODEX_GOMMAGE_MATCHER,
        claude_gommage_matcher, codex_pre_tool_use_pointer, native_permission_rules,
        translate_claude_native_rules, translate_claude_permission_allow,
        translate_claude_permission_deny,
    },
    daemon::{DaemonDryRunPlan, ServiceManager, daemon_dry_run_plan, resolve_service_manager},
    util::{env_path_or_home, path_display, read_json_object},
};

#[derive(Debug, Serialize)]
pub(crate) struct QuickstartDryRunReport {
    status: &'static str,
    dry_run: bool,
    home: String,
    agents: Vec<AgentKind>,
    replace_hooks: bool,
    import_native_permissions: bool,
    operations: Vec<PlannedOperation>,
    stdlib: StdlibPlan,
    agent_integrations: Vec<AgentPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon: Option<DaemonDryRunPlan>,
    self_test: SelfTestPlan,
    explanation: QuickstartExplanation,
}

#[derive(Debug, Serialize)]
struct PlannedOperation {
    kind: &'static str,
    action: &'static str,
    path: String,
    backup_before_replace: bool,
    reason: String,
}

#[derive(Debug, Serialize)]
struct StdlibPlan {
    policies: Vec<StdlibFilePlan>,
    capabilities: Vec<StdlibFilePlan>,
}

#[derive(Debug, Serialize)]
struct StdlibFilePlan {
    path: String,
    action: &'static str,
}

#[derive(Debug, Serialize)]
struct AgentPlan {
    agent: AgentKind,
    config_paths: Vec<String>,
    hook: HookPlan,
    native_permissions: NativePermissionPlan,
}

#[derive(Debug, Serialize)]
struct HookPlan {
    matcher: String,
    command: &'static str,
    action: &'static str,
    strategy: &'static str,
    preserve_existing_hooks: bool,
    existing_hook_groups: Vec<ExistingHookGroupPlan>,
    existing_hook_group_count: usize,
    preserved_hook_group_count: usize,
    removed_gommage_hook_group_count: usize,
    removed_unrelated_hook_group_count: usize,
}

#[derive(Debug, Serialize)]
struct ExistingHookGroupPlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    matcher: Option<String>,
    hook_count: usize,
    contains_gommage: bool,
    action: &'static str,
}

#[derive(Debug, Serialize)]
struct NativePermissionPlan {
    import_enabled: bool,
    deny: PermissionImportPlan,
    allow: PermissionImportPlan,
}

#[derive(Debug, Serialize)]
struct PermissionImportPlan {
    source_pointer: &'static str,
    native_rules: usize,
    importable_rules: usize,
    skipped_rules: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_path: Option<String>,
    action: &'static str,
    backup_before_replace: bool,
}

#[derive(Debug, Serialize)]
struct SelfTestPlan {
    enabled: bool,
    commands: Vec<&'static str>,
    checks: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct QuickstartExplanation {
    installation_mode: &'static str,
    summary: Vec<String>,
    agent_guidance: Vec<AgentQuickstartGuidance>,
    next_commands: Vec<String>,
    context_files: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AgentQuickstartGuidance {
    agent: AgentKind,
    posture: &'static str,
    preserves_existing_hooks: bool,
    imports_native_permissions: bool,
    default_coverage: Vec<&'static str>,
    boundaries: Vec<&'static str>,
    operator_notes: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_quickstart_dry_run_report(
    layout: &HomeLayout,
    agents: Vec<AgentKind>,
    replace_hooks: bool,
    import_native_permissions: bool,
    install_daemon: bool,
    daemon_manager: Option<ServiceManager>,
    daemon_force: bool,
    daemon_no_start: bool,
    self_test: bool,
) -> Result<QuickstartDryRunReport> {
    let agents = if agents.is_empty() {
        vec![AgentKind::Claude]
    } else {
        agents
    };
    let mut operations = vec![
        planned_dir("home", &layout.root, "ensure Gommage home exists"),
        planned_dir(
            "policy_dir",
            &layout.policy_dir,
            "ensure policy directory exists",
        ),
        planned_dir(
            "capabilities_dir",
            &layout.capabilities_dir,
            "ensure capability mapper directory exists",
        ),
        PlannedOperation {
            kind: "key",
            action: if layout.key_file.exists() {
                "preserve_existing"
            } else {
                "would_generate"
            },
            path: path_display(&layout.key_file),
            backup_before_replace: false,
            reason: "daemon signing key".to_string(),
        },
    ];

    let stdlib = StdlibPlan {
        policies: STDLIB_POLICIES
            .iter()
            .map(|file| stdlib_file_plan(&layout.policy_dir.join(file.name)))
            .collect(),
        capabilities: STDLIB_CAPABILITIES
            .iter()
            .map(|file| stdlib_file_plan(&layout.capabilities_dir.join(file.name)))
            .collect(),
    };

    for file in &stdlib.policies {
        operations.push(PlannedOperation {
            kind: "stdlib_policy",
            action: file.action,
            path: file.path.clone(),
            backup_before_replace: false,
            reason: "install bundled policy if missing".to_string(),
        });
    }
    for file in &stdlib.capabilities {
        operations.push(PlannedOperation {
            kind: "stdlib_capability",
            action: file.action,
            path: file.path.clone(),
            backup_before_replace: false,
            reason: "install bundled capability mapper if missing".to_string(),
        });
    }

    let agent_integrations = agents
        .iter()
        .map(|agent| build_agent_plan(*agent, layout, replace_hooks, import_native_permissions))
        .collect::<Result<Vec<_>>>()?;
    for plan in &agent_integrations {
        for path in &plan.config_paths {
            operations.push(PlannedOperation {
                kind: "agent_config",
                action: "would_write",
                path: path.clone(),
                backup_before_replace: Path::new(path).exists(),
                reason: format!("install {} hook integration", agent_name(plan.agent)),
            });
        }
        for import in [
            &plan.native_permissions.deny,
            &plan.native_permissions.allow,
        ] {
            if let Some(path) = &import.output_path {
                operations.push(PlannedOperation {
                    kind: "native_permission_import",
                    action: import.action,
                    path: path.clone(),
                    backup_before_replace: import.backup_before_replace,
                    reason: format!("import {}", import.source_pointer),
                });
            }
        }
    }

    let daemon = if install_daemon {
        let manager = resolve_service_manager(daemon_manager)?;
        let plan = daemon_dry_run_plan(manager, daemon_force, daemon_no_start)?;
        operations.push(PlannedOperation {
            kind: "daemon_service",
            action: if plan.backup_existing_service_file {
                "would_replace"
            } else {
                "would_write"
            },
            path: plan.service_file.clone(),
            backup_before_replace: plan.backup_existing_service_file,
            reason: "install user-level daemon service".to_string(),
        });
        Some(plan)
    } else {
        None
    };

    let explanation = build_quickstart_explanation(&layout.root, &agents, replace_hooks);

    Ok(QuickstartDryRunReport {
        status: "plan",
        dry_run: true,
        home: path_display(&layout.root),
        agents,
        replace_hooks,
        import_native_permissions,
        operations,
        stdlib,
        agent_integrations,
        daemon,
        self_test: build_self_test_plan(self_test),
        explanation,
    })
}

pub(crate) fn print_quickstart_explanation(report: &QuickstartDryRunReport) {
    println!("explain mode: {}", report.explanation.installation_mode);
    for line in &report.explanation.summary {
        println!("explain: {line}");
    }
    for plan in &report.agent_integrations {
        println!(
            "explain {} hooks: strategy={}, existing={}, preserved={}, removed_gommage={}, removed_unrelated={}",
            plan.agent.as_str(),
            plan.hook.strategy,
            plan.hook.existing_hook_group_count,
            plan.hook.preserved_hook_group_count,
            plan.hook.removed_gommage_hook_group_count,
            plan.hook.removed_unrelated_hook_group_count,
        );
    }
    for agent in &report.explanation.agent_guidance {
        println!(
            "explain {}: posture={}",
            agent.agent.as_str(),
            agent.posture
        );
        for note in &agent.operator_notes {
            println!("explain {}: {note}", agent.agent.as_str());
        }
        for boundary in &agent.boundaries {
            println!("explain {} boundary: {boundary}", agent.agent.as_str());
        }
    }
    for command in &report.explanation.next_commands {
        println!("next: {command}");
    }
}

fn planned_dir(kind: &'static str, path: &Path, reason: &str) -> PlannedOperation {
    PlannedOperation {
        kind,
        action: if path.exists() {
            "already_exists"
        } else {
            "would_create"
        },
        path: path_display(path),
        backup_before_replace: false,
        reason: reason.to_string(),
    }
}

fn stdlib_file_plan(path: &Path) -> StdlibFilePlan {
    StdlibFilePlan {
        path: path_display(path),
        action: if path.exists() {
            "preserve_existing"
        } else {
            "would_write"
        },
    }
}

fn build_agent_plan(
    agent: AgentKind,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
) -> Result<AgentPlan> {
    match agent {
        AgentKind::Claude => build_claude_plan(layout, replace_hooks, import_native_permissions),
        AgentKind::Codex => build_codex_plan(replace_hooks),
    }
}

fn build_claude_plan(
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
) -> Result<AgentPlan> {
    let settings_path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
    let settings = read_json_object(&settings_path)?;
    let matcher = claude_gommage_matcher(&settings);
    let hook = hook_plan(
        matcher,
        CLAUDE_GOMMAGE_HOOK_COMMAND,
        &settings,
        "/hooks/PreToolUse",
        replace_hooks,
    )?;
    let deny_rules = native_permission_rules(&settings, "/permissions/deny");
    let allow_rules = native_permission_rules(&settings, "/permissions/allow");
    let deny = permission_import_plan(
        layout,
        "/permissions/deny",
        "05-claude-import.yaml",
        &deny_rules,
        import_native_permissions,
        replace_hooks,
        translate_claude_permission_deny,
    );
    let allow = permission_import_plan(
        layout,
        "/permissions/allow",
        "90-claude-allow-import.yaml",
        &allow_rules,
        import_native_permissions,
        replace_hooks,
        translate_claude_permission_allow,
    );
    Ok(AgentPlan {
        agent: AgentKind::Claude,
        config_paths: vec![path_display(&settings_path)],
        hook,
        native_permissions: NativePermissionPlan {
            import_enabled: import_native_permissions,
            deny,
            allow,
        },
    })
}

fn build_codex_plan(replace_hooks: bool) -> Result<AgentPlan> {
    let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
    let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
    let hooks = read_json_object(&hooks_path)?;
    let hook_pointer = codex_pre_tool_use_pointer(&hooks);
    Ok(AgentPlan {
        agent: AgentKind::Codex,
        config_paths: vec![path_display(&hooks_path), path_display(&config_path)],
        hook: hook_plan(
            CODEX_GOMMAGE_MATCHER.to_string(),
            CODEX_GOMMAGE_HOOK_COMMAND,
            &hooks,
            hook_pointer,
            replace_hooks,
        )?,
        native_permissions: NativePermissionPlan {
            import_enabled: false,
            deny: empty_permission_import_plan("/permissions/deny"),
            allow: empty_permission_import_plan("/permissions/allow"),
        },
    })
}

fn hook_plan(
    matcher: String,
    command: &'static str,
    hooks_root: &serde_json::Value,
    pointer: &str,
    replace_hooks: bool,
) -> Result<HookPlan> {
    let existing_hook_groups = existing_hook_group_plans(hooks_root, pointer, replace_hooks)?;
    let preserved_hook_group_count = existing_hook_groups
        .iter()
        .filter(|group| group.action == "would_preserve")
        .count();
    let removed_gommage_hook_group_count = existing_hook_groups
        .iter()
        .filter(|group| group.contains_gommage)
        .count();
    let removed_unrelated_hook_group_count = existing_hook_groups
        .iter()
        .filter(|group| group.action == "would_remove_replace_hooks" && !group.contains_gommage)
        .count();

    Ok(HookPlan {
        matcher,
        command,
        action: "would_install",
        strategy: if replace_hooks {
            "replace_all_existing"
        } else {
            "append_preserving_unrelated"
        },
        preserve_existing_hooks: !replace_hooks,
        existing_hook_group_count: existing_hook_groups.len(),
        preserved_hook_group_count,
        removed_gommage_hook_group_count,
        removed_unrelated_hook_group_count,
        existing_hook_groups,
    })
}

fn existing_hook_group_plans(
    hooks_root: &serde_json::Value,
    pointer: &str,
    replace_hooks: bool,
) -> Result<Vec<ExistingHookGroupPlan>> {
    let Some(groups) = hooks_root.pointer(pointer) else {
        return Ok(Vec::new());
    };
    let Some(groups) = groups.as_array() else {
        anyhow::bail!("{pointer} exists but is not an array");
    };

    Ok(groups
        .iter()
        .map(|group| {
            let contains_gommage = json_hook_entry_contains_command(group, "gommage");
            ExistingHookGroupPlan {
                matcher: group
                    .get("matcher")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                hook_count: group
                    .get("hooks")
                    .and_then(|v| v.as_array())
                    .map_or(0, Vec::len),
                contains_gommage,
                action: if replace_hooks {
                    "would_remove_replace_hooks"
                } else if contains_gommage {
                    "would_remove_stale_gommage"
                } else {
                    "would_preserve"
                },
            }
        })
        .collect())
}

fn json_hook_entry_contains_command(entry: &serde_json::Value, needle: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(|v| v.as_str())
                    .is_some_and(|command| command.to_ascii_lowercase().contains(needle))
            })
        })
}

fn permission_import_plan(
    layout: &HomeLayout,
    source_pointer: &'static str,
    file_name: &str,
    rules: &[String],
    enabled: bool,
    force: bool,
    translate: fn(&str) -> Option<String>,
) -> PermissionImportPlan {
    if !enabled {
        return PermissionImportPlan {
            source_pointer,
            native_rules: rules.len(),
            importable_rules: 0,
            skipped_rules: rules.len(),
            skipped: rules.to_vec(),
            output_path: None,
            action: "skipped_disabled",
            backup_before_replace: false,
        };
    }
    let (translated, skipped) = translate_claude_native_rules(rules, translate);
    let path = layout.policy_dir.join(file_name);
    PermissionImportPlan {
        source_pointer,
        native_rules: rules.len(),
        importable_rules: translated.len(),
        skipped_rules: skipped.len(),
        skipped,
        output_path: if translated.is_empty() {
            None
        } else {
            Some(path_display(&path))
        },
        action: if translated.is_empty() {
            "skipped_no_importable_rules"
        } else if path.exists() && force {
            "would_replace"
        } else if path.exists() {
            "would_preserve_without_replace_hooks"
        } else {
            "would_write"
        },
        backup_before_replace: path.exists(),
    }
}

fn empty_permission_import_plan(source_pointer: &'static str) -> PermissionImportPlan {
    PermissionImportPlan {
        source_pointer,
        native_rules: 0,
        importable_rules: 0,
        skipped_rules: 0,
        skipped: Vec::new(),
        output_path: None,
        action: "not_supported_for_agent",
        backup_before_replace: false,
    }
}

fn build_self_test_plan(enabled: bool) -> SelfTestPlan {
    if !enabled {
        return SelfTestPlan {
            enabled,
            commands: Vec::new(),
            checks: Vec::new(),
        };
    }
    SelfTestPlan {
        enabled,
        commands: vec!["gommage verify"],
        checks: vec![
            "gommage verify --json is allowed",
            "gommage doctor --json is allowed",
            "ls -la is allowed for recovery",
            "systemctl --user status gommage-daemon.service is allowed",
            "rm -rf / remains a hard-stop",
            "git push --force origin main remains denied",
            "agent status commands remain allowed for selected agents",
        ],
    }
}

fn build_quickstart_explanation(
    home: &Path,
    agents: &[AgentKind],
    replace_hooks: bool,
) -> QuickstartExplanation {
    QuickstartExplanation {
        installation_mode: if replace_hooks {
            "replace-hooks"
        } else {
            "coexistence"
        },
        summary: vec![
            "quickstart is additive by default: it preserves unrelated host hooks and appends Gommage wiring.".to_string(),
            "changed host files are backed up before replacement.".to_string(),
            "native sandboxing and approval policy remain authoritative below the hook layer.".to_string(),
            "Gommage audits only tool calls it receives through installed hooks or an explicit MCP gateway.".to_string(),
        ],
        agent_guidance: agents
            .iter()
            .map(|agent| agent_quickstart_guidance(*agent, !replace_hooks))
            .collect(),
        next_commands: {
            let mut commands = vec![
                "gommage verify --json".to_string(),
                "gommage policy layers --json".to_string(),
                "gommage harness diagnose --json".to_string(),
            ];
            for agent in agents {
                commands.push(format!("gommage agent status {} --json", agent.as_str()));
            }
            commands.push("gommage uninstall --all --dry-run".to_string());
            commands
        },
        context_files: vec![
            path_display(&home.join("AGENT_CONTEXT.md")),
            path_display(&home.join("integration-report.json")),
        ],
    }
}

fn agent_quickstart_guidance(
    agent: AgentKind,
    preserves_existing_hooks: bool,
) -> AgentQuickstartGuidance {
    match agent {
        AgentKind::Claude => AgentQuickstartGuidance {
            agent,
            posture: "preserve existing hooks, import supported native permissions, then verify",
            preserves_existing_hooks,
            imports_native_permissions: true,
            default_coverage: vec![
                "Bash",
                "filesystem tools",
                "search tools",
                "web tools",
                "Claude-style MCP tool names",
            ],
            boundaries: vec![
                "if another hook blocks first, Gommage cannot audit that decision",
                "Claude Code does not provide OS sandboxing; add one separately when needed",
            ],
            operator_notes: vec![
                "permissions.deny imports load early into 05-claude-import.yaml".to_string(),
                "permissions.allow imports, including broad Bash, load late into 90-claude-allow-import.yaml".to_string(),
                "use --replace-hooks only after reviewing the migration plan".to_string(),
            ],
        },
        AgentKind::Codex => AgentQuickstartGuidance {
            agent,
            posture: "enable Codex hooks, install Gommage Codex matcher, keep Codex sandboxing",
            preserves_existing_hooks,
            imports_native_permissions: false,
            default_coverage: vec!["Bash", "apply_patch", "MCP tool names"],
            boundaries: vec![
                "Codex hooks do not intercept every shell or non-shell tool path",
                "apply_patch payloads fail closed when the patch file list cannot be parsed safely",
                "Codex sandbox remains the file boundary outside mapped hooks",
            ],
            operator_notes: vec![
                "keep Codex native sandboxing and hook trust enabled; Gommage is a policy decision layer, not OS confinement".to_string(),
                "use the optional legacy MCP gateway only when an operator intentionally wants a stdio MCP proxy in addition to native Codex hooks".to_string(),
            ],
        },
    }
}

fn agent_name(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Claude => "claude",
        AgentKind::Codex => "codex",
    }
}
