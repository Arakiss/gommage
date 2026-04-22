use anyhow::Result;
use gommage_core::runtime::HomeLayout;
use gommage_stdlib::{CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES};
use serde::Serialize;
use std::path::Path;

use crate::{
    agent::{
        AgentKind, claude_gommage_matcher, native_permission_rules, translate_claude_native_rules,
        translate_claude_permission_allow, translate_claude_permission_deny,
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
    preserve_existing_hooks: bool,
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
    })
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
        hook: HookPlan {
            matcher,
            command: "gommage-mcp",
            action: "would_install",
            preserve_existing_hooks: !replace_hooks,
        },
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
    Ok(AgentPlan {
        agent: AgentKind::Codex,
        config_paths: vec![path_display(&hooks_path), path_display(&config_path)],
        hook: HookPlan {
            matcher: "Bash".to_string(),
            command: "gommage-mcp",
            action: "would_install",
            preserve_existing_hooks: !replace_hooks,
        },
        native_permissions: NativePermissionPlan {
            import_enabled: false,
            deny: empty_permission_import_plan("/permissions/deny"),
            allow: empty_permission_import_plan("/permissions/allow"),
        },
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

fn agent_name(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Claude => "claude",
        AgentKind::Codex => "codex",
    }
}
