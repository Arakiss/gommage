use anyhow::{Context, Result};
use gommage_core::{
    Decision, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, Runtime, default_policy_env},
};
use std::{collections::HashSet, path::PathBuf, process::ExitCode};

use crate::{
    agent::{AgentKind, install_agent},
    daemon::{ServiceManager, daemon_install, resolve_service_manager},
    input::bash_call,
    policy_cmd::install_stdlib,
    util::env_path_or_home,
    verify::cmd_verify,
};

pub(crate) struct QuickstartOptions {
    pub(crate) agents: Vec<AgentKind>,
    pub(crate) replace_hooks: bool,
    pub(crate) import_native_permissions: bool,
    pub(crate) install_daemon: bool,
    pub(crate) daemon_manager: Option<ServiceManager>,
    pub(crate) daemon_force: bool,
    pub(crate) daemon_no_start: bool,
    pub(crate) self_test: bool,
    pub(crate) dry_run: bool,
}

pub(crate) fn cmd_quickstart(layout: HomeLayout, options: QuickstartOptions) -> Result<ExitCode> {
    let QuickstartOptions {
        agents,
        replace_hooks,
        import_native_permissions,
        install_daemon,
        daemon_manager,
        daemon_force,
        daemon_no_start,
        self_test,
        dry_run,
    } = options;

    if dry_run {
        println!("dry-run: no files will be written");
    }
    if !dry_run {
        layout.ensure().context("initializing home")?;
    } else {
        println!("plan home: ensure {}", layout.root.display());
    }

    let installed = if dry_run {
        (0, 0)
    } else {
        install_stdlib(&layout, false)?
    };
    if dry_run {
        println!("plan stdlib: install bundled policy and capability defaults if missing");
    } else {
        println!(
            "ok stdlib: {} policy files, {} capability files installed",
            installed.0, installed.1
        );
        let env = Expedition::load(&layout.expedition_file)?
            .map(|e| e.policy_env())
            .unwrap_or_else(default_policy_env);
        let policy = Policy::load_from_dir(&layout.policy_dir, &env)?;
        println!(
            "ok policy: {} rules ({})",
            policy.rules.len(),
            policy.version_hash
        );
    }

    let agents = if agents.is_empty() {
        vec![AgentKind::Claude]
    } else {
        agents
    };
    let snapshots = if self_test && !dry_run {
        capture_agent_config_snapshots(&agents)?
    } else {
        Vec::new()
    };
    for agent in &agents {
        install_agent(
            *agent,
            &layout,
            replace_hooks,
            import_native_permissions,
            dry_run,
        )?;
    }

    if install_daemon {
        daemon_install(
            HomeLayout::at(&layout.root),
            resolve_service_manager(daemon_manager)?,
            daemon_force,
            daemon_no_start,
            dry_run,
        )?;
    }

    if !dry_run {
        let env = Expedition::load(&layout.expedition_file)?
            .map(|e| e.policy_env())
            .unwrap_or_else(default_policy_env);
        let policy = Policy::load_from_dir(&layout.policy_dir, &env)?;
        println!(
            "ok final policy: {} rules ({})",
            policy.rules.len(),
            policy.version_hash
        );
    }

    if self_test {
        if dry_run {
            println!(
                "plan self-test: run `gommage verify` and recovery decision checks after quickstart"
            );
        } else {
            let code = run_quickstart_self_test(&layout, &agents)?;
            if code != ExitCode::SUCCESS {
                rollback_agent_config_snapshots(&snapshots)?;
                return Ok(code);
            }
        }
    }

    println!("ok quickstart complete");
    println!("next: start an expedition with `gommage expedition start <name>`");
    if install_daemon {
        println!("next: inspect runtime health with `gommage verify`");
    } else {
        println!("optional: run `gommage daemon install` for long sessions");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_quickstart_self_test(layout: &HomeLayout, agents: &[AgentKind]) -> Result<ExitCode> {
    println!("self-test: running `gommage verify`");
    let code = cmd_verify(HomeLayout::at(&layout.root), false, Vec::new())?;
    if code != ExitCode::SUCCESS {
        return Ok(code);
    }

    println!("self-test: checking recovery decisions");
    let failures = recovery_self_test_failures(layout, agents)?;
    if !failures.is_empty() {
        for failure in failures {
            eprintln!("self-test failed: {failure}");
        }
        return Ok(ExitCode::from(1));
    }

    println!("ok self-test complete");
    Ok(ExitCode::SUCCESS)
}

fn recovery_self_test_failures(layout: &HomeLayout, agents: &[AgentKind]) -> Result<Vec<String>> {
    let rt = Runtime::open(HomeLayout::at(&layout.root))?;
    let mut checks = vec![
        RecoveryCheck::allow("gommage_verify", bash_call("gommage verify --json")),
        RecoveryCheck::allow("gommage_doctor", bash_call("gommage doctor --json")),
        RecoveryCheck::allow("basic_ls", bash_call("ls -la")),
        RecoveryCheck::allow(
            "systemd_status",
            bash_call("systemctl --user status gommage-daemon.service"),
        ),
        RecoveryCheck::gommage_hard_stop("rm_root_hardstop", bash_call("rm -rf /")),
        RecoveryCheck::gommage(
            "force_push_still_denied",
            bash_call("git push --force origin main"),
        ),
    ];

    if agents.contains(&AgentKind::Claude) {
        checks.extend([
            RecoveryCheck::allow(
                "claude_agent_status",
                bash_call("gommage agent status claude --json"),
            ),
            RecoveryCheck::allow(
                "claude_settings_backup_inspection",
                bash_call("cat ~/.claude/settings.json.gommage-bak-123"),
            ),
            RecoveryCheck::allow(
                "claude_settings_backup_restore",
                bash_call("cp ~/.claude/settings.json.gommage-bak-123 ~/.claude/settings.json"),
            ),
        ]);
    }

    if agents.contains(&AgentKind::Codex) {
        checks.push(RecoveryCheck::allow(
            "codex_agent_status",
            bash_call("gommage agent status codex --json"),
        ));
    }

    let mut failures = Vec::new();
    for check in checks {
        let caps = rt.mapper.map(&check.call);
        let eval = evaluate(&caps, &rt.policy);
        if !check.expectation.matches(&eval.decision) {
            failures.push(format!(
                "{} expected {}, got {} (matched_rule={})",
                check.name,
                check.expectation.label(),
                decision_label(&eval.decision),
                eval.matched_rule
                    .as_ref()
                    .map(|rule| rule.name.as_str())
                    .unwrap_or("<none>")
            ));
        }
    }
    Ok(failures)
}

struct RecoveryCheck {
    name: &'static str,
    call: ToolCall,
    expectation: RecoveryExpectation,
}

impl RecoveryCheck {
    fn allow(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Allow,
        }
    }

    fn gommage(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Gommage { hard_stop: None },
        }
    }

    fn gommage_hard_stop(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Gommage {
                hard_stop: Some(true),
            },
        }
    }
}

enum RecoveryExpectation {
    Allow,
    Gommage { hard_stop: Option<bool> },
}

impl RecoveryExpectation {
    fn label(&self) -> String {
        match self {
            Self::Allow => "allow".to_string(),
            Self::Gommage {
                hard_stop: Some(value),
            } => format!("gommage hard_stop={value}"),
            Self::Gommage { hard_stop: None } => "gommage".to_string(),
        }
    }

    fn matches(&self, decision: &Decision) -> bool {
        match (self, decision) {
            (Self::Allow, Decision::Allow) => true,
            (
                Self::Gommage {
                    hard_stop: expected,
                },
                Decision::Gommage { hard_stop, .. },
            ) => expected.is_none_or(|expected| expected == *hard_stop),
            _ => false,
        }
    }
}

fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::AskPicto { required_scope, .. } => format!("ask_picto scope={required_scope}"),
        Decision::Gommage { hard_stop, reason } => {
            format!("gommage hard_stop={hard_stop} reason={reason:?}")
        }
    }
}

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

fn capture_agent_config_snapshots(agents: &[AgentKind]) -> Result<Vec<FileSnapshot>> {
    let mut paths = Vec::new();
    for agent in agents {
        match agent {
            AgentKind::Claude => {
                paths.push(env_path_or_home(
                    "GOMMAGE_CLAUDE_SETTINGS",
                    &[".claude", "settings.json"],
                ));
            }
            AgentKind::Codex => {
                paths.push(env_path_or_home(
                    "GOMMAGE_CODEX_HOOKS",
                    &[".codex", "hooks.json"],
                ));
                paths.push(env_path_or_home(
                    "GOMMAGE_CODEX_CONFIG",
                    &[".codex", "config.toml"],
                ));
            }
        }
    }

    let mut seen = HashSet::new();
    let mut snapshots = Vec::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        let contents = if path.exists() {
            Some(std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?)
        } else {
            None
        };
        snapshots.push(FileSnapshot { path, contents });
    }
    Ok(snapshots)
}

fn rollback_agent_config_snapshots(snapshots: &[FileSnapshot]) -> Result<()> {
    if snapshots.is_empty() {
        return Ok(());
    }

    eprintln!("self-test failed: restoring agent configuration snapshots");
    for snapshot in snapshots {
        match &snapshot.contents {
            Some(contents) => {
                if let Some(parent) = snapshot.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&snapshot.path, contents)
                    .with_context(|| format!("restoring {}", snapshot.path.display()))?;
                eprintln!("rollback restored: {}", snapshot.path.display());
            }
            None if snapshot.path.exists() => {
                std::fs::remove_file(&snapshot.path)
                    .with_context(|| format!("removing {}", snapshot.path.display()))?;
                eprintln!("rollback removed: {}", snapshot.path.display());
            }
            None => {}
        }
    }
    Ok(())
}
