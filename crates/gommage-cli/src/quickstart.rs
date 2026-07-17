use anyhow::{Context, Result};
use gommage_core::{
    Decision, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, Runtime, default_policy_env},
};
use gommage_stdlib::{CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES};
use std::{path::PathBuf, process::ExitCode};

use crate::{
    agent::{
        AgentKind, AgentPolicyMode, agent_transaction_files, install_agents,
        preflight_agent_installs,
    },
    agent_status::build_agent_status_report,
    daemon::{
        ServiceManager, current_recorded_daemon_runtime, daemon_install_prepared,
        preflight_daemon_install, prepare_daemon_runtime_snapshot, quiesce_daemon_runtime,
        recover_recorded_daemon_runtime, reload_policy_runtime, resolve_service_manager,
        restore_daemon_runtime_after_files, service_file_path,
    },
    harness::write_harness_context,
    input::bash_call,
    policy_cmd::install_stdlib,
    quickstart_plan::{build_quickstart_dry_run_report, print_quickstart_explanation},
    util::{InstallTransaction, TransactionFile, ensure_home},
    verify::cmd_verify,
};

pub(crate) struct QuickstartOptions {
    pub(crate) agents: Vec<AgentKind>,
    pub(crate) replace_hooks: bool,
    pub(crate) import_native_permissions: bool,
    pub(crate) policy_mode: AgentPolicyMode,
    pub(crate) install_daemon: bool,
    pub(crate) daemon_manager: Option<ServiceManager>,
    pub(crate) daemon_force: bool,
    pub(crate) daemon_no_start: bool,
    pub(crate) self_test: bool,
    pub(crate) dry_run: bool,
    pub(crate) json: bool,
    pub(crate) explain: bool,
}

pub(crate) fn cmd_quickstart(layout: HomeLayout, options: QuickstartOptions) -> Result<ExitCode> {
    let QuickstartOptions {
        agents,
        replace_hooks,
        import_native_permissions,
        policy_mode,
        install_daemon,
        daemon_manager,
        daemon_force,
        daemon_no_start,
        self_test,
        dry_run,
        json,
        explain,
    } = options;

    if json {
        let report = build_quickstart_dry_run_report(
            &layout,
            agents,
            replace_hooks,
            import_native_permissions,
            policy_mode,
            install_daemon,
            daemon_manager,
            daemon_force,
            daemon_no_start,
            self_test,
        )?;
        let execution_ready = report.execution_ready();
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if execution_ready {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }

    if dry_run {
        println!("dry-run: no files will be written");
        if explain {
            let report = build_quickstart_dry_run_report(
                &layout,
                agents.clone(),
                replace_hooks,
                import_native_permissions,
                policy_mode,
                install_daemon,
                daemon_manager,
                daemon_force,
                daemon_no_start,
                self_test,
            )?;
            print_quickstart_explanation(&report);
        }
    }

    let agents = if agents.is_empty() {
        vec![AgentKind::Claude]
    } else {
        agents
    };
    let resolved_daemon_manager = if install_daemon {
        Some(resolve_service_manager(daemon_manager)?)
    } else {
        None
    };
    let mut daemon_runtime_snapshot = None;
    let mut transaction = if dry_run {
        preflight_agent_installs(
            &agents,
            &layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
        )?;
        if let Some(manager) = resolved_daemon_manager {
            preflight_daemon_install(&layout, manager, daemon_force)?;
        }
        None
    } else {
        let mut transaction = InstallTransaction::begin(
            &layout,
            quickstart_transaction_files(&agents, &layout, resolved_daemon_manager)?,
            vec![
                layout.root.clone(),
                layout.policy_dir.clone(),
                layout.capabilities_dir.clone(),
            ],
        )?;
        if transaction.recovered_previous() {
            recover_recorded_daemon_runtime(&transaction, &layout)?;
            reload_policy_runtime(&layout)
                .context("restoring the runtime after an interrupted quickstart")?;
            transaction.acknowledge_recovery()?;
        }
        let preflight = preflight_agent_installs(
            &agents,
            &layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
        )
        .and_then(|()| {
            if let Some(manager) = resolved_daemon_manager {
                preflight_daemon_install(&layout, manager, daemon_force)
            } else {
                Ok(())
            }
        });
        if let Err(error) = preflight {
            transaction.commit()?;
            return Err(error);
        }
        Some(transaction)
    };
    let result = (|| -> Result<ExitCode> {
        if !dry_run {
            ensure_home(&layout).context("initializing home")?;
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

        install_agents(
            &agents,
            &layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
            dry_run,
        )?;

        if dry_run {
            println!("plan harness-context: write AGENT_CONTEXT.md and integration-report.json");
        } else {
            write_harness_context(&layout, agents.clone())?;
            reload_policy_runtime(&layout)?;
            if let Some(transaction) = transaction.as_mut() {
                transaction.observe_paths(
                    quickstart_runtime_paths(&layout)
                        .iter()
                        .map(PathBuf::as_path),
                )?;
            }
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
                let code = run_quickstart_self_test(&layout, &agents, policy_mode)?;
                if let Some(transaction) = transaction.as_mut() {
                    transaction.observe_paths(
                        quickstart_runtime_paths(&layout)
                            .iter()
                            .map(PathBuf::as_path),
                    )?;
                }
                if code != ExitCode::SUCCESS {
                    return Ok(code);
                }
            }
        }

        // Service activation is last, and its prior manager state is already
        // fsynced in the outer journal. The remaining observation/commit steps
        // therefore compensate both files and the manager if they fail or the
        // process is interrupted.
        if let Some(manager) = resolved_daemon_manager {
            if !dry_run {
                daemon_runtime_snapshot =
                    prepare_daemon_runtime_snapshot(&layout, manager, daemon_no_start)?;
            }
            let daemon_result = daemon_install_prepared(
                &HomeLayout::at(&layout.root),
                manager,
                daemon_force,
                daemon_no_start,
                dry_run,
                daemon_runtime_snapshot,
            );
            let observe_result = if !dry_run {
                transaction
                    .as_mut()
                    .expect("non-dry quickstart owns a transaction")
                    .observe_paths(
                        quickstart_daemon_runtime_paths(&layout)
                            .iter()
                            .map(PathBuf::as_path),
                    )
            } else {
                Ok(())
            };
            match (daemon_result, observe_result) {
                (Ok(code), Ok(())) if code == ExitCode::SUCCESS => {}
                (Ok(code), Ok(())) => return Ok(code),
                (Ok(_), Err(error)) => {
                    return Err(error.context("journaling daemon runtime activation"));
                }
                (Err(error), Ok(())) => return Err(error),
                (Err(error), Err(observe_error)) => {
                    return Err(error.context(format!(
                        "journaling daemon runtime activation also failed: {observe_error:#}"
                    )));
                }
            }
        }

        Ok(ExitCode::SUCCESS)
    })();

    match result {
        Ok(code) if code == ExitCode::SUCCESS => {
            if let Some(mut transaction) = transaction.take()
                && let Err(error) = transaction.commit()
            {
                return Err(
                    rollback_quickstart_transaction(transaction, &layout, Some(error))
                        .expect_err("primary quickstart commit error is preserved"),
                );
            }
        }
        Ok(code) => {
            if let Some(transaction) = transaction.take() {
                rollback_quickstart_transaction(transaction, &layout, None)?;
            }
            return Ok(code);
        }
        Err(error) => {
            if dry_run {
                return Err(error);
            }
            let transaction = transaction
                .take()
                .expect("non-dry quickstart owns a transaction");
            return Err(
                rollback_quickstart_transaction(transaction, &layout, Some(error))
                    .expect_err("primary quickstart error is preserved"),
            );
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

fn run_quickstart_self_test(
    layout: &HomeLayout,
    agents: &[AgentKind],
    policy_mode: AgentPolicyMode,
) -> Result<ExitCode> {
    println!("self-test: running `gommage verify`");
    let code = cmd_verify(HomeLayout::at(&layout.root), false, Vec::new())?;
    if code != ExitCode::SUCCESS {
        return Ok(code);
    }

    println!("self-test: checking recovery decisions");
    let failures = recovery_self_test_failures(layout, agents, policy_mode)?;
    if !failures.is_empty() {
        for failure in failures {
            eprintln!("self-test failed: {failure}");
        }
        return Ok(ExitCode::from(1));
    }

    println!("ok self-test complete");
    Ok(ExitCode::SUCCESS)
}

fn recovery_self_test_failures(
    layout: &HomeLayout,
    agents: &[AgentKind],
    policy_mode: AgentPolicyMode,
) -> Result<Vec<String>> {
    let rt = Runtime::open(HomeLayout::at(&layout.root))?;
    let mut checks = vec![
        RecoveryCheck::allow("gommage_verify", bash_call("gommage verify --json")),
        RecoveryCheck::allow("gommage_doctor", bash_call("gommage doctor --json")),
        RecoveryCheck::allow(
            "systemd_status",
            bash_call("systemctl --user status gommage-daemon.service"),
        ),
        RecoveryCheck::gommage_hard_stop("rm_root_hardstop", bash_call("rm -rf /")),
        RecoveryCheck::ask_picto(
            "force_push_asks_picto",
            bash_call("git push --force origin main"),
        ),
    ];

    let posture_check = |name, call| {
        if policy_mode == AgentPolicyMode::Relaxed {
            RecoveryCheck::allow(name, call)
        } else {
            RecoveryCheck::gommage_any(name, call)
        }
    };

    // Strict posture keeps unmatched routine work fail-closed. The legacy
    // convenience behavior is available only through explicit relaxed mode.
    let home = std::env::var("HOME").unwrap_or_default();
    checks.extend([
        RecoveryCheck::allow("basic_ls", bash_call("ls -la")),
        posture_check("posture_routine_bash", bash_call("echo gommage-selftest")),
        posture_check(
            "posture_project_write",
            write_call(&format!("{home}/gommage-selftest.txt")),
        ),
        RecoveryCheck::ask_picto("posture_main_push_asks", bash_call("git push origin main")),
    ]);

    if agents.contains(&AgentKind::Claude) {
        checks.push(posture_check(
            "posture_claude_config_writable",
            write_call(&format!("{home}/.claude/gommage-selftest")),
        ));
    }

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
            RecoveryCheck::gommage(
                "claude_settings_backup_restore_denied",
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
    for agent in agents {
        let status = build_agent_status_report(*agent, layout);
        if status.failures() > 0 {
            failures.push(format!(
                "{}_integration_status reported {} failure(s)",
                agent.as_str(),
                status.failures()
            ));
        }
    }
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

    fn gommage_hard_stop(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Gommage {
                hard_stop: Some(true),
            },
        }
    }

    fn gommage(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Gommage {
                hard_stop: Some(false),
            },
        }
    }

    fn gommage_any(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::Gommage { hard_stop: None },
        }
    }

    fn ask_picto(name: &'static str, call: ToolCall) -> Self {
        Self {
            name,
            call,
            expectation: RecoveryExpectation::AskPicto,
        }
    }
}

enum RecoveryExpectation {
    Allow,
    Gommage { hard_stop: Option<bool> },
    AskPicto,
}

impl RecoveryExpectation {
    fn label(&self) -> String {
        match self {
            Self::Allow => "allow".to_string(),
            Self::Gommage {
                hard_stop: Some(value),
            } => format!("gommage hard_stop={value}"),
            Self::Gommage { hard_stop: None } => "gommage".to_string(),
            Self::AskPicto => "ask_picto".to_string(),
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
            (Self::AskPicto, Decision::AskPicto { .. }) => true,
            _ => false,
        }
    }
}

fn write_call(path: &str) -> ToolCall {
    ToolCall {
        tool: "Write".to_string(),
        input: serde_json::json!({ "file_path": path }),
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

fn quickstart_transaction_files(
    agents: &[AgentKind],
    layout: &HomeLayout,
    daemon_manager: Option<ServiceManager>,
) -> Result<Vec<TransactionFile>> {
    let mut files = agent_transaction_files(agents, layout);
    for path in quickstart_runtime_paths(layout) {
        files.push(TransactionFile::new(path).preserve_existing());
    }
    for file in STDLIB_POLICIES {
        files.push(TransactionFile::new(layout.policy_dir.join(file.name)));
    }
    for file in STDLIB_CAPABILITIES {
        files.push(TransactionFile::new(
            layout.capabilities_dir.join(file.name),
        ));
    }
    files.push(TransactionFile::new(layout.root.join("AGENT_CONTEXT.md")));
    files.push(TransactionFile::new(
        layout.root.join("integration-report.json"),
    ));
    for path in quickstart_daemon_runtime_paths(layout) {
        files.push(TransactionFile::new(path).preserve_existing());
    }
    if let Some(manager) = daemon_manager {
        files.push(TransactionFile::new(service_file_path(manager)?));
    }
    files.sort_by(|left, right| left.path().cmp(right.path()));
    files.dedup_by(|left, right| left.path() == right.path());
    Ok(files)
}

fn quickstart_runtime_paths(layout: &HomeLayout) -> Vec<PathBuf> {
    let mut paths = vec![
        layout.pictos_db.clone(),
        layout.approvals_log.clone(),
        layout.approval_webhook_dlq.clone(),
        layout.audit_log.clone(),
        layout.state_db.clone(),
        layout.expedition_file.clone(),
        layout.update_check.clone(),
    ];
    for database in [&layout.pictos_db, &layout.state_db] {
        paths.push(PathBuf::from(format!("{}-wal", database.display())));
        paths.push(PathBuf::from(format!("{}-shm", database.display())));
    }
    paths
}

fn quickstart_daemon_runtime_paths(layout: &HomeLayout) -> Vec<PathBuf> {
    vec![
        layout.root.join("daemon.log"),
        layout.root.join("daemon.err.log"),
        layout.socket.clone(),
    ]
}

fn rollback_quickstart_transaction(
    mut transaction: InstallTransaction,
    layout: &HomeLayout,
    primary: Option<anyhow::Error>,
) -> Result<()> {
    if !transaction.has_mutations() {
        transaction.commit()?;
        return primary.map_or(Ok(()), Err);
    }
    eprintln!("quickstart failed: restoring filesystem journal (durable)");
    let mut snapshot_error = None;
    let daemon_runtime_snapshot = match current_recorded_daemon_runtime(&transaction) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            snapshot_error = Some(error.context("reading service-manager rollback state"));
            None
        }
    };
    let service_quiesce = match daemon_runtime_snapshot {
        Some(snapshot) => quiesce_daemon_runtime(snapshot),
        None => Ok(()),
    };
    let rollback = transaction.rollback();
    let service_restore = match (
        rollback.is_ok() && service_quiesce.is_ok(),
        daemon_runtime_snapshot,
    ) {
        (true, Some(snapshot)) => restore_daemon_runtime_after_files(layout, snapshot),
        (_, _) => Ok(()),
    };
    let reload = if rollback.is_ok() && service_restore.is_ok() {
        reload_policy_runtime(layout)
    } else {
        Ok(())
    };
    let mut secondary = Vec::new();
    if let Err(error) = &rollback {
        secondary.push(format!("filesystem rollback failed: {error:#}"));
    }
    if let Err(error) = &reload {
        secondary.push(format!(
            "restoring the prior daemon policy failed: {error:#}"
        ));
    }
    if let Err(error) = &service_restore {
        secondary.push(format!("service-manager rollback failed: {error:#}"));
    }
    if let Err(error) = &service_quiesce {
        secondary.push(format!("quiescing attempted daemon failed: {error:#}"));
    }
    if let Some(error) = &snapshot_error {
        secondary.push(format!(
            "service-manager rollback state was unreadable: {error:#}"
        ));
    }
    if rollback.is_ok()
        && service_quiesce.is_ok()
        && service_restore.is_ok()
        && snapshot_error.is_none()
        && reload.is_ok()
        && let Err(error) = transaction.commit()
    {
        secondary.push(format!("discarding rollback journal failed: {error:#}"));
    }
    match (primary, secondary.is_empty()) {
        (None, true) => Ok(()),
        (None, false) => anyhow::bail!(
            "quickstart rollback was incomplete: {}",
            secondary.join("; ")
        ),
        (Some(primary), true) => Err(primary.context("quickstart was rolled back")),
        (Some(primary), false) => Err(primary.context(format!(
            "quickstart rollback was incomplete: {}",
            secondary.join("; ")
        ))),
    }
}
