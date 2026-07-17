use super::*;

pub(crate) fn cmd_policy(sub: PolicyCmd, layout: HomeLayout) -> Result<ExitCode> {
    let sub = match sub {
        PolicyCmd::Schema => {
            println!("{}", POLICY_FIXTURE_SCHEMA.trim_end());
            return Ok(ExitCode::SUCCESS);
        }
        PolicyCmd::Diff(options) => return cmd_policy_diff(options),
        sub => sub,
    };

    let sub = match sub {
        PolicyCmd::Init {
            stdlib,
            force,
            remove_local_relaxations,
        } => {
            if !stdlib {
                anyhow::bail!("policy init currently requires --stdlib");
            }
            let (installed, removed) =
                init_stdlib_transactional(&layout, force, remove_local_relaxations)?;
            println!(
                "ok stdlib installed: {} policy files, {} capability files",
                installed.0, installed.1
            );
            if remove_local_relaxations {
                println!("ok local relaxation cleanup: {removed} file(s) removed");
            }
            return Ok(ExitCode::SUCCESS);
        }
        sub => sub,
    };

    let expedition = Expedition::load(&layout.expedition_file)?;
    let env = expedition
        .as_ref()
        .map(Expedition::policy_env)
        .unwrap_or_else(default_policy_env);
    match sub {
        PolicyCmd::Init { .. } => unreachable!("policy init returns before policy loading"),
        PolicyCmd::Check => {
            let pol = load_active_policy(&layout, expedition.as_ref(), &env)?;
            println!("ok {} rules loaded", pol.rules.len());
            println!("version: {}", pol.version_hash);
        }
        PolicyCmd::Layers { json } => {
            let report = build_policy_layer_report(&layout, expedition.as_ref(), &env)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_layer_report(&report);
            }
        }
        PolicyCmd::Lint { file, strict, json } => {
            let report = build_policy_lint_report(
                &layout,
                expedition.as_ref(),
                &env,
                file.as_deref(),
                strict,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_lint_report(&report);
            }
            return Ok(report.exit_code());
        }
        PolicyCmd::Schema => unreachable!("policy schema returns before home validation"),
        PolicyCmd::Diff(_) => unreachable!("policy diff returns before home validation"),
        PolicyCmd::Suggest { audit, json } => {
            let report = build_policy_suggest_report(&layout, expedition.as_ref(), &env, &audit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_suggest_report(&report);
            }
        }
        PolicyCmd::Test { file, json } => {
            let report = build_policy_test_report(&layout, expedition.as_ref(), &env, &file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_test_report(&report);
            }
            return Ok(report.exit_code());
        }
        PolicyCmd::Snapshot {
            name,
            description,
            case_only,
            hook,
        } => {
            let call = read_tool_call_from_stdin(hook)?;
            let case = build_policy_snapshot_case(
                &layout,
                expedition.as_ref(),
                &env,
                name,
                description,
                call,
            )?;
            if case_only {
                println!("{}", serde_yaml::to_string(&[case])?.trim_end());
            } else {
                let document = PolicySnapshotDocument {
                    version: 1,
                    cases: vec![case],
                };
                println!("{}", serde_yaml::to_string(&document)?.trim_end());
            }
        }
        PolicyCmd::Hash => {
            let pol = load_active_policy(&layout, expedition.as_ref(), &env)?;
            println!("{}", pol.version_hash);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn install_stdlib(layout: &HomeLayout, force: bool) -> Result<(usize, usize)> {
    let policies = install_embedded_files(&layout.policy_dir, STDLIB_POLICIES, force)?;
    let capabilities =
        install_embedded_files(&layout.capabilities_dir, STDLIB_CAPABILITIES, force)?;
    Ok((policies, capabilities))
}

pub(super) fn init_stdlib_transactional(
    layout: &HomeLayout,
    force: bool,
    remove_local_relaxations: bool,
) -> Result<((usize, usize), usize)> {
    let mut transaction = InstallTransaction::begin(
        layout,
        policy_init_transaction_files(layout, remove_local_relaxations),
        vec![
            layout.root.clone(),
            layout.policy_dir.clone(),
            layout.capabilities_dir.clone(),
        ],
    )?;
    if transaction.recovered_previous() {
        recover_recorded_daemon_runtime(&transaction, layout)?;
        reload_policy_runtime(layout)
            .context("restoring the runtime after an interrupted policy installation")?;
        transaction.acknowledge_recovery()?;
    }

    if remove_local_relaxations && let Err(error) = preflight_generated_relaxation_removal(layout) {
        transaction.commit()?;
        return Err(error);
    }

    let result = (|| {
        ensure_home(layout)?;
        let installed = install_stdlib(layout, force)?;
        let removed = if remove_local_relaxations {
            remove_known_local_relaxations(layout)?
        } else {
            0
        };
        reload_policy_runtime(layout)?;
        Ok((installed, removed))
    })();

    match result {
        Ok(outcome) => match transaction.commit() {
            Ok(()) => Ok(outcome),
            Err(primary) => Err(rollback_policy_init(transaction, layout, primary)),
        },
        Err(primary) if !transaction.has_mutations() => {
            transaction.commit()?;
            Err(primary)
        }
        Err(primary) => Err(rollback_policy_init(transaction, layout, primary)),
    }
}

pub(super) fn policy_init_transaction_files(
    layout: &HomeLayout,
    remove_local_relaxations: bool,
) -> Vec<TransactionFile> {
    let mut paths = vec![layout.key_file.clone()];
    paths.extend(
        STDLIB_POLICIES
            .iter()
            .map(|file| layout.policy_dir.join(file.name)),
    );
    paths.extend(
        STDLIB_CAPABILITIES
            .iter()
            .map(|file| layout.capabilities_dir.join(file.name)),
    );
    if remove_local_relaxations {
        paths.extend(
            [
                "06-agent-config-writable.yaml",
                "90-claude-allow-import.yaml",
                "95-agent-catch-all.yaml",
            ]
            .into_iter()
            .chain(LOCAL_RELAXATION_POLICY_FILES.iter().copied())
            .map(|name| layout.policy_dir.join(name)),
        );
    }
    paths.sort();
    paths.dedup();
    paths.into_iter().map(TransactionFile::new).collect()
}

pub(super) fn rollback_policy_init(
    mut transaction: InstallTransaction,
    layout: &HomeLayout,
    primary: anyhow::Error,
) -> anyhow::Error {
    let rollback = transaction.rollback();
    let reload = reload_policy_runtime(layout);
    let mut secondary = Vec::new();
    if let Err(error) = &rollback {
        secondary.push(format!("filesystem rollback failed: {error:#}"));
    }
    if let Err(error) = &reload {
        secondary.push(format!(
            "restoring the prior daemon policy failed: {error:#}"
        ));
    }
    if rollback.is_ok()
        && reload.is_ok()
        && let Err(error) = transaction.commit()
    {
        secondary.push(format!("discarding rollback journal failed: {error:#}"));
    }
    if secondary.is_empty() {
        primary.context("policy installation was rolled back")
    } else {
        primary.context(format!(
            "policy installation rollback was incomplete: {}",
            secondary.join("; ")
        ))
    }
}

pub(super) fn remove_known_local_relaxations(layout: &HomeLayout) -> Result<usize> {
    // Preflight and remove Gommage-owned generated layers first. The helper
    // refuses custom content at reserved paths before mutating anything.
    let mut removed = remove_generated_relaxation_layers(layout, false)?;
    for name in LOCAL_RELAXATION_POLICY_FILES {
        let path = layout.policy_dir.join(name);
        if !path.exists() {
            continue;
        }

        backup_and_remove_file(&path, false).with_context(|| {
            format!(
                "backing up and removing local relaxation {}",
                path.display()
            )
        })?;
        println!("ok removed local relaxation: {}", path.display());
        removed += 1;
    }
    Ok(removed)
}

pub(super) fn install_embedded_files(
    dir: &Path,
    files: &[StdlibFile],
    force: bool,
) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut installed = 0usize;
    for file in files {
        let path = dir.join(file.name);
        if path.exists() && !force {
            continue;
        }
        write_text(&path, file.contents, false)?;
        installed += 1;
    }
    Ok(installed)
}

pub(super) fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::AskPicto { required_scope, .. } => format!("ask:{required_scope}"),
        Decision::Gommage {
            hard_stop, reason, ..
        } => {
            if *hard_stop {
                format!("hard_stop:{reason}")
            } else {
                format!("gommage:{reason}")
            }
        }
    }
}
