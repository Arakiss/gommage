use anyhow::{Context, Result};
use clap::ValueEnum;
use gommage_core::runtime::HomeLayout;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    agent::{AgentKind, codex_pre_tool_use_pointer, hook_command_is_owned_by_gommage},
    daemon::{recover_recorded_daemon_runtime, reload_policy_runtime},
    util::{
        InstallTransaction, TransactionFile, env_path_or_home, read_json_object,
        write_bytes_with_mode, write_json,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AgentUninstallTarget {
    Claude,
    Codex,
    All,
}

pub(crate) fn cmd_agent_uninstall(
    target: AgentUninstallTarget,
    layout: &HomeLayout,
    restore_backup: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    uninstall_agent_target(target, layout, restore_backup, dry_run)?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn uninstall_agent_target(
    target: AgentUninstallTarget,
    layout: &HomeLayout,
    restore_backup: bool,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        return uninstall_agent_target_inner(target, restore_backup, true);
    }

    let mut transaction =
        InstallTransaction::begin(layout, uninstall_transaction_files(target), Vec::new())?;
    if transaction.recovered_previous() {
        recover_recorded_daemon_runtime(&transaction, layout)?;
        reload_policy_runtime(layout)
            .context("restoring the runtime after an interrupted agent uninstall")?;
        transaction.acknowledge_recovery()?;
    }

    let result = uninstall_agent_target_inner(target, restore_backup, false)
        .and_then(|()| reload_policy_runtime(layout));
    match result {
        Ok(()) => match transaction.commit() {
            Ok(()) => Ok(()),
            Err(error) => Err(rollback_agent_uninstall(transaction, layout, error)),
        },
        Err(error) => Err(rollback_agent_uninstall(transaction, layout, error)),
    }
}

fn uninstall_agent_target_inner(
    target: AgentUninstallTarget,
    restore_backup: bool,
    dry_run: bool,
) -> Result<()> {
    for agent in target_agents(target) {
        uninstall_agent(agent, restore_backup, dry_run)?;
    }
    Ok(())
}

fn uninstall_transaction_files(target: AgentUninstallTarget) -> Vec<TransactionFile> {
    let mut files = Vec::new();
    for agent in target_agents(target) {
        match agent {
            AgentKind::Claude => files.push(TransactionFile::new(env_path_or_home(
                "GOMMAGE_CLAUDE_SETTINGS",
                &[".claude", "settings.json"],
            ))),
            AgentKind::Codex => {
                files.push(TransactionFile::new(env_path_or_home(
                    "GOMMAGE_CODEX_HOOKS",
                    &[".codex", "hooks.json"],
                )));
                files.push(TransactionFile::new(env_path_or_home(
                    "GOMMAGE_CODEX_CONFIG",
                    &[".codex", "config.toml"],
                )));
            }
        }
    }
    files.sort_by(|left, right| left.path().cmp(right.path()));
    files.dedup_by(|left, right| left.path() == right.path());
    files
}

fn rollback_agent_uninstall(
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
        secondary.push(format!(
            "discarding the completed rollback journal failed: {error:#}"
        ));
    }
    if secondary.is_empty() {
        anyhow::anyhow!("{primary:#}; agent uninstall was rolled back")
    } else {
        anyhow::anyhow!(
            "{primary:#}; agent uninstall rollback was incomplete: {}",
            secondary.join("; ")
        )
    }
}

fn target_agents(target: AgentUninstallTarget) -> Vec<AgentKind> {
    match target {
        AgentUninstallTarget::Claude => vec![AgentKind::Claude],
        AgentUninstallTarget::Codex => vec![AgentKind::Codex],
        AgentUninstallTarget::All => vec![AgentKind::Claude, AgentKind::Codex],
    }
}

fn uninstall_agent(agent: AgentKind, restore_backup: bool, dry_run: bool) -> Result<()> {
    match agent {
        AgentKind::Claude => uninstall_claude(restore_backup, dry_run),
        AgentKind::Codex => uninstall_codex(restore_backup, dry_run),
    }
}

fn uninstall_claude(restore_backup: bool, dry_run: bool) -> Result<()> {
    let settings_path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
    if restore_backup && restore_latest_backup(&settings_path, dry_run)? {
        return Ok(());
    }
    if !settings_path.exists() {
        println!(
            "ok claude: settings file not found at {}",
            settings_path.display()
        );
        return Ok(());
    }

    let mut settings = read_json_object(&settings_path)?;
    let removed = remove_json_hook_groups(&mut settings, "/hooks/PreToolUse", AgentKind::Claude);
    if removed == 0 {
        println!(
            "ok claude: no Gommage hook found at {}",
            settings_path.display()
        );
        return Ok(());
    }
    write_json(&settings_path, &settings, dry_run)?;
    if dry_run {
        println!(
            "plan claude: remove {removed} Gommage hook group(s) from {}",
            settings_path.display()
        );
    } else {
        println!(
            "ok claude: removed {removed} Gommage hook group(s) from {}",
            settings_path.display()
        );
    }
    Ok(())
}

fn uninstall_codex(restore_backup: bool, dry_run: bool) -> Result<()> {
    let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
    let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
    let hooks_restored = restore_backup && restore_latest_backup(&hooks_path, dry_run)?;
    let config_restored = restore_backup && restore_latest_backup(&config_path, dry_run)?;
    if hooks_restored || config_restored {
        return Ok(());
    }

    if hooks_path.exists() {
        let mut hooks = read_json_object(&hooks_path)?;
        let primary_pointer = codex_pre_tool_use_pointer(&hooks);
        let secondary_pointer = if primary_pointer == "/hooks/PreToolUse" {
            "/PreToolUse"
        } else {
            "/hooks/PreToolUse"
        };
        let removed = remove_json_hook_groups(&mut hooks, primary_pointer, AgentKind::Codex)
            + remove_json_hook_groups(&mut hooks, secondary_pointer, AgentKind::Codex);
        if removed > 0 {
            write_json(&hooks_path, &hooks, dry_run)?;
            if dry_run {
                println!(
                    "plan codex: remove {removed} Gommage hook group(s) from {}",
                    hooks_path.display()
                );
            } else {
                println!(
                    "ok codex: removed {removed} Gommage hook group(s) from {}",
                    hooks_path.display()
                );
            }
        } else {
            println!(
                "ok codex: no Gommage hook found at {}",
                hooks_path.display()
            );
        }
    } else {
        println!("ok codex: hooks file not found at {}", hooks_path.display());
    }

    if config_path.exists() {
        println!(
            "{} codex: preserve shared Codex hook feature flags at {}; only --restore-backup restores config.toml",
            if dry_run { "plan" } else { "ok" },
            config_path.display()
        );
    }
    Ok(())
}

fn remove_json_hook_groups(root: &mut serde_json::Value, pointer: &str, agent: AgentKind) -> usize {
    let Some(entries) = root
        .pointer_mut(pointer)
        .and_then(|value| value.as_array_mut())
    else {
        return 0;
    };
    let mut changed_groups = 0;
    entries.retain_mut(|entry| {
        let Some(hooks) = entry
            .get_mut("hooks")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return true;
        };
        let before = hooks.len();
        hooks.retain(|hook| {
            !hook
                .get("command")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|command| hook_command_is_owned_by_gommage(command, agent, None))
        });
        if hooks.len() != before {
            changed_groups += 1;
        }
        !hooks.is_empty()
    });
    changed_groups
}

fn restore_latest_backup(path: &Path, dry_run: bool) -> Result<bool> {
    let Some(backup) = latest_gommage_backup(path)? else {
        println!("ok backup: no Gommage backup found for {}", path.display());
        return Ok(false);
    };
    if dry_run {
        println!("plan restore: {} -> {}", backup.display(), path.display());
        return Ok(true);
    }
    let metadata = std::fs::symlink_metadata(&backup)
        .with_context(|| format!("inspecting backup {}", backup.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("backup {} is not a regular file", backup.display());
    }
    let contents =
        std::fs::read(&backup).with_context(|| format!("reading backup {}", backup.display()))?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = 0;
    write_bytes_with_mode(path, &contents, mode)
        .with_context(|| format!("restoring {} from {}", path.display(), backup.display()))?;
    println!("ok restore: {} -> {}", backup.display(), path.display());
    Ok(true)
}

fn latest_gommage_backup(path: &Path) -> Result<Option<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    let prefix = format!("{file_name}.gommage-bak-");
    let mut latest: Option<(i64, PathBuf)> = None;
    if !parent.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(raw_ts) = name.strip_prefix(&prefix) else {
            continue;
        };
        if raw_ts.is_empty() || !raw_ts.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let ts = raw_ts.parse::<i64>().unwrap_or(0);
        if latest.as_ref().is_none_or(|(current, _)| ts > *current) {
            latest = Some((ts, entry.path()));
        }
    }
    Ok(latest.map(|(_, path)| path))
}
