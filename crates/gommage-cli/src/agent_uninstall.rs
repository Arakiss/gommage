use anyhow::{Context, Result};
use clap::ValueEnum;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    agent::AgentKind,
    util::{env_path_or_home, read_json_object, read_toml_document, write_json, write_text},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AgentUninstallTarget {
    Claude,
    Codex,
    All,
}

pub(crate) fn cmd_agent_uninstall(
    target: AgentUninstallTarget,
    restore_backup: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    uninstall_agent_target(target, restore_backup, dry_run)?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn uninstall_agent_target(
    target: AgentUninstallTarget,
    restore_backup: bool,
    dry_run: bool,
) -> Result<()> {
    for agent in target_agents(target) {
        uninstall_agent(agent, restore_backup, dry_run)?;
    }
    Ok(())
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
    let removed = remove_json_hook_groups(&mut settings, "/hooks/PreToolUse", "gommage-mcp");
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

    let mut removed_codex_hook = false;
    if hooks_path.exists() {
        let mut hooks = read_json_object(&hooks_path)?;
        let removed = remove_json_hook_groups(&mut hooks, "/PreToolUse", "gommage-mcp");
        if removed > 0 {
            removed_codex_hook = true;
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

    if removed_codex_hook && config_path.exists() {
        let mut config = read_toml_document(&config_path)?;
        if config
            .get("features")
            .and_then(|features| features.get("codex_hooks"))
            .is_some()
        {
            config["features"]["codex_hooks"] = toml_edit::value(false);
            write_text(&config_path, &config.to_string(), dry_run)?;
            if dry_run {
                println!(
                    "plan codex: disable features.codex_hooks at {}",
                    config_path.display()
                );
            } else {
                println!(
                    "ok codex: disabled features.codex_hooks at {}",
                    config_path.display()
                );
            }
        }
    } else if config_path.exists() {
        println!(
            "ok codex: leaving features.codex_hooks unchanged at {}; no Gommage Codex hook was found",
            config_path.display()
        );
    }
    Ok(())
}

fn remove_json_hook_groups(root: &mut serde_json::Value, pointer: &str, needle: &str) -> usize {
    let Some(entries) = root
        .pointer_mut(pointer)
        .and_then(|value| value.as_array_mut())
    else {
        return 0;
    };
    let before = entries.len();
    entries.retain(|entry| !json_hook_entry_contains_command(entry, needle));
    before - entries.len()
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

fn restore_latest_backup(path: &Path, dry_run: bool) -> Result<bool> {
    let Some(backup) = latest_gommage_backup(path)? else {
        println!("ok backup: no Gommage backup found for {}", path.display());
        return Ok(false);
    };
    if dry_run {
        println!("plan restore: {} -> {}", backup.display(), path.display());
        return Ok(true);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&backup, path)
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
