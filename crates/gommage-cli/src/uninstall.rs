use anyhow::{Context, Result};
use gommage_core::runtime::HomeLayout;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    agent_uninstall::{AgentUninstallTarget, uninstall_agent_target},
    daemon::{ServiceManager, daemon_uninstall, resolve_service_manager},
    util::env_path_or_home,
};

pub(crate) struct UninstallOptions {
    pub(crate) agent: Option<AgentUninstallTarget>,
    pub(crate) daemon: bool,
    pub(crate) daemon_manager: Option<ServiceManager>,
    pub(crate) binaries: bool,
    pub(crate) skills: bool,
    pub(crate) purge_home: bool,
    pub(crate) all: bool,
    pub(crate) restore_backup: bool,
    pub(crate) purge_backups: bool,
    pub(crate) dry_run: bool,
    pub(crate) yes: bool,
}

pub(crate) fn cmd_uninstall(layout: HomeLayout, options: UninstallOptions) -> Result<ExitCode> {
    let selected = options.all
        || options.agent.is_some()
        || options.daemon
        || options.binaries
        || options.skills
        || options.purge_home
        || options.purge_backups;
    if !selected {
        println!("no uninstall target selected; showing --all dry-run plan");
        return cmd_uninstall(
            layout,
            UninstallOptions {
                all: true,
                dry_run: true,
                purge_backups: options.purge_backups,
                ..options
            },
        );
    }

    let agent = if options.all {
        Some(AgentUninstallTarget::All)
    } else {
        options.agent
    };
    let daemon = options.all || options.daemon;
    let binaries = options.all || options.binaries;
    let skills = options.all || options.skills;
    let purge_home = options.all || options.purge_home;
    let purge_backups = options.purge_backups;

    if purge_home && !options.dry_run && !options.yes {
        anyhow::bail!(
            "refusing to remove {}; rerun with --yes after reviewing --dry-run",
            layout.root.display()
        );
    }

    if let Some(agent) = agent {
        uninstall_agent_target(agent, options.restore_backup, options.dry_run)?;
    }
    if daemon {
        daemon_uninstall(
            resolve_service_manager(options.daemon_manager)?,
            options.dry_run,
        )?;
    }
    if skills {
        uninstall_skills(options.dry_run)?;
    }
    if purge_home {
        remove_path(&layout.root, "home", options.dry_run)?;
    }
    if binaries {
        uninstall_binaries(options.dry_run)?;
    }
    if purge_backups {
        purge_backup_files(options.dry_run)?;
    }

    Ok(ExitCode::SUCCESS)
}

fn uninstall_skills(dry_run: bool) -> Result<()> {
    for path in skill_dirs() {
        remove_path(&path, "skill", dry_run)?;
    }
    Ok(())
}

fn skill_dirs() -> Vec<PathBuf> {
    vec![
        agent_skill_dir("CODEX_HOME", &[".codex"]),
        agent_skill_dir("CLAUDE_HOME", &[".claude"]),
    ]
}

fn agent_skill_dir(env_var: &str, default_home_components: &[&str]) -> PathBuf {
    let base = std::env::var(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_path(default_home_components));
    base.join("skills").join("gommage")
}

fn uninstall_binaries(dry_run: bool) -> Result<()> {
    let bin_dir = std::env::var("GOMMAGE_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_path(&[".local", "bin"]));
    for name in ["gommage", "gommage-daemon", "gommage-mcp"] {
        remove_path(&bin_dir.join(name), "binary", dry_run)?;
    }
    Ok(())
}

fn purge_backup_files(dry_run: bool) -> Result<()> {
    let known_files = [
        env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]),
        env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]),
        env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]),
    ];
    for path in known_files {
        remove_sibling_backups(&path, dry_run)?;
    }

    let bin_dir = std::env::var("GOMMAGE_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_path(&[".local", "bin"]));
    for name in ["gommage", "gommage-daemon", "gommage-mcp"] {
        remove_sibling_backups(&bin_dir.join(name), dry_run)?;
    }

    for dir in skill_dirs() {
        remove_backups_under_dir(&dir, dry_run)?;
    }
    Ok(())
}

fn remove_sibling_backups(path: &Path, dry_run: bool) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    if !parent.exists() {
        return Ok(());
    }
    let prefix = format!("{name}.gommage-bak-");
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name.starts_with(&prefix) {
            remove_path(&entry.path(), "backup", dry_run)?;
        }
    }
    Ok(())
}

fn remove_backups_under_dir(dir: &Path, dry_run: bool) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            remove_backups_under_dir(&path, dry_run)?;
        } else if entry
            .file_name()
            .to_string_lossy()
            .contains(".gommage-bak-")
        {
            remove_path(&path, "backup", dry_run)?;
        }
    }
    Ok(())
}

fn home_path(components: &[&str]) -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    for component in components {
        path.push(component);
    }
    path
}

fn remove_path(path: &Path, label: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("plan remove {label}: {}", path.display());
        return Ok(());
    }
    if !path.exists() {
        println!("ok {label}: not found at {}", path.display());
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))?;
    } else {
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    println!("ok removed {label}: {}", path.display());
    Ok(())
}
