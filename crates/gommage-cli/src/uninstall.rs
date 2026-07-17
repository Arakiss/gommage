use anyhow::{Context, Result, bail};
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
            "refusing to purge known inventory from {}; rerun with --yes after reviewing --dry-run",
            layout.root.display()
        );
    }

    if let Some(agent) = agent {
        uninstall_agent_target(agent, &layout, options.restore_backup, options.dry_run)?;
    }
    if daemon {
        daemon_uninstall(
            &layout,
            resolve_service_manager(options.daemon_manager)?,
            options.dry_run,
        )?;
    }
    if skills {
        uninstall_skills(options.dry_run)?;
    }
    if purge_home {
        purge_gommage_home(&layout, options.dry_run)?;
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

fn purge_gommage_home(layout: &HomeLayout, dry_run: bool) -> Result<()> {
    if dry_run {
        println!(
            "plan purge known Gommage home inventory: {}",
            layout.root.display()
        );
        return Ok(());
    }
    if !layout.root.exists() {
        println!("ok home: not found at {}", layout.root.display());
        return Ok(());
    }

    validate_purge_root(layout, dirs::home_dir().as_deref())?;

    for (path, label) in known_home_inventory(layout) {
        if path.exists() || std::fs::symlink_metadata(&path).is_ok() {
            remove_path(&path, label, false)?;
        }
    }

    match std::fs::remove_dir(&layout.root) {
        Ok(()) => println!("ok removed home: {}", layout.root.display()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => println!(
            "ok preserved home with unrecognized entries: {}",
            layout.root.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", layout.root.display()));
        }
    }
    Ok(())
}

fn validate_purge_root(layout: &HomeLayout, operator_home: Option<&Path>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(&layout.root)
        .with_context(|| format!("inspecting {}", layout.root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "refusing to purge Gommage home root that is not a real directory: {}",
            layout.root.display()
        );
    }

    let canonical_root = std::fs::canonicalize(&layout.root)
        .with_context(|| format!("resolving {}", layout.root.display()))?;
    if canonical_root.parent().is_none() {
        bail!(
            "refusing to purge filesystem root as Gommage home: {}",
            canonical_root.display()
        );
    }
    if let Some(operator_home) = operator_home
        && let Ok(canonical_home) = std::fs::canonicalize(operator_home)
        && (canonical_root == canonical_home || canonical_home.starts_with(&canonical_root))
    {
        bail!(
            "refusing to purge the operator home or one of its ancestors: {}",
            canonical_root.display()
        );
    }

    let conventional_name = canonical_root
        .file_name()
        .is_some_and(|name| matches!(name.to_str(), Some(".gommage") | Some("gommage-home")));
    let markers = [
        layout.key_file.is_file(),
        layout.policy_dir.is_dir(),
        layout.capabilities_dir.is_dir(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if !conventional_name && markers < 2 {
        bail!(
            "refusing to purge {} because it is not recognizably a Gommage home",
            canonical_root.display()
        );
    }
    Ok(())
}

fn known_home_inventory(layout: &HomeLayout) -> Vec<(PathBuf, &'static str)> {
    let mut inventory = vec![
        (layout.policy_dir.clone(), "policy directory"),
        (layout.capabilities_dir.clone(), "capability directory"),
        (layout.pictos_db.clone(), "picto database"),
        (layout.approvals_log.clone(), "approval log"),
        (
            layout.approval_webhook_dlq.clone(),
            "approval webhook dead-letter log",
        ),
        (layout.audit_log.clone(), "audit log"),
        (layout.state_db.clone(), "state index"),
        (layout.key_file.clone(), "signing key"),
        (layout.expedition_file.clone(), "expedition state"),
        (layout.socket.clone(), "daemon socket"),
        (layout.update_check.clone(), "update check"),
    ];
    for database in [&layout.pictos_db, &layout.state_db] {
        for suffix in ["-wal", "-shm", "-journal"] {
            inventory.push((path_with_suffix(database, suffix), "database sidecar"));
        }
    }
    for name in [
        "AGENT_CONTEXT.md",
        "integration-report.json",
        "daemon.log",
        "daemon.err.log",
    ] {
        inventory.push((layout.root.join(name), "generated runtime file"));
    }
    inventory
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_path(path: &Path, label: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("plan remove {label}: {}", path.display());
        return Ok(());
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("ok {label}: not found at {}", path.display());
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    if metadata.is_dir() {
        std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))?;
    } else {
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    println!("ok removed {label}: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn purge_removes_only_known_home_inventory() {
        let temp = tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        layout.ensure().unwrap();
        std::fs::write(&layout.audit_log, "signed evidence\n").unwrap();
        std::fs::write(layout.root.join("operator-notes.txt"), "preserve me\n").unwrap();

        purge_gommage_home(&layout, false).unwrap();

        assert!(layout.root.exists());
        assert!(layout.root.join("operator-notes.txt").exists());
        assert!(!layout.key_file.exists());
        assert!(!layout.audit_log.exists());
        assert!(!layout.policy_dir.exists());
        assert!(!layout.capabilities_dir.exists());
    }

    #[test]
    #[cfg(unix)]
    fn remove_path_removes_broken_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let link = temp.path().join("broken-link");
        symlink(temp.path().join("missing-target"), &link).unwrap();

        remove_path(&link, "test link", false).unwrap();

        assert!(std::fs::symlink_metadata(&link).is_err());
    }

    #[test]
    fn purge_rejects_filesystem_root() {
        let layout = HomeLayout::at(Path::new("/"));
        let error = validate_purge_root(&layout, None).unwrap_err();
        assert!(error.to_string().contains("filesystem root"));
    }

    #[test]
    fn purge_rejects_operator_home_ancestor() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("shared");
        let operator_home = root.join("users/operator");
        let layout = HomeLayout::at(&root);
        std::fs::create_dir_all(&operator_home).unwrap();
        std::fs::create_dir_all(&layout.policy_dir).unwrap();
        std::fs::create_dir_all(&layout.capabilities_dir).unwrap();

        let error = validate_purge_root(&layout, Some(&operator_home)).unwrap_err();
        assert!(error.to_string().contains("operator home"));
    }

    #[cfg(unix)]
    #[test]
    fn purge_rejects_symlinked_home_root() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let target = temp.path().join(".gommage");
        let link = temp.path().join("gommage-home");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();
        let layout = HomeLayout::at(&link);

        let error = validate_purge_root(&layout, None).unwrap_err();
        assert!(error.to_string().contains("not a real directory"));
    }
}
