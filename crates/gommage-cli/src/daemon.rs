use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use gommage_core::runtime::HomeLayout;
use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use crate::util::{env_path_or_home, write_text};

#[derive(Subcommand)]
pub(crate) enum DaemonCmd {
    /// Install the daemon as a user service.
    Install {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
        /// Replace an existing service file.
        #[arg(long)]
        force: bool,
        /// Write the service file but do not start/enable it.
        #[arg(long)]
        no_start: bool,
        /// Show planned file edits and commands without writing or starting.
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall the user service and remove its service file.
    Uninstall {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
        /// Show planned file edits and commands without removing or stopping.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show daemon service status.
    Status {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ServiceManager {
    Launchd,
    Systemd,
}

pub(crate) fn cmd_daemon(sub: DaemonCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        DaemonCmd::Install {
            manager,
            force,
            no_start,
            dry_run,
        } => daemon_install(
            layout,
            resolve_service_manager(manager)?,
            force,
            no_start,
            dry_run,
        ),
        DaemonCmd::Uninstall { manager, dry_run } => {
            daemon_uninstall(resolve_service_manager(manager)?, dry_run)
        }
        DaemonCmd::Status { manager } => daemon_status(resolve_service_manager(manager)?),
    }
}

pub(crate) fn daemon_install(
    layout: HomeLayout,
    manager: ServiceManager,
    force: bool,
    no_start: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    if !dry_run {
        layout.ensure()?;
    }
    let daemon_bin = find_daemon_binary()?;
    let spec = daemon_service_spec(manager, &layout, &daemon_bin)?;
    write_service_file(&spec.path, &spec.contents, force, dry_run)?;
    println!("ok daemon: service file {}", spec.path.display());
    if no_start {
        println!("ok daemon: service installed but not started (--no-start)");
        return Ok(ExitCode::SUCCESS);
    }
    if dry_run {
        if manager == ServiceManager::Launchd {
            for command in service_stop_commands(manager, &spec.path) {
                println!("plan run best-effort: {}", command.join(" "));
            }
        }
        for command in service_start_commands(manager, &spec.path) {
            println!("plan run: {}", command.join(" "));
        }
        return Ok(ExitCode::SUCCESS);
    }
    if manager == ServiceManager::Launchd {
        let _ = run_service_commands_allow_failure(service_stop_commands(manager, &spec.path));
    }
    run_service_commands(service_start_commands(manager, &spec.path))?;
    println!("ok daemon: service enabled and started");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn daemon_uninstall(manager: ServiceManager, dry_run: bool) -> Result<ExitCode> {
    let path = service_file_path(manager)?;
    if dry_run {
        for command in service_stop_commands(manager, &path) {
            println!("plan run: {}", command.join(" "));
        }
        println!("plan remove: {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    let _ = run_service_commands_allow_failure(service_stop_commands(manager, &path));
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("ok daemon: removed {}", path.display());
    } else {
        println!("ok daemon: service file not found at {}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn daemon_status(manager: ServiceManager) -> Result<ExitCode> {
    let commands = service_status_commands(manager);
    let status = run_service_commands_allow_failure(commands)?;
    Ok(if status {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

struct ServiceSpec {
    path: PathBuf,
    contents: String,
}

fn daemon_service_spec(
    manager: ServiceManager,
    layout: &HomeLayout,
    daemon_bin: &Path,
) -> Result<ServiceSpec> {
    let path = service_file_path(manager)?;
    let contents = match manager {
        ServiceManager::Launchd => launchd_plist(layout, daemon_bin),
        ServiceManager::Systemd => systemd_service(layout, daemon_bin),
    };
    Ok(ServiceSpec { path, contents })
}

pub(crate) fn resolve_service_manager(manager: Option<ServiceManager>) -> Result<ServiceManager> {
    if let Some(manager) = manager {
        return Ok(manager);
    }
    if cfg!(target_os = "macos") {
        Ok(ServiceManager::Launchd)
    } else if cfg!(target_os = "linux") {
        Ok(ServiceManager::Systemd)
    } else {
        anyhow::bail!("daemon install supports launchd on macOS and systemd user services on Linux")
    }
}

fn service_file_path(manager: ServiceManager) -> Result<PathBuf> {
    match manager {
        ServiceManager::Launchd => Ok(env_path_or_home(
            "GOMMAGE_LAUNCHD_DIR",
            &["Library", "LaunchAgents"],
        )
        .join("dev.gommage.daemon.plist")),
        ServiceManager::Systemd => Ok(env_path_or_home(
            "GOMMAGE_SYSTEMD_USER_DIR",
            &[".config", "systemd", "user"],
        )
        .join("gommage-daemon.service")),
    }
}

fn launchd_plist(layout: &HomeLayout, daemon_bin: &Path) -> String {
    let stdout = layout.root.join("daemon.log");
    let stderr = layout.root.join("daemon.err.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.gommage.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--foreground</string>
    <string>--home</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&daemon_bin.to_string_lossy()),
        xml_escape(&layout.root.to_string_lossy()),
        xml_escape(&stdout.to_string_lossy()),
        xml_escape(&stderr.to_string_lossy())
    )
}

fn systemd_service(layout: &HomeLayout, daemon_bin: &Path) -> String {
    format!(
        r#"[Unit]
Description=Gommage policy daemon
Documentation=https://github.com/Arakiss/gommage

[Service]
Type=simple
ExecStart={} --foreground --home {}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#,
        systemd_quote(&daemon_bin.to_string_lossy()),
        systemd_quote(&layout.root.to_string_lossy())
    )
}

fn write_service_file(path: &Path, contents: &str, force: bool, dry_run: bool) -> Result<()> {
    if path.exists() {
        let current = std::fs::read_to_string(path)?;
        if current == contents {
            println!("ok unchanged: {}", path.display());
            return Ok(());
        }
        if !force {
            anyhow::bail!(
                "{} exists; rerun with --force to replace it",
                path.display()
            );
        }
    }
    write_text(path, contents, dry_run)
}

fn find_daemon_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("GOMMAGE_DAEMON_BIN") {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_exe()?;
    if let Some(dir) = current.parent() {
        let sibling = dir.join("gommage-daemon");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("gommage-daemon");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!("could not find gommage-daemon; install it or set GOMMAGE_DAEMON_BIN")
}

fn service_start_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
    match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "bootstrap".to_string(),
            launchd_domain(),
            path.to_string_lossy().to_string(),
        ]],
        ServiceManager::Systemd => vec![
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "daemon-reload".to_string(),
            ],
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "enable".to_string(),
                "--now".to_string(),
                "gommage-daemon.service".to_string(),
            ],
        ],
    }
}

fn service_stop_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
    match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "bootout".to_string(),
            launchd_domain(),
            path.to_string_lossy().to_string(),
        ]],
        ServiceManager::Systemd => vec![
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "disable".to_string(),
                "--now".to_string(),
                "gommage-daemon.service".to_string(),
            ],
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "daemon-reload".to_string(),
            ],
        ],
    }
}

fn service_status_commands(manager: ServiceManager) -> Vec<Vec<String>> {
    match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "print".to_string(),
            format!("{}/dev.gommage.daemon", launchd_domain()),
        ]],
        ServiceManager::Systemd => vec![vec![
            "systemctl".to_string(),
            "--user".to_string(),
            "status".to_string(),
            "--no-pager".to_string(),
            "gommage-daemon.service".to_string(),
        ]],
    }
}

fn run_service_commands(commands: Vec<Vec<String>>) -> Result<()> {
    for command in commands {
        let status = command_status(&command)?;
        if !status {
            anyhow::bail!("service command failed: {}", command.join(" "));
        }
    }
    Ok(())
}

fn run_service_commands_allow_failure(commands: Vec<Vec<String>>) -> Result<bool> {
    let mut ok = true;
    for command in commands {
        ok &= command_status(&command)?;
    }
    Ok(ok)
}

fn command_status(command: &[String]) -> Result<bool> {
    let Some(program) = command.first() else {
        anyhow::bail!("empty service command");
    };
    let status = Command::new(program).args(&command[1..]).status()?;
    Ok(status.success())
}

fn launchd_domain() -> String {
    format!("gui/{}", unsafe { libc_getuid() })
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

#[cfg(not(unix))]
unsafe fn libc_getuid() -> u32 {
    0
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(raw: &str) -> String {
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}
