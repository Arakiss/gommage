use super::*;

pub(super) fn daemon_service_spec(
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

pub(crate) fn service_file_path(manager: ServiceManager) -> Result<PathBuf> {
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

pub(super) fn launchd_plist(layout: &HomeLayout, daemon_bin: &Path) -> String {
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

pub(super) fn systemd_service(layout: &HomeLayout, daemon_bin: &Path) -> String {
    format!(
        r#"[Unit]
Description=Gommage policy daemon
Documentation=https://github.com/Arakiss/gommage

[Service]
Type=exec
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

pub(super) fn write_service_file(
    path: &Path,
    contents: &str,
    force: bool,
    dry_run: bool,
) -> Result<()> {
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

pub(super) fn find_daemon_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("GOMMAGE_DAEMON_BIN") {
        if path.is_empty() {
            anyhow::bail!("GOMMAGE_DAEMON_BIN is empty");
        }
        return validate_daemon_binary(Path::new(&path), "GOMMAGE_DAEMON_BIN");
    }
    let current = std::env::current_exe()?;
    if let Some(dir) = current.parent() {
        let sibling = dir.join("gommage-daemon");
        match std::fs::symlink_metadata(&sibling) {
            Ok(_) => return validate_daemon_binary(&sibling, "sibling executable"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", sibling.display()));
            }
        }
    }
    let mut rejected = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("gommage-daemon");
            match std::fs::symlink_metadata(&candidate) {
                Ok(_) => match validate_daemon_binary(&candidate, "PATH") {
                    Ok(path) => return Ok(path),
                    Err(error) => rejected.push(error.to_string()),
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => rejected.push(format!("{}: {error}", candidate.display())),
            }
        }
    }
    if !rejected.is_empty() {
        anyhow::bail!(
            "could not find an executable gommage-daemon; rejected candidates: {}",
            rejected.join("; ")
        );
    }
    anyhow::bail!("could not find gommage-daemon; install it or set GOMMAGE_DAEMON_BIN")
}

pub(super) fn validate_daemon_binary(path: &Path, source: &str) -> Result<PathBuf> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("{source} daemon binary {} is unavailable", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "{source} daemon binary {} is not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            anyhow::bail!(
                "{source} daemon binary {} is not executable",
                path.display()
            );
        }
    }
    std::fs::canonicalize(path)
        .with_context(|| format!("canonicalizing {source} daemon binary {}", path.display()))
}

pub(super) fn service_start_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
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

pub(super) fn service_stop_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
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

pub(super) fn service_status_commands(manager: ServiceManager) -> Vec<Vec<String>> {
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

pub(super) fn run_service_commands(commands: Vec<Vec<String>>) -> Result<()> {
    for command in commands {
        let status = command_status(&command, false)?;
        if !status {
            anyhow::bail!("service command failed: {}", command.join(" "));
        }
    }
    Ok(())
}

pub(super) fn run_service_commands_allow_failure_verbose(
    commands: Vec<Vec<String>>,
) -> Result<bool> {
    let mut ok = true;
    for command in commands {
        ok &= command_status(&command, true)?;
    }
    Ok(ok)
}

pub(super) fn systemd_activity_state(argv: &[String]) -> Result<SystemdActivity> {
    let output = command_output(argv)
        .with_context(|| format!("capturing systemd active state: {}", argv.join(" ")))?;
    let state = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    match state.as_str() {
        "active" => Ok(SystemdActivity::Active),
        "inactive" => Ok(SystemdActivity::Inactive),
        "not-found" | "unknown" if output.status.code() == Some(4) => Ok(SystemdActivity::Absent),
        "reloading" | "activating" | "deactivating" | "failed" => anyhow::bail!(
            "systemd unit is in non-restorable `{state}` activity; wait for a stable active/inactive state or reset the failed unit before installation"
        ),
        _ => anyhow::bail!(
            "systemctl could not determine active state (status {:?}, state {:?})",
            output.status.code(),
            state
        ),
    }
}

pub(super) fn systemd_enablement_state(argv: &[String]) -> Result<SystemdEnablement> {
    let output = command_output(argv)
        .with_context(|| format!("capturing systemd enablement state: {}", argv.join(" ")))?;
    let state = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    match state.as_str() {
        "enabled" => Ok(SystemdEnablement::Enabled),
        "enabled-runtime" => Ok(SystemdEnablement::EnabledRuntime),
        "disabled" => Ok(SystemdEnablement::Disabled),
        "disabled-runtime" => Ok(SystemdEnablement::DisabledRuntime),
        "static" => Ok(SystemdEnablement::Static),
        "indirect" => Ok(SystemdEnablement::Indirect),
        "masked" => Ok(SystemdEnablement::Masked),
        "masked-runtime" => Ok(SystemdEnablement::MaskedRuntime),
        "generated" => Ok(SystemdEnablement::Generated),
        "transient" => Ok(SystemdEnablement::Transient),
        "linked" => Ok(SystemdEnablement::Linked),
        "linked-runtime" => Ok(SystemdEnablement::LinkedRuntime),
        "alias" => Ok(SystemdEnablement::Alias),
        "not-found" => Ok(SystemdEnablement::Absent),
        "" if output.status.code() == Some(4) => Ok(SystemdEnablement::Absent),
        _ => anyhow::bail!(
            "systemctl could not determine enablement state (status {:?}, state {:?})",
            output.status.code(),
            state
        ),
    }
}

pub(super) fn command_output(argv: &[String]) -> Result<std::process::Output> {
    let Some(program) = argv.first() else {
        anyhow::bail!("empty service command");
    };
    Command::new(program)
        .args(&argv[1..])
        .output()
        .with_context(|| format!("running service command: {}", argv.join(" ")))
}

pub(super) fn command_status(argv: &[String], inherit_output: bool) -> Result<bool> {
    let Some(program) = argv.first() else {
        anyhow::bail!("empty service command");
    };
    let mut command = Command::new(program);
    command.args(&argv[1..]);
    if !inherit_output {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let status = command.status()?;
    Ok(status.success())
}

pub(super) fn launchd_domain() -> String {
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

pub(super) fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(super) fn systemd_quote(raw: &str) -> String {
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(unix)]
pub(super) fn service_file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
pub(super) fn service_file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}
