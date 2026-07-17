use super::*;

pub(super) struct ServiceSpec {
    pub(super) path: PathBuf,
    pub(super) contents: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "manager", rename_all = "snake_case")]
pub(super) enum ServiceRuntimeState {
    Launchd {
        loaded: bool,
    },
    Systemd {
        activity: SystemdActivity,
        enablement: SystemdEnablement,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SystemdActivity {
    Active,
    Inactive,
    Absent,
}

impl SystemdActivity {
    pub(super) fn is_active(self) -> bool {
        self == Self::Active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SystemdEnablement {
    Enabled,
    EnabledRuntime,
    Disabled,
    DisabledRuntime,
    Static,
    Indirect,
    Masked,
    MaskedRuntime,
    Generated,
    Transient,
    Linked,
    LinkedRuntime,
    Alias,
    Absent,
}

impl SystemdEnablement {
    pub(super) fn is_supported_for_replacement(self) -> bool {
        !matches!(
            self,
            Self::Linked | Self::LinkedRuntime | Self::Alias | Self::Generated | Self::Transient
        )
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::EnabledRuntime => "enabled-runtime",
            Self::Disabled => "disabled",
            Self::DisabledRuntime => "disabled-runtime",
            Self::Static => "static",
            Self::Indirect => "indirect",
            Self::Masked => "masked",
            Self::MaskedRuntime => "masked-runtime",
            Self::Generated => "generated",
            Self::Transient => "transient",
            Self::Linked => "linked",
            Self::LinkedRuntime => "linked-runtime",
            Self::Alias => "alias",
            Self::Absent => "not-found",
        }
    }
}

pub(super) const DAEMON_RUNTIME_RECOVERY_KEY: &str = "daemon_service_runtime_v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct DaemonRuntimeSnapshot {
    pub(super) manager: ServiceManager,
    pub(super) state: ServiceRuntimeState,
}

impl DaemonRuntimeSnapshot {
    pub(super) fn state_for(self, manager: ServiceManager) -> Result<ServiceRuntimeState> {
        let state_manager = match self.state {
            ServiceRuntimeState::Launchd { .. } => ServiceManager::Launchd,
            ServiceRuntimeState::Systemd { .. } => ServiceManager::Systemd,
        };
        if self.manager != manager || state_manager != manager {
            anyhow::bail!(
                "daemon runtime snapshot manager mismatch (recorded {:?}, requested {:?})",
                self.manager,
                manager
            );
        }
        validate_service_runtime_state(self.state)?;
        Ok(self.state)
    }
}

pub(super) struct OriginalServiceFile {
    bytes: Vec<u8>,
    mode: u32,
}

pub(super) struct ServiceFileSnapshot {
    path: PathBuf,
    original: Option<OriginalServiceFile>,
    existing_backups: HashSet<PathBuf>,
}

impl ServiceFileSnapshot {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        let original = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
                "refusing to install daemon service through symbolic link {}",
                path.display()
            ),
            Ok(metadata) if metadata.is_file() => Some(OriginalServiceFile {
                bytes: std::fs::read(path)
                    .with_context(|| format!("reading {} before daemon install", path.display()))?,
                mode: service_file_mode(&metadata),
            }),
            Ok(_) => anyhow::bail!("{} is not a regular service file", path.display()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspecting {} before daemon install", path.display())
                });
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            original,
            existing_backups: service_file_backups(path)?,
        })
    }

    pub(super) fn restore(&self) -> Result<()> {
        let mut failures = Vec::new();
        match &self.original {
            Some(original) => {
                if let Err(error) =
                    restore_regular_bytes(&self.path, &original.bytes, original.mode)
                {
                    failures.push(format!(
                        "restoring service file {} failed: {error}",
                        self.path.display()
                    ));
                }
            }
            None => match std::fs::symlink_metadata(&self.path) {
                Ok(metadata) if metadata.is_dir() => failures.push(format!(
                    "cannot remove new service path {} because it became a directory",
                    self.path.display()
                )),
                Ok(metadata) if metadata.is_file() => {
                    if let Err(error) = std::fs::remove_file(&self.path) {
                        failures.push(format!(
                            "removing new service file {} failed: {error}",
                            self.path.display()
                        ));
                    }
                }
                Ok(_) => failures.push(format!(
                    "cannot remove new service path {} because it became a symbolic link or special file",
                    self.path.display()
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => failures.push(format!(
                    "inspecting new service file {} failed: {error}",
                    self.path.display()
                )),
            },
        }

        match service_file_backups(&self.path) {
            Ok(current_backups) => {
                for backup in current_backups.difference(&self.existing_backups) {
                    if let Err(error) = std::fs::remove_file(backup) {
                        failures.push(format!(
                            "removing rollback backup {} failed: {error}",
                            backup.display()
                        ));
                    }
                }
            }
            Err(error) => failures.push(format!("enumerating rollback backups failed: {error:#}")),
        }

        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(failures.join("; "))
        }
    }
}

pub(super) fn service_file_backups(path: &Path) -> Result<HashSet<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(HashSet::new());
    };
    if !parent.exists() {
        return Ok(HashSet::new());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!("service file name is not valid UTF-8: {}", path.display())
        })?;
    let prefix = format!("{file_name}.gommage-bak-");
    let mut backups = HashSet::new();
    for entry in std::fs::read_dir(parent)
        .with_context(|| format!("enumerating service backups in {}", parent.display()))?
    {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            backups.insert(entry.path());
        }
    }
    Ok(backups)
}

pub(super) fn capture_service_runtime_state(
    manager: ServiceManager,
) -> Result<ServiceRuntimeState> {
    match manager {
        ServiceManager::Launchd => Ok(ServiceRuntimeState::Launchd {
            loaded: launchd_service_is_loaded()?,
        }),
        ServiceManager::Systemd => {
            let active_command = systemd_unit_command(&["is-active"]);
            let activity = systemd_activity_state(&active_command)?;
            let enabled_command = systemd_unit_command(&["is-enabled"]);
            let enablement = systemd_enablement_state(&enabled_command)?;
            let state = ServiceRuntimeState::Systemd {
                activity,
                enablement,
            };
            validate_service_runtime_state(state)?;
            Ok(state)
        }
    }
}

pub(super) fn validate_service_runtime_state(state: ServiceRuntimeState) -> Result<()> {
    if let ServiceRuntimeState::Systemd {
        activity,
        enablement,
    } = state
    {
        if !enablement.is_supported_for_replacement() {
            anyhow::bail!(
                "systemd unit is in `{}` state; transactional replacement supports regular, runtime-enabled, masked, static, indirect, disabled, and absent units, but cannot reconstruct linked, alias, generated, or transient ownership",
                enablement.label()
            );
        }
        let activity_absent = activity == SystemdActivity::Absent;
        let enablement_absent = enablement == SystemdEnablement::Absent;
        if activity_absent != enablement_absent {
            anyhow::bail!(
                "systemd reported incoherent stable state (activity={activity:?}, enablement={}); refusing service mutation",
                enablement.label()
            );
        }
    }
    Ok(())
}

pub(crate) fn prepare_daemon_runtime_snapshot(
    layout: &HomeLayout,
    manager: ServiceManager,
    no_start: bool,
) -> Result<Option<DaemonRuntimeSnapshot>> {
    if no_start {
        preflight_service_home(layout, manager, &service_file_path(manager)?)?;
        return Ok(None);
    }
    let state = capture_service_runtime_state(manager)?;
    if service_runtime_is_live(state) {
        preflight_service_home(layout, manager, &service_file_path(manager)?)?;
    }
    let snapshot = DaemonRuntimeSnapshot { manager, state };
    Ok(Some(snapshot))
}

pub(super) fn service_runtime_is_live(state: ServiceRuntimeState) -> bool {
    matches!(
        state,
        ServiceRuntimeState::Launchd { loaded: true }
            | ServiceRuntimeState::Systemd {
                activity: SystemdActivity::Active,
                ..
            }
    )
}

pub(super) fn arm_daemon_runtime_recovery(snapshot: DaemonRuntimeSnapshot) -> Result<()> {
    record_active_recovery_value(DAEMON_RUNTIME_RECOVERY_KEY, &snapshot)
}

pub(crate) fn current_recorded_daemon_runtime(
    transaction: &InstallTransaction,
) -> Result<Option<DaemonRuntimeSnapshot>> {
    transaction.current_value(DAEMON_RUNTIME_RECOVERY_KEY)
}

/// Restore service-manager state from an interrupted operation after the
/// durable filesystem journal has restored the old unit/configuration files.
/// Returns true when a service snapshot was present.
pub(crate) fn recover_recorded_daemon_runtime(
    transaction: &InstallTransaction,
    layout: &HomeLayout,
) -> Result<bool> {
    let Some(snapshot) =
        transaction.recovered_value::<DaemonRuntimeSnapshot>(DAEMON_RUNTIME_RECOVERY_KEY)?
    else {
        return Ok(false);
    };
    restore_daemon_runtime_after_files(layout, snapshot)
        .context("restoring service-manager state after an interrupted installation")?;
    Ok(true)
}

pub(super) fn launchd_service_is_loaded() -> Result<bool> {
    let command = vec![
        "launchctl".to_string(),
        "print".to_string(),
        format!("{}/dev.gommage.daemon", launchd_domain()),
    ];
    let output = command_output(&command)
        .with_context(|| format!("capturing launchd service state: {}", command.join(" ")))?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.status.code() == Some(113)
        || stderr.contains("could not find service")
        || stderr.contains("service not found")
    {
        return Ok(false);
    }
    anyhow::bail!(
        "launchctl could not determine whether dev.gommage.daemon is loaded (status {:?})",
        output.status.code()
    )
}

pub(super) fn install_launchd_service(spec: &ServiceSpec, force: bool, loaded: bool) -> Result<()> {
    if loaded {
        run_service_commands(service_stop_commands(ServiceManager::Launchd, &spec.path))?;
    }
    write_service_file(&spec.path, &spec.contents, force, false)?;
    run_service_commands(service_start_commands(ServiceManager::Launchd, &spec.path))
}

pub(super) fn install_systemd_service(
    spec: &ServiceSpec,
    force: bool,
    was_active: bool,
) -> Result<()> {
    write_service_file(&spec.path, &spec.contents, force, false)?;
    run_service_commands(vec![systemd_manager_command(&["daemon-reload"])])?;
    run_service_commands(vec![systemd_unit_command(&["enable"])])?;
    run_service_commands(vec![systemd_unit_command(&[if was_active {
        "restart"
    } else {
        "start"
    }])])
}

pub(super) fn rollback_launchd_install(
    layout: &HomeLayout,
    path: &Path,
    file_snapshot: &ServiceFileSnapshot,
    was_loaded: bool,
) -> Result<()> {
    let mut failures = Vec::new();
    match launchd_service_is_loaded() {
        Ok(true) => record_compensation(
            &mut failures,
            "unload attempted launchd service",
            run_service_commands(service_stop_commands(ServiceManager::Launchd, path)),
        ),
        Ok(false) => {}
        Err(error) => failures.push(format!(
            "inspect attempted launchd service before rollback failed: {error:#}"
        )),
    }
    record_compensation(
        &mut failures,
        "restore launchd plist",
        file_snapshot.restore(),
    );
    if was_loaded {
        record_compensation(
            &mut failures,
            "restore launchd loaded state",
            run_service_commands(service_start_commands(ServiceManager::Launchd, path)),
        );
        record_compensation(
            &mut failures,
            "verify restored launchd daemon readiness",
            wait_for_daemon_readiness(layout),
        );
    }
    compensation_result(failures)
}

pub(super) fn rollback_systemd_install(
    layout: &HomeLayout,
    file_snapshot: &ServiceFileSnapshot,
    activity: SystemdActivity,
    enablement: SystemdEnablement,
) -> Result<()> {
    let mut failures = Vec::new();
    quiesce_systemd_service(&mut failures);
    record_compensation(
        &mut failures,
        "restore systemd unit file",
        file_snapshot.restore(),
    );
    record_compensation(
        &mut failures,
        "reload restored systemd unit",
        run_service_commands(vec![systemd_manager_command(&["daemon-reload"])]),
    );
    restore_systemd_enablement(&mut failures, enablement);
    if activity.is_active() {
        record_compensation(
            &mut failures,
            "restore systemd active state",
            run_service_commands(vec![systemd_unit_command(&["start"])]),
        );
        record_compensation(
            &mut failures,
            "verify restored systemd daemon readiness",
            wait_for_daemon_readiness(layout),
        );
    }
    compensation_result(failures)
}

pub(super) fn quiesce_systemd_service(failures: &mut Vec<String>) {
    let activity = systemd_activity_state(&systemd_unit_command(&["is-active"]));
    match activity {
        Ok(SystemdActivity::Active) => record_compensation(
            failures,
            "stop attempted systemd service",
            run_service_commands(vec![systemd_unit_command(&["stop"])]),
        ),
        Ok(SystemdActivity::Inactive | SystemdActivity::Absent) => {}
        Err(error) => failures.push(format!(
            "inspect attempted systemd active state before rollback failed: {error:#}"
        )),
    }

    let enablement = systemd_enablement_state(&systemd_unit_command(&["is-enabled"]));
    match enablement {
        Ok(SystemdEnablement::Enabled) => record_compensation(
            failures,
            "disable attempted systemd service",
            run_service_commands(vec![systemd_unit_command(&["disable"])]),
        ),
        Ok(SystemdEnablement::EnabledRuntime) => record_compensation(
            failures,
            "disable attempted runtime-enabled systemd service",
            run_service_commands(vec![systemd_unit_command(&["disable", "--runtime"])]),
        ),
        Ok(
            SystemdEnablement::Disabled
            | SystemdEnablement::DisabledRuntime
            | SystemdEnablement::Static
            | SystemdEnablement::Indirect
            | SystemdEnablement::Masked
            | SystemdEnablement::MaskedRuntime
            | SystemdEnablement::Generated
            | SystemdEnablement::Transient
            | SystemdEnablement::Absent,
        ) => {}
        Ok(
            state @ (SystemdEnablement::Linked
            | SystemdEnablement::LinkedRuntime
            | SystemdEnablement::Alias),
        ) => failures.push(format!(
            "attempted systemd service changed to unsupported `{}` state during rollback",
            state.label()
        )),
        Err(error) => failures.push(format!(
            "inspect attempted systemd enablement before rollback failed: {error:#}"
        )),
    }
}

pub(super) fn restore_systemd_enablement(
    failures: &mut Vec<String>,
    enablement: SystemdEnablement,
) {
    let (description, command) = match enablement {
        SystemdEnablement::Enabled => (
            "restore systemd enabled state",
            Some(systemd_unit_command(&["enable"])),
        ),
        SystemdEnablement::EnabledRuntime => (
            "restore systemd runtime-enabled state",
            Some(systemd_unit_command(&["enable", "--runtime"])),
        ),
        SystemdEnablement::Disabled => (
            "restore systemd disabled state",
            Some(systemd_unit_command(&["disable"])),
        ),
        SystemdEnablement::DisabledRuntime => (
            "restore systemd runtime-disabled state",
            Some(systemd_unit_command(&["disable", "--runtime"])),
        ),
        SystemdEnablement::Masked => (
            "restore systemd masked state",
            Some(systemd_unit_command(&["mask"])),
        ),
        SystemdEnablement::MaskedRuntime => (
            "restore systemd runtime-masked state",
            Some(systemd_unit_command(&["mask", "--runtime"])),
        ),
        SystemdEnablement::Static | SystemdEnablement::Indirect | SystemdEnablement::Absent => {
            ("", None)
        }
        SystemdEnablement::Linked
        | SystemdEnablement::LinkedRuntime
        | SystemdEnablement::Alias
        | SystemdEnablement::Generated
        | SystemdEnablement::Transient => {
            failures.push(format!(
                "cannot reconstruct unsupported systemd `{}` state",
                enablement.label()
            ));
            return;
        }
    };
    if let Some(command) = command {
        record_compensation(failures, description, run_service_commands(vec![command]));
    }
}

pub(crate) fn restore_daemon_runtime_after_files(
    layout: &HomeLayout,
    snapshot: DaemonRuntimeSnapshot,
) -> Result<()> {
    let state = snapshot.state_for(snapshot.manager)?;
    match state {
        ServiceRuntimeState::Launchd { loaded } => {
            let path = service_file_path(ServiceManager::Launchd)?;
            let mut failures = Vec::new();
            match launchd_service_is_loaded() {
                Ok(true) => record_compensation(
                    &mut failures,
                    "unload attempted launchd service",
                    run_service_commands(service_stop_commands(ServiceManager::Launchd, &path)),
                ),
                Ok(false) => {}
                Err(error) => failures.push(format!(
                    "inspect attempted launchd service before recovery failed: {error:#}"
                )),
            }
            if loaded {
                if !path.is_file() {
                    failures.push(format!(
                        "cannot restore loaded launchd service because {} is not a regular plist",
                        path.display()
                    ));
                } else {
                    record_compensation(
                        &mut failures,
                        "restore launchd loaded state",
                        run_service_commands(service_start_commands(
                            ServiceManager::Launchd,
                            &path,
                        )),
                    );
                    record_compensation(
                        &mut failures,
                        "verify restored launchd daemon readiness",
                        wait_for_daemon_readiness(layout),
                    );
                }
            }
            compensation_result(failures)
        }
        ServiceRuntimeState::Systemd {
            activity,
            enablement,
        } => {
            let mut failures = Vec::new();
            quiesce_systemd_service(&mut failures);
            record_compensation(
                &mut failures,
                "reload restored systemd unit",
                run_service_commands(vec![systemd_manager_command(&["daemon-reload"])]),
            );
            restore_systemd_enablement(&mut failures, enablement);
            if activity.is_active() {
                record_compensation(
                    &mut failures,
                    "restore systemd active state",
                    run_service_commands(vec![systemd_unit_command(&["start"])]),
                );
                record_compensation(
                    &mut failures,
                    "verify restored systemd daemon readiness",
                    wait_for_daemon_readiness(layout),
                );
            }
            compensation_result(failures)
        }
    }
}

pub(crate) fn quiesce_daemon_runtime(snapshot: DaemonRuntimeSnapshot) -> Result<()> {
    let state = snapshot.state_for(snapshot.manager)?;
    let mut failures = Vec::new();
    match state {
        ServiceRuntimeState::Launchd { .. } => match launchd_service_is_loaded() {
            Ok(true) => {
                let path = service_file_path(ServiceManager::Launchd)?;
                record_compensation(
                    &mut failures,
                    "unload attempted launchd service",
                    run_service_commands(service_stop_commands(ServiceManager::Launchd, &path)),
                );
            }
            Ok(false) => {}
            Err(error) => failures.push(format!(
                "inspect attempted launchd service before rollback failed: {error:#}"
            )),
        },
        ServiceRuntimeState::Systemd { .. } => quiesce_systemd_service(&mut failures),
    }
    compensation_result(failures)
}

pub(super) fn systemd_manager_command(args: &[&str]) -> Vec<String> {
    let mut command = vec!["systemctl".to_string(), "--user".to_string()];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

pub(super) fn systemd_unit_command(args: &[&str]) -> Vec<String> {
    let mut command = systemd_manager_command(args);
    command.push("gommage-daemon.service".to_string());
    command
}

pub(super) fn record_compensation(failures: &mut Vec<String>, step: &str, result: Result<()>) {
    if let Err(error) = result {
        failures.push(format!("{step} failed: {error:#}"));
    }
}

pub(super) fn compensation_result(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}

pub(super) fn with_service_rollback_error(
    primary: anyhow::Error,
    rollback: Result<()>,
) -> anyhow::Error {
    match rollback {
        Ok(()) => primary,
        Err(rollback_error) => {
            anyhow::anyhow!("{primary:#}; daemon install rollback also failed: {rollback_error:#}")
        }
    }
}
