use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env, load_active_policy};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

use crate::util::{
    InstallTransaction, TransactionFile, backup_and_remove_file, clear_active_recovery_value,
    env_path_or_home, record_active_recovery_value, restore_regular_bytes, transaction_is_active,
    write_text,
};

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
    /// Tell the running daemon to reload policy + capability mappers from disk,
    /// without a restart. Use after editing `~/.gommage/policy.d/*.yaml` so the
    /// daemon's in-memory policy matches what `gommage decide` reads fresh.
    Reload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceManager {
    Launchd,
    Systemd,
}

#[derive(Debug, Serialize)]
pub(crate) struct DaemonDryRunPlan {
    pub(crate) manager: ServiceManager,
    pub(crate) service_file: String,
    pub(crate) daemon_binary: Option<String>,
    pub(crate) daemon_binary_error: Option<String>,
    pub(crate) no_start: bool,
    pub(crate) force: bool,
    pub(crate) backup_existing_service_file: bool,
    pub(crate) start_commands: Vec<Vec<String>>,
    pub(crate) stop_commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonReloadOutcome {
    Reloaded(String),
    Unavailable(String),
    Failed(String),
}

const DAEMON_RELOAD_IO_TIMEOUT: Duration = Duration::from_secs(2);
const DAEMON_RELOAD_MAX_RESPONSE_BYTES: u64 = 4 * 1024;
const DAEMON_READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_READINESS_RETRY: Duration = Duration::from_millis(100);
const DAEMON_READINESS_IO_TIMEOUT: Duration = Duration::from_millis(500);

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
            daemon_uninstall(&layout, resolve_service_manager(manager)?, dry_run)
        }
        DaemonCmd::Status { manager } => daemon_status(resolve_service_manager(manager)?),
        DaemonCmd::Reload => daemon_reload(&layout),
    }
}

/// Connect to the running daemon's Unix socket and ask it to reload policy +
/// capability mappers from disk (the `{"op":"reload"}` IPC the daemon already
/// serves). Exits non-zero with a clear message if no daemon is listening.
fn daemon_reload(layout: &HomeLayout) -> Result<ExitCode> {
    match request_daemon_reload(layout)? {
        DaemonReloadOutcome::Reloaded(detail) => {
            println!("ok daemon: {detail}");
            match wait_for_daemon_readiness(layout) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => {
                    eprintln!("daemon reload failed readiness verification: {error:#}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        DaemonReloadOutcome::Unavailable(message) => {
            eprintln!("{message}");
            Ok(ExitCode::from(1))
        }
        DaemonReloadOutcome::Failed(error) => {
            eprintln!("daemon reload failed: {error}");
            Ok(ExitCode::from(1))
        }
    }
}

pub(crate) fn request_daemon_reload(layout: &HomeLayout) -> Result<DaemonReloadOutcome> {
    use std::io::{BufRead, BufReader, Read, Write};
    let socket = &layout.socket;
    let mut stream = match connect_daemon_with_timeout(socket) {
        Ok(stream) => stream,
        Err(error) => return Ok(classify_daemon_connect_error(socket, &error)),
    };
    stream.set_read_timeout(Some(DAEMON_RELOAD_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_RELOAD_IO_TIMEOUT))?;
    if let Err(error) = stream
        .write_all(b"{\"op\":\"reload\"}\n")
        .and_then(|()| stream.flush())
    {
        return Ok(DaemonReloadOutcome::Failed(format!(
            "writing reload request to {} failed or timed out: {error}",
            socket.display()
        )));
    }

    let mut line = String::new();
    let read_result = BufReader::new(&stream)
        .take(DAEMON_RELOAD_MAX_RESPONSE_BYTES + 1)
        .read_line(&mut line);
    if let Err(error) = read_result {
        return Ok(DaemonReloadOutcome::Failed(format!(
            "reading reload response from {} failed or timed out: {error}",
            socket.display()
        )));
    }
    if line.is_empty() {
        return Ok(DaemonReloadOutcome::Failed(
            "daemon closed the reload socket without a response".to_string(),
        ));
    }
    if line.len() as u64 > DAEMON_RELOAD_MAX_RESPONSE_BYTES
        || (line.len() as u64 == DAEMON_RELOAD_MAX_RESPONSE_BYTES && !line.ends_with('\n'))
    {
        return Ok(DaemonReloadOutcome::Failed(format!(
            "daemon reload response exceeded {} bytes",
            DAEMON_RELOAD_MAX_RESPONSE_BYTES
        )));
    }
    if !line.ends_with('\n') {
        return Ok(DaemonReloadOutcome::Failed(
            "daemon reload response was incomplete".to_string(),
        ));
    }
    let resp: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(resp) => resp,
        Err(error) => {
            return Ok(DaemonReloadOutcome::Failed(format!(
                "daemon reload response was invalid JSON: {error}"
            )));
        }
    };
    if resp.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        let detail = resp
            .get("result")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("policy reloaded");
        Ok(DaemonReloadOutcome::Reloaded(detail.to_string()))
    } else {
        let error = resp
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("daemon returned an error");
        Ok(DaemonReloadOutcome::Failed(error.to_string()))
    }
}

fn connect_daemon_with_timeout(socket: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    connect_daemon_with_timeout_for(socket, DAEMON_RELOAD_IO_TIMEOUT)
}

fn connect_daemon_with_timeout_for(
    socket: &Path,
    timeout: Duration,
) -> io::Result<std::os::unix::net::UnixStream> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| io::Error::other(format!("building daemon connector: {error}")))?;
    let stream = runtime.block_on(async {
        tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket)).await
    });
    let stream = match stream {
        Ok(result) => result?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "connecting to daemon socket {} timed out after {} ms",
                    socket.display(),
                    timeout.as_millis()
                ),
            ));
        }
    };
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn classify_daemon_connect_error(socket: &Path, error: &io::Error) -> DaemonReloadOutcome {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            DaemonReloadOutcome::Unavailable(format!(
                "no daemon listening on {} ({error}). Is it running? `gommage daemon status`",
                socket.display()
            ))
        }
        _ => DaemonReloadOutcome::Failed(format!(
            "connecting to daemon socket {} failed: {error}",
            socket.display()
        )),
    }
}

fn report_daemon_reload(outcome: DaemonReloadOutcome) -> Result<()> {
    match outcome {
        DaemonReloadOutcome::Reloaded(detail) => println!("ok daemon: {detail}"),
        DaemonReloadOutcome::Unavailable(message) => {
            println!("warn daemon reload skipped: {message}");
        }
        DaemonReloadOutcome::Failed(error) => {
            anyhow::bail!(
                "daemon rejected policy reload: {error}; stale in-memory policy may still be active"
            )
        }
    }
    Ok(())
}

pub(crate) fn reload_policy_runtime(layout: &HomeLayout) -> Result<()> {
    let outcome = request_daemon_reload(layout)?;
    let reachable = matches!(outcome, DaemonReloadOutcome::Reloaded(_));
    report_daemon_reload(outcome)?;
    if reachable {
        wait_for_daemon_readiness(layout)?;
    }
    Ok(())
}

fn wait_for_daemon_readiness(layout: &HomeLayout) -> Result<()> {
    let expected_policy = expected_policy_version(layout)?;
    let deadline = std::time::Instant::now() + DAEMON_READINESS_TIMEOUT;
    loop {
        let last_error = match request_daemon_policy_version(layout) {
            Ok(actual) if actual == expected_policy => {
                println!("ok daemon: socket ready with policy {actual}");
                return Ok(());
            }
            Ok(actual) => {
                format!("daemon reported policy {actual}, expected {expected_policy}")
            }
            Err(error) => error.to_string(),
        };
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "daemon readiness failed after {} ms: {last_error}",
                DAEMON_READINESS_TIMEOUT.as_millis()
            );
        }
        std::thread::sleep(DAEMON_READINESS_RETRY);
    }
}

fn expected_policy_version(layout: &HomeLayout) -> Result<String> {
    let expedition = Expedition::load(&layout.expedition_file)?;
    let env = expedition
        .as_ref()
        .map(Expedition::policy_env)
        .unwrap_or_else(default_policy_env);
    Ok(load_active_policy(layout, expedition.as_ref(), &env)?.version_hash)
}

fn request_daemon_policy_version(layout: &HomeLayout) -> Result<String> {
    use std::io::{BufRead, BufReader, Read, Write};

    let mut stream = connect_daemon_with_timeout_for(&layout.socket, DAEMON_READINESS_IO_TIMEOUT)
        .with_context(|| format!("connecting to {}", layout.socket.display()))?;
    stream.set_read_timeout(Some(DAEMON_READINESS_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_READINESS_IO_TIMEOUT))?;
    stream.write_all(
        b"{\"op\":\"decide\",\"call\":{\"tool\":\"GommageReadiness\",\"input\":{}}}\n",
    )?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(&stream)
        .take(DAEMON_RELOAD_MAX_RESPONSE_BYTES + 1)
        .read_line(&mut line)?;
    if line.is_empty() || !line.ends_with('\n') {
        anyhow::bail!("daemon readiness response was empty or incomplete");
    }
    if line.len() as u64 > DAEMON_RELOAD_MAX_RESPONSE_BYTES {
        anyhow::bail!("daemon readiness response exceeded the protocol limit");
    }
    let response: serde_json::Value =
        serde_json::from_str(line.trim()).context("parsing daemon readiness response")?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        anyhow::bail!(
            "daemon readiness probe failed: {}",
            response
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("daemon returned an error")
        );
    }
    response
        .pointer("/result/policy_version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("daemon readiness response omitted policy_version"))
}

pub(crate) fn daemon_install(
    layout: HomeLayout,
    manager: ServiceManager,
    force: bool,
    no_start: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    if dry_run || transaction_is_active() {
        return daemon_install_inner(&layout, manager, force, no_start, dry_run, None);
    }

    let service_path = service_file_path(manager)?;
    let runtime_paths = daemon_runtime_paths(&layout);
    let mut files = vec![TransactionFile::new(service_path)];
    files.extend(
        runtime_paths
            .iter()
            .cloned()
            .map(|path| TransactionFile::new(path).preserve_existing()),
    );
    let mut transaction = InstallTransaction::begin(&layout, files, Vec::new())?;
    if transaction.recovered_previous() {
        if !recover_recorded_daemon_runtime(&transaction, &layout)? {
            reconcile_recovered_daemon(&layout, manager)?;
        }
        transaction.acknowledge_recovery()?;
    }
    let runtime_snapshot = prepare_daemon_runtime_snapshot(&layout, manager, no_start)?;
    let install_result =
        daemon_install_inner(&layout, manager, force, no_start, false, runtime_snapshot);
    let observe_result = transaction.observe_paths(runtime_paths.iter().map(PathBuf::as_path));
    let result = match (install_result, observe_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(error)) => Err(error.context("journaling daemon runtime activation")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(observe_error)) => Err(error.context(format!(
            "journaling daemon runtime activation also failed: {observe_error:#}"
        ))),
    };
    match result {
        Ok(code) if code == ExitCode::SUCCESS => {
            if let Err(error) = transaction.commit() {
                return Err(
                    rollback_daemon_transaction(transaction, &layout, Some(error))
                        .expect_err("primary daemon commit error is preserved"),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Ok(code) => {
            rollback_daemon_transaction(transaction, &layout, None)?;
            Ok(code)
        }
        Err(error) => Err(
            rollback_daemon_transaction(transaction, &layout, Some(error))
                .expect_err("primary daemon install error is preserved"),
        ),
    }
}

pub(crate) fn daemon_install_prepared(
    layout: &HomeLayout,
    manager: ServiceManager,
    force: bool,
    no_start: bool,
    dry_run: bool,
    runtime_snapshot: Option<DaemonRuntimeSnapshot>,
) -> Result<ExitCode> {
    daemon_install_inner(layout, manager, force, no_start, dry_run, runtime_snapshot)
}

fn daemon_install_inner(
    layout: &HomeLayout,
    manager: ServiceManager,
    force: bool,
    no_start: bool,
    dry_run: bool,
    runtime_snapshot: Option<DaemonRuntimeSnapshot>,
) -> Result<ExitCode> {
    preflight_daemon_install(layout, manager, force)?;
    let daemon_bin = find_daemon_binary()?;
    let spec = daemon_service_spec(manager, layout, &daemon_bin)?;

    if dry_run {
        write_service_file(&spec.path, &spec.contents, force, true)?;
        println!("ok daemon: service file {}", spec.path.display());
        if no_start {
            println!("ok daemon: service installed but not started (--no-start)");
            return Ok(ExitCode::SUCCESS);
        }
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

    let runtime_state = if no_start {
        None
    } else {
        let state = match runtime_snapshot {
            Some(snapshot) => snapshot.state_for(manager)?,
            None => capture_service_runtime_state(manager)?,
        };
        if matches!(state, ServiceRuntimeState::Launchd { loaded: true }) && !spec.path.exists() {
            anyhow::bail!(
                "launchd reports dev.gommage.daemon as loaded, but {} does not exist; cannot safely replace a service without a restorable plist",
                spec.path.display()
            );
        }
        Some(state)
    };

    let file_snapshot = ServiceFileSnapshot::capture(&spec.path)?;

    if no_start {
        if let Err(error) = write_service_file(&spec.path, &spec.contents, force, false) {
            return Err(with_service_rollback_error(error, file_snapshot.restore()));
        }
        println!("ok daemon: service file {}", spec.path.display());
        println!("ok daemon: service installed but not started (--no-start)");
        return Ok(ExitCode::SUCCESS);
    }

    let runtime_state = runtime_state.expect("runtime state captured when start is requested");
    let recovery_snapshot = runtime_snapshot.unwrap_or(DaemonRuntimeSnapshot {
        manager,
        state: runtime_state,
    });
    arm_daemon_runtime_recovery(recovery_snapshot)?;
    let install_result = match runtime_state {
        ServiceRuntimeState::Launchd { loaded } => install_launchd_service(&spec, force, loaded),
        ServiceRuntimeState::Systemd { activity, .. } => {
            install_systemd_service(&spec, force, activity.is_active())
        }
    }
    .and_then(|()| wait_for_daemon_readiness(layout));
    if let Err(error) = install_result {
        let rollback = match runtime_state {
            ServiceRuntimeState::Launchd { loaded } => {
                rollback_launchd_install(layout, &spec.path, &file_snapshot, loaded)
            }
            ServiceRuntimeState::Systemd {
                activity,
                enablement,
            } => rollback_systemd_install(layout, &file_snapshot, activity, enablement),
        }
        .and_then(|()| clear_active_recovery_value(DAEMON_RUNTIME_RECOVERY_KEY));
        return Err(with_service_rollback_error(error, rollback));
    }

    println!("ok daemon: service file {}", spec.path.display());
    println!("ok daemon: service enabled and started");
    Ok(ExitCode::SUCCESS)
}

fn daemon_runtime_paths(layout: &HomeLayout) -> Vec<PathBuf> {
    vec![
        layout.root.join("daemon.log"),
        layout.root.join("daemon.err.log"),
        layout.socket.clone(),
    ]
}

fn reconcile_recovered_daemon(layout: &HomeLayout, manager: ServiceManager) -> Result<()> {
    let path = service_file_path(manager)?;
    match capture_service_runtime_state(manager)? {
        ServiceRuntimeState::Launchd { loaded: false } => Ok(()),
        ServiceRuntimeState::Launchd { loaded: true } => {
            run_service_commands(service_stop_commands(manager, &path))?;
            if !path.is_file() {
                anyhow::bail!(
                    "recovered launchd service was loaded but {} has no restorable plist",
                    path.display()
                );
            }
            run_service_commands(service_start_commands(manager, &path))?;
            wait_for_daemon_readiness(layout)
        }
        ServiceRuntimeState::Systemd { activity, .. } => {
            run_service_commands(vec![systemd_manager_command(&["daemon-reload"])])?;
            if activity.is_active() {
                run_service_commands(vec![systemd_unit_command(&["restart"])])?;
                wait_for_daemon_readiness(layout)?;
            }
            Ok(())
        }
    }
}

fn rollback_daemon_transaction(
    mut transaction: InstallTransaction,
    layout: &HomeLayout,
    primary: Option<anyhow::Error>,
) -> Result<()> {
    if !transaction.has_mutations() {
        transaction.commit()?;
        return primary.map_or(Ok(()), Err);
    }
    let mut secondary = Vec::new();
    let runtime_snapshot = match current_recorded_daemon_runtime(&transaction) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            secondary.push(format!(
                "reading service-manager rollback state failed: {error:#}"
            ));
            None
        }
    };
    let service_quiesce = runtime_snapshot.map_or(Ok(()), quiesce_daemon_runtime);
    if let Err(error) = &service_quiesce {
        secondary.push(format!("quiescing attempted daemon failed: {error:#}"));
    }
    let rollback = transaction.rollback();
    if let Err(error) = &rollback {
        secondary.push(format!("filesystem rollback failed: {error:#}"));
    }
    let service_restore = match (
        rollback.is_ok() && service_quiesce.is_ok(),
        runtime_snapshot,
    ) {
        (true, Some(snapshot)) => restore_daemon_runtime_after_files(layout, snapshot),
        (_, _) => Ok(()),
    };
    if let Err(error) = &service_restore {
        secondary.push(format!("service-manager rollback failed: {error:#}"));
    }
    if rollback.is_ok()
        && service_quiesce.is_ok()
        && service_restore.is_ok()
        && let Err(error) = transaction.commit()
    {
        secondary.push(format!("discarding rollback journal failed: {error:#}"));
    }
    match (primary, secondary.is_empty()) {
        (None, true) => Ok(()),
        (None, false) => anyhow::bail!("daemon rollback was incomplete: {}", secondary.join("; ")),
        (Some(primary), true) => Err(primary.context("daemon installation was rolled back")),
        (Some(primary), false) => Err(primary.context(format!(
            "daemon rollback was incomplete: {}",
            secondary.join("; ")
        ))),
    }
}

pub(crate) fn preflight_daemon_install(
    layout: &HomeLayout,
    manager: ServiceManager,
    force: bool,
) -> Result<()> {
    let daemon_bin = find_daemon_binary()?;
    let spec = daemon_service_spec(manager, layout, &daemon_bin)?;
    match std::fs::symlink_metadata(&spec.path) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "refusing to install daemon service through symbolic link {}",
            spec.path.display()
        ),
        Ok(metadata) if metadata.is_file() => {
            let current = std::fs::read_to_string(&spec.path)
                .with_context(|| format!("reading {}", spec.path.display()))?;
            if current != spec.contents && !force {
                anyhow::bail!(
                    "{} exists; rerun with --force to replace it",
                    spec.path.display()
                );
            }
        }
        Ok(_) => anyhow::bail!("{} exists but is not a regular file", spec.path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = spec.path.parent()
                && parent.exists()
                && !parent.is_dir()
            {
                anyhow::bail!(
                    "daemon service parent {} is not a directory",
                    parent.display()
                );
            }
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", spec.path.display()));
        }
    }
    Ok(())
}

fn preflight_service_home(layout: &HomeLayout, manager: ServiceManager, path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "refusing daemon service mutation through non-regular path {}",
            path.display()
        );
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading daemon service file {}", path.display()))?;
    if !service_selects_home(manager, &contents, &layout.root) {
        anyhow::bail!(
            "{} does not select the requested Gommage home {}; refusing to mutate a service whose runtime cannot be restored from this authority root",
            path.display(),
            layout.root.display()
        );
    }
    Ok(())
}

fn service_selects_home(manager: ServiceManager, contents: &str, home: &Path) -> bool {
    match manager {
        ServiceManager::Launchd => launchd_program_arguments(contents).is_some_and(|arguments| {
            let selected = arguments
                .iter()
                .enumerate()
                .filter(|(_, value)| value.as_str() == "--home")
                .collect::<Vec<_>>();
            selected.len() == 1
                && arguments.get(selected[0].0 + 1).map(String::as_str)
                    == Some(xml_escape(&home.to_string_lossy()).as_str())
        }),
        ServiceManager::Systemd => {
            let exec = contents
                .lines()
                .map(str::trim)
                .filter_map(|line| line.strip_prefix("ExecStart="))
                .collect::<Vec<_>>();
            if exec.len() != 1 {
                return false;
            }
            let marker = format!(" --home {}", systemd_quote(&home.to_string_lossy()));
            exec[0].matches(" --home ").count() == 1 && exec[0].ends_with(&marker)
        }
    }
}

fn launchd_program_arguments(contents: &str) -> Option<Vec<String>> {
    let key = contents.find("<key>ProgramArguments</key>")?;
    let suffix = &contents[key + "<key>ProgramArguments</key>".len()..];
    let array_start = suffix.find("<array>")? + "<array>".len();
    let array = &suffix[array_start..];
    let array_end = array.find("</array>")?;
    let mut remaining = &array[..array_end];
    let mut arguments = Vec::new();
    while let Some(start) = remaining.find("<string>") {
        remaining = &remaining[start + "<string>".len()..];
        let end = remaining.find("</string>")?;
        arguments.push(remaining[..end].to_string());
        remaining = &remaining[end + "</string>".len()..];
    }
    Some(arguments)
}

pub(crate) fn daemon_dry_run_plan(
    manager: ServiceManager,
    force: bool,
    no_start: bool,
) -> Result<DaemonDryRunPlan> {
    let path = service_file_path(manager)?;
    let daemon_binary = match find_daemon_binary() {
        Ok(path) => (Some(path.display().to_string()), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let start_commands = if no_start {
        Vec::new()
    } else {
        service_start_commands(manager, &path)
    };
    let stop_commands = if no_start {
        Vec::new()
    } else if manager == ServiceManager::Launchd {
        service_stop_commands(manager, &path)
    } else {
        Vec::new()
    };
    Ok(DaemonDryRunPlan {
        manager,
        service_file: path.display().to_string(),
        daemon_binary: daemon_binary.0,
        daemon_binary_error: daemon_binary.1,
        no_start,
        force,
        backup_existing_service_file: path.exists() && force,
        start_commands,
        stop_commands,
    })
}

pub(crate) fn daemon_uninstall(
    layout: &HomeLayout,
    manager: ServiceManager,
    dry_run: bool,
) -> Result<ExitCode> {
    let path = service_file_path(manager)?;
    preflight_service_home(layout, manager, &path)?;
    if dry_run {
        for command in service_stop_commands(manager, &path) {
            println!("plan run: {}", command.join(" "));
        }
        println!("plan remove: {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    let runtime_paths = daemon_runtime_paths(layout);
    let mut files = vec![TransactionFile::new(path.clone())];
    files.extend(
        runtime_paths
            .iter()
            .cloned()
            .map(|path| TransactionFile::new(path).preserve_existing()),
    );
    let mut transaction = InstallTransaction::begin(layout, files, Vec::new())?;
    if transaction.recovered_previous() {
        recover_recorded_daemon_runtime(&transaction, layout)?;
        transaction.acknowledge_recovery()?;
    }
    let snapshot = prepare_daemon_runtime_snapshot(layout, manager, false)?
        .expect("uninstall always captures daemon runtime state");
    arm_daemon_runtime_recovery(snapshot)?;

    let uninstall_result = daemon_uninstall_inner(layout, manager, &path, snapshot);
    let observe_result = transaction.observe_paths(runtime_paths.iter().map(PathBuf::as_path));
    let result = match (uninstall_result, observe_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error.context("journaling daemon runtime removal")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(observe_error)) => Err(error.context(format!(
            "journaling daemon runtime removal also failed: {observe_error:#}"
        ))),
    };

    match result {
        Ok(()) => {
            if let Err(error) = transaction.commit() {
                return Err(
                    rollback_daemon_transaction(transaction, layout, Some(error))
                        .expect_err("primary daemon uninstall commit error is preserved"),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => Err(
            rollback_daemon_transaction(transaction, layout, Some(error))
                .expect_err("primary daemon uninstall error is preserved"),
        ),
    }
}

fn daemon_uninstall_inner(
    layout: &HomeLayout,
    manager: ServiceManager,
    path: &Path,
    snapshot: DaemonRuntimeSnapshot,
) -> Result<()> {
    quiesce_daemon_runtime(snapshot).context("stopping daemon before uninstall")?;
    match backup_and_remove_file(path, false)? {
        Some(_) => println!("ok daemon: removed {}", path.display()),
        None => println!("ok daemon: service file not found at {}", path.display()),
    }
    if manager == ServiceManager::Systemd {
        run_service_commands(vec![systemd_manager_command(&["daemon-reload"])])
            .context("reloading systemd after daemon unit removal")?;
    }
    verify_daemon_uninstalled(layout, manager, path)
}

fn verify_daemon_uninstalled(
    _layout: &HomeLayout,
    manager: ServiceManager,
    path: &Path,
) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!("daemon service file still exists at {}", path.display()),
        Err(error) => {
            return Err(error).with_context(|| format!("verifying removal of {}", path.display()));
        }
    }
    match capture_service_runtime_state(manager)? {
        ServiceRuntimeState::Launchd { loaded: false }
        | ServiceRuntimeState::Systemd {
            activity: SystemdActivity::Absent,
            enablement: SystemdEnablement::Absent,
        } => Ok(()),
        state => anyhow::bail!("daemon service manager still reports state {state:?}"),
    }
}

fn daemon_status(manager: ServiceManager) -> Result<ExitCode> {
    let commands = service_status_commands(manager);
    let status = run_service_commands_allow_failure_verbose(commands)?;
    Ok(if status {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

mod runtime;
mod service;

use runtime::*;
pub(crate) use runtime::{
    DaemonRuntimeSnapshot, current_recorded_daemon_runtime, prepare_daemon_runtime_snapshot,
    quiesce_daemon_runtime, recover_recorded_daemon_runtime, restore_daemon_runtime_after_files,
};
use service::*;
pub(crate) use service::{resolve_service_manager, service_file_path};

#[cfg(test)]
mod tests;
