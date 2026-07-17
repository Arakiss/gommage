mod support;

use std::fs;
use support::{doctor_check, gommage};
use tempfile::tempdir;

#[cfg(unix)]
struct FakeReadyDaemon {
    stop: std::sync::mpsc::Sender<()>,
    worker: std::thread::JoinHandle<()>,
    socket: std::path::PathBuf,
}

#[cfg(unix)]
impl FakeReadyDaemon {
    fn finish(self) {
        let _ = self.stop.send(());
        self.worker.join().unwrap();
        let _ = fs::remove_file(&self.socket);
    }
}

#[cfg(unix)]
fn start_fake_ready_daemon(home: &std::path::Path) -> FakeReadyDaemon {
    use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env, load_active_policy};
    use std::{
        io::{BufRead, BufReader, ErrorKind, Write},
        os::unix::net::UnixListener,
        sync::mpsc,
        time::Duration,
    };

    fs::create_dir_all(home).unwrap();
    let socket = home.join("gommage.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let layout = HomeLayout::at(home);
    let (stop, stopped) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut request = String::new();
                    BufReader::new(&stream).read_line(&mut request).unwrap();
                    assert!(request.contains(r#""op":"decide""#), "{request}");
                    let expedition = Expedition::load(&layout.expedition_file).unwrap();
                    let env = expedition
                        .as_ref()
                        .map(Expedition::policy_env)
                        .unwrap_or_else(default_policy_env);
                    let policy = load_active_policy(&layout, expedition.as_ref(), &env).unwrap();
                    let response = serde_json::json!({
                        "ok": true,
                        "result": { "policy_version": policy.version_hash }
                    });
                    writeln!(stream, "{response}").unwrap();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if stopped.recv_timeout(Duration::from_millis(5)).is_ok() {
                        break;
                    }
                }
                Err(error) => panic!("fake readiness daemon failed: {error}"),
            }
        }
    });
    FakeReadyDaemon {
        stop,
        worker,
        socket,
    }
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn owned_launchd_service(home: &std::path::Path) -> String {
    let home = home
        .to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    format!(
        "<plist><dict><key>ProgramArguments</key><array><string>/tmp/gommage-daemon</string><string>--foreground</string><string>--home</string><string>{home}</string></array></dict></plist>\n"
    )
}

#[cfg(unix)]
fn owned_systemd_service(home: &std::path::Path) -> String {
    format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    )
}

fn hook_group_contains_command(entry: &serde_json::Value, expected: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some(expected))
        })
}

fn bound_hook_command(home: &std::path::Path, agent: &str) -> String {
    format!(
        "gommage --home '{}' hook --agent {agent}",
        fs::canonicalize(home).unwrap().display()
    )
}

#[path = "cli_host_cleanup/agent_cleanup.rs"]
mod agent_cleanup;
#[path = "cli_host_cleanup/agent_repair.rs"]
mod agent_repair;
#[path = "cli_host_cleanup/agent_status.rs"]
mod agent_status;
#[path = "cli_host_cleanup/daemon_install.rs"]
mod daemon_install;
#[path = "cli_host_cleanup/daemon_rollback.rs"]
mod daemon_rollback;
