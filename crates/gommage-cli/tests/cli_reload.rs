#![cfg(unix)]

mod support;

use gommage_core::{Policy, runtime::default_policy_env};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use support::gommage;
use tempfile::tempdir;

struct FakeReloadDaemon {
    stop: Sender<()>,
    worker: JoinHandle<Vec<String>>,
}

#[derive(Clone, Copy)]
enum ReloadReply {
    Success,
    Error,
    Delayed(Duration),
    Incomplete,
    Oversized,
}

impl FakeReloadDaemon {
    fn finish(self) -> Vec<String> {
        self.stop.send(()).unwrap();
        self.worker.join().unwrap()
    }
}

fn start_fake_reload_daemon(
    socket: &Path,
    expected_mutations: Vec<(PathBuf, &'static str)>,
) -> FakeReloadDaemon {
    start_fake_reload_daemon_with_reply(socket, expected_mutations, ReloadReply::Success)
}

fn start_fake_reload_daemon_with_reply(
    socket: &Path,
    expected_mutations: Vec<(PathBuf, &'static str)>,
    reply: ReloadReply,
) -> FakeReloadDaemon {
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(socket).unwrap();
    let home = socket.parent().unwrap().to_path_buf();
    listener.set_nonblocking(true).unwrap();
    let (stop, stopped) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut requests = Vec::new();
        let mut reloads = 0_usize;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = String::new();
                    BufReader::new(&stream).read_line(&mut request).unwrap();

                    if request.contains(r#""op":"reload""#) && reloads == 0 {
                        for (path, marker) in &expected_mutations {
                            let contents = fs::read_to_string(path).unwrap_or_else(|error| {
                                panic!(
                                    "daemon reload arrived before {} was readable: {error}",
                                    path.display()
                                )
                            });
                            assert!(
                                contents.contains(marker),
                                "daemon reload arrived before {} contained its final mutation",
                                path.display()
                            );
                        }
                    }

                    requests.push(request.trim_end().to_string());
                    if request.contains(r#""op":"decide""#) {
                        let policy =
                            Policy::load_from_dir(&home.join("policy.d"), &default_policy_env())
                                .unwrap();
                        let response = serde_json::json!({
                            "ok": true,
                            "result": { "policy_version": policy.version_hash }
                        });
                        let _ = writeln!(stream, "{response}");
                        let _ = stream.flush();
                        continue;
                    }
                    reloads += 1;
                    match reply {
                        ReloadReply::Success => {
                            let _ = stream
                                .write_all(b"{\"ok\":true,\"result\":\"fake policy reloaded\"}\n");
                        }
                        ReloadReply::Error => {
                            let _ = stream
                                .write_all(b"{\"ok\":false,\"error\":\"synthetic rejection\"}\n");
                        }
                        ReloadReply::Delayed(delay) if reloads == 1 => {
                            match stopped.recv_timeout(delay) {
                                Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                                Err(RecvTimeoutError::Timeout) => {
                                    let _ = stream.write_all(
                                        b"{\"ok\":true,\"result\":\"late policy reload\"}\n",
                                    );
                                }
                            }
                        }
                        ReloadReply::Delayed(_) => {
                            let _ = stream.write_all(
                                b"{\"ok\":true,\"result\":\"recovered policy reload\"}\n",
                            );
                        }
                        ReloadReply::Incomplete => {
                            let _ = stream.write_all(b"{\"ok\":true}");
                        }
                        ReloadReply::Oversized => {
                            let mut response = vec![b'x'; 4_096];
                            response.push(b'\n');
                            let _ = stream.write_all(&response);
                        }
                    }
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    match stopped.recv_timeout(Duration::from_millis(5)) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                }
                Err(error) => panic!("fake reload daemon failed to accept: {error}"),
            }
        }
        requests
    });
    FakeReloadDaemon { stop, worker }
}

#[test]
fn agent_install_reloads_the_daemon_once_after_mutating_agent_config() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let daemon = start_fake_reload_daemon(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "hook --agent claude")],
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        requests,
        [
            r#"{"op":"reload"}"#,
            r#"{"op":"decide","call":{"tool":"GommageReadiness","input":{}}}"#,
        ]
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ok daemon: fake policy reloaded"));
}

#[test]
fn failed_preflight_does_not_reload_or_mutate() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    let reserved = home.join("policy.d/95-agent-catch-all.yaml");
    fs::write(&reserved, "# operator-owned\n[]\n").unwrap();
    let daemon = start_fake_reload_daemon(&home.join("gommage.sock"), Vec::new());

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert!(requests.is_empty());
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
    assert_eq!(
        fs::read_to_string(&reserved).unwrap(),
        "# operator-owned\n[]\n"
    );
}

#[test]
fn quickstart_reloads_the_daemon_once_after_all_mutations() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let daemon = start_fake_reload_daemon(
        &home.join("gommage.sock"),
        vec![
            (settings.clone(), "hook --agent claude"),
            (
                home.join("policy.d/00-hard-stops.yaml"),
                "deny-ambiguous-shell-effects",
            ),
            (
                home.join("AGENT_CONTEXT.md"),
                "generated by `gommage harness write-context` or `gommage quickstart`",
            ),
        ],
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--no-import-native-permissions",
            "--no-self-test",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        requests,
        [
            r#"{"op":"reload"}"#,
            r#"{"op":"decide","call":{"tool":"GommageReadiness","input":{}}}"#,
        ]
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ok daemon: fake policy reloaded"));
}

#[test]
fn policy_init_force_and_relaxation_cleanup_roll_back_on_reload_rejection() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let initial = gommage(&home)
        .args(["policy", "init", "--stdlib"])
        .output()
        .unwrap();
    assert!(initial.status.success());

    let bundled = home.join("policy.d/20-git.yaml");
    let relaxation = home.join("policy.d/19-operator-main-push.yaml");
    let old_bundled = b"# operator-modified bundled policy\n[]\n";
    let old_relaxation = b"# operator local relaxation\n[]\n";
    fs::write(&bundled, old_bundled).unwrap();
    fs::write(&relaxation, old_relaxation).unwrap();
    let daemon = start_fake_reload_daemon_with_reply(
        &home.join("gommage.sock"),
        vec![(bundled.clone(), "gate-main-push")],
        ReloadReply::Error,
    );

    let output = gommage(&home)
        .args([
            "policy",
            "init",
            "--stdlib",
            "--force",
            "--remove-local-relaxations",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(requests, [r#"{"op":"reload"}"#, r#"{"op":"reload"}"#]);
    assert_eq!(fs::read(&bundled).unwrap(), old_bundled);
    assert_eq!(fs::read(&relaxation).unwrap(), old_relaxation);
    assert!(fs::read_dir(home.join("policy.d")).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("20-git.yaml.gommage-bak-")
    }));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("policy installation"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn daemon_rejection_makes_agent_install_fail_after_exactly_one_reload_attempt() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let daemon = start_fake_reload_daemon_with_reply(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "hook --agent claude")],
        ReloadReply::Error,
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(requests, [r#"{"op":"reload"}"#, r#"{"op":"reload"}"#]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("synthetic rejection"));
}

#[test]
fn daemon_reload_timeout_is_bounded_and_fails_the_install() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let daemon = start_fake_reload_daemon_with_reply(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "hook --agent claude")],
        ReloadReply::Delayed(Duration::from_millis(2_500)),
    );

    let started = Instant::now();
    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let command_elapsed = started.elapsed();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(
        requests,
        [
            r#"{"op":"reload"}"#,
            r#"{"op":"reload"}"#,
            r#"{"op":"decide","call":{"tool":"GommageReadiness","input":{}}}"#,
        ]
    );
    assert!(
        command_elapsed < Duration::from_millis(4_500),
        "reload timeout was not bounded: {command_elapsed:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(stderr.contains("timed out") || stderr.contains("temporarily unavailable"));
}

#[test]
fn daemon_reload_rejects_incomplete_and_oversized_responses() {
    for (reply, expected) in [
        (ReloadReply::Incomplete, "incomplete"),
        (ReloadReply::Oversized, "exceeded"),
    ] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let daemon =
            start_fake_reload_daemon_with_reply(&home.join("gommage.sock"), Vec::new(), reply);

        let output = gommage(&home).args(["daemon", "reload"]).output().unwrap();
        let requests = daemon.finish();

        assert!(!output.status.success());
        assert_eq!(requests, [r#"{"op":"reload"}"#]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "expected {expected:?} in {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn failed_agent_install_rolls_back_then_reloads_once() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let combined_config = temp.path().join("codex").join("combined-config");
    fs::create_dir_all(combined_config.parent().unwrap()).unwrap();
    fs::write(&combined_config, "").unwrap();
    let daemon = start_fake_reload_daemon(
        &home.join("gommage.sock"),
        vec![(combined_config.clone(), "")],
    );

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &combined_config)
        .env("GOMMAGE_CODEX_CONFIG", &combined_config)
        .args([
            "agent",
            "install",
            "codex",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(
        requests,
        [
            r#"{"op":"reload"}"#,
            r#"{"op":"decide","call":{"tool":"GommageReadiness","input":{}}}"#,
        ]
    );
    assert_eq!(fs::read_to_string(&combined_config).unwrap(), "");
}

#[test]
fn repair_agent_reloads_the_daemon_once() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let daemon = start_fake_reload_daemon(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "hook --agent claude")],
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["repair", "agent", "claude"])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        requests,
        [
            r#"{"op":"reload"}"#,
            r#"{"op":"decide","call":{"tool":"GommageReadiness","input":{}}}"#,
        ]
    );
}

#[test]
fn agent_uninstall_rolls_back_when_daemon_rejects_the_new_config() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"gommage hook --agent claude\"}]}]},\"keep\":true}\n";
    fs::write(&settings, original).unwrap();
    let daemon = start_fake_reload_daemon_with_reply(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "PreToolUse")],
        ReloadReply::Error,
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "uninstall", "claude"])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(requests, [r#"{"op":"reload"}"#, r#"{"op":"reload"}"#]);
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
}

#[test]
fn repair_restore_backup_rolls_back_when_daemon_rejects_it() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"gommage hook --agent claude\"}]}]},\"version\":\"current\"}\n";
    let restored = "{\"version\":\"restored\"}\n";
    fs::write(&settings, original).unwrap();
    let backup = settings.with_file_name("settings.json.gommage-bak-1");
    fs::write(&backup, restored).unwrap();
    let daemon = start_fake_reload_daemon_with_reply(
        &home.join("gommage.sock"),
        vec![(settings.clone(), "restored")],
        ReloadReply::Error,
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["repair", "agent", "claude", "--restore-backup"])
        .output()
        .unwrap();
    let requests = daemon.finish();

    assert!(!output.status.success());
    assert_eq!(requests, [r#"{"op":"reload"}"#, r#"{"op":"reload"}"#]);
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
    assert_eq!(fs::read_to_string(backup).unwrap(), restored);
}

#[test]
fn agent_install_lock_contention_is_bounded_across_processes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    let lock_path = temp.path().join(".gommage.gommage-install.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    lock.lock().unwrap();

    let started = Instant::now();
    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    File::unlock(&lock).unwrap();

    assert!(!output.status.success());
    assert!(elapsed >= Duration::from_millis(1_900));
    assert!(elapsed < Duration::from_millis(3_500));
    assert!(String::from_utf8_lossy(&output.stderr).contains("another Gommage installation"));
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
    assert!(!home.exists());
}
