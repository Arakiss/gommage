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
        os::unix::net::{UnixListener, UnixStream},
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
        let write_response =
            |stream: &mut UnixStream, response: &str| match writeln!(stream, "{response}") {
                Ok(()) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ) =>
                {
                    false
                }
                Err(error) => panic!("fake readiness daemon response failed: {error}"),
            };
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut request = String::new();
                    match BufReader::new(&stream).read_line(&mut request) {
                        Ok(0) => continue,
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => panic!("fake readiness daemon request failed: {error}"),
                    }
                    if request.contains(r#""op":"reload""#) {
                        write_response(&mut stream, r#"{"ok":true,"result":"policy reloaded"}"#);
                        continue;
                    }
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
                    write_response(&mut stream, &response.to_string());
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

#[test]
fn quickstart_installs_claude_hook_and_imports_native_denies() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "language": "spanish",
  "permissions": {
    "allow": [
      "Bash",
      "Bash(git status *)",
      "Read(./docs/**)",
      "Write",
      "Edit",
      "MultiEdit(./src/**)",
      "NotebookEdit(*)",
      "WebFetch(domain:example.com)",
      "WebSearch"
    ],
    "deny": [
      "Read(./secrets/**)",
      "Read(~/.ssh/id_*)",
      "Bash(sudo rm -rf:*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/tmp/old-break-glass.sh" }
        ]
      }
    ]
  },
  "enabledPlugins": ["example"]
}"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--replace-hooks",
            "--relaxed",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let imported = fs::read_to_string(home.join("policy.d/05-claude-import.yaml")).unwrap();
    assert!(imported.contains("fs.read:${EXPEDITION_ROOT}/secrets/**"));
    assert!(imported.contains("fs.read:${HOME}/.ssh/id_*"));
    assert!(imported.contains("proc.exec:sudo rm -rf*"));
    let imported_allows =
        fs::read_to_string(home.join("policy.d/90-claude-allow-import.yaml")).unwrap();
    assert!(imported_allows.contains("proc.exec:git status *"));
    assert!(imported_allows.contains("proc.exec:*"));
    assert!(imported_allows.contains("fs.read:${EXPEDITION_ROOT}/docs/**"));
    assert!(imported_allows.contains("fs.write:${EXPEDITION_ROOT}/src/**"));
    assert_eq!(imported_allows.matches("fs.write:**").count(), 1);
    assert!(
        imported_allows
            .contains("imported from Claude Code permissions.allow: Write, Edit, NotebookEdit(*)")
    );
    assert!(imported_allows.contains("net.fetch:example.com"));
    assert!(imported_allows.contains("net.search:web"));

    let settings_raw = fs::read_to_string(&settings).unwrap();
    assert!(
        settings_raw.find("\"language\"").unwrap() < settings_raw.find("\"permissions\"").unwrap()
    );
    assert!(
        settings_raw.find("\"permissions\"").unwrap() < settings_raw.find("\"hooks\"").unwrap()
    );
    assert!(
        settings_raw.find("\"hooks\"").unwrap() < settings_raw.find("\"enabledPlugins\"").unwrap()
    );

    let settings_json: serde_json::Value = serde_json::from_str(&settings_raw).unwrap();
    let pre_tool_use = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert_eq!(
        pre_tool_use[0].get("matcher").and_then(|v| v.as_str()),
        Some("*")
    );
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|v| v.as_str())
                == Some(bound_hook_command(&home, "claude").as_str()))
    );

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        doctor_check(&report, "pre_tool_use")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "allow_import")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        doctor_check(&report, "allow_import")
            .pointer("/details/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(9)
    );
}

#[test]
fn quickstart_defaults_to_strict_policy_and_skips_native_allows() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "permissions": {
    "allow": ["Bash", "Write"],
    "deny": ["Read(~/.ssh/id_*)"]
  }
}"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join("policy.d/05-claude-import.yaml").exists());
    for name in [
        "06-agent-config-writable.yaml",
        "90-claude-allow-import.yaml",
        "95-agent-catch-all.yaml",
    ] {
        assert!(!home.join("policy.d").join(name).exists(), "{name}");
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("agent posture: strict"));
    assert!(stdout.contains("native allow permissions remain outside strict"));
}

#[test]
fn quickstart_preserves_unrelated_claude_hooks_by_default() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/protect-files.sh" }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/guard-commands.sh" }
        ]
      },
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
        ]
      }
    ]
  }
}"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserving existing PreToolUse hook group(s)"));

    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let pre_tool_use = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();

    assert_eq!(pre_tool_use.len(), 3);
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("Edit|Write")
            && hook_group_contains_command(entry, "~/.claude/hooks/protect-files.sh")
    }));
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("Bash")
            && hook_group_contains_command(entry, "~/.claude/hooks/guard-commands.sh")
    }));
    assert!(pre_tool_use.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|hook| {
                hook.get("command").and_then(|v| v.as_str())
                    == Some(bound_hook_command(&home, "claude").as_str())
            })
    }));
    assert!(
        !pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, "GOMMAGE_BYPASS=1 gommage mcp"))
    );
}

#[test]
fn quickstart_can_install_daemon_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--daemon-no-start",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ok daemon: service installed but not started"));
    assert!(stdout.contains("ok quickstart complete"));

    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    let canonical_daemon = fs::canonicalize(&fake_daemon).unwrap();
    assert!(service.contains(&canonical_daemon.to_string_lossy().to_string()));

    let settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(
        settings
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry.get("matcher").and_then(|v| v.as_str()) == Some("*"))
    );
}

#[test]
fn quickstart_self_test_runs_verify_gate() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("self-test: checking recovery decisions"));
    assert!(stdout.contains("warn doctor:"));
    assert!(stdout.contains("pass smoke:"));
    assert!(stdout.contains("ok self-test complete"));
    assert!(stdout.contains("ok quickstart complete"));
}

#[test]
fn quickstart_self_test_runs_by_default() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("self-test: checking recovery decisions"));
    assert!(stdout.contains("ok self-test complete"));
}

#[test]
fn quickstart_no_self_test_skips_readiness_gate() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("ok quickstart complete"));
}

#[test]
fn quickstart_rolls_back_agent_config_when_self_test_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = r#"{
  "permissions": {
    "allow": ["Bash"],
    "deny": []
  }
}
"#;
    fs::write(&settings, original).unwrap();
    let policy_dir = home.join("policy.d");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::write(
        policy_dir.join("02-test-bad-gommage-deny.yaml"),
        r#"
- name: test-bad-gommage-deny
  decision: gommage
  match: { any_capability: ["proc.exec:gommage verify *"] }
  reason: "fixture intentionally breaks quickstart self-test"
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("self-test failed: gommage_verify expected allow"));
    assert!(stderr.contains("quickstart failed: restoring filesystem journal"));
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
    for path in [
        home.join("policy.d/05-claude-import.yaml"),
        home.join("policy.d/06-agent-config-writable.yaml"),
        home.join("policy.d/90-claude-allow-import.yaml"),
        home.join("policy.d/95-agent-catch-all.yaml"),
        home.join("AGENT_CONTEXT.md"),
        home.join("integration-report.json"),
    ] {
        assert!(!path.exists(), "rollback left {}", path.display());
    }
    assert!(
        fs::read_dir(settings.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".gommage-bak-"))
    );
}

#[test]
fn quickstart_preflights_harness_paths_before_agent_mutation_without_self_test() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\n  \"language\": \"spanish\"\n}\n";
    fs::write(&settings, original).unwrap();
    fs::create_dir_all(home.join("AGENT_CONTEXT.md")).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
    for name in [
        "05-claude-import.yaml",
        "06-agent-config-writable.yaml",
        "90-claude-allow-import.yaml",
        "95-agent-catch-all.yaml",
    ] {
        assert!(!home.join("policy.d").join(name).exists(), "{name}");
    }
    assert!(!home.join("key.ed25519").exists());
    assert!(!home.join("policy.d/00-hard-stops.yaml").exists());
    assert!(
        !home.join("capabilities.d").exists()
            || fs::read_dir(home.join("capabilities.d"))
                .unwrap()
                .next()
                .is_none()
    );
    assert!(
        fs::read_dir(settings.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".gommage-bak-"))
    );
}

#[test]
fn quickstart_late_failure_restores_a_fresh_home_completely() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let org_policy = temp.path().join("org-policy");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&org_policy).unwrap();
    let original = "{\n  \"language\": \"spanish\"\n}\n";
    fs::write(&settings, original).unwrap();
    fs::write(
        org_policy.join("00-break-self-test.yaml"),
        r#"
- name: test-org-deny-gommage-verify
  decision: gommage
  match: { any_capability: ["proc.exec:gommage verify *"] }
  reason: "fixture intentionally breaks a late quickstart gate"
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_ORG_POLICY_DIR", &org_policy)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("quickstart failed: restoring filesystem journal")
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
    assert!(!home.exists(), "fresh quickstart home survived rollback");
    assert!(
        fs::read_dir(settings.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".gommage-bak-"))
    );
}

#[test]
fn quickstart_rollback_never_rewrites_existing_runtime_evidence() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(&settings, "{}").unwrap();
    let existing_picto_bytes = b"operator-owned-runtime-evidence\n";
    let existing_audit_bytes = b"existing-signed-audit-evidence\n";
    fs::write(home.join("pictos.sqlite"), existing_picto_bytes).unwrap();
    fs::write(home.join("audit.log"), existing_audit_bytes).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(
        fs::read(home.join("pictos.sqlite")).unwrap(),
        existing_picto_bytes
    );
    assert_eq!(
        fs::read(home.join("audit.log")).unwrap(),
        existing_audit_bytes
    );
}

#[test]
#[cfg(unix)]
fn quickstart_recovers_service_manager_after_crash_between_start_and_commit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude/settings.json");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    let active_state = temp.path().join("active-state");
    let enabled_state = temp.path().join("enabled-state");
    let killed_once = temp.path().join("killed-once");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&settings, "{\n  \"language\": \"spanish\"\n}\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_ACTIVE_STATE" ]; then printf 'active\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'inactive\n'; exit 3
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLED_STATE" ]; then printf 'enabled\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'disabled\n'; exit 1
    ;;
  daemon-reload) exit 0 ;;
  enable) : > "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  disable) rm -f "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  stop) rm -f "$GOMMAGE_ACTIVE_STATE"; exit 0 ;;
  start)
    : > "$GOMMAGE_ACTIVE_STATE"
    if [ ! -e "$GOMMAGE_KILLED_ONCE" ]; then
      : > "$GOMMAGE_KILLED_ONCE"
      kill -9 "$PPID"
    fi
    exit 0
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let command = || {
        let mut command = gommage(&home);
        command
            .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("GOMMAGE_ACTIVE_STATE", &active_state)
            .env("GOMMAGE_ENABLED_STATE", &enabled_state)
            .env("GOMMAGE_KILLED_ONCE", &killed_once)
            .env("GOMMAGE_SERVICE_FILE", &service_file)
            .env("PATH", &path);
        command
    };

    let crashed = command()
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--no-self-test",
            "--daemon",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();
    assert!(!crashed.status.success());
    assert!(active_state.exists(), "fake service never reached start");
    assert!(enabled_state.exists(), "fake service was never enabled");
    assert!(
        temp.path()
            .join(".gommage.gommage-install-journal/manifest.json")
            .is_file(),
        "crash did not leave the durable journal"
    );

    let recovered = command()
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(
        !service_file.exists(),
        "recovery retained the attempted unit"
    );
    assert!(
        !active_state.exists(),
        "recovery retained the attempted process"
    );
    assert!(
        !enabled_state.exists(),
        "recovery retained attempted enablement"
    );
    assert!(
        !temp
            .path()
            .join(".gommage.gommage-install-journal")
            .exists(),
        "recovery did not close the interrupted journal"
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user stop gommage-daemon.service\n"));
    assert!(calls.contains("--user disable gommage-daemon.service\n"));
}

#[test]
#[cfg(unix)]
fn quickstart_compensates_service_when_journal_fails_after_start() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude/settings.json");
    let original_settings = "{\n  \"language\": \"spanish\"\n}\n";
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let journal = temp.path().join(".gommage.gommage-install-journal");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    let active_state = temp.path().join("active-state");
    let enabled_state = temp.path().join("enabled-state");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&settings, original_settings).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    let ready_daemon = start_fake_ready_daemon(&home);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_ACTIVE_STATE" ]; then printf 'active\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'inactive\n'; exit 3
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLED_STATE" ]; then printf 'enabled\n'; exit 0; fi
    if [ ! -e "$GOMMAGE_SERVICE_FILE" ]; then printf 'not-found\n'; exit 4; fi
    printf 'disabled\n'; exit 1
    ;;
  daemon-reload) exit 0 ;;
  enable) : > "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  disable) rm -f "$GOMMAGE_ENABLED_STATE"; exit 0 ;;
  start)
    : > "$GOMMAGE_ACTIVE_STATE"
    chmod 0500 "$GOMMAGE_INSTALL_JOURNAL"
    exit 0
    ;;
  stop)
    rm -f "$GOMMAGE_ACTIVE_STATE"
    chmod 0700 "$GOMMAGE_INSTALL_JOURNAL"
    exit 0
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_ACTIVE_STATE", &active_state)
        .env("GOMMAGE_ENABLED_STATE", &enabled_state)
        .env("GOMMAGE_SERVICE_FILE", &service_file)
        .env("GOMMAGE_INSTALL_JOURNAL", &journal)
        .env("PATH", path)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--no-self-test",
            "--daemon",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();
    ready_daemon.finish();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("journaling daemon runtime activation"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), original_settings);
    assert!(
        !service_file.exists(),
        "rollback retained the attempted unit"
    );
    assert!(
        !active_state.exists(),
        "rollback retained the attempted process"
    );
    assert!(!enabled_state.exists(), "rollback retained enablement");
    assert!(!journal.exists(), "rollback did not close its journal");
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user stop gommage-daemon.service\n"));
    assert!(calls.contains("--user disable gommage-daemon.service\n"));
}

#[test]
fn quickstart_self_test_dry_run_only_prints_plan() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--self-test",
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(
        "plan self-test: run `gommage verify` and recovery decision checks after quickstart"
    ));
    assert!(stdout.contains("ok quickstart complete"));
    assert!(!home.exists());
    assert!(!settings.exists());
}

#[test]
fn quickstart_dry_run_json_reports_plan_without_writes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    let original_settings = r#"{
  "permissions": {
    "allow": ["Bash(git status *)"],
    "deny": ["Read(./secrets/**)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/guard-commands.sh" }
        ]
      },
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
        ]
      }
    ]
  }
}
"#;
    fs::write(&settings, original_settings).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--daemon",
            "--daemon-manager",
            "systemd",
            "--daemon-no-start",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("plan")
    );
    assert_eq!(
        report.get("dry_run").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        report.get("home").and_then(|value| value.as_str()),
        Some(home.to_str().unwrap())
    );
    assert!(
        report
            .pointer("/stdlib/policies")
            .and_then(|value| value.as_array())
            .unwrap()
            .len()
            >= 8
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/agent")
            .and_then(|value| value.as_str()),
        Some("claude")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/matcher")
            .and_then(|value| value.as_str()),
        Some("*")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/strategy")
            .and_then(|value| value.as_str()),
        Some("append_preserving_unrelated")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/preserved_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/removed_gommage_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/removed_unrelated_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_groups/0/action")
            .and_then(|value| value.as_str()),
        Some("would_preserve")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_groups/1/action")
            .and_then(|value| value.as_str()),
        Some("would_remove_stale_gommage")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/native_permissions/deny/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/native_permissions/allow/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/native_permissions/allow/action")
            .and_then(|value| value.as_str()),
        Some("skipped_disabled")
    );
    assert_eq!(
        report
            .get("policy_posture")
            .and_then(|value| value.as_str()),
        Some("strict")
    );
    assert_eq!(
        report
            .pointer("/daemon/manager")
            .and_then(|value| value.as_str()),
        Some("systemd")
    );
    assert_eq!(
        report
            .pointer("/daemon/no_start")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        report
            .pointer("/daemon/daemon_binary")
            .and_then(|value| value.as_str()),
        Some(fs::canonicalize(&fake_daemon).unwrap().to_str().unwrap())
    );
    assert_eq!(
        report
            .pointer("/self_test/enabled")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        report
            .pointer("/explanation/installation_mode")
            .and_then(|value| value.as_str()),
        Some("coexistence")
    );
    assert!(
        report
            .pointer("/explanation/agent_guidance/0/operator_notes")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("permissions.allow remains outside")))
    );
    assert_eq!(
        report
            .pointer("/explanation/context_files/0")
            .and_then(|value| value.as_str()),
        Some(home.join("AGENT_CONTEXT.md").to_str().unwrap())
    );
    let operations = report
        .get("operations")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(operations.iter().any(|operation| {
        operation.get("kind").and_then(|value| value.as_str()) == Some("agent_config")
            && operation.get("path").and_then(|value| value.as_str())
                == Some(settings.to_str().unwrap())
            && operation
                .get("backup_before_replace")
                .and_then(|value| value.as_bool())
                == Some(true)
    }));

    assert!(!home.exists());
    assert!(!systemd.join("gommage-daemon.service").exists());
    assert_eq!(fs::read_to_string(&settings).unwrap(), original_settings);
}

#[test]
fn quickstart_json_blocks_when_explicit_daemon_binary_is_missing() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let systemd = temp.path().join("systemd-user");
    let missing_daemon = temp.path().join("missing").join("gommage-daemon");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &missing_daemon)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--daemon",
            "--daemon-manager",
            "systemd",
            "--daemon-no-start",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("blocked"));
    assert_eq!(report["execution_ready"].as_bool(), Some(false));
    assert!(report["daemon"]["daemon_binary"].is_null());
    assert!(
        report["daemon"]["daemon_binary_error"]
            .as_str()
            .is_some_and(|error| error.contains("is unavailable"))
    );
    assert!(!home.exists());
    assert!(!systemd.exists());
}

#[test]
fn quickstart_preflights_missing_daemon_binary_before_writes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let systemd = temp.path().join("systemd-user");
    let missing_daemon = temp.path().join("missing").join("gommage-daemon");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\n  \"language\": \"spanish\"\n}\n";
    fs::write(&settings, original).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &missing_daemon)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--daemon",
            "--daemon-manager",
            "systemd",
            "--daemon-no-start",
            "--no-self-test",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
    assert!(!home.exists());
    assert!(!systemd.exists());
}

#[test]
fn quickstart_dry_run_json_reports_codex_hook_coexistence() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    let original_hooks = r#"{
  "PreToolUse": [
    {
      "matcher": "apply_patch",
      "hooks": [
        { "type": "command", "command": "~/.codex/hooks/patch-audit.sh" }
      ]
    },
    {
      "matcher": "*",
      "hooks": [
        { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
      ]
    }
  ]
}
"#;
    fs::write(&hooks, original_hooks).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["quickstart", "--agent", "codex", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report
            .pointer("/agent_integrations/0/agent")
            .and_then(|value| value.as_str()),
        Some("codex")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/strategy")
            .and_then(|value| value.as_str()),
        Some("append_preserving_unrelated")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/matcher")
            .and_then(|value| value.as_str()),
        Some("*")
    );
    let coverage = report
        .pointer("/explanation/agent_guidance/0/default_coverage")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(coverage, vec!["all PreToolUse tool calls"]);
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/preserved_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/removed_gommage_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_groups/0/action")
            .and_then(|value| value.as_str()),
        Some("would_preserve")
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_groups/1/action")
            .and_then(|value| value.as_str()),
        Some("would_remove_stale_gommage")
    );
    assert!(!home.exists());
    assert_eq!(fs::read_to_string(&hooks).unwrap(), original_hooks);
    assert!(!config.exists());
}

#[test]
fn quickstart_dry_run_json_reports_nested_codex_hook_coexistence() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    let original_hooks = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "apply_patch",
        "hooks": [
          { "type": "command", "command": "~/.codex/hooks/patch-audit.sh" }
        ]
      },
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
        ]
      }
    ]
  }
}
"#;
    fs::write(&hooks, original_hooks).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["quickstart", "--agent", "codex", "--dry-run", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/existing_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/preserved_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/agent_integrations/0/hook/removed_gommage_hook_group_count")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(fs::read_to_string(&hooks).unwrap(), original_hooks);
    assert!(!config.exists());
}

#[test]
fn quickstart_dry_run_explain_prints_harness_guidance() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--dry-run", "--explain"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("explain mode: coexistence"));
    assert!(stdout.contains("explain claude hooks: strategy=append_preserving_unrelated"));
    assert!(stdout.contains("explain claude: posture="));
    assert!(stdout.contains("next: gommage harness diagnose --json"));
    assert!(stdout.contains("plan harness-context"));
    assert!(!home.exists());
}

#[test]
fn quickstart_writes_agent_context_files() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ok harness context"));

    let context = fs::read_to_string(home.join("AGENT_CONTEXT.md")).unwrap();
    assert!(context.contains("# Gommage Local Integration Context"));
    assert!(context.contains("Default install mode"));

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join("integration-report.json")).unwrap())
            .unwrap();
    assert_eq!(
        report
            .pointer("/agents/0/agent")
            .and_then(|value| value.as_str()),
        Some("claude")
    );
}

#[test]
fn generated_native_deny_import_is_refreshed_and_removed_when_source_changes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"permissions":{"deny":["Read(./old-sensitive/**)"]}}"#,
    )
    .unwrap();

    let first = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let import_path = home.join("policy.d/05-claude-import.yaml");
    assert!(
        fs::read_to_string(&import_path)
            .unwrap()
            .contains("old-sensitive")
    );

    fs::write(
        &settings,
        r#"{"permissions":{"deny":["Read(./new-sensitive/**)"]}}"#,
    )
    .unwrap();
    let stale_status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();
    let stale_report: serde_json::Value = serde_json::from_slice(&stale_status.stdout).unwrap();
    assert!(!stale_status.status.success());
    assert_eq!(
        doctor_check(&stale_report, "deny_import")["status"].as_str(),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&stale_report, "deny_import")
            .pointer("/details/content_state")
            .and_then(|value| value.as_str()),
        Some("stale_generated")
    );

    let refreshed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    let imported = fs::read_to_string(&import_path).unwrap();
    assert!(imported.contains("new-sensitive"));
    assert!(!imported.contains("old-sensitive"));
    assert!(imported.contains("# Generated content SHA-256:"));

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        doctor_check(&report, "deny_import")
            .pointer("/details/content_state")
            .and_then(|value| value.as_str()),
        Some("current")
    );

    fs::write(&settings, r#"{"permissions":{"deny":[]}}"#).unwrap();
    let removed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(!import_path.exists());
    assert!(
        fs::read_dir(home.join("policy.d"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("05-claude-import.yaml.gommage-bak-"))
    );
}

#[test]
fn modified_generated_posture_blocks_before_any_agent_config_write() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();

    let relaxed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--relaxed",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(relaxed.status.success());
    let settings_before = fs::read(&settings).unwrap();
    let catch_all = home.join("policy.d/95-agent-catch-all.yaml");
    let mut modified = fs::read_to_string(&catch_all).unwrap();
    modified.push_str(
        "\n- name: operator-owned-extra\n  decision: allow\n  match:\n    any_capability: [\"custom:**\"]\n",
    );
    fs::write(&catch_all, &modified).unwrap();

    let failed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("custom or modified"));
    assert_eq!(fs::read(&settings).unwrap(), settings_before);
    assert_eq!(fs::read_to_string(&catch_all).unwrap(), modified);
}

#[test]
fn relaxed_install_does_not_overwrite_a_custom_reserved_policy() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    let reserved = home.join("policy.d/06-agent-config-writable.yaml");
    let custom = "# operator-owned\n[]\n";
    fs::write(&reserved, custom).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--relaxed",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&reserved).unwrap(), custom);
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
}

#[test]
fn digestless_legacy_import_requires_review_and_is_not_removed() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"permissions":{"deny":[]}}"#).unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    let import_path = home.join("policy.d/05-claude-import.yaml");
    let legacy_modified = r#"# Generated by `gommage quickstart` from Claude Code permissions.deny.
# Review before sharing; native permission syntax is broader than Gommage capabilities.
# Deny imports live before stdlib allow rules so native blocks remain fail-closed.

- name: claude-import-deny-01
  decision: gommage
  match:
    any_capability:
      - "proc.exec:operator-deny"
  reason: "imported from Claude Code permissions.deny: operator hardening"
"#;
    fs::write(&import_path, legacy_modified).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("custom or modified"));
    assert_eq!(fs::read_to_string(&import_path).unwrap(), legacy_modified);
    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        r#"{"permissions":{"deny":[]}}"#
    );
}

#[test]
fn quickstart_json_marks_custom_reserved_policy_as_blocked() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    fs::write(
        home.join("policy.d/95-agent-catch-all.yaml"),
        "# operator-owned\n[]\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("blocked"));
    assert_eq!(report["execution_ready"].as_bool(), Some(false));
    assert!(
        report["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| { operation["action"].as_str() == Some("custom_requires_review") })
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
}

#[test]
fn agent_install_rolls_back_prior_writes_when_a_later_config_write_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let combined_config = temp.path().join("codex").join("combined-config");
    fs::create_dir_all(combined_config.parent().unwrap()).unwrap();
    let original = "";
    fs::write(&combined_config, original).unwrap();

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
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rolled back"));
    assert_eq!(fs::read_to_string(&combined_config).unwrap(), original);
    assert!(!home.exists());
    assert!(
        !fs::read_dir(combined_config.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("combined-config.gommage-bak-"))
    );
}
