mod support;

use std::fs;
use support::{doctor_check, gommage};
use tempfile::tempdir;

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
        .args(["quickstart", "--agent", "claude", "--replace-hooks"])
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
        Some("Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch")
    );
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp"))
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
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "pre_tool_use")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "allow_import")
            .pointer("/details/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(9)
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
    assert!(service.contains(&fake_daemon.to_string_lossy().to_string()));

    let settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(
        settings
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry.get("matcher").and_then(|v| v.as_str()) == Some(
                "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*"
            ))
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
    assert!(stderr.contains("self-test failed: restoring agent configuration snapshots"));
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
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
    let original_settings = r#"{
  "permissions": {
    "allow": ["Bash(git status *)"],
    "deny": ["Read(./secrets/**)"]
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
    assert!(
        report
            .pointer("/agent_integrations/0/hook/matcher")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("Bash")
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
        Some(1)
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
        Some(fake_daemon.to_str().unwrap())
    );
    assert_eq!(
        report
            .pointer("/self_test/enabled")
            .and_then(|value| value.as_bool()),
        Some(true)
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
