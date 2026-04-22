use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};
use tempfile::tempdir;

fn gommage(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gommage"));
    cmd.env("GOMMAGE_HOME", home);
    cmd
}

fn doctor_check<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report
        .get("checks")
        .and_then(|checks| checks.as_array())
        .unwrap()
        .iter()
        .find(|check| check.get("name").and_then(|value| value.as_str()) == Some(name))
        .unwrap()
}

#[test]
fn mascot_plain_is_script_safe() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["mascot", "--plain"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gestral signature"));
    assert!(stdout.contains("Gommage Gestral"));
    assert!(stdout.contains("Gommage Teal #00B3A4"));
    assert!(stdout.contains("tool call -> typed capabilities -> signed audit"));
    assert!(stdout.contains("██████"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn mascot_compact_plain_is_single_line() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["mascot", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains("[Gestral]"));
    assert!(stdout.contains("GOMMAGE policy sentinel"));
    assert!(stdout.contains("signed audit"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn logo_alias_prints_the_same_signature() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["logo", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[Gestral]"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn grant_rejects_invalid_uses_without_panic() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());

    let output = gommage(&home)
        .args([
            "grant", "--scope", "test", "--uses", "0", "--ttl", "60", "--reason", "invalid",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid picto"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn grant_accepts_human_ttl_suffix() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());

    let output = gommage(&home)
        .args([
            "grant",
            "--scope",
            "git.push:main",
            "--uses",
            "1",
            "--ttl",
            "10m",
            "--reason",
            "test",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("granted"));
}

#[test]
fn policy_init_stdlib_installs_loadable_defaults() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home).args(["policy", "check"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("rules loaded"));
}

#[test]
fn smoke_json_reports_semantic_passes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home).args(["smoke", "--json"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert!(
        report
            .pointer("/summary/passed")
            .and_then(|value| value.as_u64())
            .unwrap()
            >= 7
    );
    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("ask_mcp_write")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("ask_picto")
    }));
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("allow_feature_push")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("allow")
    }));
}

#[test]
fn policy_test_json_reports_fixture_passes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    let fixture = temp.path().join("policy-fixtures.yaml");
    fs::write(
        &fixture,
        r#"version: 1
cases:
  - name: ask_main_push
    description: main branch pushes require a picto
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: ask_picto
      required_scope: git.push:main
      matched_rule: gate-main-push
  - name: allow_feature_push
    tool: Bash
    input:
      command: git push origin chore/test-branch
    expect:
      decision: allow
      matched_rule: allow-feature-push
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
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
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert!(
        report
            .get("cases")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|case| {
                case.get("name").and_then(|value| value.as_str()) == Some("ask_main_push")
                    && case
                        .pointer("/actual/kind")
                        .and_then(|value| value.as_str())
                        == Some("ask_picto")
                    && case
                        .pointer("/matched_rule/name")
                        .and_then(|value| value.as_str())
                        == Some("gate-main-push")
            })
    );
}

#[test]
fn policy_test_exits_nonzero_on_fixture_failure() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    let fixture = temp.path().join("policy-fixtures.yaml");
    fs::write(
        &fixture,
        r#"version: 1
cases:
  - name: wrong_main_push_expectation
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: allow
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert!(
        report
            .pointer("/cases/0/errors")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("expected decision allow"))
    );
}

#[test]
fn doctor_json_reports_missing_home_as_failure() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["doctor", "--json"]).output().unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert!(
        report
            .pointer("/summary/failures")
            .and_then(|value| value.as_u64())
            .unwrap()
            >= 1
    );
    assert_eq!(
        doctor_check(&report, "home")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("fail")
    );
}

#[test]
fn doctor_json_reports_initialized_home_with_warnings() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home).args(["doctor", "--json"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        report
            .pointer("/summary/failures")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert!(
        report
            .pointer("/summary/warnings")
            .and_then(|value| value.as_u64())
            .unwrap()
            >= 1
    );
    assert_eq!(
        doctor_check(&report, "policy")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert!(
        doctor_check(&report, "policy")
            .pointer("/details/rules")
            .and_then(|value| value.as_u64())
            .unwrap()
            > 0
    );
    assert_eq!(
        doctor_check(&report, "daemon")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
}

#[test]
fn explain_prints_structured_decision_for_exact_audit_id() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let mut child = gommage(&home)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
        )
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    let value: serde_json::Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    let id = value.get("id").and_then(|v| v.as_str()).unwrap();

    let output = gommage(&home).args(["explain", id]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("kind: decision"));
    assert!(stdout.contains("decision:"));
    assert!(stdout.contains("policy_version:"));
    assert!(stdout.contains("capabilities:"));
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
  "permissions": {
    "allow": ["Bash", "Read", "MultiEdit", "WebSearch"],
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
  }
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

    let settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let pre_tool_use = settings
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert_eq!(
        pre_tool_use[0].get("matcher").and_then(|v| v.as_str()),
        Some("Bash|Read|MultiEdit|WebSearch")
    );
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp"))
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
fn agent_install_codex_writes_hook_and_enables_feature_flag() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nfoo = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "install", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert!(
        hooks
            .pointer("/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry
                .get("hooks")
                .and_then(|v| v.as_array())
                .unwrap()
                .iter()
                .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp")))
    );
    let config = fs::read_to_string(config).unwrap();
    assert!(config.contains("codex_hooks = true"));
    assert!(config.contains("foo = true"));
}

#[test]
fn daemon_install_launchd_writes_plist_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "launchd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plist = fs::read_to_string(launchd.join("dev.gommage.daemon.plist")).unwrap();
    assert!(plist.contains("<string>dev.gommage.daemon</string>"));
    assert!(plist.contains("<string>--foreground</string>"));
    assert!(plist.contains("<string>--home</string>"));
    assert!(plist.contains(&home.to_string_lossy().to_string()));
    assert!(plist.contains(&fake_daemon.to_string_lossy().to_string()));
}

#[test]
fn daemon_install_systemd_writes_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "systemd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("Description=Gommage policy daemon"));
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    assert!(service.contains(&fake_daemon.to_string_lossy().to_string()));
}
