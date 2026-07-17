use super::*;

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
