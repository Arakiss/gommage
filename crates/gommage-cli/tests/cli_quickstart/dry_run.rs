use super::*;

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
