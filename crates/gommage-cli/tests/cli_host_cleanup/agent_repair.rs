use super::*;

#[test]
fn repair_agent_claude_replaces_legacy_gommage_hook() {
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
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/tmp/protect-files.sh" }
        ]
      },
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/gommage mcp --old" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["repair", "agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let pre_tool_use = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 2);
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("/tmp/protect-files.sh")
    );
    assert!(
        !serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("gommage mcp --old")
    );
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains(&bound_hook_command(&home, "claude"))
    );
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("\"matcher\":\"*\"")
    );
}

#[test]
fn repair_agent_preserves_mixed_group_commands_and_gommage_text_false_positives() {
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" },
          { "type": "command", "command": "/tmp/protect-files.sh" },
          { "type": "command", "command": "echo gommage" },
          { "type": "command", "command": "gommage hook --agent claude && /tmp/operator-command" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["repair", "agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let groups = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(groups.len(), 2);
    let mixed = groups
        .iter()
        .find(|group| hook_group_contains_command(group, "/tmp/protect-files.sh"))
        .unwrap();
    assert!(hook_group_contains_command(mixed, "echo gommage"));
    assert!(hook_group_contains_command(
        mixed,
        "gommage hook --agent claude && /tmp/operator-command"
    ));
    assert!(!hook_group_contains_command(mixed, "gommage-mcp"));
    assert!(
        groups.iter().any(|group| {
            hook_group_contains_command(group, &bound_hook_command(&home, "claude"))
        })
    );
}

#[test]
fn repair_agent_codex_dry_run_does_not_mutate_legacy_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"GOMMAGE_BYPASS=1 gommage mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = false\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["repair", "agent", "codex", "--dry-run"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan write"));
    assert!(stdout.contains("next codex"));
    assert!(fs::read_to_string(&hooks).unwrap().contains("gommage mcp"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("codex_hooks = false")
    );
}

#[test]
fn repair_agent_codex_preserves_nested_hooks_object() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/tmp/protect-files.sh" }
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
"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["repair", "agent", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert!(hooks_json.pointer("/PreToolUse").is_none());
    let pre_tool_use = hooks_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 2);
    assert!(
        pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, "/tmp/protect-files.sh"))
    );
    assert!(
        !serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("GOMMAGE_BYPASS=1 gommage mcp")
    );
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|value| value.as_str()) == Some("*")
            && hook_group_contains_command(entry, &bound_hook_command(&home, "codex"))
    }));
}

#[test]
fn agent_status_warns_on_legacy_and_global_gommage_hooks() {
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
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "gommage mcp --old" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
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
        Some("warn")
    );
    assert_eq!(
        doctor_check(&report, "legacy_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
    assert!(
        doctor_check(&report, "legacy_hooks")
            .pointer("/details/repair")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("gommage repair agent claude")
    );
}

#[test]
fn uninstall_all_dry_run_lists_every_surface() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    let systemd = temp.path().join("systemd-user");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_HOME", &claude_home)
        .args([
            "uninstall",
            "--all",
            "--dry-run",
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
    assert!(stdout.contains("plan remove"));
    assert!(stdout.contains("gommage-daemon.service"));
    assert!(stdout.contains("skills/gommage"));
    assert!(stdout.contains("gommage-mcp"));
    assert!(stdout.contains(home.to_string_lossy().as_ref()));
    assert!(!home.exists());
}

#[test]
fn uninstall_requires_yes_for_home_removal() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    fs::create_dir_all(&home).unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rerun with --yes"));
    assert!(home.exists());
}

#[test]
fn uninstall_removes_selected_local_surfaces() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(codex_home.join("skills/gommage")).unwrap();
    fs::create_dir_all(claude_home.join("skills/gommage")).unwrap();
    for name in ["gommage", "gommage-daemon", "gommage-mcp"] {
        fs::write(bin_dir.join(name), "").unwrap();
    }

    let output = gommage(&home)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_HOME", &claude_home)
        .args([
            "uninstall",
            "--binaries",
            "--skills",
            "--purge-home",
            "--yes",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists());
    assert!(!bin_dir.join("gommage").exists());
    assert!(!bin_dir.join("gommage-daemon").exists());
    assert!(!bin_dir.join("gommage-mcp").exists());
    assert!(!codex_home.join("skills/gommage").exists());
    assert!(!claude_home.join("skills/gommage").exists());
}

#[test]
fn uninstall_purge_home_preserves_unrecognized_entries() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    fs::create_dir_all(home.join("policy.d")).unwrap();
    fs::create_dir_all(home.join("capabilities.d")).unwrap();
    fs::write(home.join("key.ed25519"), [0_u8; 32]).unwrap();
    fs::write(home.join("operator-notes.txt"), "preserve me\n").unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home", "--yes"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserved home with unrecognized entries"));
    assert!(home.join("operator-notes.txt").exists());
    assert!(!home.join("key.ed25519").exists());
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("capabilities.d").exists());
}

#[test]
fn uninstall_rejects_unrecognized_custom_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("ordinary-data");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("keep.txt"), "keep me\n").unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home", "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not recognizably a Gommage home"));
    assert!(home.join("keep.txt").exists());
}

#[test]
fn uninstall_can_purge_known_backup_files_explicitly() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let skill_dir = codex_home.join("skills/gommage");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(settings.with_file_name("settings.json.gommage-bak-100"), "").unwrap();
    fs::write(hooks.with_file_name("hooks.json.gommage-bak-100"), "").unwrap();
    fs::write(config.with_file_name("config.toml.gommage-bak-100"), "").unwrap();
    fs::write(bin_dir.join("gommage.gommage-bak-100"), "").unwrap();
    fs::write(skill_dir.join("SKILL.md.gommage-bak-100"), "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .args(["uninstall", "--purge-backups"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !settings
            .with_file_name("settings.json.gommage-bak-100")
            .exists()
    );
    assert!(!hooks.with_file_name("hooks.json.gommage-bak-100").exists());
    assert!(
        !config
            .with_file_name("config.toml.gommage-bak-100")
            .exists()
    );
    assert!(!bin_dir.join("gommage.gommage-bak-100").exists());
    assert!(!skill_dir.join("SKILL.md.gommage-bak-100").exists());
}
