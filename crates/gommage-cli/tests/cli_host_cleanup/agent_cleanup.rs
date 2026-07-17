use super::*;

#[test]
fn agent_uninstall_claude_removes_only_gommage_hook() {
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
        "matcher": "Bash|Read",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
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
        .args(["agent", "uninstall", "claude"])
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
    assert_eq!(pre_tool_use.len(), 1);
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|value| value.as_str())
                == Some("/tmp/protect-files.sh"))
    );
}

#[test]
fn agent_uninstall_preserves_non_gommage_commands_inside_a_mixed_group() {
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
        .args(["agent", "uninstall", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let hooks = settings_json
        .pointer("/hooks/PreToolUse/0/hooks")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(hooks.len(), 3);
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("/tmp/protect-files.sh")
    }));
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("echo gommage")
    }));
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str)
            == Some("gommage hook --agent claude && /tmp/operator-command")
    }));
    assert!(!hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("gommage-mcp")
    }));
}

#[test]
fn agent_uninstall_claude_can_restore_latest_valid_backup() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\n  \"language\": \"spanish\"\n}\n";
    fs::write(&settings, original).unwrap();
    fs::write(
        settings.with_file_name("settings.json.gommage-bak-100"),
        original,
    )
    .unwrap();
    fs::write(
        settings.with_file_name("settings.json.gommage-bak-not-a-timestamp"),
        "{}\n",
    )
    .unwrap();
    fs::write(
        &settings,
        r#"{
  "language": "spanish",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
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
        .args(["agent", "uninstall", "claude", "--restore-backup"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
}

#[test]
fn agent_uninstall_dry_run_uses_plan_language_without_mutating() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\ncodex_hooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "all", "--dry-run"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan claude: remove"));
    assert!(stdout.contains("plan codex: remove"));
    assert!(stdout.contains("plan codex: preserve shared Codex hook feature flags"));
    assert!(!stdout.contains("ok claude: removed"));
    assert!(!stdout.contains("ok codex: removed"));
    assert!(!stdout.contains("ok codex: disabled"));
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("gommage-mcp")
    );
    assert!(fs::read_to_string(&hooks).unwrap().contains("gommage-mcp"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("codex_hooks = true")
    );
}

#[test]
fn agent_uninstall_codex_leaves_feature_flag_without_gommage_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(&hooks, r#"{"PreToolUse":[]}"#).unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("no Gommage hook found"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
}

#[test]
fn agent_uninstall_codex_keeps_feature_flag_when_other_hooks_remain() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]},{"matcher":"Bash","hooks":[{"type":"command","command":"/tmp/protect-files.sh"}]}]}"#,
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
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed 1 Gommage hook group"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert!(hook_group_contains_command(
        &pre_tool_use[0],
        "/tmp/protect-files.sh"
    ));
}

#[test]
fn agent_uninstall_codex_keeps_shared_feature_flag_after_removing_last_file_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(&config, "[features]\nhooks = true\ncodex_hooks = true\n").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        hooks_json
            .pointer("/PreToolUse")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .len(),
        0
    );
    let config_text = fs::read_to_string(&config).unwrap();
    assert!(config_text.contains("hooks = true"));
    assert!(config_text.contains("codex_hooks = true"));
}

#[test]
fn agent_uninstall_codex_removes_nested_gommage_hook() {
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
          { "type": "command", "command": "gommage-mcp" }
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
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed 1 Gommage hook group"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert!(hook_group_contains_command(
        &pre_tool_use[0],
        "/tmp/protect-files.sh"
    ));
}

#[test]
fn agent_uninstall_codex_keeps_feature_flag_for_non_pre_tool_hooks() {
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/tmp/preserve-stop-hook.sh" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();
    fs::write(&config, "[features]\nhooks = true\n").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        hooks_json
            .pointer("/hooks/PreToolUse")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .len(),
        0
    );
    assert!(hook_group_contains_command(
        hooks_json.pointer("/hooks/Stop/0").unwrap(),
        "/tmp/preserve-stop-hook.sh"
    ));
}
