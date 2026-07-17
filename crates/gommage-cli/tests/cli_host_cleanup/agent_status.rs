use super::*;

#[test]
fn agent_install_codex_writes_hook_and_enables_feature_flag() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\nfeatures = { foo = true }\n",
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
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert!(
        hooks_json
            .pointer("/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry
                .get("hooks")
                .and_then(|v| v.as_array())
                .unwrap()
                .iter()
                .any(|hook| hook.get("command").and_then(|v| v.as_str())
                    == Some(bound_hook_command(&home, "codex").as_str())))
    );
    let config = fs::read_to_string(config).unwrap();
    assert!(config.contains("hooks = true"));
    assert!(!config.contains("codex_hooks = true"));
    assert!(config.contains("foo = true"));

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env(
            "GOMMAGE_CODEX_CONFIG",
            temp.path().join("codex").join("config.toml"),
        )
        .args(["agent", "status", "codex", "--json"])
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
        doctor_check(&report, "codex_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "hook_home")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
}

#[test]
fn agent_status_fails_when_codex_hook_home_drifts() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[features]\nhooks = true\n").unwrap();

    let install = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "install", "codex"])
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );

    let mut hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let command = hooks_json
        .pointer_mut("/PreToolUse/0/hooks/0/command")
        .unwrap();
    *command = serde_json::Value::String(
        "gommage --home '/tmp/different-gommage-home' hook --agent codex".to_string(),
    );
    fs::write(&hooks, serde_json::to_vec_pretty(&hooks_json).unwrap()).unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();
    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let check = doctor_check(&report, "hook_home");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        check
            .pointer("/details/expected_command")
            .and_then(|value| value.as_str()),
        Some(bound_hook_command(&home, "codex").as_str())
    );
}

#[test]
fn agent_status_warns_for_legacy_codex_hook_feature_flag() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
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
    let check = doctor_check(&report, "codex_hooks");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("warn")
    );
    assert!(
        check
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("legacy features.codex_hooks")
    );
}

#[test]
fn agent_status_fails_when_claude_hook_is_not_global() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch","hooks":[{"type":"command","command":"gommage-mcp"}]}]}}"#,
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    let check = doctor_check(&report, "hook_coverage");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert!(
        check
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
}

#[test]
fn agent_status_fails_when_codex_hook_is_not_global() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"^Bash$|^apply_patch$","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    let check = doctor_check(&report, "hook_coverage");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert!(
        check
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
}

#[test]
fn agent_status_codex_fails_on_narrow_nested_legacy_wrapper_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*","hooks":[{"type":"command","command":"GOMMAGE_MCP_BIN=\"$(command -v gommage-mcp)\" \"$HOME/.codex/hooks/gommage-codex-pretooluse.sh\""}]}]}}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&report, "pre_tool_use")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert!(
        doctor_check(&report, "hook_coverage")
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
    assert_eq!(
        doctor_check(&report, "hook_coverage")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&report, "legacy_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
}

#[test]
fn agent_install_codex_preserves_unrelated_hooks_by_default() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{
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
}"#,
    )
    .unwrap();
    fs::write(&config, "sandbox_mode = \"workspace-write\"\n").unwrap();

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
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserving existing PreToolUse hook group(s)"));

    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();

    assert_eq!(pre_tool_use.len(), 2);
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("apply_patch")
            && hook_group_contains_command(entry, "~/.codex/hooks/patch-audit.sh")
    }));
    assert!(
        pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, &bound_hook_command(&home, "codex")))
    );
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("*")
            && hook_group_contains_command(entry, &bound_hook_command(&home, "codex"))
    }));
    assert!(
        !pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, "GOMMAGE_BYPASS=1 gommage mcp"))
    );
    assert!(fs::read_to_string(config).unwrap().contains("hooks = true"));
}
