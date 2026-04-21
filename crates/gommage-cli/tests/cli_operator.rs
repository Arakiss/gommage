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
        Some("Bash|Read|MultiEdit")
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
