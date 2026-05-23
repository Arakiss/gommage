mod support;

use std::fs;
use support::gommage;
use tempfile::tempdir;

#[test]
fn harness_diagnose_json_reports_existing_claude_setup_without_installing() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "permissions": {
    "allow": ["Bash", "Read(./docs/**)"],
    "deny": ["Read(./secrets/**)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/tmp/guard-commands.sh" }
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
        .args(["harness", "diagnose", "--agent", "claude", "--json"])
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
        report
            .pointer("/agents/0/existing_hooks_detected")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        report
            .pointer("/agents/0/native_permissions/allow/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        report
            .pointer("/agents/0/native_permissions/allow/broad_allow_entries/0")
            .and_then(|value| value.as_str()),
        Some("Bash")
    );
    assert!(!home.exists());
}

#[test]
fn harness_explain_prints_agent_context_markdown() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(&hooks, "{}").unwrap();
    fs::write(&config, "sandbox_mode = \"workspace-write\"\n").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["harness", "explain", "--agent", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("# Gommage Local Integration Context"));
    assert!(stdout.contains("Codex sandbox remains authoritative"));
    assert!(stdout.contains("apply_patch"));
    assert!(stdout.contains("mapped"));
    assert!(!stdout.contains("not default-wired"));
}

#[test]
fn harness_write_context_dry_run_does_not_mutate_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["harness", "write-context", "--agent", "claude", "--dry-run"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan harness context"));
    assert!(!home.join("AGENT_CONTEXT.md").exists());
    assert!(!home.join("integration-report.json").exists());
}
