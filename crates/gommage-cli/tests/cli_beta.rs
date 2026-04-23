mod support;

use std::fs;

use support::{gommage, workspace_path};
use tempfile::tempdir;

#[test]
fn beta_check_json_preinit_points_to_quickstart() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .args(["beta", "check", "--json"])
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
            .pointer("/checks/0/name")
            .and_then(|value| value.as_str()),
        Some("doctor")
    );
    assert_eq!(
        report
            .pointer("/checks/1/status")
            .and_then(|value| value.as_str()),
        Some("skip")
    );
    assert!(
        report
            .get("next")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .unwrap()
                    .contains("gommage quickstart --agent claude --daemon --self-test")
            })
    );
}

#[test]
fn beta_check_reports_initialized_host_with_policy_fixture() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");
    let fixture = temp.path().join("policy-fixtures.yaml");
    fs::write(
        &fixture,
        r#"version: 1
cases:
  - name: ask_main_push
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: ask_picto
      required_scope: git.push:main
      matched_rule: gate-main-push
"#,
    )
    .unwrap();

    assert!(
        gommage(&home)
            .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
            .args(["quickstart", "--agent", "claude", "--no-self-test"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .args([
            "beta",
            "check",
            "--json",
            "--policy-test",
            fixture.to_str().unwrap(),
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
        Some("warn")
    );
    assert!(
        report
            .get("checks")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|check| {
                check.get("name").and_then(|value| value.as_str()) == Some("agent claude")
                    && check.get("status").and_then(|value| value.as_str()) == Some("pass")
            })
    );
    assert!(
        report
            .get("checks")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|check| {
                check
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap()
                    .starts_with("policy fixture")
                    && check.get("status").and_then(|value| value.as_str()) == Some("pass")
            })
    );
}

#[test]
fn beta_check_accepts_public_fixture_library() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");
    let fixture = workspace_path("examples/policy-fixtures.yaml");

    assert!(
        gommage(&home)
            .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
            .args(["quickstart", "--agent", "claude", "--no-self-test"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .args([
            "beta",
            "check",
            "--json",
            "--policy-test",
            fixture.to_str().unwrap(),
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
        Some("warn")
    );
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["name"].as_str().unwrap().starts_with("policy fixture")
                    && check["status"].as_str() == Some("pass")
                    && check["message"]
                        .as_str()
                        .unwrap()
                        .contains("7 passed, 0 failed")
            })
    );
}

#[test]
fn beta_check_human_output_is_plain_and_actionable() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["beta", "check"]).output().unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage beta readiness"));
    assert!(stdout.contains("status: fail"));
    assert!(stdout.contains("checks:"));
    assert!(stdout.contains("- doctor [fail]"));
    assert!(stdout.contains("next:"));
    assert!(stdout.contains("gommage quickstart --agent claude --daemon --self-test"));
    assert!(!stdout.contains("\x1b["));
}
