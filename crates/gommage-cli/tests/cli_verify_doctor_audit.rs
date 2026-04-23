mod support;

use std::{fs, io::Write, process::Stdio};
use support::{doctor_check, gommage, workspace_path};
use tempfile::tempdir;

#[test]
fn verify_json_reports_doctor_smoke_and_policy_tests() {
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

    let output = gommage(&home)
        .args([
            "verify",
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
    assert_eq!(
        report
            .pointer("/doctor/status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        report
            .pointer("/smoke/status")
            .and_then(|value| value.as_str()),
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/policy_tests/0/status")
            .and_then(|value| value.as_str()),
        Some("pass")
    );
}

#[test]
fn verify_exits_nonzero_when_policy_test_fails() {
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
        .args([
            "verify",
            "--json",
            "--policy-test",
            fixture.to_str().unwrap(),
        ])
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
            .pointer("/summary/failures")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
}

#[test]
fn verify_json_accepts_public_fixture_library() {
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
    let fixture = workspace_path("examples/policy-fixtures.yaml");

    let output = gommage(&home)
        .args([
            "verify",
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
        report
            .pointer("/policy_tests/0/status")
            .and_then(|value| value.as_str()),
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/policy_tests/0/report/summary/passed")
            .and_then(|value| value.as_u64()),
        Some(7)
    );
}

#[test]
fn verify_json_preinit_reports_hint_and_skips_smoke() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["verify", "--json"]).output().unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        report.get("hint").and_then(|value| value.as_str()),
        Some("run 'gommage init' or 'gommage quickstart' first")
    );
    assert_eq!(
        report
            .pointer("/summary/failures")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report
            .pointer("/smoke/status")
            .and_then(|value| value.as_str()),
        Some("skip")
    );
    assert!(
        report
            .pointer("/smoke/error")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("skipped: doctor failed")
    );
}

#[test]
fn verify_human_preinit_prints_hint_next_steps_and_no_ansi() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).arg("verify").output().unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage verify"));
    assert!(stdout.contains("status: fail"));
    assert!(stdout.contains("hint: run 'gommage init' or 'gommage quickstart' first"));
    assert!(stdout.contains("fail doctor:"));
    assert!(stdout.contains("skip smoke: skipped: doctor failed"));
    assert!(stdout.contains("summary: 1 failure(s), 0 warning(s), 0 policy test file(s)"));
    assert!(stdout.contains("gommage quickstart --agent claude --daemon --self-test"));
    assert!(stdout.contains("gommage tui --snapshot"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn verify_human_initialized_keeps_readable_section_lines() {
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

    let output = gommage(&home).arg("verify").output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage verify"));
    assert!(stdout.contains("status: warn"));
    assert!(stdout.contains("warn doctor:"));
    assert!(stdout.contains("pass smoke:"));
    assert!(stdout.contains("summary: 0 failure(s),"));
    assert!(stdout.contains("gommage doctor --json"));
    assert!(!stdout.contains("\x1b["));
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
    let decision_line = audit
        .lines()
        .find(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| value.get("tool").cloned())
                .is_some()
        })
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(decision_line).unwrap();
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
fn audit_verify_explain_human_prints_forensic_summary() {
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

    let output = gommage(&home)
        .args(["audit-verify", "--explain", "--format", "human"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("audit verification report"));
    assert!(stdout.contains("status: ok"));
    assert!(stdout.contains("entries:"));
    assert!(stdout.contains("verified"));
    assert!(stdout.contains("key_fingerprint:"));
    assert!(stdout.contains("policy_versions:"));
    assert!(stdout.contains("bypass_activations: 0"));
    assert!(stdout.contains("anomalies: none"));

    let output = gommage(&home)
        .args(["audit-verify", "--explain"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("policy_versions").is_some());
    assert!(report.get("expeditions").is_some());
    assert!(report.get("policy_versions_seen").is_none());
    assert!(report.get("expeditions_seen").is_none());
    assert_eq!(
        report
            .get("bypass_activations")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
}

#[test]
fn audit_verify_format_requires_explain() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["audit-verify", "--format", "human"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--explain"));
}
