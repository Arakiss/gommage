use super::*;

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

    let output = gommage(&home)
        .args(["audit-verify", "--explain", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("policy_versions").is_some());
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

    let output = gommage(&home)
        .args(["audit-verify", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--explain"));
}

#[test]
fn audit_verify_json_rejects_human_format() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["audit-verify", "--explain", "--json", "--format", "human"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--json cannot be combined with --format human"));
}
