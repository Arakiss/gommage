mod support;

use std::{fs, io::Write, process::Stdio};
use support::gommage;
use tempfile::tempdir;

#[test]
fn policy_test_json_reports_fixture_passes() {
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
    description: main branch pushes require a picto
    tool: Bash
    input:
      command: git push origin main
    expect:
      decision: ask_picto
      required_scope: git.push:main
      matched_rule: gate-main-push
  - name: allow_feature_push
    tool: Bash
    input:
      command: git push origin chore/test-branch
    expect:
      decision: allow
      matched_rule: allow-feature-push
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
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
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert!(
        report
            .get("cases")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|case| {
                case.get("name").and_then(|value| value.as_str()) == Some("ask_main_push")
                    && case
                        .pointer("/actual/kind")
                        .and_then(|value| value.as_str())
                        == Some("ask_picto")
                    && case
                        .pointer("/matched_rule/name")
                        .and_then(|value| value.as_str())
                        == Some("gate-main-push")
            })
    );
}

#[test]
fn policy_schema_outputs_fixture_contract() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["policy", "schema"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let schema: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        schema.get("$id").and_then(|value| value.as_str()),
        Some("https://github.com/Arakiss/gommage/schemas/policy-fixture.schema.json")
    );
    assert_eq!(
        schema
            .pointer("/$defs/policyFixtureDocument/properties/version/const")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        schema
            .pointer("/$defs/policyFixtureExpectation/properties/decision/enum")
            .and_then(|value| value.as_array())
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn policy_snapshot_outputs_fixture_that_policy_test_accepts() {
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
        .args([
            "policy",
            "snapshot",
            "--name",
            "ask_main_push",
            "--description",
            "captured main push fixture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git push origin main"}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixture_value: serde_json::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    assert_eq!(
        fixture_value
            .pointer("/cases/0/name")
            .and_then(|value| value.as_str()),
        Some("ask_main_push")
    );
    assert_eq!(
        fixture_value
            .pointer("/cases/0/expect/decision")
            .and_then(|value| value.as_str()),
        Some("ask_picto")
    );
    assert_eq!(
        fixture_value
            .pointer("/cases/0/expect/required_scope")
            .and_then(|value| value.as_str()),
        Some("git.push:main")
    );
    assert_eq!(
        fixture_value
            .pointer("/cases/0/expect/matched_rule")
            .and_then(|value| value.as_str()),
        Some("gate-main-push")
    );

    let fixture = temp.path().join("captured-policy-fixtures.yaml");
    fs::write(&fixture, output.stdout).unwrap();
    let test_output = gommage(&home)
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(
        test_output.status.success(),
        "{}",
        String::from_utf8_lossy(&test_output.stderr)
    );
}

#[test]
fn policy_test_exits_nonzero_on_fixture_failure() {
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
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
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
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert!(
        report
            .pointer("/cases/0/errors")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("expected decision allow"))
    );
}
