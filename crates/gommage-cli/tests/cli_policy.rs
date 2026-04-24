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
fn policy_lint_strict_json_passes_stdlib() {
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

    let output = gommage(&home)
        .args(["policy", "lint", "--strict", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["strict"].as_bool(), Some(true));
    assert!(report["rules"].as_u64().unwrap() > 0);
    assert_eq!(report["summary"]["errors"].as_u64(), Some(0));
    assert_eq!(report["issues"].as_array().unwrap().len(), 0);
}

#[test]
fn policy_layers_json_reports_project_before_user_and_decide_uses_it() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let project = temp.path().join("project");
    let project_policy_dir = project.join(".gommage/policy.d");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    fs::create_dir_all(home.join("capabilities.d")).unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    fs::create_dir_all(&project_policy_dir).unwrap();
    fs::write(
        home.join("capabilities.d/bash.yaml"),
        r#"
- name: bash-proc-exec
  tool: Bash
  emit:
    - "proc.exec:${input.command}"
"#,
    )
    .unwrap();
    fs::write(
        project_policy_dir.join("10-project.yaml"),
        r#"
- name: project-deny-status
  decision: gommage
  match:
    any_capability: ["proc.exec:git status"]
  reason: "project policy wins"
"#,
    )
    .unwrap();
    fs::write(
        home.join("policy.d/90-user.yaml"),
        r#"
- name: user-allow-status
  decision: allow
  match:
    any_capability: ["proc.exec:git status"]
"#,
    )
    .unwrap();
    assert!(
        gommage(&home)
            .args([
                "expedition",
                "start",
                "phase-10",
                "--root",
                project.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    let layers = gommage(&home)
        .args(["policy", "layers", "--json"])
        .output()
        .unwrap();
    assert!(
        layers.status.success(),
        "{}",
        String::from_utf8_lossy(&layers.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&layers.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["layers"][0]["name"].as_str(), Some("project"));
    assert_eq!(report["layers"][1]["name"].as_str(), Some("user"));
    assert_eq!(report["layers"][0]["rules"].as_u64(), Some(1));
    assert_eq!(report["layers"][1]["rules"].as_u64(), Some(1));

    let mut child = gommage(&home)
        .arg("decide")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git status"}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decision: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"]["kind"].as_str(), Some("gommage"));
    assert_eq!(
        decision["matched_rule"]["name"].as_str(),
        Some("project-deny-status")
    );
}

#[test]
fn policy_lint_strict_json_fails_duplicate_rule_names() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let policy_file = temp.path().join("duplicate-policy.yaml");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    fs::write(
        &policy_file,
        r#"
- name: duplicate
  decision: allow
  match:
    any_capability: ["proc.exec:git status"]
  reason: "first"
- name: duplicate
  decision: allow
  match:
    any_capability: ["proc.exec:git log"]
  reason: "second"
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args([
            "policy",
            "lint",
            policy_file.to_str().unwrap(),
            "--strict",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"].as_str() == Some("duplicate_rule_name"))
    );
}

#[test]
fn policy_suggest_json_reports_advisory_rule_and_fixture_from_audit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let audit = temp.path().join("audit.log");
    assert!(gommage(&home).arg("init").status().unwrap().success());
    fs::write(
        &audit,
        r#"{"v":1,"id":"legacy_allow_1","ts":"2026-04-24T00:00:00Z","tool":"Bash","input_hash":"sha256:status","capabilities":["proc.exec:git status"],"decision":{"kind":"allow"},"matched_rule":{"name":"old-allow-status","file":"old.yaml","index":0},"policy_version":"sha256:old","expedition":"migration","sig":"ed25519:test"}
{"v":1,"id":"event_1","ts":"2026-04-24T00:00:01Z","kind":"event","event":{"type":"policy_reloaded","source":"test","rules":0,"mapper_rules":0,"policy_version":"sha256:empty"},"sig":"ed25519:test"}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args([
            "policy",
            "suggest",
            "--audit",
            audit.to_str().unwrap(),
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
    assert_eq!(report["status"].as_str(), Some("suggestions"));
    assert_eq!(report["mutated"].as_bool(), Some(false));
    assert_eq!(report["summary"]["decisions"].as_u64(), Some(1));
    assert_eq!(report["summary"]["suggestions"].as_u64(), Some(1));
    assert_eq!(report["summary"]["skipped_events"].as_u64(), Some(1));

    let suggestion = &report["suggestions"][0];
    assert_eq!(suggestion["advisory"].as_bool(), Some(true));
    assert_eq!(suggestion["review_required"].as_bool(), Some(true));
    assert_eq!(suggestion["rule"]["decision"].as_str(), Some("allow"));
    assert_eq!(
        suggestion["rule"]["match"]["all_capability"][0].as_str(),
        Some("proc.exec:git status")
    );
    assert_eq!(suggestion["fixture_case"]["usable"].as_bool(), Some(false));
    assert_eq!(
        suggestion["fixture_case"]["input_available"].as_bool(),
        Some(false)
    );
    assert_eq!(
        suggestion["fixture_case"]["expect"]["matched_rule"].as_str(),
        Some("advisory-bash-allow-legacy-allow-1")
    );
    assert!(
        suggestion["fixture_yaml"]
            .as_str()
            .unwrap()
            .contains("__replace_with_captured_input_for_hash")
    );
    assert_eq!(
        suggestion["evidence"][0]["audited_matched_rule"]["name"].as_str(),
        Some("old-allow-status")
    );
    assert_eq!(
        suggestion["evidence"][0]["active_decision"]["kind"].as_str(),
        Some("gommage")
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
