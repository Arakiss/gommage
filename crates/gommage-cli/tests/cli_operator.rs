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

fn doctor_check<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report
        .get("checks")
        .and_then(|checks| checks.as_array())
        .unwrap()
        .iter()
        .find(|check| check.get("name").and_then(|value| value.as_str()) == Some(name))
        .unwrap()
}

#[test]
fn mascot_plain_is_script_safe() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["mascot", "--plain"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gestral signature"));
    assert!(stdout.contains("Gommage Gestral"));
    assert!(stdout.contains("Gommage Teal #00B3A4"));
    assert!(stdout.contains("tool call -> typed capabilities -> signed audit"));
    assert!(stdout.contains("██████"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn mascot_compact_plain_is_single_line() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["mascot", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains("[Gestral]"));
    assert!(stdout.contains("GOMMAGE policy sentinel"));
    assert!(stdout.contains("signed audit"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn logo_alias_prints_the_same_signature() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["logo", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[Gestral]"));
    assert!(!stdout.contains("\x1b["));
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
fn map_json_reports_capabilities_without_policy_files() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let capabilities_dir = home.join("capabilities.d");
    fs::create_dir_all(&capabilities_dir).unwrap();
    fs::write(
        capabilities_dir.join("bash.yaml"),
        r#"
- name: bash-proc-exec
  tool: Bash
  emit:
    - "proc.exec:${input.command}"
- name: bash-git-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push(?:\\s+[-\\w]+)*\\s+(?P<remote>[\\w.-]+)\\s+(?P<ref>\\S+)"
  emit:
    - "git.push:refs/heads/${ref}"
    - "net.out:github.com"
- name: bash-git-force-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push[^#]*--force\\b"
  emit:
    - "git.push.force:<any>"
"#,
    )
    .unwrap();

    let mut child = gommage(&home)
        .args(["map", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git push --force origin main"}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("tool").and_then(|value| value.as_str()),
        Some("Bash")
    );
    assert_eq!(
        report.get("mapper_rules").and_then(|value| value.as_u64()),
        Some(3)
    );
    let capabilities = report
        .get("capabilities")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"proc.exec:git push --force origin main"));
    assert!(capabilities.contains(&"git.push:refs/heads/main"));
    assert!(capabilities.contains(&"net.out:github.com"));
    assert!(capabilities.contains(&"git.push.force:<any>"));
    assert!(
        report
            .get("input_hash")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("sha256:"))
    );
    assert!(report.get("decision").is_none());
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("audit.log").exists());

    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report
        .get("capabilities")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"proc.exec:git push --force origin main"));
    assert!(capabilities.contains(&"git.push:refs/heads/main"));
    assert!(capabilities.contains(&"net.out:github.com"));
    assert!(capabilities.contains(&"git.push.force:<any>"));
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("audit.log").exists());
}

#[test]
fn smoke_json_reports_semantic_passes() {
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

    let output = gommage(&home).args(["smoke", "--json"]).output().unwrap();

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
            .pointer("/summary/passed")
            .and_then(|value| value.as_u64())
            .unwrap()
            >= 7
    );
    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("ask_mcp_write")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("ask_picto")
    }));
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("allow_feature_push")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("allow")
    }));
}

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
    assert!(stdout.contains("anomalies: none"));
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

#[test]
fn quickstart_installs_claude_hook_and_imports_native_denies() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "language": "spanish",
  "permissions": {
    "allow": [
      "Bash",
      "Bash(git status *)",
      "Read(./docs/**)",
      "MultiEdit(./src/**)",
      "WebFetch(domain:example.com)",
      "WebSearch"
    ],
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
  },
  "enabledPlugins": ["example"]
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
    let imported_allows =
        fs::read_to_string(home.join("policy.d/90-claude-allow-import.yaml")).unwrap();
    assert!(imported_allows.contains("proc.exec:git status *"));
    assert!(imported_allows.contains("proc.exec:*"));
    assert!(imported_allows.contains("fs.read:${EXPEDITION_ROOT}/docs/**"));
    assert!(imported_allows.contains("fs.write:${EXPEDITION_ROOT}/src/**"));
    assert!(imported_allows.contains("net.fetch:example.com"));
    assert!(imported_allows.contains("net.search:web"));

    let settings_raw = fs::read_to_string(&settings).unwrap();
    assert!(
        settings_raw.find("\"language\"").unwrap() < settings_raw.find("\"permissions\"").unwrap()
    );
    assert!(
        settings_raw.find("\"permissions\"").unwrap() < settings_raw.find("\"hooks\"").unwrap()
    );
    assert!(
        settings_raw.find("\"hooks\"").unwrap() < settings_raw.find("\"enabledPlugins\"").unwrap()
    );

    let settings_json: serde_json::Value = serde_json::from_str(&settings_raw).unwrap();
    let pre_tool_use = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert_eq!(
        pre_tool_use[0].get("matcher").and_then(|v| v.as_str()),
        Some("Bash|Read|MultiEdit|WebFetch|WebSearch")
    );
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp"))
    );

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
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
        doctor_check(&report, "allow_import")
            .pointer("/details/importable_rules")
            .and_then(|value| value.as_u64()),
        Some(6)
    );
}

#[test]
fn quickstart_can_install_daemon_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--daemon-no-start",
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
    assert!(stdout.contains("ok daemon: service installed but not started"));
    assert!(stdout.contains("ok quickstart complete"));

    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    assert!(service.contains(&fake_daemon.to_string_lossy().to_string()));

    let settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(
        settings
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry.get("matcher").and_then(|v| v.as_str()) == Some(
                "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*"
            ))
    );
}

#[test]
fn quickstart_self_test_runs_verify_gate() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("self-test: checking recovery decisions"));
    assert!(stdout.contains("warn doctor:"));
    assert!(stdout.contains("pass smoke:"));
    assert!(stdout.contains("ok self-test complete"));
    assert!(stdout.contains("ok quickstart complete"));
}

#[test]
fn quickstart_self_test_runs_by_default() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("self-test: checking recovery decisions"));
    assert!(stdout.contains("ok self-test complete"));
}

#[test]
fn quickstart_no_self_test_skips_readiness_gate() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("self-test: running `gommage verify`"));
    assert!(stdout.contains("ok quickstart complete"));
}

#[test]
fn quickstart_rolls_back_agent_config_when_self_test_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = r#"{
  "permissions": {
    "allow": ["Bash"],
    "deny": ["Bash(gommage verify *)"]
  }
}
"#;
    fs::write(&settings, original).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("self-test failed: gommage_verify expected allow"));
    assert!(stderr.contains("self-test failed: restoring agent configuration snapshots"));
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
}

#[test]
fn quickstart_self_test_dry_run_only_prints_plan() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "quickstart",
            "--agent",
            "claude",
            "--self-test",
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(
        "plan self-test: run `gommage verify` and recovery decision checks after quickstart"
    ));
    assert!(stdout.contains("ok quickstart complete"));
    assert!(!home.exists());
    assert!(!settings.exists());
}

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
                .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp")))
    );
    let config = fs::read_to_string(config).unwrap();
    assert!(config.contains("codex_hooks = true"));
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
}

#[test]
fn daemon_install_launchd_writes_plist_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "launchd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plist = fs::read_to_string(launchd.join("dev.gommage.daemon.plist")).unwrap();
    assert!(plist.contains("<string>dev.gommage.daemon</string>"));
    assert!(plist.contains("<string>--foreground</string>"));
    assert!(plist.contains("<string>--home</string>"));
    assert!(plist.contains(&home.to_string_lossy().to_string()));
    assert!(plist.contains(&fake_daemon.to_string_lossy().to_string()));
}

#[test]
fn daemon_install_systemd_writes_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "systemd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("Description=Gommage policy daemon"));
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    assert!(service.contains(&fake_daemon.to_string_lossy().to_string()));
}
