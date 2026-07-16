mod support;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Output, Stdio},
};
use support::{doctor_check, gommage, workspace_path};
use tempfile::tempdir;

fn init_trace_home(home: &Path, policy: &str, mapper: &str) {
    assert!(gommage(home).arg("init").status().unwrap().success());
    assert!(
        gommage(home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    replace_yaml_dir(&home.join("policy.d"), "10-trace.yaml", policy);
    replace_yaml_dir(&home.join("capabilities.d"), "10-trace.yaml", mapper);
}

fn replace_yaml_dir(dir: &Path, file: &str, contents: &str) {
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(file), contents).unwrap();
}

fn emit_trace_probe(home: &Path, org: Option<&Path>, project: Option<&Path>) -> String {
    let mut command = gommage(home);
    command
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    set_policy_layer_env(&mut command, org, project);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"hook_event_name":"PreToolUse","tool_name":"TraceProbe","tool_input":{}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    audit
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("tool").and_then(Value::as_str) == Some("TraceProbe"))
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_string))
        .unwrap()
}

fn explain_trace(
    home: &Path,
    id: &str,
    org: Option<&Path>,
    project: Option<&Path>,
    json: bool,
) -> Output {
    let mut command = gommage(home);
    command.args(["explain", id, "--trace"]);
    if json {
        command.arg("--json");
    }
    set_policy_layer_env(&mut command, org, project);
    command.output().unwrap()
}

fn set_policy_layer_env(
    command: &mut std::process::Command,
    org: Option<&Path>,
    project: Option<&Path>,
) {
    command.env_remove("GOMMAGE_ORG_POLICY_DIR");
    command.env_remove("GOMMAGE_PROJECT_POLICY_DIR");
    if let Some(org) = org {
        command.env("GOMMAGE_ORG_POLICY_DIR", org);
    }
    if let Some(project) = project {
        command.env("GOMMAGE_PROJECT_POLICY_DIR", project);
    }
}

fn provenance_for<'a>(report: &'a Value, field: &str, capability: &str) -> &'a Value {
    report[field]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["capability"].as_str() == Some(capability))
        .unwrap()
}

fn base64_standard_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[usize::from(first >> 2)] as char);
        encoded.push(ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[usize::from(third & 0x3f)] as char);
        }
    }
    encoded
}

fn write_signed_legacy_v1(home: &Path) -> &'static str {
    const ID: &str = "audit_legacy_cli";
    let key_bytes: [u8; 32] = fs::read(home.join("key.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&key_bytes);
    let canonical = br#"{"capabilities":["trace.a"],"decision":{"kind":"allow"},"expedition":null,"id":"audit_legacy_cli","input_hash":"sha256:input","matched_rule":null,"policy_version":"sha256:legacy","tool":"TraceProbe","ts":"2026-04-24T00:00:00Z","v":1}"#;
    let signature = key.sign(canonical);
    let line = serde_json::json!({
        "v": 1,
        "id": ID,
        "ts": "2026-04-24T00:00:00Z",
        "tool": "TraceProbe",
        "input_hash": "sha256:input",
        "capabilities": ["trace.a"],
        "decision": {"kind": "allow"},
        "matched_rule": null,
        "policy_version": "sha256:legacy",
        "expedition": null,
        "sig": format!(
            "ed25519:{}",
            base64_standard_no_pad(&signature.to_bytes())
        ),
    });
    fs::write(
        home.join("audit.log"),
        format!("{}\n", serde_json::to_string(&line).unwrap()),
    )
    .unwrap();
    ID
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
        Some(8)
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
    assert!(stdout.contains("signature_verified: true"));
    assert!(stdout.contains("decision:"));
    assert!(stdout.contains("policy_version:"));
    assert!(stdout.contains("primary_matched_rule:"));
    assert!(stdout.contains("audited_capability_provenance:"));
    assert!(stdout.contains("capabilities:"));
}

#[test]
fn explain_trace_json_reports_signed_v2_and_active_provenance() {
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

    let output = gommage(&home)
        .args(["explain", id, "--trace", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"].as_str(), Some("decision"));
    assert_eq!(report["audit_schema_version"].as_u64(), Some(2));
    assert_eq!(report["signature_verified"].as_bool(), Some(true));
    assert_eq!(report["input_available"].as_bool(), Some(false));
    assert_eq!(
        report["active_primary_matched_rule"]["name"].as_str(),
        Some("gate-main-push")
    );
    assert_eq!(
        report["audited_capability_provenance"],
        report["active_capability_provenance"]
    );
    assert!(report.get("rules").is_none());
    assert!(report.get("shadowed_rules").is_none());
    assert!(
        report["fixture_hints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hint| hint.as_str().unwrap().contains("gommage replay"))
    );
}

#[test]
fn explain_trace_preserves_allow_a_and_deny_b_provenance() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_trace_home(
        &home,
        r#"
- name: allow-a
  decision: allow
  match:
    any_capability: ["trace.a"]
  reason: "A is allowed"
- name: deny-b
  decision: gommage
  match:
    any_capability: ["trace.b"]
  reason: "B is denied"
"#,
        r#"
- name: trace-probe
  tool: TraceProbe
  emit: ["trace.b", "trace.a", "trace.a"]
"#,
    );
    let id = emit_trace_probe(&home, None, None);
    let output = explain_trace(&home, &id, None, None, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(
        report["active_capabilities"],
        serde_json::json!(["trace.a", "trace.b"])
    );
    assert_eq!(
        report["active_primary_matched_rule"]["name"].as_str(),
        Some("deny-b")
    );
    assert_eq!(
        provenance_for(&report, "active_capability_provenance", "trace.a")
            ["effective_decision"]["kind"]
            .as_str(),
        Some("allow")
    );
    assert_eq!(
        provenance_for(&report, "active_capability_provenance", "trace.b")
            ["effective_decision"]["kind"]
            .as_str(),
        Some("gommage")
    );
    assert_eq!(
        report["audited_capability_provenance"],
        report["active_capability_provenance"]
    );
}

#[test]
fn explain_trace_reports_every_layer_contribution_in_json_and_human_output() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let org = temp.path().join("org-policy");
    let project = temp.path().join("project-policy");
    init_trace_home(
        &home,
        r#"
- name: user-ask-a
  decision: ask_picto
  required_scope: trace.a
  match:
    any_capability: ["trace.a"]
  reason: "user review"
"#,
        r#"
- name: trace-probe
  tool: TraceProbe
  emit: ["trace.a"]
"#,
    );
    replace_yaml_dir(
        &org,
        "10-org.yaml",
        r#"
- name: org-allow-a
  decision: allow
  match:
    any_capability: ["trace.a"]
  reason: "organization allows A"
"#,
    );
    replace_yaml_dir(
        &project,
        "10-project.yaml",
        r#"
- name: project-deny-a
  decision: gommage
  match:
    any_capability: ["trace.a"]
  reason: "project tightens A"
"#,
    );

    let id = emit_trace_probe(&home, Some(&org), Some(&project));
    let output = explain_trace(&home, &id, Some(&org), Some(&project), true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let contributions =
        provenance_for(&report, "active_capability_provenance", "trace.a")["contributions"]
            .as_array()
            .unwrap();
    assert_eq!(
        contributions
            .iter()
            .map(|entry| entry["layer"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["org", "user", "project"]
    );
    assert_eq!(
        contributions
            .iter()
            .map(|entry| entry["rule"]["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["org-allow-a", "user-ask-a", "project-deny-a"]
    );

    let human = explain_trace(&home, &id, Some(&org), Some(&project), false);
    assert!(human.status.success());
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(stdout.contains("capability=trace.a status=resolved"));
    assert!(stdout.contains("layer=org"));
    assert!(stdout.contains("layer=user"));
    assert!(stdout.contains("layer=project"));
}

#[test]
fn explain_trace_keeps_unresolved_sibling_visible() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_trace_home(
        &home,
        r#"
- name: allow-a
  decision: allow
  match:
    any_capability: ["trace.a"]
  reason: "A is allowed"
"#,
        r#"
- name: trace-probe
  tool: TraceProbe
  emit: ["trace.a", "trace.c"]
"#,
    );
    let id = emit_trace_probe(&home, None, None);
    let output = explain_trace(&home, &id, None, None, true);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(report["active_decision"]["kind"].as_str(), Some("gommage"));
    assert!(report["active_primary_matched_rule"].is_null());
    let unresolved = provenance_for(&report, "active_capability_provenance", "trace.c");
    assert_eq!(unresolved["status"].as_str(), Some("unresolved"));
    assert!(unresolved.get("effective_decision").is_none());
    assert!(unresolved.get("contributions").is_none());
}

#[test]
fn explain_trace_distinguishes_legacy_v1_provenance_absence() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_trace_home(
        &home,
        r#"
- name: allow-a
  decision: allow
  match:
    any_capability: ["trace.a"]
  reason: "A is allowed"
"#,
        r#"
- name: trace-probe
  tool: TraceProbe
  emit: ["trace.a"]
"#,
    );
    let id = write_signed_legacy_v1(&home);
    let output = explain_trace(&home, id, None, None, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(report["audit_schema_version"].as_u64(), Some(1));
    assert_eq!(report["signature_verified"].as_bool(), Some(true));
    assert!(report["audited_capability_provenance"].is_null());
    assert!(
        report["audited_provenance_note"]
            .as_str()
            .unwrap()
            .contains("schema v1")
    );
    assert_eq!(
        provenance_for(&report, "active_capability_provenance", "trace.a")["status"].as_str(),
        Some("resolved")
    );
}

#[test]
fn explain_rejects_tampered_selected_provenance_before_printing_it() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_trace_home(
        &home,
        r#"
- name: allow-a
  decision: allow
  match:
    any_capability: ["trace.a"]
  reason: "A is allowed"
"#,
        r#"
- name: trace-probe
  tool: TraceProbe
  emit: ["trace.a"]
"#,
    );
    let id = emit_trace_probe(&home, None, None);
    let audit_path = home.join("audit.log");
    let mut entry: Value =
        serde_json::from_str(fs::read_to_string(&audit_path).unwrap().trim()).unwrap();
    entry["capability_provenance"][0]["status"] = Value::String("unresolved".to_string());
    fs::write(
        &audit_path,
        format!("{}\n", serde_json::to_string(&entry).unwrap()),
    )
    .unwrap();

    let output = explain_trace(&home, &id, None, None, true);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed signature verification"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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
