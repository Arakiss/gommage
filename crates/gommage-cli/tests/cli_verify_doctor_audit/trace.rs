use super::*;

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
    assert_eq!(report["audit_schema_version"].as_u64(), Some(3));
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
