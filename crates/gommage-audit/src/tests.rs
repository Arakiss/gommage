use super::*;
use gommage_core::{CapabilityProvenance, CapabilityProvenanceStatus, Decision};
use rand_core::OsRng;
use serde_json::json;
use tempfile::tempdir;

fn legacy_v1_decision_line(sk: &SigningKey) -> String {
    let canonical = br#"{"capabilities":["proc.exec:ls"],"decision":{"kind":"allow"},"expedition":null,"id":"audit_legacy","input_hash":"sha256:input","matched_rule":null,"policy_version":"sha256:old","tool":"Bash","ts":"2026-04-24T00:00:00Z","v":1}"#;
    let signature = sk.sign(canonical);
    let sig = format!(
        "ed25519:{}",
        base64::encode_standard_no_pad(signature.to_bytes().as_slice())
    );
    serde_json::to_string(&json!({
        "v": 1,
        "id": "audit_legacy",
        "ts": "2026-04-24T00:00:00Z",
        "tool": "Bash",
        "input_hash": "sha256:input",
        "capabilities": ["proc.exec:ls"],
        "decision": {"kind": "allow"},
        "matched_rule": null,
        "policy_version": "sha256:old",
        "expedition": null,
        "sig": sig,
    }))
    .unwrap()
}

fn v2_decision_line(sk: &SigningKey) -> String {
    let mut entry = AuditEntry {
        version: DECISION_SCHEMA_VERSION,
        id: "audit_v2".to_string(),
        ts: "2026-07-16T20:00:00Z".to_string(),
        tool: "Bash".to_string(),
        input_hash: "sha256:input".to_string(),
        capabilities: vec![Capability::new("proc.exec:ls")],
        capability_provenance: vec![CapabilityProvenance {
            capability: Capability::new("proc.exec:ls"),
            status: CapabilityProvenanceStatus::PolicyBypassed,
            effective_decision: Some(Decision::Allow),
            contributions: Vec::new(),
        }],
        decision: Decision::Allow,
        matched_rule: None,
        policy_version: "sha256:test".to_string(),
        expedition: None,
        sig: String::new(),
    };
    let signature = sk.sign(&canonical_decision_v2_bytes(&entry));
    entry.sig = format!(
        "ed25519:{}",
        base64::encode_standard_no_pad(signature.to_bytes().as_slice())
    );
    serde_json::to_string(&entry).unwrap()
}

fn object_with_field_order(value: &serde_json::Value, fields: &[&str]) -> String {
    let object = value.as_object().unwrap();
    let fields = fields
        .iter()
        .map(|field| {
            format!(
                "{}:{}",
                serde_json::to_string(field).unwrap(),
                serde_json::to_string(&object[*field]).unwrap()
            )
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", fields.join(","))
}

#[test]
fn decision_v2_round_trips_with_provenance() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![Capability::new("proc.exec:ls")],
        policy_version: "sha256:test".into(),
        capability_provenance: vec![CapabilityProvenance {
            capability: Capability::new("proc.exec:ls"),
            status: CapabilityProvenanceStatus::PolicyBypassed,
            effective_decision: Some(Decision::Allow),
            contributions: Vec::new(),
        }],
    };
    let entry = w.append(&call, &eval, Some("expedition-x")).unwrap();
    assert_eq!(entry.version, DECISION_SCHEMA_VERSION);
    assert_eq!(entry.capability_provenance, eval.capability_provenance);
    w.append(&call, &eval, Some("expedition-x")).unwrap();
    drop(w);

    let value: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["v"], json!(2));
    assert_eq!(
        value["capability_provenance"][0]["capability"],
        json!("proc.exec:ls")
    );

    let n = verify_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(n, 2);
}

#[test]
fn legacy_v1_decision_without_provenance_still_verifies() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::from_bytes(&[7; 32]);
    let line = legacy_v1_decision_line(&sk);
    std::fs::write(&path, format!("{line}\n")).unwrap();

    let entry: AuditEntry = serde_json::from_str(&line).unwrap();

    assert_eq!(entry.version, LEGACY_DECISION_SCHEMA_VERSION);
    assert!(entry.capability_provenance.is_empty());
    assert!(
        serde_json::to_value(&entry)
            .unwrap()
            .get("capability_provenance")
            .is_none()
    );
    assert_eq!(verify_log(&path, &sk.verifying_key()).unwrap(), 1);
}

#[test]
fn decision_v2_always_serializes_empty_provenance() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut writer = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![Capability::new("proc.exec:ls")],
        policy_version: "sha256:test".into(),
        capability_provenance: Vec::new(),
    };

    writer.append(&call, &eval, None).unwrap();
    drop(writer);

    let line = std::fs::read_to_string(&path).unwrap();
    let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(value["v"], json!(2));
    assert_eq!(value["capability_provenance"], json!([]));
    assert_eq!(verify_log(&path, &sk.verifying_key()).unwrap(), 1);
}

#[test]
fn tampering_v2_provenance_breaks_the_signature() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut writer = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![Capability::new("proc.exec:ls")],
        policy_version: "sha256:test".into(),
        capability_provenance: vec![CapabilityProvenance {
            capability: Capability::new("proc.exec:ls"),
            status: CapabilityProvenanceStatus::PolicyBypassed,
            effective_decision: Some(Decision::Allow),
            contributions: Vec::new(),
        }],
    };

    writer.append(&call, &eval, None).unwrap();
    drop(writer);

    let mut value: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    value["capability_provenance"][0]["status"] = json!("resolved");
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&value).unwrap()),
    )
    .unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::BadSignature { line: 1 })
    ));
}

#[test]
fn unsupported_decision_and_event_versions_are_not_reported_as_tamper() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let decision = r#"{"v":99,"id":"future-decision","sig":"ed25519:invalid"}"#;
    let event = r#"{"v":3,"id":"future-event","kind":"event","sig":"ed25519:invalid"}"#;
    std::fs::write(&path, format!("{decision}\n{event}\n")).unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::UnsupportedSchema {
            line: 1,
            record_kind: "decision",
            version: 99,
        })
    ));

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_total, 2);
    assert_eq!(report.entries_verified, 0);
    assert!(report.anomalies.iter().any(|anomaly| {
        matches!(
            anomaly,
            Anomaly::MalformedEntry { line: 1, error }
                if error == "unsupported decision audit schema version 99 at line 1"
        )
    }));
    assert!(report.anomalies.iter().any(|anomaly| {
        matches!(
            anomaly,
            Anomaly::MalformedEntry { line: 2, error }
                if error == "unsupported event audit schema version 3 at line 2"
        )
    }));
    assert!(
        !report
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, Anomaly::BadSignature { .. }))
    );
}

#[test]
fn known_decision_versions_enforce_their_provenance_shape() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);

    std::fs::write(
        &path,
        r#"{"v":1,"capability_provenance":[],"sig":"ed25519:invalid"}"#,
    )
    .unwrap();
    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::InvalidSchema {
            line: 1,
            record_kind: "decision",
            reason,
        }) if reason == "v1 must not contain capability_provenance"
    ));

    std::fs::write(&path, r#"{"v":2,"sig":"ed25519:invalid"}"#).unwrap();
    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::InvalidSchema {
            line: 1,
            record_kind: "decision",
            reason,
        }) if reason == "v2 requires capability_provenance"
    ));
}

#[test]
fn unknown_top_level_fields_are_invalid_schema_not_bad_signatures() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut value: serde_json::Value = serde_json::from_str(&v2_decision_line(&sk)).unwrap();
    value["unsigned_extension"] = json!(true);
    std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::InvalidSchema {
            line: 1,
            record_kind: "decision",
            reason,
        }) if reason == "unexpected top-level field `unsigned_extension` in v2"
    ));
}

#[test]
fn nested_unknown_fields_are_covered_by_the_signature() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut value: serde_json::Value = serde_json::from_str(&v2_decision_line(&sk)).unwrap();
    value["capability_provenance"][0]["unsigned_extension"] = json!(true);
    std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::BadSignature { line: 1 })
    ));
}

#[test]
fn duplicate_top_level_keys_are_rejected_before_verification() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let line = v2_decision_line(&sk).replacen(
        "\"tool\":\"Bash\"",
        "\"tool\":\"Bash\",\"tool\":\"Bash\"",
        1,
    );
    std::fs::write(&path, line).unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::Json(error))
            if error.to_string().contains("duplicate object key `tool`")
    ));
}

#[test]
fn duplicate_nested_keys_are_rejected_before_verification() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let line = v2_decision_line(&sk).replacen(
        "\"status\":\"policy_bypassed\"",
        "\"status\":\"policy_bypassed\",\"status\":\"policy_bypassed\"",
        1,
    );
    std::fs::write(&path, line).unwrap();

    assert!(matches!(
        verify_log(&path, &sk.verifying_key()),
        Err(AuditError::Json(error))
            if error.to_string().contains("duplicate object key `status`")
    ));
}

#[test]
fn signature_verification_is_independent_of_object_field_order() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let value: serde_json::Value = serde_json::from_str(&v2_decision_line(&sk)).unwrap();
    let reordered_top_level = object_with_field_order(
        &value,
        &[
            "sig",
            "expedition",
            "policy_version",
            "matched_rule",
            "decision",
            "capability_provenance",
            "capabilities",
            "input_hash",
            "tool",
            "ts",
            "id",
            "v",
        ],
    );
    let original_provenance = serde_json::to_string(&value["capability_provenance"]).unwrap();
    let reordered_provenance = format!(
        "[{}]",
        object_with_field_order(
            &value["capability_provenance"][0],
            &["status", "effective_decision", "capability"],
        )
    );
    let reordered = reordered_top_level.replacen(&original_provenance, &reordered_provenance, 1);
    assert_ne!(reordered, reordered_top_level);
    std::fs::write(&path, reordered).unwrap();

    assert_eq!(verify_log(&path, &sk.verifying_key()).unwrap(), 1);
}

#[test]
fn append_event_and_verify() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let entry = w
        .append_event(AuditEvent::PictoRevoked { id: "p1".into() })
        .unwrap();
    assert_eq!(entry.version, EVENT_SCHEMA_VERSION);
    drop(w);

    let n = verify_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn recent_stream_items_summarizes_decisions_and_events() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![Capability::new("proc.exec:ls")],
        policy_version: "sha256:test".into(),
        capability_provenance: Vec::new(),
    };
    w.append(&call, &eval, Some("expedition-x")).unwrap();
    w.append_event(AuditEvent::PictoRevoked { id: "p1".into() })
        .unwrap();
    drop(w);

    let items = recent_stream_items(&path, 8).unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].summary, "decision allow Bash");
    assert_eq!(items[1].summary, "picto revoked p1");
}

#[test]
fn explain_counts_bypass_events_and_flags_hard_stop_allows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    w.append_event(AuditEvent::BypassActivated {
        tool: "Bash".into(),
        input_hash: "sha256:test".into(),
        capabilities: vec![Capability::new("proc.exec:rm -rf /")],
        original_decision: "deny".into(),
        original_reason: "hard-stop hs.rm-rf-root".into(),
        hard_stop: true,
        bypass_decision: "allow".into(),
    })
    .unwrap();
    drop(w);

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_total, 1);
    assert_eq!(report.entries_verified, 1);
    assert_eq!(report.bypass_activations, 1);
    assert_eq!(report.hard_stop_bypass_attempts, 1);
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::HardStopBypassAttempt { .. }))
    );
}

#[test]
fn mixed_decision_and_event_log_verifies() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v1".into(),
        capability_provenance: Vec::new(),
    };
    w.append(&call, &eval, Some("exp")).unwrap();
    w.append_event(AuditEvent::PictoRevoked { id: "p1".into() })
        .unwrap();
    drop(w);

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_total, 2);
    assert_eq!(report.entries_verified, 2);
    assert_eq!(report.policy_versions_seen, vec!["sha256:v1"]);
    assert_eq!(report.expeditions_seen, vec!["exp"]);
}

#[test]
fn explain_reports_total_verified_and_no_anomalies_on_clean_log() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v1".into(),
        capability_provenance: Vec::new(),
    };
    for _ in 0..3 {
        w.append(&call, &eval, Some("exp")).unwrap();
    }
    drop(w);

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_total, 3);
    assert_eq!(report.entries_verified, 3);
    assert_eq!(report.key_fingerprint.len(), 16);
    assert!(report.anomalies.is_empty());
    assert_eq!(report.policy_versions_seen, vec!["sha256:v1"]);
    assert_eq!(report.expeditions_seen, vec!["exp"]);
}

#[test]
fn explain_flags_policy_version_change() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval_a = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v1".into(),
        capability_provenance: Vec::new(),
    };
    let eval_b = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v2".into(),
        capability_provenance: Vec::new(),
    };
    w.append(&call, &eval_a, None).unwrap();
    w.append(&call, &eval_b, None).unwrap();
    drop(w);

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_verified, 2);
    assert_eq!(report.policy_versions_seen.len(), 2);
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::PolicyVersionChanged { .. }))
    );
}

#[test]
fn explain_flags_bad_signature_but_keeps_walking() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v1".into(),
        capability_provenance: Vec::new(),
    };
    w.append(&call, &eval, None).unwrap();
    w.append(&call, &eval, None).unwrap();
    drop(w);

    // Tamper one line in the middle.
    let content = std::fs::read_to_string(&path).unwrap();
    let corrupted = content.replacen("\"Bash\"", "\"Bashh\"", 1);
    std::fs::write(&path, corrupted).unwrap();

    let report = explain_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(report.entries_total, 2);
    assert_eq!(report.entries_verified, 1);
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::BadSignature { .. }))
    );
}

#[test]
fn tampered_line_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command":"ls"}),
    };
    let eval = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:test".into(),
        capability_provenance: Vec::new(),
    };
    w.append(&call, &eval, None).unwrap();
    drop(w);
    // Corrupt a field
    let content = std::fs::read_to_string(&path).unwrap();
    let corrupted = content.replace("\"Bash\"", "\"Sneak\"");
    std::fs::write(&path, corrupted).unwrap();
    assert!(verify_log(&path, &sk.verifying_key()).is_err());
}
