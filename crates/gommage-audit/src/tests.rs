use super::*;
use gommage_core::Decision;
use rand_core::OsRng;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn append_and_verify() {
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
    };
    w.append(&call, &eval, Some("expedition-x")).unwrap();
    w.append(&call, &eval, Some("expedition-x")).unwrap();
    let n = verify_log(&path, &sk.verifying_key()).unwrap();
    assert_eq!(n, 2);
}

#[test]
fn append_event_and_verify() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sk = SigningKey::generate(&mut OsRng);
    let mut w = AuditWriter::open(&path, sk.clone()).unwrap();
    w.append_event(AuditEvent::PictoRevoked { id: "p1".into() })
        .unwrap();
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
    };
    let eval_b = EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: vec![],
        policy_version: "sha256:v2".into(),
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
    };
    w.append(&call, &eval, None).unwrap();
    drop(w);
    // Corrupt a field
    let content = std::fs::read_to_string(&path).unwrap();
    let corrupted = content.replace("\"Bash\"", "\"Sneak\"");
    std::fs::write(&path, corrupted).unwrap();
    assert!(verify_log(&path, &sk.verifying_key()).is_err());
}
