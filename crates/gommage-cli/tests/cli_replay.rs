mod support;

use std::fs;

use support::gommage;
use tempfile::tempdir;

#[test]
fn replay_json_reports_changed_decision_and_skips_events() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let audit = temp.path().join("audit.log");
    let policy_dir = temp.path().join("policy.d");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::write(
        policy_dir.join("10-replay.yaml"),
        r#"
- name: allow-main-push-now
  decision: allow
  match:
    any_capability: ["git.push:refs/heads/main"]
  reason: "candidate policy allows main pushes"
"#,
    )
    .unwrap();
    fs::write(
        &audit,
        r#"{"v":1,"id":"audit_1","ts":"2026-04-24T00:00:00Z","tool":"Bash","input_hash":"sha256:input","capabilities":["git.push:refs/heads/main"],"decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"old policy required approval"},"matched_rule":{"name":"gate-main-push","file":"old.yaml","index":0},"policy_version":"sha256:old","expedition":null,"sig":"ed25519:test"}
{"v":1,"id":"event_1","ts":"2026-04-24T00:00:01Z","kind":"event","event":{"type":"policy_reloaded","source":"test","rules":1,"mapper_rules":1,"policy_version":"sha256:new"},"sig":"ed25519:test"}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args([
            "replay",
            "--audit",
            audit.to_str().unwrap(),
            "--policy",
            policy_dir.to_str().unwrap(),
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
    assert_eq!(report["status"].as_str(), Some("changed"));
    assert_eq!(report["summary"]["decisions"].as_u64(), Some(1));
    assert_eq!(report["summary"]["changed"].as_u64(), Some(1));
    assert_eq!(report["summary"]["skipped_events"].as_u64(), Some(1));
    assert_eq!(
        report["entries"][0]["original_decision"]["kind"].as_str(),
        Some("ask_picto")
    );
    assert_eq!(
        report["entries"][0]["replayed_decision"]["kind"].as_str(),
        Some("allow")
    );
    assert_eq!(report["entries"][0]["changed"].as_bool(), Some(true));
    assert_eq!(
        report["entries"][0]["original_matched_rule"]["name"].as_str(),
        Some("gate-main-push")
    );
    assert_eq!(
        report["entries"][0]["replayed_matched_rule"]["name"].as_str(),
        Some("allow-main-push-now")
    );
}

#[test]
fn replay_human_output_is_plain_and_summarized() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let audit = temp.path().join("audit.log");
    let policy_dir = temp.path().join("policy.d");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::write(
        policy_dir.join("10-replay.yaml"),
        r#"
- name: allow-status
  decision: allow
  match:
    any_capability: ["proc.exec:git status"]
  reason: "safe status"
"#,
    )
    .unwrap();
    fs::write(
        &audit,
        r#"{"v":1,"id":"audit_2","ts":"2026-04-24T00:00:00Z","tool":"Bash","input_hash":"sha256:status","capabilities":["proc.exec:git status"],"decision":{"kind":"allow"},"matched_rule":{"name":"allow-status","file":"old.yaml","index":0},"policy_version":"sha256:old","expedition":"demo","sig":"ed25519:test"}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args([
            "replay",
            "--audit",
            audit.to_str().unwrap(),
            "--policy",
            policy_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage replay"));
    assert!(stdout.contains("status: unchanged"));
    assert!(stdout.contains("summary: 1 decision(s), 0 changed, 1 unchanged"));
    assert!(stdout.contains("audit_2 [unchanged] allow -> allow"));
    assert!(!stdout.contains("\x1b["));
}
