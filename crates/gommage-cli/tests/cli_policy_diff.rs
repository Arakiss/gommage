mod support;

use std::fs;

use support::gommage;
use tempfile::tempdir;

#[test]
fn policy_diff_json_reports_decision_and_rule_changes_without_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let audit = temp.path().join("audit.log");
    let from_policy = temp.path().join("from-policy.d");
    let to_policy = temp.path().join("to-policy.d");
    fs::create_dir_all(&from_policy).unwrap();
    fs::create_dir_all(&to_policy).unwrap();
    fs::write(
        from_policy.join("10-main.yaml"),
        r#"
- name: gate-main-push
  decision: ask_picto
  required_scope: "git.push:main"
  match:
    any_capability: ["git.push:refs/heads/main"]
  reason: "baseline gates main pushes"
"#,
    )
    .unwrap();
    fs::write(
        to_policy.join("10-main.yaml"),
        r#"
- name: allow-main-push
  decision: allow
  match:
    any_capability: ["git.push:refs/heads/main"]
  reason: "candidate allows main pushes"
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
            "policy",
            "diff",
            "--from",
            from_policy.to_str().unwrap(),
            "--to",
            to_policy.to_str().unwrap(),
            "--against",
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
    assert!(
        !home.exists(),
        "policy diff should not initialize or require a Gommage home"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("changed"));
    assert_eq!(report["policy_version_changed"].as_bool(), Some(true));
    assert_eq!(report["summary"]["decisions"].as_u64(), Some(1));
    assert_eq!(report["summary"]["changed"].as_u64(), Some(1));
    assert_eq!(report["summary"]["decision_changed"].as_u64(), Some(1));
    assert_eq!(report["summary"]["matched_rule_changed"].as_u64(), Some(1));
    assert_eq!(report["summary"]["ask_picto_to_allow"].as_u64(), Some(1));
    assert_eq!(report["summary"]["skipped_events"].as_u64(), Some(1));
    assert_eq!(
        report["entries"][0]["from_decision"]["kind"].as_str(),
        Some("ask_picto")
    );
    assert_eq!(
        report["entries"][0]["to_decision"]["kind"].as_str(),
        Some("allow")
    );
    assert_eq!(report["entries"][0]["changed"].as_bool(), Some(true));
    assert_eq!(
        report["entries"][0]["from_matched_rule"]["name"].as_str(),
        Some("gate-main-push")
    );
    assert_eq!(
        report["entries"][0]["to_matched_rule"]["name"].as_str(),
        Some("allow-main-push")
    );
}

#[test]
fn policy_diff_human_output_is_plain_and_summarized() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let audit = temp.path().join("audit.log");
    let policy_dir = temp.path().join("policy.d");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::write(
        policy_dir.join("10-status.yaml"),
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
            "policy",
            "diff",
            "--from",
            policy_dir.to_str().unwrap(),
            "--to",
            policy_dir.to_str().unwrap(),
            "--against",
            audit.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage policy diff"));
    assert!(stdout.contains("status: unchanged"));
    assert!(stdout.contains("summary: 1 decision(s), 0 changed, 1 unchanged"));
    assert!(stdout.contains("audit_2 [unchanged] allow -> allow"));
    assert!(!stdout.contains("\x1b["));
}
