mod support;

use std::fs;
use support::gommage;
use tempfile::tempdir;

#[test]
fn stats_json_reports_friction_hygiene_and_deny_loops() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    fs::create_dir_all(&home).unwrap();

    fs::write(
        home.join("audit.log"),
        r#"{"v":1,"id":"ask_1","ts":"2026-07-01T00:00:00Z","tool":"Bash","input_hash":"sha256:ask1","capabilities":["git.push:refs/heads/main"],"decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"main requires approval"},"matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"policy_version":"sha256:p","expedition":null,"sig":"ed25519:test"}
{"v":1,"id":"ask_2","ts":"2026-07-02T00:00:00Z","tool":"Bash","input_hash":"sha256:ask2","capabilities":["git.push:refs/heads/main"],"decision":{"kind":"ask_picto","required_scope":"git.push:main","reason":"main requires approval"},"matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"policy_version":"sha256:p","expedition":null,"sig":"ed25519:test"}
{"v":1,"id":"deny_1","ts":"2026-07-02T00:01:00Z","tool":"Bash","input_hash":"sha256:deny","capabilities":["proc.exec:git add -A"],"decision":{"kind":"gommage","reason":"stage explicit paths","hard_stop":false},"matched_rule":{"name":"deny-bulk-git-stage","file":"20-git.yaml","index":0},"policy_version":"sha256:p","expedition":null,"sig":"ed25519:test"}
{"v":1,"id":"deny_2","ts":"2026-07-02T00:02:00Z","tool":"Bash","input_hash":"sha256:deny","capabilities":["proc.exec:git add -A"],"decision":{"kind":"gommage","reason":"stage explicit paths","hard_stop":false},"matched_rule":{"name":"deny-bulk-git-stage","file":"20-git.yaml","index":0},"policy_version":"sha256:p","expedition":null,"sig":"ed25519:test"}
{"v":1,"id":"null_1","ts":"2026-07-02T00:03:00Z","tool":null,"decision":null,"sig":"ed25519:test"}
{"v":1,"id":"event_1","ts":"2026-07-02T00:04:00Z","kind":"event","event":{"type":"approval_requested","id":"apr_1","tool":"Bash","input_hash":"sha256:ask1","required_scope":"git.push:main","reason":"main requires approval","policy_version":"sha256:p"},"sig":"ed25519:test"}
not json
"#,
    )
    .unwrap();

    fs::write(
        home.join("approvals.jsonl"),
        r#"{"type":"requested","request":{"id":"apr_1","created_at":"2026-07-01T00:00:00Z","tool":"Bash","input_hash":"sha256:ask1","required_scope":"git.push:main","reason":"main requires approval","capabilities":["git.push:refs/heads/main"],"matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"policy_version":"sha256:p"}}
{"type":"resolved","resolution":{"request_id":"apr_1","resolved_at":"2026-07-01T00:01:00Z","status":"approved","reason":"ok","picto_id":"picto_1"}}
{"type":"requested","request":{"id":"apr_2","created_at":"2026-07-02T00:00:00Z","tool":"Bash","input_hash":"sha256:ask2","required_scope":"git.push:main","reason":"main requires approval","capabilities":["git.push:refs/heads/main"],"matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"policy_version":"sha256:p"}}
{"type":"resolved","resolution":{"request_id":"apr_2","resolved_at":"2026-07-02T00:01:00Z","status":"approved","reason":"ok","picto_id":"picto_2"}}
{"type":"requested","request":{"id":"apr_3","created_at":"2026-07-03T00:00:00Z","tool":"Bash","input_hash":"sha256:ask3","required_scope":"git.push:main","reason":"main requires approval","capabilities":["git.push:refs/heads/main"],"matched_rule":{"name":"gate-main-push","file":"20-git.yaml","index":0},"policy_version":"sha256:p"}}
{"type":"resolved","resolution":{"request_id":"apr_3","resolved_at":"2026-07-03T00:01:00Z","status":"approved","reason":"ok","picto_id":"picto_3"}}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args(["stats", "--json", "--window-days", "14"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"].as_str(), Some("gommage_stats"));
    assert_eq!(report["totals"]["audit_records"].as_u64(), Some(6));
    assert_eq!(report["totals"]["decisions"].as_u64(), Some(4));
    assert_eq!(report["totals"]["asks"].as_u64(), Some(2));
    assert_eq!(report["totals"]["denies"].as_u64(), Some(2));
    assert_eq!(report["hygiene"]["malformed_records"].as_u64(), Some(1));
    assert_eq!(report["hygiene"]["null_tool_records"].as_u64(), Some(1));
    assert_eq!(report["hygiene"]["null_decision_records"].as_u64(), Some(1));
    assert_eq!(report["approvals"]["pending"].as_u64(), Some(0));
    assert_eq!(report["approvals"]["stale_pending"].as_u64(), Some(0));

    let main_rule = report["asks_by_rule"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["rule"].as_str() == Some("gate-main-push"))
        .unwrap();
    assert_eq!(main_rule["total_asks"].as_u64(), Some(2));
    assert_eq!(main_rule["approval_requests"].as_u64(), Some(3));
    assert_eq!(main_rule["approvals_approved"].as_u64(), Some(3));
    assert_eq!(main_rule["approval_rate"].as_f64(), Some(1.0));
    assert_eq!(
        main_rule["avg_time_to_resolution_seconds"].as_f64(),
        Some(60.0)
    );

    let loop_stats = &report["deny_loops"].as_array().unwrap()[0];
    assert_eq!(loop_stats["rule"].as_str(), Some("deny-bulk-git-stage"));
    assert_eq!(loop_stats["occurrences"].as_u64(), Some(2));

    let candidates = report["reclassification_candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|candidate| {
        candidate["rule"].as_str() == Some("gate-main-push")
            && candidate["kind"].as_str() == Some("candidate_allow")
    }));

    let watchlist = report["watchlist"].as_array().unwrap();
    assert!(watchlist.iter().any(|item| {
        item["kind"].as_str() == Some("audit_hygiene")
            && item["severity"].as_str() == Some("action")
    }));
    assert!(watchlist.iter().any(|item| {
        item["kind"].as_str() == Some("deny_loop") && item["severity"].as_str() == Some("review")
    }));
    assert!(watchlist.iter().any(|item| {
        item["kind"].as_str() == Some("candidate_allow")
            && item["message"]
                .as_str()
                .is_some_and(|message| message.contains("gate-main-push"))
    }));
}
