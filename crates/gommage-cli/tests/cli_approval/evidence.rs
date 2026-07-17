use super::*;

#[test]
fn approval_replay_and_evidence_are_machine_readable() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request_id = approvals[0]["request"]["id"].as_str().unwrap();

    for name in [
        "key.ed25519",
        "pictos.sqlite",
        "pictos.sqlite-wal",
        "pictos.sqlite-shm",
    ] {
        let path = home.join(name);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }

    let replay = gommage(&home)
        .args(["approval", "replay", request_id, "--json"])
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(
        replay.get("request_id").and_then(|value| value.as_str()),
        Some(request_id)
    );
    assert_eq!(
        replay.get("conclusion").and_then(|value| value.as_str()),
        Some("still_requires_same_scope")
    );
    for name in [
        "key.ed25519",
        "pictos.sqlite",
        "pictos.sqlite-wal",
        "pictos.sqlite-shm",
    ] {
        assert!(
            !home.join(name).exists(),
            "approval replay recreated read-only state {name}"
        );
    }

    let evidence_path = temp.path().join("approval-evidence.json");
    let evidence = gommage(&home)
        .args([
            "approval",
            "evidence",
            request_id,
            "--redact",
            "--output",
            evidence_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        evidence.status.success(),
        "{}",
        String::from_utf8_lossy(&evidence.stderr)
    );
    let bundle: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(evidence_path).unwrap()).unwrap();
    assert_eq!(
        bundle.get("redacted").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        bundle
            .pointer("/state/request/id")
            .and_then(|value| value.as_str()),
        Some(request_id)
    );
    assert!(
        bundle
            .get("relevant_audit_entries")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry.to_string().contains("approval_requested"))
    );
    assert!(
        bundle
            .get("home")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("<gommage-home>")
    );
}

#[test]
fn approval_template_explains_ntfy_without_sending() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["approval", "template", "--provider", "ntfy", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("provider").and_then(|value| value.as_str()),
        Some("ntfy")
    );
    assert_eq!(
        report
            .pointer("/payload/topic")
            .and_then(|value| value.as_str()),
        Some("gommage-approvals")
    );
    assert!(
        report
            .get("notes")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|note| note
                .as_str()
                .unwrap()
                .contains("does not send ntfy directly"))
    );
}
