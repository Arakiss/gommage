use super::*;

#[test]
fn approval_webhook_dry_run_json_includes_provider_payloads() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);

    let generic = gommage(&home)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://approval.example.invalid/hook",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        generic.status.success(),
        "{}",
        String::from_utf8_lossy(&generic.stderr)
    );
    let generic: serde_json::Value = serde_json::from_slice(&generic.stdout).unwrap();
    assert_eq!(generic["requests"][0]["status"].as_str(), Some("dry_run"));
    assert_eq!(
        generic["requests"][0]["payload"]["kind"].as_str(),
        Some("gommage_approval_request")
    );
    let created_at = generic["requests"][0]["payload"]["created_at"]
        .as_str()
        .unwrap();
    assert!(created_at.contains('T'));
    assert!(created_at.ends_with('Z'));

    let slack = gommage(&home)
        .args([
            "approval",
            "webhook",
            "--provider",
            "slack",
            "--url",
            "https://approval.example.invalid/slack",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(slack.status.success());
    let slack: serde_json::Value = serde_json::from_slice(&slack.stdout).unwrap();
    assert!(slack["requests"][0]["payload"]["blocks"].is_array());

    let discord = gommage(&home)
        .args([
            "approval",
            "webhook",
            "--provider",
            "discord",
            "--url",
            "https://approval.example.invalid/discord",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(discord.status.success());
    let discord: serde_json::Value = serde_json::from_slice(&discord.stdout).unwrap();
    assert!(discord["requests"][0]["payload"]["embeds"].is_array());
}

#[test]
fn approval_webhook_dry_run_json_includes_signature_metadata() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);

    let output = gommage(&home)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://approval.example.invalid/hook",
            "--dry-run",
            "--json",
            "--signing-secret",
            "test-secret",
            "--signing-key-id",
            "local-test",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = &report["requests"][0];
    assert_eq!(
        request["signature"]["algorithm"].as_str(),
        Some("hmac-sha256")
    );
    assert_eq!(request["signature"]["key_id"].as_str(), Some("local-test"));
    assert!(
        request["signature"]["signature"]
            .as_str()
            .unwrap()
            .starts_with("v1=")
    );
    assert!(
        request["body"]
            .as_str()
            .unwrap()
            .contains("gommage_approval_request")
    );
    let headers = request["signature"]["headers"].as_array().unwrap();
    assert!(headers.iter().any(|header| {
        header["name"].as_str() == Some("x-gommage-signature")
            && header["value"].as_str().unwrap().starts_with("v1=")
    }));
}

#[test]
#[cfg(unix)]
fn approval_webhook_posts_pending_payloads_with_curl() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let (fake_bin, capture) = fake_curl(&temp);
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("PATH", path)
        .env("GOMMAGE_FAKE_CURL_CAPTURE", &capture)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://approval.example.test/hook",
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
    assert_eq!(report.get("sent").and_then(|value| value.as_u64()), Some(1));
    assert_eq!(
        report
            .pointer("/requests/0/http_status")
            .and_then(|value| value.as_i64()),
        Some(202)
    );
    let captured = fs::read_to_string(capture).unwrap();
    assert!(captured.contains(r#""kind":"gommage_approval_request""#));
    assert!(captured.contains(r#""approve":"gommage approval approve apr_"#));
    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains(r#""type":"approval_webhook_delivered""#));
}

#[test]
#[cfg(unix)]
fn approval_webhook_posts_signature_headers_and_audits_metadata() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let (fake_bin, capture) = fake_curl(&temp);
    let args_capture = temp.path().join("curl-args.txt");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("PATH", path)
        .env("GOMMAGE_FAKE_CURL_CAPTURE", &capture)
        .env("GOMMAGE_FAKE_CURL_ARGS", &args_capture)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://approval.example.test/hook",
            "--json",
            "--signing-secret",
            "test-secret",
            "--signing-key-id",
            "local-test",
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
        report["requests"][0]["signature"]["key_id"].as_str(),
        Some("local-test")
    );
    let args = fs::read_to_string(args_capture).unwrap();
    assert!(args.contains("x-gommage-signature: v1="));
    assert!(args.contains("x-gommage-signature-key-id: local-test"));
    let body = fs::read_to_string(capture).unwrap();
    assert!(body.contains(r#""kind":"gommage_approval_request""#));
    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains(r#""type":"approval_webhook_delivered""#));
    assert!(audit.contains(r#""signature_prefix":"v1="#));
    assert!(audit.contains(r#""key_id":"local-test""#));
}

#[test]
#[cfg(unix)]
fn approval_webhook_can_shape_slack_payloads() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let (fake_bin, capture) = fake_curl(&temp);
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("PATH", path)
        .env("GOMMAGE_FAKE_CURL_CAPTURE", &capture)
        .args([
            "approval",
            "webhook",
            "--provider",
            "slack",
            "--url",
            "https://hooks.slack.test/services/example",
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
    assert_eq!(
        report.get("provider").and_then(|value| value.as_str()),
        Some("slack")
    );
    let captured = fs::read_to_string(capture).unwrap();
    assert!(captured.contains(r#""text":"Gommage approval required"#));
    assert!(captured.contains(r#""blocks""#));
    assert!(captured.contains("exact tool input"));
}

#[test]
#[cfg(unix)]
fn approval_webhook_dead_letters_after_retry_exhaustion() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let (fake_bin, capture) = failing_curl(&temp);
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("PATH", path)
        .env("GOMMAGE_FAKE_CURL_CAPTURE", &capture)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://approval.example.test/hook",
            "--json",
            "--attempts",
            "2",
            "--backoff-ms",
            "1",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("failed").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        report["requests"][0]["status"].as_str(),
        Some("dead_lettered")
    );
    assert_eq!(report["requests"][0]["attempts"].as_u64(), Some(2));
    assert!(
        report["requests"][0]["dead_letter_id"]
            .as_str()
            .unwrap()
            .starts_with("dlq_")
    );
    assert!(
        report["requests"][0]["error"]
            .as_str()
            .unwrap()
            .contains("simulated failure")
    );
    let body = fs::read_to_string(capture).unwrap();
    assert!(body.contains(r#""kind":"gommage_approval_request""#));

    let dlq = gommage(&home)
        .args(["approval", "dlq", "--json"])
        .output()
        .unwrap();
    assert!(dlq.status.success());
    let dlq: serde_json::Value = serde_json::from_slice(&dlq.stdout).unwrap();
    assert_eq!(dlq["count"].as_u64(), Some(1));
    assert_eq!(dlq["entries"][0]["attempts"].as_u64(), Some(2));
    assert_eq!(dlq["entries"][0]["source"].as_str(), Some("cli"));
    assert_eq!(dlq["entries"][0]["provider"].as_str(), Some("generic"));
    assert!(
        dlq["entries"][0]["body"]
            .as_str()
            .unwrap()
            .contains("gommage_approval_request")
    );

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains(r#""type":"approval_webhook_failed""#));
    assert!(audit.contains(r#""type":"approval_webhook_dead_lettered""#));
}
