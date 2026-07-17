use super::*;

#[test]
fn signed_approval_callback_dry_run_and_apply_approve_pending_request() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let webhook = gommage(&home)
        .args([
            "approval",
            "webhook",
            "--url",
            "https://example.invalid/gommage",
            "--dry-run",
            "--json",
            "--signing-secret",
            "secret",
        ])
        .output()
        .unwrap();
    assert!(
        webhook.status.success(),
        "{}",
        String::from_utf8_lossy(&webhook.stderr)
    );
    let rendered: serde_json::Value = serde_json::from_slice(&webhook.stdout).unwrap();
    let request = &rendered["requests"][0]["payload"];
    assert_eq!(request["bind_input"].as_bool(), Some(true));
    let request_id = request["id"].as_str().unwrap();
    let nonce = request["callback"]["nonce"].as_str().unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "kind": "gommage_approval_callback",
        "request_id": request_id,
        "action": "approve",
        "nonce": nonce,
        "reason": "signed callback test",
        "ttl": 600,
        "uses": 1
    }))
    .unwrap();
    let body_file = temp.path().join("callback.json");
    fs::write(&body_file, &body).unwrap();
    let signature = sign_webhook_body(&body, "secret", None);

    let dry_run = gommage(&home)
        .args([
            "approval",
            "callback",
            "--body",
            body_file.to_str().unwrap(),
            "--signature",
            &signature.signature,
            "--timestamp",
            &signature.timestamp,
            "--signing-secret",
            "secret",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_report: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_report["status"].as_str(), Some("valid"));
    assert_eq!(dry_report["nonce_match"].as_bool(), Some(true));
    assert_eq!(dry_report["pending"].as_bool(), Some(true));

    let apply = gommage(&home)
        .args([
            "approval",
            "callback",
            "--body",
            body_file.to_str().unwrap(),
            "--signature",
            &signature.signature,
            "--timestamp",
            &signature.timestamp,
            "--signing-secret",
            "secret",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert_eq!(applied["status"].as_str(), Some("applied"));
    assert_eq!(applied["outcome"]["status"].as_str(), Some("approved"));
    assert_eq!(applied["outcome"]["request_id"].as_str(), Some(request_id));
    assert_eq!(
        applied["outcome"]["picto"]["kind"].as_str(),
        Some("exact_input")
    );

    let allowed = run_mcp(&home, payload);
    assert_eq!(
        allowed
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("allow")
    );
}

#[test]
fn approval_human_output_is_scannable_for_operators() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);

    let list = gommage(&home).args(["approval", "list"]).output().unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8(list.stdout).unwrap();
    assert!(list_stdout.contains("Approval inbox"));
    assert!(list_stdout.contains("filter:   pending"));
    assert!(list_stdout.contains("requests: 1"));
    assert!(list_stdout.contains("  scope:  mcp.write:mcp__db__write_row"));
    assert!(list_stdout.contains("  next:   gommage approval show apr_"));

    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request_id = approvals[0]["request"]["id"].as_str().unwrap();

    let show = gommage(&home)
        .args(["approval", "show", request_id])
        .output()
        .unwrap();
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let show_stdout = String::from_utf8(show.stdout).unwrap();
    assert!(show_stdout.contains("Approval request"));
    assert!(show_stdout.contains("status:  pending"));
    assert!(show_stdout.contains("Capabilities"));
    assert!(show_stdout.contains("- mcp.write:mcp__db__write_row"));
    assert!(show_stdout.contains("approve: gommage approval approve apr_"));

    let approve = gommage(&home)
        .args([
            "approval", "approve", request_id, "--ttl", "10m", "--uses", "1",
        ])
        .output()
        .unwrap();
    assert!(
        approve.status.success(),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );
    let approve_stdout = String::from_utf8(approve.stdout).unwrap();
    assert!(approve_stdout.contains("Approval granted"));
    assert!(approve_stdout.contains("status:  approved"));
    assert!(approve_stdout.contains("scope:   mcp.write:mcp__db__write_row"));
    assert!(approve_stdout.contains("Picto minted"));
    assert!(approve_stdout.contains("kind:    exact-input"));
    assert!(approve_stdout.contains("binding: exact tool input only"));
    assert!(
        approve_stdout.contains("spends:  one use per matching call; non-matches do not consume")
    );
    assert!(approve_stdout.contains(
        "next:    retry the intended blocked call; only the exact-input match spends a use"
    ));
}

#[test]
fn approval_deny_removes_request_from_pending_work() {
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

    let deny = gommage(&home)
        .args([
            "approval",
            "deny",
            request_id,
            "--reason",
            "not enough context",
        ])
        .output()
        .unwrap();
    assert!(deny.status.success());

    let output = gommage(&home)
        .args(["approval", "list", "--status", "pending", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 0);

    let audit = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains(r#""status":"denied""#));
}

#[test]
fn approval_deny_stale_is_dry_run_until_apply() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let approvals_log = home.join("approvals.jsonl");
    let old = time::OffsetDateTime::now_utc() - time::Duration::hours(25);
    let fresh = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    fs::write(
        &approvals_log,
        format!(
            "{{\"type\":\"requested\",\"request\":{{\"id\":\"apr_old\",\"created_at\":\"{}\",\"tool\":\"Bash\",\"input_hash\":\"sha256:old\",\"required_scope\":\"git.push:main\",\"reason\":\"old request\",\"capabilities\":[],\"matched_rule\":null,\"policy_version\":\"sha256:p\"}}}}\n\
{{\"type\":\"requested\",\"request\":{{\"id\":\"apr_fresh\",\"created_at\":\"{}\",\"tool\":\"Bash\",\"input_hash\":\"sha256:fresh\",\"required_scope\":\"pkg.cargo:install\",\"reason\":\"fresh request\",\"capabilities\":[],\"matched_rule\":null,\"policy_version\":\"sha256:p\"}}}}\n",
            old.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            fresh
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ),
    )
    .unwrap();

    let dry_run = gommage(&home)
        .args(["approval", "deny-stale", "--older-than", "24h", "--json"])
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run_report: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_run_report["matched"].as_u64(), Some(1));
    assert_eq!(dry_run_report["denied"].as_u64(), Some(0));
    assert_eq!(
        dry_run_report["requests"][0]["id"].as_str(),
        Some("apr_old")
    );

    let pending_after_dry_run = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending_after_dry_run.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 2);

    let applied = gommage(&home)
        .args([
            "approval",
            "deny-stale",
            "--older-than",
            "24h",
            "--apply",
            "--reason",
            "test stale cleanup",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied_report: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied_report["matched"].as_u64(), Some(1));
    assert_eq!(applied_report["denied"].as_u64(), Some(1));
    assert_eq!(
        applied_report["requests"][0]["status"].as_str(),
        Some("denied")
    );

    let pending_after_apply = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&pending_after_apply.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_eq!(pending[0]["request"]["id"].as_str(), Some("apr_fresh"));

    let all = gommage(&home)
        .args(["approval", "list", "--status", "all", "--json"])
        .output()
        .unwrap();
    let all: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    let old = all
        .as_array()
        .unwrap()
        .iter()
        .find(|state| state["request"]["id"].as_str() == Some("apr_old"))
        .unwrap();
    assert_eq!(old["status"].as_str(), Some("denied"));
    assert_eq!(
        old["resolution"]["reason"].as_str(),
        Some("test stale cleanup")
    );
}

#[test]
fn approval_deny_stale_human_output_is_capped_unless_show_all() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    write_stale_approvals(&home, 25);

    let capped = gommage(&home)
        .args(["approval", "deny-stale", "--older-than", "24h", "--apply"])
        .output()
        .unwrap();
    assert!(
        capped.status.success(),
        "{}",
        String::from_utf8_lossy(&capped.stderr)
    );
    let stdout = String::from_utf8(capped.stdout).unwrap();
    assert!(stdout.contains("matched: 25"));
    assert!(stdout.contains("denied:  25"));
    assert!(stdout.contains("apr_stale_24"));
    assert!(stdout.contains("apr_stale_05"));
    assert!(!stdout.contains("apr_stale_04"));
    assert!(!stdout.contains("apr_stale_00"));
    assert!(stdout.contains("omitted: 5 request(s)"));
    assert!(stdout.contains("--show-all"));
    assert!(stdout.contains("--json"));

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    write_stale_approvals(&home, 25);
    let show_all = gommage(&home)
        .args([
            "approval",
            "deny-stale",
            "--older-than",
            "24h",
            "--apply",
            "--show-all",
        ])
        .output()
        .unwrap();
    assert!(
        show_all.status.success(),
        "{}",
        String::from_utf8_lossy(&show_all.stderr)
    );
    let stdout = String::from_utf8(show_all.stdout).unwrap();
    assert!(stdout.contains("apr_stale_24"));
    assert!(stdout.contains("apr_stale_00"));
    assert!(!stdout.contains("omitted:"));

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    write_stale_approvals(&home, 25);
    let verbose = gommage(&home)
        .args(["approval", "deny-stale", "--older-than", "24h", "--verbose"])
        .output()
        .unwrap();
    assert!(
        verbose.status.success(),
        "{}",
        String::from_utf8_lossy(&verbose.stderr)
    );
    let stdout = String::from_utf8(verbose.stdout).unwrap();
    assert!(stdout.contains("apr_stale_24"));
    assert!(stdout.contains("apr_stale_00"));
    assert!(!stdout.contains("omitted:"));
    assert!(stdout.contains("next:    rerun with --apply"));
}

#[test]
fn approval_list_defaults_to_pending_and_exposes_top_level_fields() {
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
    assert!(output.status.success());
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 1);
    let request_id = pending[0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        pending[0]["request"]["id"].as_str(),
        Some(request_id.as_str())
    );
    let created_at = pending[0]["created_at"].as_str().unwrap();
    assert!(created_at.contains('T'));
    assert!(created_at.ends_with('Z'));

    let deny = gommage(&home)
        .args(["approval", "deny", &request_id])
        .output()
        .unwrap();
    assert!(deny.status.success());

    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 0);

    let output = gommage(&home)
        .args(["approval", "list", "--status", "all", "--json"])
        .output()
        .unwrap();
    let all: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(all.as_array().unwrap().len(), 1);
    assert_eq!(all[0]["status"].as_str(), Some("denied"));
}

#[test]
fn resolved_approval_can_be_requested_again() {
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
    let original_id = approvals[0]["request"]["id"].as_str().unwrap();

    let deny = gommage(&home)
        .args(["approval", "deny", original_id])
        .output()
        .unwrap();
    assert!(deny.status.success());

    let repeated = run_mcp(&home, payload);
    let reason = repeated
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(|value| value.as_str())
        .unwrap();
    assert!(reason.contains("approval request apr_"));

    let output = gommage(&home)
        .args(["approval", "list", "--status", "pending", "--json"])
        .output()
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_ne!(pending[0]["request"]["id"].as_str().unwrap(), original_id);
}
