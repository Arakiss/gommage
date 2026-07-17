use super::*;

#[test]
fn ask_picto_creates_approval_and_approval_mints_consumable_picto() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let ask = run_mcp(&home, payload);
    let reason = ask
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );
    assert!(reason.contains("approval request apr_"));

    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = approvals.as_array().unwrap().first().unwrap();
    let request_id = request
        .pointer("/request/id")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        request.pointer("/status").and_then(|value| value.as_str()),
        Some("pending")
    );
    assert_eq!(
        request
            .pointer("/request/required_scope")
            .and_then(|value| value.as_str()),
        Some("mcp.write:mcp__db__write_row")
    );
    assert_eq!(
        request
            .pointer("/request/bind_input")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let approve = gommage(&home)
        .args([
            "approval", "approve", request_id, "--ttl", "10m", "--uses", "1", "--json",
        ])
        .output()
        .unwrap();
    assert!(
        approve.status.success(),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );
    let approved: serde_json::Value = serde_json::from_slice(&approve.stdout).unwrap();
    assert_eq!(
        approved.get("status").and_then(|value| value.as_str()),
        Some("approved")
    );
    assert_eq!(
        approved
            .get("schema_version")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        approved.get("kind").and_then(|value| value.as_str()),
        Some("approval_action")
    );
    assert_eq!(
        approved.get("tool").and_then(|value| value.as_str()),
        Some("mcp__db__write_row")
    );
    assert_eq!(
        approved.get("scope").and_then(|value| value.as_str()),
        Some("mcp.write:mcp__db__write_row")
    );
    assert_eq!(
        approved.get("next_action").and_then(|value| value.as_str()),
        Some("retry_blocked_call")
    );
    assert!(
        approved
            .get("picto_id")
            .and_then(|value| value.as_str())
            .unwrap()
            .starts_with("picto_")
    );
    let approved_picto_id = approved["picto_id"].as_str().unwrap().to_string();
    assert_eq!(
        approved
            .pointer("/picto/kind")
            .and_then(|value| value.as_str()),
        Some("exact_input")
    );
    assert_eq!(
        approved
            .pointer("/picto/input_bound")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        approved
            .pointer("/picto/authorizes")
            .and_then(|value| value.as_str()),
        Some("only_the_exact_observed_tool_input")
    );
    assert_eq!(
        approved
            .pointer("/picto/consumption")
            .and_then(|value| value.as_str()),
        Some("one_use_per_matching_call")
    );
    assert_eq!(
        approved
            .pointer("/picto/matching_call_consumes_use")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        approved
            .pointer("/picto/non_matching_call_consumes_use")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        approved
            .pointer("/picto/scope")
            .and_then(|value| value.as_str()),
        Some("mcp.write:mcp__db__write_row")
    );
    assert_eq!(
        approved
            .pointer("/picto/max_uses")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        approved
            .pointer("/picto/uses_remaining")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert!(
        approved
            .pointer("/picto/expires_at")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains('T')
    );

    let listed = gommage(&home).args(["list", "--json"]).output().unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed[0]["binding"]["kind"], "exact_input");
    assert_eq!(
        listed[0]["binding"]["input_hash"],
        request["request"]["input_hash"]
    );

    let allowed = run_mcp(&home, payload);
    assert_eq!(
        allowed
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("allow")
    );

    let audit = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains(r#""type":"approval_requested""#));
    assert!(audit.contains(r#""type":"approval_resolved""#));
    assert!(audit.contains(r#""type":"picto_consumed""#));
    let allow_decision = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|entry| entry["tool"] == "mcp__db__write_row" && entry["decision"]["kind"] == "allow")
        .unwrap();
    let consumed_event = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|entry| entry["event"]["type"] == "picto_consumed")
        .unwrap();
    assert_eq!(
        allow_decision["authorization"]["picto_id"],
        approved_picto_id
    );
    assert_eq!(consumed_event["event"]["id"], approved_picto_id);
    assert_eq!(
        allow_decision["authorization"]["binding"]["kind"],
        "exact_input"
    );
    assert_eq!(
        allow_decision["authorization"]["binding"]["input_hash"],
        request["request"]["input_hash"]
    );
}

#[test]
fn approval_supersedes_stale_scope_without_minting_a_picto() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let request_id = first_pending_request_id(&home);

    let policy_path = home.join("policy.d/15-agent-tools.yaml");
    let policy = fs::read_to_string(&policy_path).unwrap();
    let changed = policy.replacen(
        "required_scope_from_capability: \"mcp.write:*\"",
        "required_scope: \"mcp.write.changed\"",
        1,
    );
    assert_ne!(changed, policy);
    fs::write(policy_path, changed).unwrap();

    let approve = gommage(&home)
        .args(["approval", "approve", &request_id, "--json"])
        .output()
        .unwrap();
    assert!(!approve.status.success());
    assert!(String::from_utf8_lossy(&approve.stderr).contains("was superseded"));

    let state = gommage(&home)
        .args(["approval", "show", &request_id, "--json"])
        .output()
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state.stdout).unwrap();
    assert_eq!(state["status"], "superseded");
    assert_eq!(state["resolution"]["picto_id"], serde_json::Value::Null);

    let pictos = gommage(&home).args(["list", "--json"]).output().unwrap();
    let pictos: serde_json::Value = serde_json::from_slice(&pictos.stdout).unwrap();
    assert_eq!(pictos, serde_json::json!([]));
}

#[test]
fn approval_supersedes_stale_binding_without_minting_a_picto() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let _ = run_mcp(&home, payload);
    let request_id = first_pending_request_id(&home);

    let policy_path = home.join("policy.d/15-agent-tools.yaml");
    let policy = fs::read_to_string(&policy_path).unwrap();
    let changed = policy.replacen("bind_input: true", "bind_input: false", 1);
    assert_ne!(changed, policy);
    fs::write(policy_path, changed).unwrap();

    let approve = gommage(&home)
        .args(["approval", "approve", &request_id, "--json"])
        .output()
        .unwrap();
    assert!(!approve.status.success());
    assert!(String::from_utf8_lossy(&approve.stderr).contains("was superseded"));

    let state = gommage(&home)
        .args(["approval", "show", &request_id, "--json"])
        .output()
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state.stdout).unwrap();
    assert_eq!(state["status"], "superseded");
    let pictos = gommage(&home).args(["list", "--json"]).output().unwrap();
    let pictos: serde_json::Value = serde_json::from_slice(&pictos.stdout).unwrap();
    assert_eq!(pictos, serde_json::json!([]));
}

#[test]
fn consumed_scope_picto_satisfies_matching_pending_request_and_signs_evidence() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com/docs"}}"#;
    let ask = run_mcp(&home, payload);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(serde_json::Value::as_str),
        Some("ask")
    );
    let request_id = first_pending_request_id(&home);

    let grant = gommage(&home)
        .args([
            "grant",
            "--scope",
            "net.fetch",
            "--uses",
            "1",
            "--reason",
            "approved exact retry window",
        ])
        .output()
        .unwrap();
    assert!(
        grant.status.success(),
        "{}",
        String::from_utf8_lossy(&grant.stderr)
    );
    let pictos = gommage(&home).args(["list", "--json"]).output().unwrap();
    let pictos: serde_json::Value = serde_json::from_slice(&pictos.stdout).unwrap();
    let granted_picto_id = pictos[0]["id"].as_str().unwrap().to_string();

    let allowed = run_mcp(&home, payload);
    assert_eq!(
        allowed
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(serde_json::Value::as_str),
        Some("allow")
    );
    let state = gommage(&home)
        .args(["approval", "show", &request_id, "--json"])
        .output()
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state.stdout).unwrap();
    assert_eq!(state["status"], "satisfied");
    assert_eq!(state["resolution"]["picto_id"], granted_picto_id);

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    let decision = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|entry| entry["tool"] == "WebFetch" && entry["decision"]["kind"] == "allow")
        .expect("allow decision is audited");
    assert_eq!(decision["v"], 3);
    assert_eq!(decision["authorization"]["picto_id"], granted_picto_id);
    assert_eq!(decision["authorization"]["scope"], "net.fetch");
    assert_eq!(decision["authorization"]["binding"]["kind"], "scope_only");
}

#[test]
fn scope_only_picto_authorizes_a_different_input_in_the_same_scope() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    let original = br#"{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com/original"}}"#;
    let different = br#"{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com/different"}}"#;

    let ask = run_mcp(&home, original);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(serde_json::Value::as_str),
        Some("ask")
    );
    let request_id = first_pending_request_id(&home);

    let grant = gommage(&home)
        .args([
            "grant",
            "--scope",
            "net.fetch",
            "--uses",
            "1",
            "--reason",
            "scope-only regression",
        ])
        .output()
        .unwrap();
    assert!(
        grant.status.success(),
        "{}",
        String::from_utf8_lossy(&grant.stderr)
    );

    let allowed = run_mcp(&home, different);
    assert_eq!(
        allowed
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(serde_json::Value::as_str),
        Some("allow")
    );

    let state = gommage(&home)
        .args(["approval", "show", &request_id, "--json"])
        .output()
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state.stdout).unwrap();
    assert_eq!(state["status"], "pending");

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    let records = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let request = records
        .iter()
        .find(|entry| entry["event"]["type"] == "approval_requested")
        .expect("original request is audited");
    let decision = records
        .iter()
        .find(|entry| entry["tool"] == "WebFetch" && entry["decision"]["kind"] == "allow")
        .expect("different input is allowed and audited");
    assert_ne!(request["event"]["input_hash"], decision["input_hash"]);
    assert_eq!(decision["authorization"]["binding"]["kind"], "scope_only");
}

#[test]
fn input_bound_probe_does_not_consume_the_only_use_before_the_intended_retry() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let intended_payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let probe_payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"probe"}}"#;
    let ask = run_mcp(&home, intended_payload);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );

    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request_id = approvals[0]["request"]["id"].as_str().unwrap();
    let approve = gommage(&home)
        .args([
            "approval", "approve", request_id, "--ttl", "10m", "--uses", "1", "--json",
        ])
        .output()
        .unwrap();
    assert!(approve.status.success());
    let approved: serde_json::Value = serde_json::from_slice(&approve.stdout).unwrap();
    assert_eq!(approved["picto"]["kind"], "exact_input");
    assert_eq!(
        approved["picto"]["authorizes"],
        "only_the_exact_observed_tool_input"
    );
    assert_eq!(
        approved["picto"]["consumption"],
        "one_use_per_matching_call"
    );
    assert_eq!(approved["picto"]["matching_call_consumes_use"], true);
    assert_eq!(approved["picto"]["non_matching_call_consumes_use"], false);

    let probe = run_mcp(&home, probe_payload);
    assert_eq!(
        probe
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );

    let retry = run_mcp(&home, intended_payload);
    assert_eq!(
        retry
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("allow")
    );
}

#[test]
fn input_bound_approval_does_not_unlock_a_different_mcp_write() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);

    let approved_payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let different_payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"accounts"}}"#;
    let ask = run_mcp(&home, approved_payload);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );

    let output = gommage(&home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request_id = approvals[0]["request"]["id"].as_str().unwrap();
    let approved = gommage(&home)
        .args([
            "approval", "approve", request_id, "--ttl", "10m", "--uses", "1", "--json",
        ])
        .output()
        .unwrap();
    assert!(approved.status.success());
    let approved: serde_json::Value = serde_json::from_slice(&approved.stdout).unwrap();
    assert_eq!(
        approved
            .pointer("/picto/kind")
            .and_then(|value| value.as_str()),
        Some("exact_input")
    );
    assert_eq!(
        approved
            .pointer("/picto/input_bound")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        approved
            .pointer("/picto/authorizes")
            .and_then(|value| value.as_str()),
        Some("only_the_exact_observed_tool_input")
    );
    assert_eq!(approved["picto"]["matching_call_consumes_use"], true);
    assert_eq!(approved["picto"]["non_matching_call_consumes_use"], false);

    let different = run_mcp(&home, different_payload);
    assert_eq!(
        different
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );

    let webhook = gommage(&home)
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
    assert!(webhook.status.success());
    let webhook: serde_json::Value = serde_json::from_slice(&webhook.stdout).unwrap();
    assert_eq!(
        webhook
            .pointer("/requests/0/payload/bind_input")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let allowed = run_mcp(&home, approved_payload);
    assert_eq!(
        allowed
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("allow")
    );
}
