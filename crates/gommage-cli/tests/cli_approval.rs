mod support;

use gommage_core::webhook_signature::sign_webhook_body;
use std::{fs, io::Write, process::Stdio};
use support::gommage;
use tempfile::tempdir;

fn setup_home(home: &std::path::Path) {
    assert!(gommage(home).arg("init").status().unwrap().success());
    assert!(
        gommage(home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
}

fn write_stale_approvals(home: &std::path::Path, count: usize) {
    let approvals_log = home.join("approvals.jsonl");
    let mut lines = String::new();
    for index in 0..count {
        let created_at = time::OffsetDateTime::now_utc()
            - time::Duration::hours(25)
            - time::Duration::minutes(index as i64);
        lines.push_str(&format!(
            "{{\"type\":\"requested\",\"request\":{{\"id\":\"apr_stale_{index:02}\",\"created_at\":\"{}\",\"tool\":\"Bash\",\"input_hash\":\"sha256:stale-{index:02}\",\"required_scope\":\"git.push:main\",\"reason\":\"stale request\",\"capabilities\":[],\"matched_rule\":null,\"policy_version\":\"sha256:p\"}}}}\n",
            created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ));
    }
    fs::write(approvals_log, lines).unwrap();
}

fn run_mcp(home: &std::path::Path, payload: &[u8]) -> serde_json::Value {
    let mut child = gommage(home)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(payload).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(unix)]
fn fake_curl(temp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let capture = temp.path().join("webhook-payload.json");
    let script = bin.join("curl");
    fs::write(
        &script,
        "#!/bin/sh\nif [ -n \"${GOMMAGE_FAKE_CURL_ARGS:-}\" ]; then printf '%s\n' \"$@\" > \"$GOMMAGE_FAKE_CURL_ARGS\"; fi\ncat > \"$GOMMAGE_FAKE_CURL_CAPTURE\"\nprintf 202\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();
    (bin, capture)
}

#[cfg(unix)]
fn failing_curl(temp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let bin = temp.path().join("bin-fail");
    fs::create_dir_all(&bin).unwrap();
    let capture = temp.path().join("webhook-failure.json");
    let script = bin.join("curl");
    fs::write(
        &script,
        "#!/bin/sh\nif [ -n \"${GOMMAGE_FAKE_CURL_ARGS:-}\" ]; then printf '%s\n' \"$@\" > \"$GOMMAGE_FAKE_CURL_ARGS\"; fi\ncat > \"$GOMMAGE_FAKE_CURL_CAPTURE\"\nprintf 'curl: (22) simulated failure\\n' >&2\nexit 22\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();
    (bin, capture)
}

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
        Some("mcp.write")
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
        Some("mcp.write")
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
    assert_eq!(
        approved
            .pointer("/picto/kind")
            .and_then(|value| value.as_str()),
        Some("scope_only")
    );
    assert_eq!(
        approved
            .pointer("/picto/authorizes")
            .and_then(|value| value.as_str()),
        Some("any_matching_call_in_scope")
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
        Some("mcp.write")
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
}

#[test]
fn scope_only_probe_consumes_the_only_use_before_the_intended_retry() {
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
    assert_eq!(approved["picto"]["kind"], "scope_only");
    assert_eq!(
        approved["picto"]["authorizes"],
        "any_matching_call_in_scope"
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
        Some("allow")
    );

    let retry = run_mcp(&home, intended_payload);
    assert_eq!(
        retry
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );
    assert!(
        retry
            .pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("approval request apr_")
    );
}

#[test]
fn input_bound_approval_does_not_unlock_a_different_mcp_write() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    fs::write(
        home.join("policy.d/00-input-bound-mcp.yaml"),
        r#"
- name: input-bound-mcp-write
  decision: ask_picto
  required_scope: "mcp.write"
  bind_input: true
  match:
    any_capability:
      - "mcp.write:*"
  reason: "this write needs approval for its exact input"
"#,
    )
    .unwrap();

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

#[test]
fn signed_approval_callback_dry_run_and_apply_approve_pending_request() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    setup_home(&home);
    fs::write(
        home.join("policy.d/00-input-bound-mcp.yaml"),
        r#"
- name: input-bound-mcp-write
  decision: ask_picto
  required_scope: "mcp.write"
  bind_input: true
  match:
    any_capability:
      - "mcp.write:*"
  reason: "this write needs approval for its exact input"
"#,
    )
    .unwrap();

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
    assert!(list_stdout.contains("  scope:  mcp.write"));
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
    assert!(show_stdout.contains("- mcp.write"));
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
    assert!(approve_stdout.contains("scope:   mcp.write"));
    assert!(approve_stdout.contains("Picto minted"));
    assert!(approve_stdout.contains("kind:    scope-only"));
    assert!(approve_stdout.contains("binding: scope only — not tied to the request input hash"));
    assert!(
        approve_stdout.contains("spends:  one use per matching call; non-matches do not consume")
    );
    assert!(approve_stdout.contains("next:    retry the intended blocked call directly"));
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
    fs::write(
        home.join("policy.d/00-input-bound-mcp.yaml"),
        r#"
- name: input-bound-mcp-write
  decision: ask_picto
  required_scope: "mcp.write"
  bind_input: true
  match:
    any_capability:
      - "mcp.write:*"
  reason: "this write needs approval for its exact input"
"#,
    )
    .unwrap();

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
