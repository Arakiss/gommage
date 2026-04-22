mod support;

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
        "#!/bin/sh\ncat > \"$GOMMAGE_FAKE_CURL_CAPTURE\"\nprintf 202\n",
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
    assert!(
        approved
            .get("picto_id")
            .and_then(|value| value.as_str())
            .unwrap()
            .starts_with("picto_")
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
