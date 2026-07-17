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

fn first_pending_request_id(home: &std::path::Path) -> String {
    let output = gommage(home)
        .args(["approval", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let approvals: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    approvals[0]["request"]["id"].as_str().unwrap().to_string()
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

#[path = "cli_approval/callbacks.rs"]
mod callbacks;
#[path = "cli_approval/evidence.rs"]
mod evidence;
#[path = "cli_approval/lifecycle.rs"]
mod lifecycle;
#[path = "cli_approval/webhooks.rs"]
mod webhooks;
