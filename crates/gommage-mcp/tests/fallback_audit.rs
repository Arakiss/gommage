use gommage_audit::{explain_log, verify_log};
use gommage_core::runtime::HomeLayout;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};
use tempfile::tempdir;

fn copy_yaml_files(from: &std::path::Path, to: &std::path::Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
        }
    }
}

#[cfg(unix)]
fn fake_curl(temp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let capture = temp.path().join("webhook.json");
    let script = bin.join("curl");
    fs::write(
        &script,
        "#!/bin/sh\ncat > \"$GOMMAGE_FAKE_CURL_CAPTURE\"\nprintf 204\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();
    (bin, capture)
}

#[test]
fn fallback_path_writes_signed_audit_entry_when_daemon_is_absent() {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    layout.ensure().unwrap();

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    copy_yaml_files(&repo_root.join("policies"), &layout.policy_dir);
    copy_yaml_files(&repo_root.join("capabilities"), &layout.capabilities_dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", &layout.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""permissionDecision":"ask""#));
    assert!(stdout.contains("approval request apr_"));
    assert_eq!(
        verify_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap(),
        2
    );
    let approvals = fs::read_to_string(&layout.approvals_log).unwrap();
    assert!(approvals.contains(r#""required_scope":"git.push:main""#));
}

#[test]
#[cfg(unix)]
fn fallback_path_can_notify_approval_webhook_best_effort() {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    layout.ensure().unwrap();

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    copy_yaml_files(&repo_root.join("policies"), &layout.policy_dir);
    copy_yaml_files(&repo_root.join("capabilities"), &layout.capabilities_dir);
    let (fake_bin, capture) = fake_curl(&temp);
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", &layout.root)
        .env("GOMMAGE_APPROVAL_WEBHOOK_URL", "https://example.test/hook")
        .env("GOMMAGE_FAKE_CURL_CAPTURE", &capture)
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let captured = fs::read_to_string(capture).unwrap();
    assert!(captured.contains(r#""kind":"gommage_approval_request""#));
    let audit = fs::read_to_string(&layout.audit_log).unwrap();
    assert!(audit.contains(r#""type":"approval_webhook_delivered""#));
    assert_eq!(
        verify_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap(),
        3
    );
}

#[test]
fn version_flag_does_not_read_hook_json_from_stdin() {
    let output = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("gommage-mcp "));
}

#[test]
fn bypass_env_allows_without_home_or_valid_hook_json() {
    let temp = tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", temp.path().join("missing-home"))
        .env("GOMMAGE_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""permissionDecision":"allow""#));
    assert!(stdout.contains("GOMMAGE_BYPASS=1"));
    assert!(!temp.path().join("missing-home").exists());
}

#[test]
fn bypass_env_does_not_bypass_hard_stops() {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    layout.ensure().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", &layout.root)
        .env("GOMMAGE_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""permissionDecision":"deny""#));
    assert!(stdout.contains("hard-stops cannot be bypassed"));
    assert_eq!(
        verify_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap(),
        1
    );
    let report = explain_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap();
    assert_eq!(report.bypass_activations, 1);
    assert_eq!(report.hard_stop_bypass_attempts, 1);
    assert!(report.anomalies.is_empty());
}

#[test]
fn quoted_hardstop_fixture_data_is_not_reported_as_hardstop() {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    layout.ensure().unwrap();

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    copy_yaml_files(&repo_root.join("policies"), &layout.policy_dir);
    copy_yaml_files(&repo_root.join("capabilities"), &layout.capabilities_dir);

    let mut child = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", &layout.root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo '{\"tool_input\":{\"command\":\"rm -rf /\"}}' | gommage-mcp"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""permissionDecision":"deny""#));
    assert!(
        !stdout.contains("hard-stop"),
        "quoted fixture data must not trigger hard-stop output: {stdout}"
    );
}

#[test]
fn bypass_env_allows_non_hardstop_and_audits_when_home_has_key() {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    layout.ensure().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_gommage-mcp"))
        .env("GOMMAGE_HOME", &layout.root)
        .env("GOMMAGE_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#""permissionDecision":"allow""#));
    assert!(stdout.contains("hard-stop check"));
    let report = explain_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap();
    assert_eq!(report.entries_verified, 1);
    assert_eq!(report.bypass_activations, 1);
    assert_eq!(report.hard_stop_bypass_attempts, 0);
    assert!(report.anomalies.is_empty());
}
