use gommage_audit::verify_log;
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
    assert_eq!(
        verify_log(&layout.audit_log, &layout.load_verifying_key().unwrap()).unwrap(),
        1
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
