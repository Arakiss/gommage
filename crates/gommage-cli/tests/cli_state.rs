mod support;

use std::{io::Write, process::Stdio};
use support::gommage;
use tempfile::tempdir;

fn init_home(home: &std::path::Path) {
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

fn write_audit_fixture(home: &std::path::Path) {
    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let output = run_mcp(home, payload);
    assert_eq!(
        output
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );
}

#[test]
fn state_rebuild_verify_and_stats_index_signed_audit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home(&home);
    write_audit_fixture(&home);

    let rebuild = gommage(&home)
        .args(["state", "rebuild", "--json"])
        .output()
        .unwrap();
    assert!(
        rebuild.status.success(),
        "{}",
        String::from_utf8_lossy(&rebuild.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&rebuild.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("ok"));
    assert_eq!(report["source_of_truth"].as_str(), Some("audit.log"));
    assert_eq!(report["indexed"]["audit_entries"].as_u64(), Some(2));
    assert_eq!(report["indexed"]["decisions"].as_u64(), Some(1));
    assert_eq!(report["indexed"]["events"].as_u64(), Some(1));
    assert_eq!(report["indexed"]["asks"].as_u64(), Some(1));
    assert_eq!(report["indexed"]["approval_requests"].as_u64(), Some(1));
    assert!(home.join("state.sqlite").exists());

    let verify = gommage(&home)
        .args(["state", "verify", "--json"])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("ok"));
    assert_eq!(report["current"].as_bool(), Some(true));
    assert_eq!(report["entries_indexed"].as_u64(), Some(2));

    let stats = gommage(&home)
        .args(["state", "stats", "--json"])
        .output()
        .unwrap();
    assert!(
        stats.status.success(),
        "{}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("ok"));
    assert_eq!(report["current"].as_bool(), Some(true));
    assert_eq!(report["counters"]["audit_entries"].as_u64(), Some(2));
    assert_eq!(report["counters"]["approval_requests"].as_u64(), Some(1));
}

#[test]
fn state_verify_warns_when_audit_changes_after_rebuild() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home(&home);
    write_audit_fixture(&home);
    assert!(
        gommage(&home)
            .args(["state", "rebuild"])
            .status()
            .unwrap()
            .success()
    );

    let grant = gommage(&home)
        .args([
            "grant",
            "--scope",
            "git.push:main",
            "--ttl",
            "10m",
            "--uses",
            "1",
            "--reason",
            "stale state test",
        ])
        .output()
        .unwrap();
    assert!(
        grant.status.success(),
        "{}",
        String::from_utf8_lossy(&grant.stderr)
    );

    let verify = gommage(&home)
        .args(["state", "verify", "--json"])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("warn"));
    assert_eq!(report["current"].as_bool(), Some(false));
    assert!(
        report["reason"]
            .as_str()
            .unwrap()
            .contains("audit.log changed")
    );
}

#[test]
fn state_reset_removes_only_rebuildable_index() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home(&home);
    write_audit_fixture(&home);
    assert!(
        gommage(&home)
            .args(["state", "rebuild"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        gommage(&home)
            .args(["state", "vacuum"])
            .status()
            .unwrap()
            .success()
    );

    let dry_run = gommage(&home)
        .args(["state", "reset", "--dry-run"])
        .output()
        .unwrap();
    assert!(dry_run.status.success());
    assert!(home.join("state.sqlite").exists());

    let reset = gommage(&home).args(["state", "reset"]).output().unwrap();
    assert!(
        reset.status.success(),
        "{}",
        String::from_utf8_lossy(&reset.stderr)
    );
    assert!(!home.join("state.sqlite").exists());
    assert!(home.join("audit.log").exists());
}

#[test]
fn tui_stream_uses_state_index_when_current() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home(&home);
    write_audit_fixture(&home);
    assert!(
        gommage(&home)
            .args(["state", "rebuild"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home)
        .args([
            "tui",
            "--stream",
            "--stream-ticks",
            "1",
            "--stream-limit",
            "8",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("source: state.sqlite"));
    assert!(stdout.contains("approval requested apr_"));
    assert!(stdout.contains("decision ask_picto"));
}
