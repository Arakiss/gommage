mod support;

use std::fs;

use support::gommage;
use tempfile::tempdir;

#[test]
fn run_codex_dry_run_json_reports_verified_launch_plan() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let codex_home = temp.path().join("codex-home");
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(
        codex_home.join("hooks.json"),
        r#"{"PreToolUse":[{"matcher":"^Bash$|^apply_patch$|^mcp__.*$","hooks":[{"type":"command","command":"gommage hook --agent codex"}]}]}"#,
    )
    .unwrap();
    fs::write(
        codex_home.join("config.toml"),
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("CODEX_HOME", &codex_home)
        .args([
            "run",
            "codex",
            "--dry-run",
            "--json",
            "--sandbox",
            "workspace-write",
            "--",
            "audit",
            "this",
            "repo",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("ok"));
    assert_eq!(report["agent"].as_str(), Some("codex"));
    assert_eq!(report["dry_run"].as_bool(), Some(true));
    assert_eq!(report["sandbox"].as_str(), Some("workspace-write"));
    assert_eq!(
        report["argv"].as_array().unwrap(),
        &vec![
            serde_json::json!("exec"),
            serde_json::json!("--sandbox"),
            serde_json::json!("workspace-write"),
            serde_json::json!("audit"),
            serde_json::json!("this"),
            serde_json::json!("repo"),
        ]
    );
    assert_eq!(
        report["hook_report"]["summary"]["failures"].as_u64(),
        Some(0)
    );
}
