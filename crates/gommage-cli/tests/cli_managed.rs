mod support;

use std::fs;

use support::gommage;
use tempfile::tempdir;

#[test]
fn managed_status_json_reports_user_mode_without_isolation_claims() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");
    fs::create_dir_all(&codex_home).unwrap();
    fs::create_dir_all(&claude_home).unwrap();
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
    fs::write(
        claude_home.join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*","hooks":[{"type":"command","command":"gommage hook --agent claude"}]}]}}"#,
    )
    .unwrap();
    assert!(gommage(&home).arg("init").status().unwrap().success());

    let output = gommage(&home)
        .env("HOME", temp.path())
        .env("GOMMAGE_CODEX_HOOKS", codex_home.join("hooks.json"))
        .env("GOMMAGE_CODEX_CONFIG", codex_home.join("config.toml"))
        .env("GOMMAGE_CLAUDE_SETTINGS", claude_home.join("settings.json"))
        .args(["managed", "status", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("warn"));
    assert_eq!(report["mode"].as_str(), Some("user_level"));
    assert_eq!(report["status_requires_root"].as_bool(), Some(false));
    assert_eq!(report["isolation"].as_str(), Some("none"));
    assert_eq!(report["tamper_resistance"].as_str(), Some("none"));
    assert_eq!(report["reference_ready"].as_bool(), Some(false));
    assert!(report.get("root_required").is_none());
    assert_eq!(report["summary"]["failures"].as_u64(), Some(0));
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["name"].as_str() == Some("user_daemon_service_file")
            && check["status"].as_str() == Some("warn")
    }));
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["name"].as_str() == Some("key_permissions") && check["status"].as_str() == Some("ok")
    }));
}
