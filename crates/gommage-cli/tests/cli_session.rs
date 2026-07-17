mod support;

use std::fs;

use support::gommage;
use tempfile::tempdir;

#[test]
fn session_doctor_json_reports_gommage_wired_agent_processes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");
    fs::create_dir_all(&codex_home).unwrap();
    fs::create_dir_all(&claude_home).unwrap();
    let codex_hook = format!(
        "gommage --home '{}' hook --agent codex",
        fs::canonicalize(temp.path())
            .unwrap()
            .join(".gommage")
            .display()
    );
    fs::write(
        codex_home.join("hooks.json"),
        serde_json::to_vec(&serde_json::json!({
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{"type": "command", "command": codex_hook}],
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        codex_home.join("config.toml"),
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();
    let claude_hook = format!(
        "gommage --home '{}' hook --agent claude",
        fs::canonicalize(temp.path())
            .unwrap()
            .join(".gommage")
            .display()
    );
    fs::write(
        claude_home.join("settings.json"),
        serde_json::to_vec(&serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "*",
                "hooks": [{"type": "command", "command": claude_hook}],
            }]},
        }))
        .unwrap(),
    )
    .unwrap();
    let process_table = format!(
        "100 /Applications/Claude.app/Contents/MacOS/Claude\n101 CODEX_HOME={} codex exec audit\n102 CLAUDE_HOME={} claude\n103 /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper --type=gpu-process\n104 /Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler --database=/Users/example/Library/Application Support/Claude/Crashpad\n",
        codex_home.display(),
        claude_home.display()
    );

    let output = gommage(&home)
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_HOME", &claude_home)
        .env("GOMMAGE_SESSION_PROCESS_TABLE", process_table)
        .args(["session", "doctor", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("ok"));
    assert_eq!(report["summary"]["agent_processes"].as_u64(), Some(2));
    assert_eq!(report["summary"]["protected_processes"].as_u64(), Some(2));
    assert_eq!(
        report["process_source"].as_str(),
        Some("GOMMAGE_SESSION_PROCESS_TABLE")
    );
    assert!(
        report["processes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|process| {
                process["hook_status"].as_str() == Some("ok")
                    && process["hook_report"]["summary"]["failures"].as_u64() == Some(0)
            })
    );
}
