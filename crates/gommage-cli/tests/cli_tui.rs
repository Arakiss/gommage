mod support;

use support::gommage;
use tempfile::tempdir;

#[test]
fn tui_snapshot_is_plain_and_actionable_preinit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");
    let codex_hooks = temp.path().join("codex-hooks.json");
    let codex_config = temp.path().join("codex-config.toml");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .env("GOMMAGE_CODEX_HOOKS", &codex_hooks)
        .env("GOMMAGE_CODEX_CONFIG", &codex_config)
        .args(["tui", "--snapshot"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gommage dashboard"));
    assert!(stdout.contains("version:"));
    assert!(stdout.contains("status: fail"));
    assert!(stdout.contains("summary: 4 check(s): 0 ok, 0 warn, 3 fail, 1 skip"));
    assert!(stdout.contains("focus: doctor [fail]"));
    assert!(stdout.contains("readiness:"));
    assert!(stdout.contains("- doctor [fail]"));
    assert!(stdout.contains("- smoke [skip]"));
    assert!(stdout.contains("- agent claude [fail]"));
    assert!(stdout.contains("- agent codex [fail]"));
    assert!(stdout.contains("gommage quickstart --agent claude --daemon --self-test"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_snapshot_respects_agent_filter_and_deduplicates() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .args([
            "tui",
            "--snapshot",
            "--agent",
            "claude",
            "--agent",
            "claude",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("- agent claude").count(), 1);
    assert!(!stdout.contains("- agent codex"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_snapshot_reports_initialized_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let claude_settings = temp.path().join("claude-settings.json");

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &claude_settings)
        .args(["tui", "--snapshot", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("home:"));
    assert!(stdout.contains(&home.to_string_lossy().to_string()));
    assert!(stdout.contains("summary:"));
    assert!(stdout.contains("focus:"));
    assert!(stdout.contains("- doctor ["));
    assert!(stdout.contains("- smoke ["));
    assert!(stdout.contains("- agent claude [fail]"));
    assert!(stdout.contains("gommage verify --json"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_help_lists_snapshot_and_refresh_controls() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["tui", "--help"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--snapshot"));
    assert!(stdout.contains("--agent"));
    assert!(stdout.contains("--refresh-ms"));
}
