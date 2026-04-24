mod support;

use std::{io::Write, process::Stdio};
use support::gommage;
use tempfile::tempdir;

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
fn failing_curl(temp: &tempfile::TempDir) -> std::path::PathBuf {
    use std::{fs, os::unix::fs::PermissionsExt};
    let bin = temp.path().join("bin-fail");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("curl");
    fs::write(
        &script,
        "#!/bin/sh\ncat > /dev/null\nprintf 'curl: (22) simulated failure\\n' >&2\nexit 22\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();
    bin
}

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
    assert!(stdout.contains("--view"));
    assert!(stdout.contains("--watch"));
    assert!(stdout.contains("--watch-ticks"));
    assert!(stdout.contains("--stream"));
    assert!(stdout.contains("--stream-ticks"));
    assert!(stdout.contains("--refresh-ms"));
}

#[test]
fn tui_watch_ticks_prints_bounded_plain_frames() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args([
            "tui",
            "--watch",
            "--watch-ticks",
            "2",
            "--refresh-ms",
            "250",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("--- gommage tui frame").count(), 2);
    assert_eq!(stdout.matches("Gommage dashboard").count(), 2);
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_stream_ticks_prints_recent_decisions_without_ansi() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let ask = run_mcp(&home, payload);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );
    assert!(
        gommage(&home)
            .args([
                "grant",
                "--scope",
                "git.push:main",
                "--ttl",
                "10m",
                "--uses",
                "2",
                "--reason",
                "stream visibility test",
            ])
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
    assert!(stdout.contains("Gommage live decision stream"));
    assert!(stdout.contains("source: audit-log"));
    assert!(stdout.contains("daemon: warn - not reachable"));
    assert!(stdout.contains("pictos: 1 active"));
    assert!(stdout.contains("next active picto: picto_"));
    assert!(stdout.contains("metrics:"));
    assert!(stdout.contains("approval requested apr_"));
    assert!(stdout.contains("mcp__db__write_row"));
    assert!(stdout.contains("decision ask_picto"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_snapshot_metrics_reports_daemon_pictos_and_local_counters() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        gommage(&home)
            .args([
                "grant",
                "--scope",
                "git.push:main",
                "--ttl",
                "10m",
                "--uses",
                "1",
                "--reason",
                "metrics visibility test",
            ])
            .status()
            .unwrap()
            .success()
    );

    let output = gommage(&home)
        .args(["tui", "--snapshot", "--view", "metrics"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("operator:"));
    assert!(stdout.contains("daemon: warn - not reachable"));
    assert!(stdout.contains("pictos: 1 active"));
    assert!(stdout.contains("next active picto: picto_"));
    assert!(stdout.contains("metrics:"));
    assert!(stdout.contains("picto events: 1 created, 0 consumed, 0 rejected"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_snapshot_view_all_includes_operator_sections() {
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
        .args(["tui", "--snapshot", "--view", "all", "--agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("policies:"));
    assert!(stdout.contains("approvals:"));
    assert!(stdout.contains("- requests:"));
    assert!(stdout.contains("- policy files:"));
    assert!(stdout.contains("audit:"));
    assert!(stdout.contains("- approval requests:"));
    assert!(stdout.contains("capabilities:"));
    assert!(stdout.contains("- mapper rules:"));
    assert!(stdout.contains("recovery:"));
    assert!(stdout.contains("- pending approvals:"));
    assert!(stdout.contains("onboarding:"));
    assert!(stdout.contains("- safe first minute:"));
    assert!(stdout.contains("metrics:"));
    assert!(stdout.contains("- daemon:"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
#[cfg(unix)]
fn tui_snapshot_view_all_mentions_webhook_dead_letters() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let bin = failing_curl(&temp);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    let _ = run_mcp(
        &home,
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#,
    );
    let dead_letter = gommage(&home)
        .env("PATH", path)
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
    assert!(!dead_letter.status.success());

    let snapshot = gommage(&home)
        .args(["tui", "--snapshot", "--view", "all"])
        .output()
        .unwrap();

    assert!(snapshot.status.success());
    let stdout = String::from_utf8(snapshot.stdout).unwrap();
    assert!(stdout.contains("webhook dead letters: 1"));
    assert!(stdout.contains("gommage approval dlq --json"));
}

#[test]
fn tui_onboarding_snapshot_guides_first_minute() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["tui", "--snapshot", "--view", "onboarding"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("onboarding:"));
    assert!(stdout.contains("stage: pre-init or unhealthy"));
    assert!(stdout.contains("safe first minute:"));
    assert!(stdout.contains("gommage quickstart --agent claude --daemon --dry-run --json"));
    assert!(stdout.contains("gommage beta check --json --policy-test"));
    assert!(stdout.contains("gommage uninstall --all --restore-backup --dry-run"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn tui_approval_snapshot_lists_pending_requests() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    let payload =
        br#"{"hook_event_name":"PreToolUse","tool_name":"mcp__db__write_row","tool_input":{"table":"users"}}"#;
    let ask = run_mcp(&home, payload);
    assert_eq!(
        ask.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );

    let output = gommage(&home)
        .args(["tui", "--snapshot", "--view", "approvals"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("approvals:"));
    assert!(stdout.contains("requests: 1 pending"));
    assert!(stdout.contains("mcp__db__write_row"));
    assert!(stdout.contains("selected:"));
    assert!(stdout.contains("scope: mcp.write"));
    assert!(stdout.contains("created:"));
    assert!(stdout.contains("input: sha256:"));
    assert!(stdout.contains("capabilities:"));
    assert!(stdout.contains("current policy: ask_picto scope=mcp.write"));
    assert!(stdout.contains("current rule:"));
    assert!(stdout.contains("gommage approval evidence apr_"));
    assert!(stdout.contains("gommage approval approve apr_"));
    assert!(stdout.contains("gommage approval replay apr_"));
    assert!(!stdout.contains("\x1b["));
}
