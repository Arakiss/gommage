mod support;

use std::fs;
use support::{doctor_check, gommage};
use tempfile::tempdir;

#[test]
fn agent_uninstall_claude_removes_only_gommage_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/tmp/protect-files.sh" }
        ]
      },
      {
        "matcher": "Bash|Read",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "uninstall", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let pre_tool_use = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert!(
        pre_tool_use[0]
            .get("hooks")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|hook| hook.get("command").and_then(|value| value.as_str())
                == Some("/tmp/protect-files.sh"))
    );
}

#[test]
fn agent_uninstall_claude_can_restore_latest_valid_backup() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = "{\n  \"language\": \"spanish\"\n}\n";
    fs::write(&settings, original).unwrap();
    fs::write(
        settings.with_file_name("settings.json.gommage-bak-100"),
        original,
    )
    .unwrap();
    fs::write(
        settings.with_file_name("settings.json.gommage-bak-not-a-timestamp"),
        "{}\n",
    )
    .unwrap();
    fs::write(
        &settings,
        r#"{
  "language": "spanish",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "uninstall", "claude", "--restore-backup"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
}

#[test]
fn agent_uninstall_dry_run_uses_plan_language_without_mutating() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "all", "--dry-run"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan claude: remove"));
    assert!(stdout.contains("plan codex: remove"));
    assert!(stdout.contains("plan codex: disable features.codex_hooks"));
    assert!(!stdout.contains("ok claude: removed"));
    assert!(!stdout.contains("ok codex: removed"));
    assert!(!stdout.contains("ok codex: disabled"));
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("gommage-mcp")
    );
    assert!(fs::read_to_string(&hooks).unwrap().contains("gommage-mcp"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("codex_hooks = true")
    );
}

#[test]
fn uninstall_all_dry_run_lists_every_surface() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    let systemd = temp.path().join("systemd-user");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_HOME", &claude_home)
        .args([
            "uninstall",
            "--all",
            "--dry-run",
            "--daemon-manager",
            "systemd",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan remove"));
    assert!(stdout.contains("gommage-daemon.service"));
    assert!(stdout.contains("skills/gommage"));
    assert!(stdout.contains("gommage-mcp"));
    assert!(stdout.contains(home.to_string_lossy().as_ref()));
    assert!(!home.exists());
}

#[test]
fn uninstall_requires_yes_for_home_removal() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    fs::create_dir_all(&home).unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rerun with --yes"));
    assert!(home.exists());
}

#[test]
fn uninstall_removes_selected_local_surfaces() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let claude_home = temp.path().join("claude-home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(codex_home.join("skills/gommage")).unwrap();
    fs::create_dir_all(claude_home.join("skills/gommage")).unwrap();
    for name in ["gommage", "gommage-daemon", "gommage-mcp"] {
        fs::write(bin_dir.join(name), "").unwrap();
    }

    let output = gommage(&home)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_HOME", &claude_home)
        .args([
            "uninstall",
            "--binaries",
            "--skills",
            "--purge-home",
            "--yes",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists());
    assert!(!bin_dir.join("gommage").exists());
    assert!(!bin_dir.join("gommage-daemon").exists());
    assert!(!bin_dir.join("gommage-mcp").exists());
    assert!(!codex_home.join("skills/gommage").exists());
    assert!(!claude_home.join("skills/gommage").exists());
}

#[test]
fn uninstall_can_purge_known_backup_files_explicitly() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    let bin_dir = temp.path().join("bin");
    let codex_home = temp.path().join("codex-home");
    let skill_dir = codex_home.join("skills/gommage");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(settings.with_file_name("settings.json.gommage-bak-100"), "").unwrap();
    fs::write(hooks.with_file_name("hooks.json.gommage-bak-100"), "").unwrap();
    fs::write(config.with_file_name("config.toml.gommage-bak-100"), "").unwrap();
    fs::write(bin_dir.join("gommage.gommage-bak-100"), "").unwrap();
    fs::write(skill_dir.join("SKILL.md.gommage-bak-100"), "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .env("GOMMAGE_BIN_DIR", &bin_dir)
        .env("CODEX_HOME", &codex_home)
        .args(["uninstall", "--purge-backups"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !settings
            .with_file_name("settings.json.gommage-bak-100")
            .exists()
    );
    assert!(!hooks.with_file_name("hooks.json.gommage-bak-100").exists());
    assert!(
        !config
            .with_file_name("config.toml.gommage-bak-100")
            .exists()
    );
    assert!(!bin_dir.join("gommage.gommage-bak-100").exists());
    assert!(!skill_dir.join("SKILL.md.gommage-bak-100").exists());
}

#[test]
fn agent_install_codex_writes_hook_and_enables_feature_flag() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nfoo = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "install", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert!(
        hooks_json
            .pointer("/PreToolUse")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| entry
                .get("hooks")
                .and_then(|v| v.as_array())
                .unwrap()
                .iter()
                .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some("gommage-mcp")))
    );
    let config = fs::read_to_string(config).unwrap();
    assert!(config.contains("codex_hooks = true"));
    assert!(config.contains("foo = true"));

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env(
            "GOMMAGE_CODEX_CONFIG",
            temp.path().join("codex").join("config.toml"),
        )
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "pre_tool_use")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert_eq!(
        doctor_check(&report, "codex_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
}

#[test]
fn daemon_install_launchd_writes_plist_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "launchd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plist = fs::read_to_string(launchd.join("dev.gommage.daemon.plist")).unwrap();
    assert!(plist.contains("<string>dev.gommage.daemon</string>"));
    assert!(plist.contains("<string>--foreground</string>"));
    assert!(plist.contains("<string>--home</string>"));
    assert!(plist.contains(&home.to_string_lossy().to_string()));
    assert!(plist.contains(&fake_daemon.to_string_lossy().to_string()));
}

#[test]
fn daemon_install_systemd_writes_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .args(["daemon", "install", "--manager", "systemd", "--no-start"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let service = fs::read_to_string(systemd.join("gommage-daemon.service")).unwrap();
    assert!(service.contains("Description=Gommage policy daemon"));
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    assert!(service.contains(&fake_daemon.to_string_lossy().to_string()));
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_suppresses_service_manager_output() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(systemd.join("gommage-daemon.service"), "[Unit]\n").unwrap();
    fs::write(
        &fake_systemctl,
        "#!/bin/sh\necho \"Removed '/tmp/raw.service'.\"\necho 'raw stderr' >&2\nexit 0\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&fake_systemctl).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_systemctl, perms).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("PATH", path)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("ok daemon: removed"));
    assert!(!stdout.contains("Removed '/tmp/raw.service'"));
    assert!(!stderr.contains("raw stderr"));
    assert!(!systemd.join("gommage-daemon.service").exists());
}
