mod support;

use std::fs;
use support::{doctor_check, gommage};
use tempfile::tempdir;

#[cfg(unix)]
struct FakeReadyDaemon {
    stop: std::sync::mpsc::Sender<()>,
    worker: std::thread::JoinHandle<()>,
    socket: std::path::PathBuf,
}

#[cfg(unix)]
impl FakeReadyDaemon {
    fn finish(self) {
        let _ = self.stop.send(());
        self.worker.join().unwrap();
        let _ = fs::remove_file(&self.socket);
    }
}

#[cfg(unix)]
fn start_fake_ready_daemon(home: &std::path::Path) -> FakeReadyDaemon {
    use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env, load_active_policy};
    use std::{
        io::{BufRead, BufReader, ErrorKind, Write},
        os::unix::net::UnixListener,
        sync::mpsc,
        time::Duration,
    };

    fs::create_dir_all(home).unwrap();
    let socket = home.join("gommage.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let layout = HomeLayout::at(home);
    let (stop, stopped) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut request = String::new();
                    BufReader::new(&stream).read_line(&mut request).unwrap();
                    assert!(request.contains(r#""op":"decide""#), "{request}");
                    let expedition = Expedition::load(&layout.expedition_file).unwrap();
                    let env = expedition
                        .as_ref()
                        .map(Expedition::policy_env)
                        .unwrap_or_else(default_policy_env);
                    let policy = load_active_policy(&layout, expedition.as_ref(), &env).unwrap();
                    let response = serde_json::json!({
                        "ok": true,
                        "result": { "policy_version": policy.version_hash }
                    });
                    writeln!(stream, "{response}").unwrap();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if stopped.recv_timeout(Duration::from_millis(5)).is_ok() {
                        break;
                    }
                }
                Err(error) => panic!("fake readiness daemon failed: {error}"),
            }
        }
    });
    FakeReadyDaemon {
        stop,
        worker,
        socket,
    }
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn owned_launchd_service(home: &std::path::Path) -> String {
    let home = home
        .to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    format!(
        "<plist><dict><key>ProgramArguments</key><array><string>/tmp/gommage-daemon</string><string>--foreground</string><string>--home</string><string>{home}</string></array></dict></plist>\n"
    )
}

#[cfg(unix)]
fn owned_systemd_service(home: &std::path::Path) -> String {
    format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    )
}

fn hook_group_contains_command(entry: &serde_json::Value, expected: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|v| v.as_array())
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|hook| hook.get("command").and_then(|v| v.as_str()) == Some(expected))
        })
}

fn bound_hook_command(home: &std::path::Path, agent: &str) -> String {
    format!(
        "gommage --home '{}' hook --agent {agent}",
        fs::canonicalize(home).unwrap().display()
    )
}

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
fn agent_uninstall_preserves_non_gommage_commands_inside_a_mixed_group() {
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" },
          { "type": "command", "command": "/tmp/protect-files.sh" },
          { "type": "command", "command": "echo gommage" },
          { "type": "command", "command": "gommage hook --agent claude && /tmp/operator-command" }
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
    let hooks = settings_json
        .pointer("/hooks/PreToolUse/0/hooks")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(hooks.len(), 3);
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("/tmp/protect-files.sh")
    }));
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("echo gommage")
    }));
    assert!(hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str)
            == Some("gommage hook --agent claude && /tmp/operator-command")
    }));
    assert!(!hooks.iter().any(|hook| {
        hook.get("command").and_then(serde_json::Value::as_str) == Some("gommage-mcp")
    }));
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
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\ncodex_hooks = true\n",
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
    assert!(stdout.contains("plan codex: preserve shared Codex hook feature flags"));
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
            .contains("hooks = true")
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("codex_hooks = true")
    );
}

#[test]
fn agent_uninstall_codex_leaves_feature_flag_without_gommage_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(&hooks, r#"{"PreToolUse":[]}"#).unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("no Gommage hook found"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
}

#[test]
fn agent_uninstall_codex_keeps_feature_flag_when_other_hooks_remain() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"gommage-mcp"}]},{"matcher":"Bash","hooks":[{"type":"command","command":"/tmp/protect-files.sh"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed 1 Gommage hook group"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert!(hook_group_contains_command(
        &pre_tool_use[0],
        "/tmp/protect-files.sh"
    ));
}

#[test]
fn agent_uninstall_codex_keeps_shared_feature_flag_after_removing_last_file_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(&config, "[features]\nhooks = true\ncodex_hooks = true\n").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        hooks_json
            .pointer("/PreToolUse")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .len(),
        0
    );
    let config_text = fs::read_to_string(&config).unwrap();
    assert!(config_text.contains("hooks = true"));
    assert!(config_text.contains("codex_hooks = true"));
}

#[test]
fn agent_uninstall_codex_removes_nested_gommage_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
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
        "matcher": "*",
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
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("removed 1 Gommage hook group"));
    assert!(stdout.contains("preserve shared Codex hook feature flags"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 1);
    assert!(hook_group_contains_command(
        &pre_tool_use[0],
        "/tmp/protect-files.sh"
    ));
}

#[test]
fn agent_uninstall_codex_keeps_feature_flag_for_non_pre_tool_hooks() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/tmp/preserve-stop-hook.sh" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();
    fs::write(&config, "[features]\nhooks = true\n").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "uninstall", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("hooks = true")
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        hooks_json
            .pointer("/hooks/PreToolUse")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .len(),
        0
    );
    assert!(hook_group_contains_command(
        hooks_json.pointer("/hooks/Stop/0").unwrap(),
        "/tmp/preserve-stop-hook.sh"
    ));
}

#[test]
fn repair_agent_claude_replaces_legacy_gommage_hook() {
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/gommage mcp --old" }
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
        .args(["repair", "agent", "claude"])
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
    assert_eq!(pre_tool_use.len(), 2);
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("/tmp/protect-files.sh")
    );
    assert!(
        !serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("gommage mcp --old")
    );
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains(&bound_hook_command(&home, "claude"))
    );
    assert!(
        serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("\"matcher\":\"*\"")
    );
}

#[test]
fn repair_agent_preserves_mixed_group_commands_and_gommage_text_false_positives() {
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" },
          { "type": "command", "command": "/tmp/protect-files.sh" },
          { "type": "command", "command": "echo gommage" },
          { "type": "command", "command": "gommage hook --agent claude && /tmp/operator-command" }
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
        .args(["repair", "agent", "claude"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    let groups = settings_json
        .pointer("/hooks/PreToolUse")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(groups.len(), 2);
    let mixed = groups
        .iter()
        .find(|group| hook_group_contains_command(group, "/tmp/protect-files.sh"))
        .unwrap();
    assert!(hook_group_contains_command(mixed, "echo gommage"));
    assert!(hook_group_contains_command(
        mixed,
        "gommage hook --agent claude && /tmp/operator-command"
    ));
    assert!(!hook_group_contains_command(mixed, "gommage-mcp"));
    assert!(
        groups.iter().any(|group| {
            hook_group_contains_command(group, &bound_hook_command(&home, "claude"))
        })
    );
}

#[test]
fn repair_agent_codex_dry_run_does_not_mutate_legacy_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"GOMMAGE_BYPASS=1 gommage mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = false\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["repair", "agent", "codex", "--dry-run"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan write"));
    assert!(stdout.contains("next codex"));
    assert!(fs::read_to_string(&hooks).unwrap().contains("gommage mcp"));
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("codex_hooks = false")
    );
}

#[test]
fn repair_agent_codex_preserves_nested_hooks_object() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(hooks.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
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
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["repair", "agent", "codex"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert!(hooks_json.pointer("/PreToolUse").is_none());
    let pre_tool_use = hooks_json
        .pointer("/hooks/PreToolUse")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(pre_tool_use.len(), 2);
    assert!(
        pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, "/tmp/protect-files.sh"))
    );
    assert!(
        !serde_json::to_string(pre_tool_use)
            .unwrap()
            .contains("GOMMAGE_BYPASS=1 gommage mcp")
    );
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|value| value.as_str()) == Some("*")
            && hook_group_contains_command(entry, &bound_hook_command(&home, "codex"))
    }));
}

#[test]
fn agent_status_warns_on_legacy_and_global_gommage_hooks() {
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
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "gommage-mcp" }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "gommage mcp --old" }
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
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("warn")
    );
    assert_eq!(
        doctor_check(&report, "legacy_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
    assert!(
        doctor_check(&report, "legacy_hooks")
            .pointer("/details/repair")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("gommage repair agent claude")
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
fn uninstall_purge_home_preserves_unrecognized_entries() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    fs::create_dir_all(home.join("policy.d")).unwrap();
    fs::create_dir_all(home.join("capabilities.d")).unwrap();
    fs::write(home.join("key.ed25519"), [0_u8; 32]).unwrap();
    fs::write(home.join("operator-notes.txt"), "preserve me\n").unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home", "--yes"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserved home with unrecognized entries"));
    assert!(home.join("operator-notes.txt").exists());
    assert!(!home.join("key.ed25519").exists());
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("capabilities.d").exists());
}

#[test]
fn uninstall_rejects_unrecognized_custom_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("ordinary-data");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("keep.txt"), "keep me\n").unwrap();

    let output = gommage(&home)
        .args(["uninstall", "--purge-home", "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not recognizably a Gommage home"));
    assert!(home.join("keep.txt").exists());
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
        "sandbox_mode = \"workspace-write\"\nfeatures = { foo = true }\n",
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
                .any(|hook| hook.get("command").and_then(|v| v.as_str())
                    == Some(bound_hook_command(&home, "codex").as_str())))
    );
    let config = fs::read_to_string(config).unwrap();
    assert!(config.contains("hooks = true"));
    assert!(!config.contains("codex_hooks = true"));
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
    assert_eq!(
        doctor_check(&report, "hook_home")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
}

#[test]
fn agent_status_fails_when_codex_hook_home_drifts() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[features]\nhooks = true\n").unwrap();

    let install = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "install", "codex"])
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );

    let mut hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let command = hooks_json
        .pointer_mut("/PreToolUse/0/hooks/0/command")
        .unwrap();
    *command = serde_json::Value::String(
        "gommage --home '/tmp/different-gommage-home' hook --agent codex".to_string(),
    );
    fs::write(&hooks, serde_json::to_vec_pretty(&hooks_json).unwrap()).unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();
    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let check = doctor_check(&report, "hook_home");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        check
            .pointer("/details/expected_command")
            .and_then(|value| value.as_str()),
        Some(bound_hook_command(&home, "codex").as_str())
    );
}

#[test]
fn agent_status_warns_for_legacy_codex_hook_feature_flag() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
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
        Some("warn")
    );
    let check = doctor_check(&report, "codex_hooks");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("warn")
    );
    assert!(
        check
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("legacy features.codex_hooks")
    );
}

#[test]
fn agent_status_fails_when_claude_hook_is_not_global() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch","hooks":[{"type":"command","command":"gommage-mcp"}]}]}}"#,
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    let check = doctor_check(&report, "hook_coverage");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert!(
        check
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
}

#[test]
fn agent_status_fails_when_codex_hook_is_not_global() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"PreToolUse":[{"matcher":"^Bash$|^apply_patch$","hooks":[{"type":"command","command":"gommage-mcp"}]}]}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    let check = doctor_check(&report, "hook_coverage");
    assert_eq!(
        check.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert!(
        check
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
}

#[test]
fn agent_status_codex_fails_on_narrow_nested_legacy_wrapper_hook() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*","hooks":[{"type":"command","command":"GOMMAGE_MCP_BIN=\"$(command -v gommage-mcp)\" \"$HOME/.codex/hooks/gommage-codex-pretooluse.sh\""}]}]}}"#,
    )
    .unwrap();
    fs::write(
        &config,
        "sandbox_mode = \"workspace-write\"\n[features]\nhooks = true\n",
    )
    .unwrap();

    let status = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &hooks)
        .env("GOMMAGE_CODEX_CONFIG", &config)
        .args(["agent", "status", "codex", "--json"])
        .output()
        .unwrap();

    assert!(!status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&report, "pre_tool_use")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("ok")
    );
    assert!(
        doctor_check(&report, "hook_coverage")
            .pointer("/details/missing")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("*"))
    );
    assert_eq!(
        doctor_check(&report, "hook_coverage")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&report, "legacy_hooks")
            .get("status")
            .and_then(|value| value.as_str()),
        Some("warn")
    );
}

#[test]
fn agent_install_codex_preserves_unrelated_hooks_by_default() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let hooks = temp.path().join("codex").join("hooks.json");
    let config = temp.path().join("codex").join("config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &hooks,
        r#"{
  "PreToolUse": [
    {
      "matcher": "apply_patch",
      "hooks": [
        { "type": "command", "command": "~/.codex/hooks/patch-audit.sh" }
      ]
    },
    {
      "matcher": "*",
      "hooks": [
        { "type": "command", "command": "GOMMAGE_BYPASS=1 gommage mcp" }
      ]
    }
  ]
}"#,
    )
    .unwrap();
    fs::write(&config, "sandbox_mode = \"workspace-write\"\n").unwrap();

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
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preserving existing PreToolUse hook group(s)"));

    let hooks_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    let pre_tool_use = hooks_json
        .pointer("/PreToolUse")
        .and_then(|v| v.as_array())
        .unwrap();

    assert_eq!(pre_tool_use.len(), 2);
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("apply_patch")
            && hook_group_contains_command(entry, "~/.codex/hooks/patch-audit.sh")
    }));
    assert!(
        pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, &bound_hook_command(&home, "codex")))
    );
    assert!(pre_tool_use.iter().any(|entry| {
        entry.get("matcher").and_then(|v| v.as_str()) == Some("*")
            && hook_group_contains_command(entry, &bound_hook_command(&home, "codex"))
    }));
    assert!(
        !pre_tool_use
            .iter()
            .any(|entry| hook_group_contains_command(entry, "GOMMAGE_BYPASS=1 gommage mcp"))
    );
    assert!(fs::read_to_string(config).unwrap().contains("hooks = true"));
}

#[test]
fn daemon_install_launchd_writes_plist_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);

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
    let canonical_daemon = fs::canonicalize(&fake_daemon).unwrap();
    assert!(plist.contains(&canonical_daemon.to_string_lossy().to_string()));
    assert!(!home.exists());
}

#[test]
fn daemon_install_systemd_writes_service_without_starting() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let fake_daemon = temp.path().join("bin").join("gommage-daemon");
    fs::create_dir_all(fake_daemon.parent().unwrap()).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);

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
    assert!(service.contains("Type=exec"));
    assert!(!service.contains("Type=simple"));
    assert!(service.contains("ExecStart="));
    assert!(service.contains("--foreground --home"));
    assert!(service.contains(&home.to_string_lossy().to_string()));
    let canonical_daemon = fs::canonicalize(&fake_daemon).unwrap();
    assert!(service.contains(&canonical_daemon.to_string_lossy().to_string()));
    assert!(!home.exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_restores_loaded_service_after_bootstrap_failure() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let existing_backup = launchd.join("dev.gommage.daemon.plist.gommage-bak-existing");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    let first_bootstrap = temp.path().join("first-bootstrap-failed");
    let loaded_state = temp.path().join("launchd-loaded-state");
    let bootout_count = temp.path().join("launchd-bootout-count");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let original = owned_launchd_service(&home).into_bytes();
    fs::write(&service_file, &original).unwrap();
    let mut service_permissions = fs::metadata(&service_file).unwrap().permissions();
    service_permissions.set_mode(0o640);
    fs::set_permissions(&service_file, service_permissions).unwrap();
    fs::write(&existing_backup, b"older backup\n").unwrap();
    fs::write(&loaded_state, "1").unwrap();
    fs::write(&bootout_count, "0").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$1" in
  print)
    if [ "$(/bin/cat "$GOMMAGE_LAUNCHD_LOADED_STATE")" = "1" ]; then
      exit 0
    fi
    printf 'Could not find service\n' >&2
    exit 113
    ;;
  bootout)
    count="$(/bin/cat "$GOMMAGE_LAUNCHD_BOOTOUT_COUNT")"
    if [ "$count" = "1" ]; then
      case "$(/bin/cat "$GOMMAGE_LAUNCHD_SERVICE_FILE")" in
        *"<string>dev.gommage.daemon</string>"*) ;;
        *) exit 45 ;;
      esac
    fi
    printf '%s' "$((count + 1))" > "$GOMMAGE_LAUNCHD_BOOTOUT_COUNT"
    printf '0' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
    exit 0
    ;;
  bootstrap)
    if [ ! -e "$GOMMAGE_FIRST_BOOTSTRAP" ]; then
      : > "$GOMMAGE_FIRST_BOOTSTRAP"
      printf '1' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
      exit 42
    fi
    case "$(/bin/cat "$GOMMAGE_LAUNCHD_SERVICE_FILE")" in
      *"<string>--home</string>"*) ;;
      *) exit 46 ;;
    esac
    printf '1' > "$GOMMAGE_LAUNCHD_LOADED_STATE"
    exit 0
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ready_daemon = start_fake_ready_daemon(&home);

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_FIRST_BOOTSTRAP", &first_bootstrap)
        .env("GOMMAGE_LAUNCHD_LOADED_STATE", &loaded_state)
        .env("GOMMAGE_LAUNCHD_BOOTOUT_COUNT", &bootout_count)
        .env("GOMMAGE_LAUNCHD_SERVICE_FILE", &service_file)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();
    ready_daemon.finish();
    fs::remove_dir(&home).unwrap();

    assert!(!output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("rollback also failed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("service command failed: launchctl bootstrap"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&service_file).unwrap(), original);
    assert_eq!(
        fs::metadata(&service_file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let backups = fs::read_dir(&launchd)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("dev.gommage.daemon.plist.gommage-bak-")
        })
        .collect::<Vec<_>>();
    assert_eq!(backups, vec![existing_backup]);
    assert_eq!(fs::read_to_string(loaded_state).unwrap(), "1");
    assert_eq!(fs::read_to_string(bootout_count).unwrap(), "2");
    assert!(!home.exists());

    let calls = fs::read_to_string(log).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 6, "{calls:?}");
    assert!(calls[0].starts_with("print gui/"), "{calls:?}");
    assert!(calls[1].starts_with("bootout gui/"), "{calls:?}");
    assert!(calls[2].starts_with("bootstrap gui/"), "{calls:?}");
    assert!(calls[3].starts_with("print gui/"), "{calls:?}");
    assert!(calls[4].starts_with("bootout gui/"), "{calls:?}");
    assert!(calls[5].starts_with("bootstrap gui/"), "{calls:?}");
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_accepts_not_loaded_during_rollback_probe() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    let loaded_state = temp.path().join("launchd-loaded-state");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let original = b"original unloaded launchd plist\n";
    fs::write(&service_file, original).unwrap();
    fs::write(&loaded_state, "0").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$1" in
  print)
    if [ "$(/bin/cat "$GOMMAGE_LAUNCHD_LOADED_STATE")" = "1" ]; then
      exit 0
    fi
    printf 'Could not find service\n' >&2
    exit 113
    ;;
  bootstrap)
    exit 42
    ;;
  bootout)
    exit 65
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("GOMMAGE_LAUNCHD_LOADED_STATE", &loaded_state)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("service command failed: launchctl bootstrap"),
        "{stderr}"
    );
    assert!(!stderr.contains("rollback also failed"), "{stderr}");
    assert_eq!(fs::read(&service_file).unwrap(), original);
    assert_eq!(fs::read_to_string(loaded_state).unwrap(), "0");
    assert!(!home.exists());
    let backups = fs::read_dir(&launchd)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("dev.gommage.daemon.plist.gommage-bak-")
        })
        .collect::<Vec<_>>();
    assert!(backups.is_empty(), "{backups:?}");

    let calls = fs::read_to_string(log).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].starts_with("print gui/"), "{calls:?}");
    assert!(calls[1].starts_with("bootstrap gui/"), "{calls:?}");
    assert!(calls[2].starts_with("print gui/"), "{calls:?}");
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_state_probe_error_is_not_treated_as_unloaded() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let service_file = launchd.join("dev.gommage.daemon.plist");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    fs::create_dir_all(&launchd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, "original plist\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        "#!/bin/sh\nprintf 'permission denied\\n' >&2\nexit 77\n",
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not determine"));
    assert_eq!(
        fs::read_to_string(&service_file).unwrap(),
        "original plist\n"
    );
    assert!(!home.exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_launchd_rejects_loaded_service_without_restorable_plist() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let launchd = temp.path().join("LaunchAgents");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_launchctl = bin.join("launchctl");
    let log = temp.path().join("launchctl.log");
    fs::create_dir_all(&bin).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_launchctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
if [ "$1" = "print" ]; then
  exit 0
fi
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_launchctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_LAUNCHD_DIR", &launchd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "launchd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("without a restorable plist"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(log).unwrap().lines().count(), 1);
    assert!(!launchd.join("dev.gommage.daemon.plist").exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restores_independent_runtime_states_after_enable_failure() {
    use std::os::unix::fs::PermissionsExt;

    for (was_enabled, was_active) in [(true, true), (true, false), (false, true), (false, false)] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let existing_backup = systemd.join("gommage-daemon.service.gommage-bak-existing");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        let enabled_state = temp.path().join("enabled-state");
        let active_state = temp.path().join("active-state");
        let first_enable = temp.path().join("first-enable-failed");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let original = owned_systemd_service(&home).into_bytes();
        fs::write(&service_file, &original).unwrap();
        let mut service_permissions = fs::metadata(&service_file).unwrap().permissions();
        service_permissions.set_mode(0o640);
        fs::set_permissions(&service_file, service_permissions).unwrap();
        fs::write(&existing_backup, b"older backup\n").unwrap();
        fs::write(&enabled_state, if was_enabled { "1" } else { "0" }).unwrap();
        fs::write(&active_state, if was_active { "1" } else { "0" }).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active)
    if [ "$(/bin/cat "$GOMMAGE_ACTIVE_STATE")" = "1" ]; then
      printf 'active\n'
      exit 0
    fi
    printf 'inactive\n'
    exit 3
    ;;
  is-enabled)
    if [ "$(/bin/cat "$GOMMAGE_ENABLED_STATE")" = "1" ]; then
      printf 'enabled\n'
      exit 0
    fi
    printf 'disabled\n'
    exit 1
    ;;
  daemon-reload)
    exit 0
    ;;
  enable)
    if [ ! -e "$GOMMAGE_FIRST_ENABLE" ]; then
      : > "$GOMMAGE_FIRST_ENABLE"
      exit 43
    fi
    printf '1' > "$GOMMAGE_ENABLED_STATE"
    ;;
  disable)
    printf '0' > "$GOMMAGE_ENABLED_STATE"
    if [ "$3" = "--now" ]; then
      printf '0' > "$GOMMAGE_ACTIVE_STATE"
    fi
    ;;
  start)
    printf '1' > "$GOMMAGE_ACTIVE_STATE"
    ;;
  stop)
    printf '0' > "$GOMMAGE_ACTIVE_STATE"
    ;;
  *)
    exit 64
    ;;
esac
"#,
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let ready_daemon = was_active.then(|| start_fake_ready_daemon(&home));

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("GOMMAGE_ENABLED_STATE", &enabled_state)
            .env("GOMMAGE_ACTIVE_STATE", &active_state)
            .env("GOMMAGE_FIRST_ENABLE", &first_enable)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();
        if let Some(ready_daemon) = ready_daemon {
            ready_daemon.finish();
            fs::remove_dir(&home).unwrap();
        }

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("service command failed: systemctl --user enable gommage-daemon.service"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&service_file).unwrap(), original);
        assert_eq!(
            fs::metadata(&service_file).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let backups = fs::read_dir(&systemd)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("gommage-daemon.service.gommage-bak-")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups, vec![existing_backup]);
        assert_eq!(
            fs::read_to_string(&enabled_state).unwrap(),
            if was_enabled { "1" } else { "0" }
        );
        assert_eq!(
            fs::read_to_string(&active_state).unwrap(),
            if was_active { "1" } else { "0" }
        );
        assert!(!home.exists());

        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.contains("--user is-active gommage-daemon.service\n"));
        assert!(calls.contains("--user is-enabled gommage-daemon.service\n"));
        assert!(calls.contains("--user daemon-reload\n"));
        assert!(calls.contains("--user enable gommage-daemon.service\n"));
        assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
        assert!(calls.contains(if was_enabled {
            "--user enable gommage-daemon.service\n"
        } else {
            "--user disable gommage-daemon.service\n"
        }));
        if was_active {
            assert!(calls.contains("--user stop gommage-daemon.service\n"));
            assert!(calls.contains("--user start gommage-daemon.service\n"));
        } else {
            assert!(!calls.contains("--user stop gommage-daemon.service\n"));
            assert!(!calls.contains("--user start gommage-daemon.service\n"));
        }
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restarts_an_already_active_service() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, owned_systemd_service(&home)).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'active\n'; exit 0 ;;
  is-enabled) printf 'enabled\n'; exit 0 ;;
  daemon-reload|enable|restart) exit 0 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ready_daemon = start_fake_ready_daemon(&home);

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd", "--force"])
        .output()
        .unwrap();
    ready_daemon.finish();
    fs::remove_dir(&home).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user daemon-reload\n"));
    assert!(calls.contains("--user enable gommage-daemon.service\n"));
    assert!(calls.contains("--user restart gommage-daemon.service\n"));
    assert!(!calls.contains("--user start gommage-daemon.service\n"));
    assert!(
        fs::read_to_string(&service_file)
            .unwrap()
            .contains("Type=exec")
    );
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_state_probe_error_is_not_treated_as_inactive() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&service_file, "original unit\n").unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) exit 42 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd", "--force"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not determine active state"));
    assert_eq!(
        fs::read_to_string(&service_file).unwrap(),
        "original unit\n"
    );
    assert!(!home.exists());
}

#[test]
#[cfg(unix)]
fn daemon_install_readiness_failure_rolls_back_service_file_and_state() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let service_file = systemd.join("gommage-daemon.service");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf 'disabled\n'; exit 1 ;;
  daemon-reload|enable|start|disable|stop) exit 0 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let started = std::time::Instant::now();
    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd"])
        .output()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(!output.status.success());
    assert!(elapsed >= std::time::Duration::from_millis(4_900));
    assert!(elapsed < std::time::Duration::from_millis(7_000));
    assert!(String::from_utf8_lossy(&output.stderr).contains("daemon readiness failed"));
    assert!(!service_file.exists());
    assert!(!home.exists());
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.contains("--user start gommage-daemon.service\n"));
    assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
    assert!(!calls.contains("--user stop gommage-daemon.service\n"));
}

#[test]
#[cfg(unix)]
fn daemon_install_rollback_preserves_static_and_indirect_enablement() {
    for enablement in ["static", "indirect"] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(&service_file, format!("original {enablement} unit\n")).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
  daemon-reload|disable|stop) exit 0 ;;
  enable) exit 43 ;;
esac
exit 64
"#
            ),
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            format!("original {enablement} unit\n")
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls
                .lines()
                .filter(|line| *line == "--user enable gommage-daemon.service")
                .count(),
            1
        );
        assert_eq!(
            calls
                .lines()
                .filter(|line| *line == "--user disable gommage-daemon.service")
                .count(),
            0
        );
        assert!(!calls.contains("--user disable --now gommage-daemon.service\n"));
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_restores_runtime_and_mask_enablement_exactly() {
    for (enablement, restore_command) in [
        (
            "enabled-runtime",
            "--user enable --runtime gommage-daemon.service",
        ),
        (
            "disabled-runtime",
            "--user disable --runtime gommage-daemon.service",
        ),
        ("masked", "--user mask gommage-daemon.service"),
        (
            "masked-runtime",
            "--user mask --runtime gommage-daemon.service",
        ),
    ] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(&service_file, format!("original {enablement} unit\n")).unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
  daemon-reload|disable|mask) exit 0 ;;
  enable)
    if [ "$3" = "--runtime" ]; then exit 0; fi
    exit 43
    ;;
esac
exit 64
"#
            ),
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            format!("original {enablement} unit\n")
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.lines().any(|line| line == restore_command), "{calls}");
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_rejects_unreconstructable_enablement_before_mutation() {
    for enablement in [
        "linked",
        "linked-runtime",
        "alias",
        "generated",
        "transient",
    ] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(&service_file, "original unit\n").unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled) printf '{enablement}\n'; exit 1 ;;
esac
exit 64
"#
            ),
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot reconstruct"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            "original unit\n"
        );
        let calls = fs::read_to_string(&log).unwrap();
        assert!(!calls.contains("daemon-reload"), "{calls}");
        assert!(!calls.lines().any(|line| line.starts_with("--user enable ")));
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_rejects_transitional_activity_before_mutation() {
    for (activity, status) in [
        ("failed", 3),
        ("activating", 0),
        ("deactivating", 0),
        ("reloading", 0),
    ] {
        let temp = tempdir().unwrap();
        let home = temp.path().join(".gommage");
        let systemd = temp.path().join("systemd-user");
        let service_file = systemd.join("gommage-daemon.service");
        let bin = temp.path().join("bin");
        let fake_daemon = bin.join("gommage-daemon");
        let fake_systemctl = bin.join("systemctl");
        let log = temp.path().join("systemctl.log");
        fs::create_dir_all(&systemd).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(&service_file, "original unit\n").unwrap();
        fs::write(&fake_daemon, "").unwrap();
        make_executable(&fake_daemon);
        fs::write(
            &fake_systemctl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GOMMAGE_SERVICE_MANAGER_LOG\"\nprintf '{activity}\\n'\nexit {status}\n"
            ),
        )
        .unwrap();
        make_executable(&fake_systemctl);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let output = gommage(&home)
            .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
            .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
            .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
            .env("PATH", path)
            .args(["daemon", "install", "--manager", "systemd", "--force"])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("non-restorable"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&service_file).unwrap(),
            "original unit\n"
        );
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);
    }
}

#[test]
#[cfg(unix)]
fn daemon_install_systemd_absent_inactive_rollback_never_stops_missing_unit() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_daemon = bin.join("gommage-daemon");
    let fake_systemctl = bin.join("systemctl");
    let log = temp.path().join("systemctl.log");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&fake_daemon, "").unwrap();
    make_executable(&fake_daemon);
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$GOMMAGE_SERVICE_MANAGER_LOG"
case "$2" in
  is-active|is-enabled) printf 'not-found\n'; exit 4 ;;
  daemon-reload) exit 0 ;;
  enable) exit 43 ;;
  stop) exit 99 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_DAEMON_BIN", &fake_daemon)
        .env("GOMMAGE_SERVICE_MANAGER_LOG", &log)
        .env("PATH", path)
        .args(["daemon", "install", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!systemd.join("gommage-daemon.service").exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("rollback also failed"), "{stderr}");
    let calls = fs::read_to_string(&log).unwrap();
    assert!(
        !calls.contains("--user stop gommage-daemon.service"),
        "{calls}"
    );
    assert!(!calls.contains("--user disable --now"), "{calls}");
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
    fs::write(
        systemd.join("gommage-daemon.service"),
        format!(
            "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
            home.display()
        ),
    )
    .unwrap();
    let runtime_state = temp.path().join("systemd-active");
    fs::write(&runtime_state, "active\n").unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active)
    if [ -e "$GOMMAGE_SERVICE_RUNTIME_STATE" ]; then printf 'active\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  is-enabled)
    if [ -e "$GOMMAGE_SERVICE_RUNTIME_STATE" ]; then printf 'enabled\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  stop|disable)
    rm -f "$GOMMAGE_SERVICE_RUNTIME_STATE"
    echo "Removed '/tmp/raw.service'."
    echo 'raw stderr' >&2
    exit 0
    ;;
  daemon-reload) exit 0 ;;
esac
exit 64
"#,
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
        .env("GOMMAGE_SERVICE_RUNTIME_STATE", &runtime_state)
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

#[test]
#[cfg(unix)]
fn daemon_uninstall_preserves_service_file_when_stop_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    );
    fs::write(&service_file, &original).unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) printf 'active\n'; exit 0 ;;
  is-enabled) printf 'enabled\n'; exit 0 ;;
  stop) exit 42 ;;
  disable) exit 0 ;;
  daemon-reload) exit 0 ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
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

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(String::from_utf8_lossy(&output.stderr).contains("stopping daemon before uninstall"));
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_restores_file_and_enablement_when_reload_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let systemd = temp.path().join("systemd-user");
    let bin = temp.path().join("bin");
    let fake_systemctl = bin.join("systemctl");
    let enablement = temp.path().join("enabled");
    let reload_count = temp.path().join("reload-count");
    fs::create_dir_all(&systemd).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(&enablement, "enabled\n").unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        home.display()
    );
    fs::write(&service_file, &original).unwrap();
    fs::write(
        &fake_systemctl,
        r#"#!/bin/sh
case "$2" in
  is-active) printf 'inactive\n'; exit 3 ;;
  is-enabled)
    if [ -e "$GOMMAGE_ENABLEMENT_STATE" ]; then printf 'enabled\n'; exit 0; fi
    printf 'not-found\n'; exit 4
    ;;
  disable) rm -f "$GOMMAGE_ENABLEMENT_STATE"; exit 0 ;;
  enable) : > "$GOMMAGE_ENABLEMENT_STATE"; exit 0 ;;
  daemon-reload)
    count=0
    if [ -e "$GOMMAGE_RELOAD_COUNT" ]; then count="$(cat "$GOMMAGE_RELOAD_COUNT")"; fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$GOMMAGE_RELOAD_COUNT"
    if [ "$count" -eq 1 ]; then exit 42; fi
    exit 0
    ;;
esac
exit 64
"#,
    )
    .unwrap();
    make_executable(&fake_systemctl);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .env("GOMMAGE_ENABLEMENT_STATE", &enablement)
        .env("GOMMAGE_RELOAD_COUNT", &reload_count)
        .env("PATH", path)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(enablement.exists());
    assert_eq!(fs::read_to_string(&reload_count).unwrap().trim(), "2");
    assert!(String::from_utf8_lossy(&output.stderr).contains("rolled back"));
}

#[test]
#[cfg(unix)]
fn daemon_uninstall_refuses_a_service_bound_to_another_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("selected-home");
    let other_home = temp.path().join("other-home");
    let systemd = temp.path().join("systemd-user");
    fs::create_dir_all(&systemd).unwrap();
    let service_file = systemd.join("gommage-daemon.service");
    let original = format!(
        "[Service]\nExecStart=\"/tmp/gommage-daemon\" --foreground --home \"{}\"\n",
        other_home.display()
    );
    fs::write(&service_file, &original).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_SYSTEMD_USER_DIR", &systemd)
        .args(["daemon", "uninstall", "--manager", "systemd"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&service_file).unwrap(), original);
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not select"));
}
