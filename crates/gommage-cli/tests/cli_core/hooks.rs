use super::*;

#[test]
fn hook_missing_runtime_fails_closed_with_decision_json() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = run_hook_command(
        &home,
        &["hook"],
        br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&serde_json::Value::String("deny".to_string()))
    );
    assert!(
        response
            .pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("loading Gommage signing key")
    );
}

#[test]
fn hook_claude_agent_preserves_ask_picto_decision() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let output = run_hook_command(
        &home,
        &["hook", "--agent", "claude"],
        br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&serde_json::Value::String("ask".to_string()))
    );
}

#[test]
fn hook_only_gates_gommage_reconfiguration_from_trusted_executable_roots() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    for command in [
        "gommage policy init --stdlib --force",
        "/usr/local/bin/gommage policy init --stdlib --force",
        "/opt/homebrew/bin/gommage policy init --stdlib --force",
    ] {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command }
        })
        .to_string();
        let output = run_hook_command(&home, &["hook", "--agent", "claude"], payload.as_bytes());

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&serde_json::Value::String("ask".to_string())),
            "{command}"
        );
        assert!(
            response
                .pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(|value| value.as_str())
                .is_some_and(|reason| reason.contains("gommage.reconfigure")),
            "{command}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    for command in [
        "target/debug/gommage policy init --stdlib --force",
        "/tmp/build/target/debug/gommage policy init --stdlib --force",
    ] {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command }
        })
        .to_string();
        let output = run_hook_command(&home, &["hook", "--agent", "claude"], payload.as_bytes());

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response.pointer("/hookSpecificOutput/permissionDecision"),
            Some(&serde_json::Value::String("deny".to_string())),
            "{command}"
        );
        assert!(
            response
                .pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(|value| value.as_str())
                .is_some_and(|reason| reason.contains("fails closed")),
            "{command}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn hook_codex_agent_converts_ask_picto_to_deny() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let output = run_hook_command(
        &home,
        &["hook", "--agent", "codex"],
        br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&serde_json::Value::String("deny".to_string()))
    );
    assert!(
        response
            .pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(|value| value.as_str())
            .unwrap()
            .contains("Codex PreToolUse does not support ask")
    );
}

#[test]
fn hook_codex_agent_suppresses_plain_allow_output() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);
    fs::write(
        home.join("policy.d").join("19-operator-main-push.yaml"),
        r#"- name: operator-allow-main-push
  decision: allow
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
    all_capability:
      - "git.push:*"
      - "net.out:github.com"
      - "proc.exec:**git push**"
  reason: "operator opts into routine main pushes"
"#,
    )
    .unwrap();

    let output = run_hook_command(
        &home,
        &["hook", "--agent", "codex"],
        br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"");
}

#[test]
fn hook_codex_agent_suppresses_bypass_allow_output() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let mut child = gommage(&home)
        .env("GOMMAGE_BYPASS", "1")
        .args(["hook", "--agent", "codex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"");
}
