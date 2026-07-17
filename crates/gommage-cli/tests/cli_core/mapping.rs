use super::*;

#[test]
fn map_hook_json_reports_codex_apply_patch_and_mcp_capabilities() {
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

    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","cwd":"/tmp/proj","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: src/lib.rs\n*** Add File: docs/new.md\n*** End Patch\n"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report
        .get("capabilities")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"fs.write:/tmp/proj/src/lib.rs"));
    assert!(capabilities.contains(&"fs.write:/tmp/proj/docs/new.md"));

    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","cwd":"/tmp/proj","tool_name":"mcp__github__create_issue","tool_input":{"title":"smoke"}}"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report
        .get("capabilities")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"mcp.write:mcp__github__create_issue"));
    assert!(capabilities.contains(&"mcp.call:mcp__github__create_issue"));
}

#[test]
fn map_hook_session_context_is_private_spoof_resistant_and_mapper_neutral() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let payload = |session_id: Option<&str>, spoof: bool| {
        let mut tool_input = serde_json::json!({"code": "1 + 1"});
        if spoof {
            tool_input["__gommage_session_hash"] = serde_json::json!("sha256:spoofed");
        }
        let mut payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__node_repl__js",
            "tool_input": tool_input
        });
        if let Some(session_id) = session_id {
            payload["session_id"] = serde_json::json!(session_id);
        }
        map_hook_report(&home, &payload)
    };

    let session_a = payload(Some("session-a"), false);
    let session_b = payload(Some("session-b"), false);
    let no_session = payload(None, false);

    assert_ne!(session_a["input_hash"], session_b["input_hash"]);
    assert_eq!(session_a["capabilities"], session_b["capabilities"]);
    assert_eq!(session_a["capabilities"], no_session["capabilities"]);
    assert_eq!(no_session["input_hash"], payload(None, false)["input_hash"]);
    assert_eq!(
        session_a["input_hash"],
        payload(Some("session-a"), true)["input_hash"]
    );
    assert_eq!(no_session["input_hash"], payload(None, true)["input_hash"]);
}

#[test]
fn map_hook_rejects_non_object_input_when_session_context_is_present() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let output = run_hook_command(
        &home,
        &["map", "--json", "--hook"],
        br#"{"session_id":"session-a","tool_name":"mcp__node_repl__js","tool_input":"1 + 1"}"#,
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tool_input must be an object"));

    let hook = run_hook_command(
        &home,
        &["hook", "--agent", "claude"],
        br#"{"session_id":"session-a","tool_name":"mcp__node_repl__js","tool_input":"1 + 1"}"#,
    );
    assert!(hook.status.success());
    let response: serde_json::Value = serde_json::from_slice(&hook.stdout).unwrap();
    assert_eq!(
        response.pointer("/hookSpecificOutput/permissionDecision"),
        Some(&serde_json::Value::String("deny".to_string()))
    );
    assert!(
        response
            .pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("tool_input must be an object"))
    );
}

#[test]
fn root_and_embedded_agent_tool_policies_are_byte_identical() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_policy = manifest_dir.join("../../policies/15-agent-tools.yaml");
    let embedded_policy = manifest_dir.join("../gommage-stdlib/policies/15-agent-tools.yaml");

    assert_eq!(
        fs::read(root_policy).unwrap(),
        fs::read(embedded_policy).unwrap()
    );
}

#[test]
fn map_hook_json_emits_only_canonical_resolved_write_paths() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("src")).unwrap();
    let git_status = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&project)
        .status()
        .unwrap();
    assert!(git_status.success());
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let project_path = project.to_string_lossy().to_string();
    let write_payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": project_path.clone(),
        "tool_name": "Write",
        "tool_input": {
            "file_path": "src/lib.rs",
            "content": "x",
            "__gommage_file_path": "/spoofed"
        }
    });
    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&write_payload).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    let resolved = format!("{}/src/lib.rs", project.display());
    let resolved_capability = format!("fs.write:{resolved}");
    assert!(!capabilities.contains(&"fs.write:src/lib.rs"));
    assert!(capabilities.contains(&resolved_capability.as_str()));
    assert!(!capabilities.contains(&"fs.write:/spoofed"));
    assert!(
        !capabilities
            .iter()
            .any(|cap| cap.starts_with("fs.write.git_branch:"))
    );

    let bash_payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": project_path,
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat > src/lib.rs <<EOF\nx\nEOF"
        }
    });
    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&bash_payload).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(!capabilities.contains(&"fs.write:src/lib.rs"));
    assert!(capabilities.contains(&resolved_capability.as_str()));
    assert!(
        !capabilities
            .iter()
            .any(|cap| cap.starts_with("fs.write.git_branch:"))
    );
    assert!(
        !capabilities
            .iter()
            .any(|cap| cap.starts_with("git.cwd_branch:"))
    );
    assert!(!capabilities.contains(&"fs.read:>"));

    let sed_payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": project.to_string_lossy().to_string(),
        "tool_name": "Bash",
        "tool_input": {
            "command": "sed -i 's/x/y/' src/lib.rs"
        }
    });
    let mut child = gommage(&home)
        .args(["map", "--json", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&sed_payload).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(!capabilities.contains(&"fs.write:src/lib.rs"));
    assert!(capabilities.contains(&resolved_capability.as_str()));
    assert!(
        !capabilities
            .iter()
            .any(|cap| cap.starts_with("fs.write.git_branch:"))
    );
    assert!(
        !capabilities
            .iter()
            .any(|cap| cap.starts_with("git.cwd_branch:"))
    );
}

#[test]
fn decide_suggests_hook_flag_for_pre_tool_use_payload() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let mut child = gommage(&home)
        .arg("decide")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
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

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("use --hook"));
    assert!(stderr.contains("tool_name/tool_input"));
}

#[test]
fn hook_malformed_payload_fails_closed_with_decision_json() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let mut child = gommage(&home)
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{not-json"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();

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
            .contains("gommage hook failed closed")
    );
}
