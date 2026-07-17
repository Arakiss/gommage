mod support;

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use support::gommage;
use tempfile::tempdir;

fn run_hook_command(home: &Path, args: &[&str], payload: &[u8]) -> std::process::Output {
    let mut child = gommage(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(payload).unwrap();
    child.wait_with_output().unwrap()
}

fn init_home_with_stdlib(home: &Path) {
    assert!(gommage(home).arg("init").status().unwrap().success());
    assert!(
        gommage(home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
}

fn map_hook_report(home: &Path, payload: &serde_json::Value) -> serde_json::Value {
    let payload = serde_json::to_vec(payload).unwrap();
    let output = run_hook_command(home, &["map", "--json", "--hook"], &payload);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn mascot_plain_is_script_safe() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home).args(["mascot", "--plain"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Gestral signature"));
    assert!(stdout.contains("Gommage Gestral"));
    assert!(stdout.contains("Gommage Teal #00B3A4"));
    assert!(stdout.contains("tool call -> typed capabilities -> signed audit"));
    assert!(stdout.contains("██████"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn mascot_compact_plain_is_single_line() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["mascot", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains("[Gestral]"));
    assert!(stdout.contains("GOMMAGE policy sentinel"));
    assert!(stdout.contains("signed audit"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn logo_alias_prints_the_same_signature() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["logo", "--plain", "--compact"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[Gestral]"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn grant_rejects_invalid_uses_without_panic() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());

    let output = gommage(&home)
        .args([
            "grant", "--scope", "test", "--uses", "0", "--ttl", "60", "--reason", "invalid",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid picto"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn grant_accepts_human_ttl_suffix() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    assert!(gommage(&home).arg("init").status().unwrap().success());

    let output = gommage(&home)
        .args([
            "grant",
            "--scope",
            "git.push:main",
            "--uses",
            "1",
            "--ttl",
            "10m",
            "--reason",
            "test",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("granted"));
}

#[test]
fn grant_rejects_scope_only_picto_for_input_bound_dynamic_scope() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let output = gommage(&home)
        .args([
            "grant",
            "--scope",
            "mcp.write:mcp__db__write_row",
            "--ttl",
            "10m",
            "--reason",
            "would be unusable",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("only used by input-bound ask_picto rules"));
    assert!(stderr.contains("gommage approval approve <request-id>"));

    let listed = gommage(&home).args(["list", "--json"]).output().unwrap();
    assert!(listed.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&listed.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn grant_unknown_scope_warning_lists_dynamic_selectors() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    init_home_with_stdlib(&home);

    let output = gommage(&home)
        .args([
            "grant",
            "--scope",
            "unknown.scope",
            "--ttl",
            "10m",
            "--reason",
            "warning coverage",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Known scopes/selectors"));
    assert!(stderr.contains("mcp.write:* [derived selector; input-bound approval]"));
}

#[test]
fn policy_init_stdlib_installs_loadable_defaults() {
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

    let output = gommage(&home).args(["policy", "check"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("rules loaded"));
}

#[test]
fn read_only_inspection_commands_never_initialize_home() {
    let temp = tempdir().unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("policy-schema", &["policy", "schema"]),
        ("policy-check", &["policy", "check"]),
        ("policy-layers", &["policy", "layers", "--json"]),
        ("policy-lint", &["policy", "lint", "--json"]),
        ("policy-hash", &["policy", "hash"]),
        ("posture", &["posture", "--json"]),
        ("sandbox-advise", &["sandbox", "advise", "--json"]),
        ("expedition-status", &["expedition", "status"]),
    ];

    for (name, args) in cases {
        let home = temp.path().join(name);
        let output = gommage(&home).args(*args).output().unwrap();
        assert!(
            output.status.success(),
            "read-only command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !home.exists(),
            "read-only command {args:?} initialized {} (status={}, stderr={})",
            home.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let home = temp.path().join("policy-snapshot");
    let output = run_hook_command(
        &home,
        &["policy", "snapshot", "--name", "read-only"],
        br#"{"tool":"Read","input":{"file_path":"/tmp/example"}}"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists(), "policy snapshot initialized the home");

    let home = temp.path().join("policy-capture");
    let output = run_hook_command(
        &home,
        &["policy", "capture", "--name", "read-only"],
        br#"{"tool":"Read","input":{"file_path":"/tmp/example"}}"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists(), "policy capture initialized the home");

    let fixture = temp.path().join("policy-fixture.yaml");
    fs::write(
        &fixture,
        r#"version: 1
cases:
  - name: empty-home-fails-closed
    tool: Read
    input:
      file_path: /tmp/example
    expect:
      decision: gommage
"#,
    )
    .unwrap();
    let home = temp.path().join("policy-test");
    let output = gommage(&home)
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists(), "policy test initialized the home");

    let home = temp.path().join("policy-suggest");
    let output = gommage(&home)
        .args(["policy", "suggest", "--audit", "/dev/null", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.exists(), "policy suggest initialized the home");
}

#[test]
fn policy_check_preserves_an_existing_uninitialized_home_exactly() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("selected-home");
    fs::create_dir(&home).unwrap();
    let sentinel = home.join("operator-note.txt");
    fs::write(&sentinel, "keep\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o750)).unwrap();
    }

    let output = gommage(&home).args(["policy", "check"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep\n");
    assert!(!home.join("key.ed25519").exists());
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("capabilities.d").exists());
    for name in [
        "pictos.sqlite",
        "pictos.sqlite-wal",
        "pictos.sqlite-shm",
        "state.sqlite",
        "state.sqlite-wal",
        "state.sqlite-shm",
    ] {
        assert!(!home.join(name).exists(), "unexpected state file {name}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
}

#[test]
fn sandbox_advise_json_is_explicitly_advisory() {
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

    let output = gommage(&home)
        .args(["sandbox", "advise", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["advisory_only"].as_bool(), Some(true));
    assert!(
        report["warning"]
            .as_str()
            .unwrap()
            .contains("does not enforce OS confinement")
    );
    let targets = report["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|suggestion| suggestion["target"].as_str())
        .collect::<Vec<_>>();
    assert!(targets.contains(&"codex"));
    assert!(targets.contains(&"bwrap"));
    assert!(targets.contains(&"macos-seatbelt"));
    assert!(targets.contains(&"apparmor"));
}

#[test]
fn release_verify_help_describes_strict_evidence_gates() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args(["release", "verify", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--all-assets"));
    assert!(stdout.contains("--require-sbom"));
    assert!(stdout.contains("--require-provenance"));
    assert!(stdout.contains("--asset"));
}

#[test]
fn map_json_reports_capabilities_without_policy_files() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let capabilities_dir = home.join("capabilities.d");
    fs::create_dir_all(&capabilities_dir).unwrap();
    fs::write(
        capabilities_dir.join("bash.yaml"),
        r#"
- name: bash-proc-exec
  tool: Bash
  emit:
    - "proc.exec:${input.command}"
- name: bash-git-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push(?:\\s+[-\\w]+)*\\s+(?P<remote>[\\w.-]+)\\s+(?P<ref>\\S+)"
  emit:
    - "git.push:refs/heads/${ref}"
    - "net.out:github.com"
- name: bash-git-force-push
  tool: Bash
  match_input:
    command: "^\\s*git\\s+push[^#]*--force\\b"
  emit:
    - "git.push.force:<any>"
"#,
    )
    .unwrap();

    let mut child = gommage(&home)
        .args(["map", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git push --force origin main"}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("tool").and_then(|value| value.as_str()),
        Some("Bash")
    );
    assert_eq!(
        report.get("mapper_rules").and_then(|value| value.as_u64()),
        Some(3)
    );
    let capabilities = report
        .get("capabilities")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"proc.exec:git push --force origin main"));
    assert!(capabilities.contains(&"git.push:refs/heads/main"));
    assert!(capabilities.contains(&"net.out:github.com"));
    assert!(capabilities.contains(&"git.push.force:<any>"));
    assert!(
        report
            .get("input_hash")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("sha256:"))
    );
    assert!(report.get("decision").is_none());
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("audit.log").exists());

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
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#,
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
    assert!(capabilities.contains(&"proc.exec:git push --force origin main"));
    assert!(capabilities.contains(&"git.push:refs/heads/main"));
    assert!(capabilities.contains(&"net.out:github.com"));
    assert!(capabilities.contains(&"git.push.force:<any>"));
    assert!(!home.join("policy.d").exists());
    assert!(!home.join("audit.log").exists());
}

#[test]
fn decide_teaches_explicit_paths_for_bulk_git_stage() {
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
        .args(["decide", "--pretty"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git add -A"}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"]["kind"].as_str(), Some("gommage"));
    assert_eq!(
        report["matched_rule"]["name"].as_str(),
        Some("deny-bulk-git-stage")
    );
    let reason = report["decision"]["reason"].as_str().unwrap();
    assert!(reason.contains("Stage explicit paths"));
    assert!(reason.contains("git add path/to/file.rs path/to/test.rs"));
}

#[test]
fn list_and_decide_do_not_initialize_selected_home_state() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("selected-home");
    init_home_with_stdlib(&home);
    for path in [
        home.join("key.ed25519"),
        home.join("pictos.sqlite"),
        home.join("pictos.sqlite-wal"),
        home.join("pictos.sqlite-shm"),
    ] {
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }

    let listed = gommage(&home).args(["list", "--json"]).output().unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&listed.stdout).unwrap(),
        serde_json::json!([])
    );

    let mut child = gommage(&home)
        .arg("decide")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool":"Bash","input":{"command":"git status"}}"#)
        .unwrap();
    let decided = child.wait_with_output().unwrap();
    assert!(
        decided.status.success(),
        "{}",
        String::from_utf8_lossy(&decided.stderr)
    );

    for path in [
        home.join("key.ed25519"),
        home.join("pictos.sqlite"),
        home.join("pictos.sqlite-wal"),
        home.join("pictos.sqlite-shm"),
    ] {
        assert!(
            !path.exists(),
            "read-only command created {}",
            path.display()
        );
    }
}

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

#[test]
fn smoke_json_reports_semantic_passes() {
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

    let output = gommage(&home).args(["smoke", "--json"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report.get("status").and_then(|value| value.as_str()),
        Some("pass")
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert!(
        report
            .pointer("/summary/passed")
            .and_then(|value| value.as_u64())
            .unwrap()
            >= 7
    );
    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("ask_mcp_write")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("ask_picto")
    }));
    assert!(checks.iter().any(|check| {
        check.get("name").and_then(|value| value.as_str()) == Some("allow_feature_push")
            && check
                .pointer("/actual/kind")
                .and_then(|value| value.as_str())
                == Some("allow")
    }));
}

#[test]
fn smoke_json_warns_for_local_policy_relaxations() {
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

    fs::write(
        home.join("policy.d")
            .join("14-operator-allow-agent-tools.yaml"),
        r#"- name: operator-allow-web-fetch
  decision: allow
  match:
    any_capability:
      - "net.fetch:*"
    all_capability:
      - "net.fetch:*"
      - "net.out:*"
  reason: "operator opts into frictionless WebFetch"

- name: operator-allow-mcp
  decision: allow
  match:
    any_capability:
      - "mcp.write:*"
    all_capability:
      - "mcp.write:*"
      - "mcp.call:*"
  reason: "operator opts into frictionless MCP"
"#,
    )
    .unwrap();
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

    let output = gommage(&home).args(["smoke", "--json"]).output().unwrap();

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
        report
            .pointer("/summary/warnings")
            .and_then(|value| value.as_u64()),
        Some(3)
    );
    assert_eq!(
        report
            .pointer("/summary/failed")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    let checks = report
        .get("checks")
        .and_then(|value| value.as_array())
        .unwrap();
    for name in ["ask_main_push", "ask_web_fetch", "ask_mcp_write"] {
        assert!(checks.iter().any(|check| {
            check.get("name").and_then(|value| value.as_str()) == Some(name)
                && check.get("status").and_then(|value| value.as_str()) == Some("warn")
                && check
                    .get("warning")
                    .and_then(|value| value.as_str())
                    .is_some()
        }));
    }
}

#[test]
fn posture_json_reports_strict_stdlib_policy() {
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

    let output = gommage(&home).args(["posture", "--json"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["posture"].as_str(), Some("strict"));
    assert_eq!(report["summary"]["relaxed"].as_u64(), Some(0));
    assert!(report["checks"].as_array().unwrap().iter().all(|check| {
        check["classification"].as_str() == Some("same") && check["status"].as_str() == Some("pass")
    }));
}

#[test]
fn posture_json_reports_local_policy_relaxations() {
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

    fs::write(
        home.join("policy.d")
            .join("14-operator-allow-agent-tools.yaml"),
        r#"- name: operator-allow-web-fetch
  decision: allow
  match:
    any_capability:
      - "net.fetch:*"
    all_capability:
      - "net.fetch:*"
      - "net.out:*"
  reason: "operator opts into frictionless WebFetch"

- name: operator-allow-mcp
  decision: allow
  match:
    any_capability:
      - "mcp.write:*"
    all_capability:
      - "mcp.write:*"
      - "mcp.call:*"
  reason: "operator opts into frictionless MCP"
"#,
    )
    .unwrap();
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

    let output = gommage(&home).args(["posture", "--json"]).output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("warn"));
    assert_eq!(report["posture"].as_str(), Some("relaxed"));
    assert_eq!(report["summary"]["relaxed"].as_u64(), Some(3));
    let checks = report["checks"].as_array().unwrap();
    for name in ["ask_main_push", "ask_web_fetch", "ask_mcp_write"] {
        assert!(checks.iter().any(|check| {
            check["name"].as_str() == Some(name)
                && check["classification"].as_str() == Some("relaxed")
                && check["active_decision"]["kind"].as_str() == Some("allow")
        }));
    }
}

#[test]
fn policy_init_can_remove_known_local_relaxation_layers() {
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

    let agent_allow_path = home
        .join("policy.d")
        .join("14-operator-allow-agent-tools.yaml");
    let main_push_path = home.join("policy.d").join("19-operator-main-push.yaml");
    let bundled_git_path = home.join("policy.d").join("20-git.yaml");
    fs::write(
        &agent_allow_path,
        r#"- name: operator-allow-web-fetch
  decision: allow
  match:
    any_capability:
      - "net.fetch:*"
    all_capability:
      - "net.fetch:*"
      - "net.out:*"
  reason: "operator opts into frictionless WebFetch"

- name: operator-allow-mcp
  decision: allow
  match:
    any_capability:
      - "mcp.write:*"
    all_capability:
      - "mcp.write:*"
      - "mcp.call:*"
  reason: "operator opts into frictionless MCP"
"#,
    )
    .unwrap();
    fs::write(
        &main_push_path,
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
    fs::write(
        &bundled_git_path,
        r#"- name: operator-allow-main-push
  decision: allow
  match:
    any_capability:
      - "git.push:refs/heads/main"
      - "git.push:refs/heads/master"
  reason: "operator modified bundled git policy locally"
"#,
    )
    .unwrap();

    let output = gommage(&home)
        .args([
            "policy",
            "init",
            "--stdlib",
            "--force",
            "--remove-local-relaxations",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("warn daemon reload skipped: no daemon listening"));
    assert!(!agent_allow_path.exists());
    assert!(!main_push_path.exists());
    assert!(bundled_git_path.exists());
    let restored_git_policy = fs::read_to_string(&bundled_git_path).unwrap();
    assert!(restored_git_policy.contains("gate-main-push"));
    assert!(!restored_git_policy.contains("operator modified bundled git policy locally"));

    let backups = fs::read_dir(home.join("policy.d"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        backups
            .iter()
            .any(|name| name.starts_with("14-operator-allow-agent-tools.yaml.gommage-bak-"))
    );
    assert!(
        backups
            .iter()
            .any(|name| name.starts_with("19-operator-main-push.yaml.gommage-bak-"))
    );
    assert!(
        backups
            .iter()
            .any(|name| name.starts_with("20-git.yaml.gommage-bak-"))
    );

    let posture = gommage(&home).args(["posture", "--json"]).output().unwrap();
    assert!(
        posture.status.success(),
        "{}",
        String::from_utf8_lossy(&posture.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&posture.stdout).unwrap();
    assert_eq!(report["posture"].as_str(), Some("strict"));
    assert_eq!(report["summary"]["relaxed"].as_u64(), Some(0));
}
