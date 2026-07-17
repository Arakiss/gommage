use super::*;

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
