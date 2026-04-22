mod support;

use std::{fs, io::Write, process::Stdio};
use support::gommage;
use tempfile::tempdir;

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
