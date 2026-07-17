use super::*;

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
