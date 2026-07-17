use super::*;

#[test]
fn quickstart_dry_run_explain_prints_harness_guidance() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--dry-run", "--explain"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("explain mode: coexistence"));
    assert!(stdout.contains("explain claude hooks: strategy=append_preserving_unrelated"));
    assert!(stdout.contains("explain claude: posture="));
    assert!(stdout.contains("next: gommage harness diagnose --json"));
    assert!(stdout.contains("plan harness-context"));
    assert!(!home.exists());
}

#[test]
fn quickstart_writes_agent_context_files() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ok harness context"));

    let context = fs::read_to_string(home.join("AGENT_CONTEXT.md")).unwrap();
    assert!(context.contains("# Gommage Local Integration Context"));
    assert!(context.contains("Default install mode"));

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join("integration-report.json")).unwrap())
            .unwrap();
    assert_eq!(
        report
            .pointer("/agents/0/agent")
            .and_then(|value| value.as_str()),
        Some("claude")
    );
}

#[test]
fn generated_native_deny_import_is_refreshed_and_removed_when_source_changes() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"permissions":{"deny":["Read(./old-sensitive/**)"]}}"#,
    )
    .unwrap();

    let first = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--no-self-test"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let import_path = home.join("policy.d/05-claude-import.yaml");
    assert!(
        fs::read_to_string(&import_path)
            .unwrap()
            .contains("old-sensitive")
    );

    fs::write(
        &settings,
        r#"{"permissions":{"deny":["Read(./new-sensitive/**)"]}}"#,
    )
    .unwrap();
    let stale_status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();
    let stale_report: serde_json::Value = serde_json::from_slice(&stale_status.stdout).unwrap();
    assert!(!stale_status.status.success());
    assert_eq!(
        doctor_check(&stale_report, "deny_import")["status"].as_str(),
        Some("fail")
    );
    assert_eq!(
        doctor_check(&stale_report, "deny_import")
            .pointer("/details/content_state")
            .and_then(|value| value.as_str()),
        Some("stale_generated")
    );

    let refreshed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    let imported = fs::read_to_string(&import_path).unwrap();
    assert!(imported.contains("new-sensitive"));
    assert!(!imported.contains("old-sensitive"));
    assert!(imported.contains("# Generated content SHA-256:"));

    let status = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "status", "claude", "--json"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        doctor_check(&report, "deny_import")
            .pointer("/details/content_state")
            .and_then(|value| value.as_str()),
        Some("current")
    );

    fs::write(&settings, r#"{"permissions":{"deny":[]}}"#).unwrap();
    let removed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(!import_path.exists());
    assert!(
        fs::read_dir(home.join("policy.d"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("05-claude-import.yaml.gommage-bak-"))
    );
}

#[test]
fn modified_generated_posture_blocks_before_any_agent_config_write() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();

    let relaxed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--relaxed",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(relaxed.status.success());
    let settings_before = fs::read(&settings).unwrap();
    let catch_all = home.join("policy.d/95-agent-catch-all.yaml");
    let mut modified = fs::read_to_string(&catch_all).unwrap();
    modified.push_str(
        "\n- name: operator-owned-extra\n  decision: allow\n  match:\n    any_capability: [\"custom:**\"]\n",
    );
    fs::write(&catch_all, &modified).unwrap();

    let failed = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("custom or modified"));
    assert_eq!(fs::read(&settings).unwrap(), settings_before);
    assert_eq!(fs::read_to_string(&catch_all).unwrap(), modified);
}

#[test]
fn relaxed_install_does_not_overwrite_a_custom_reserved_policy() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    let reserved = home.join("policy.d/06-agent-config-writable.yaml");
    let custom = "# operator-owned\n[]\n";
    fs::write(&reserved, custom).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args([
            "agent",
            "install",
            "claude",
            "--relaxed",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&reserved).unwrap(), custom);
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
}

#[test]
fn digestless_legacy_import_requires_review_and_is_not_removed() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"permissions":{"deny":[]}}"#).unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    let import_path = home.join("policy.d/05-claude-import.yaml");
    let legacy_modified = r#"# Generated by `gommage quickstart` from Claude Code permissions.deny.
# Review before sharing; native permission syntax is broader than Gommage capabilities.
# Deny imports live before stdlib allow rules so native blocks remain fail-closed.

- name: claude-import-deny-01
  decision: gommage
  match:
    any_capability:
      - "proc.exec:operator-deny"
  reason: "imported from Claude Code permissions.deny: operator hardening"
"#;
    fs::write(&import_path, legacy_modified).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["agent", "install", "claude"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("custom or modified"));
    assert_eq!(fs::read_to_string(&import_path).unwrap(), legacy_modified);
    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        r#"{"permissions":{"deny":[]}}"#
    );
}

#[test]
fn quickstart_json_marks_custom_reserved_policy_as_blocked() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}\n").unwrap();
    fs::create_dir_all(home.join("policy.d")).unwrap();
    fs::write(
        home.join("policy.d/95-agent-catch-all.yaml"),
        "# operator-owned\n[]\n",
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .args(["quickstart", "--agent", "claude", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("blocked"));
    assert_eq!(report["execution_ready"].as_bool(), Some(false));
    assert!(
        report["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| { operation["action"].as_str() == Some("custom_requires_review") })
    );
    assert_eq!(fs::read_to_string(&settings).unwrap(), "{}\n");
}

#[test]
fn agent_install_rolls_back_prior_writes_when_a_later_config_write_fails() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let combined_config = temp.path().join("codex").join("combined-config");
    fs::create_dir_all(combined_config.parent().unwrap()).unwrap();
    let original = "";
    fs::write(&combined_config, original).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_CODEX_HOOKS", &combined_config)
        .env("GOMMAGE_CODEX_CONFIG", &combined_config)
        .args([
            "agent",
            "install",
            "codex",
            "--no-import-native-permissions",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rolled back"));
    assert_eq!(fs::read_to_string(&combined_config).unwrap(), original);
    assert!(!home.exists());
    assert!(
        !fs::read_dir(combined_config.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("combined-config.gommage-bak-"))
    );
}
