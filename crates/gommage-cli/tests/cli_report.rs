mod support;

use std::fs;
use support::gommage;
use tempfile::tempdir;

#[test]
fn report_bundle_writes_redacted_support_json() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let settings = temp.path().join("claude").join("settings.json");
    let codex_hooks = temp.path().join("codex").join("hooks.json");
    let codex_config = temp.path().join("codex").join("config.toml");
    let output = temp.path().join("reports").join("gommage-report.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::create_dir_all(codex_hooks.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"permissions":{"allow":["Bash"]}}"#).unwrap();
    fs::write(&codex_hooks, r#"{"PreToolUse":[]}"#).unwrap();
    fs::write(
        &codex_config,
        "sandbox_mode = \"workspace-write\"\n[features]\ncodex_hooks = true\n",
    )
    .unwrap();

    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let command = gommage(&home)
        .env("GOMMAGE_CLAUDE_SETTINGS", &settings)
        .env("GOMMAGE_CODEX_HOOKS", &codex_hooks)
        .env("GOMMAGE_CODEX_CONFIG", &codex_config)
        .env("GH_TOKEN", "super-secret-token")
        .args([
            "report",
            "bundle",
            "--redact",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        command.status.success(),
        "{}",
        String::from_utf8_lossy(&command.stderr)
    );
    assert!(
        String::from_utf8_lossy(&command.stdout)
            .contains(&format!("ok report bundle: {}", output.display()))
    );

    let raw = fs::read_to_string(&output).unwrap();
    assert!(!raw.contains("super-secret-token"));
    let report: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        report.pointer("/schema_version").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        report.pointer("/redacted").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        report.pointer("/cli/version").and_then(|v| v.as_str()),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        report.pointer("/doctor/status").and_then(|v| v.as_str()),
        Some("warn")
    );
    assert_eq!(
        report.pointer("/verify/status").and_then(|v| v.as_str()),
        Some("warn")
    );
    assert_eq!(
        report
            .pointer("/approvals/requests_total")
            .and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/approvals/webhook_dead_letters")
            .and_then(|v| v.as_u64()),
        Some(0)
    );
    assert!(
        report
            .pointer("/home/approval_webhook_dlq")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains(".gommage")
    );
    assert_eq!(
        report
            .pointer("/inventory/policies/files")
            .and_then(|v| v.as_array())
            .unwrap()
            .len(),
        8
    );
    assert!(
        report
            .pointer("/environment")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .any(|entry| {
                entry.get("name").and_then(|v| v.as_str()) == Some("GH_TOKEN")
                    && entry.get("value").and_then(|v| v.as_str()) == Some("<redacted>")
            })
    );
}

#[test]
fn report_bundle_requires_redaction() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let output = temp.path().join("report.json");

    let command = gommage(&home)
        .args(["report", "bundle", "--output", output.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("requires --redact"));
    assert!(!output.exists());
}

#[test]
fn report_bundle_refuses_to_replace_without_force() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let output = temp.path().join("report.json");
    fs::write(&output, "existing").unwrap();

    let command = gommage(&home)
        .args([
            "report",
            "bundle",
            "--redact",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("already exists"));
    assert_eq!(fs::read_to_string(&output).unwrap(), "existing");
}
