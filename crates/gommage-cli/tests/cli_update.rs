mod support;

use std::fs;
use support::gommage;
use tempfile::tempdir;

fn releases_fixture(tag: &str) -> String {
    format!(
        r#"[
  {{
    "tag_name": "{tag}",
    "assets": [
      {{ "name": "gommage-aarch64-darwin.tar.gz" }},
      {{ "name": "gommage-aarch64-linux.tar.gz" }},
      {{ "name": "gommage-x86_64-darwin.tar.gz" }},
      {{ "name": "gommage-x86_64-linux.tar.gz" }}
    ]
  }}
]
"#
    )
}

#[test]
fn update_json_reports_upgrade_available() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let releases = temp.path().join("releases.json");
    fs::write(&releases, releases_fixture("gommage-cli-v999.0.0")).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_RELEASES_JSON", &releases)
        .args(["update", "--json"])
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
        Some("upgrade_available")
    );
    assert_eq!(
        report.get("latest_tag").and_then(|value| value.as_str()),
        Some("gommage-cli-v999.0.0")
    );
    assert_eq!(
        report
            .get("upgrade_command")
            .and_then(|value| value.as_str()),
        Some("gommage upgrade")
    );
}

#[test]
fn update_check_exits_nonzero_when_upgrade_is_available() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let releases = temp.path().join("releases.json");
    fs::write(&releases, releases_fixture("gommage-cli-v999.0.0")).unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_RELEASES_JSON", &releases)
        .args(["update", "--check"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("status: upgrade_available"));
    assert!(stdout.contains("next: gommage upgrade"));
}

#[test]
fn update_reports_up_to_date_for_current_release() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let releases = temp.path().join("releases.json");
    fs::write(
        &releases,
        releases_fixture(&format!("gommage-cli-v{}", env!("CARGO_PKG_VERSION"))),
    )
    .unwrap();

    let output = gommage(&home)
        .env("GOMMAGE_RELEASES_JSON", &releases)
        .arg("update")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("status: up_to_date"));
    assert!(stdout.contains("next: no binary upgrade needed"));
    assert!(stdout.contains("gommage upgrade --skill-only"));
}

#[test]
fn upgrade_dry_run_prints_installer_command() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");
    let bin_dir = temp.path().join("bin");

    let output = gommage(&home)
        .args([
            "upgrade",
            "--dry-run",
            "--version",
            "gommage-cli-v999.0.0",
            "--bin-dir",
            bin_dir.to_str().unwrap(),
            "--with-skill",
            "--skill-agent",
            "codex",
            "--skill-agent",
            "claude",
            "--no-prompt",
            "--verify",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("plan upgrade: run the Gommage installer"));
    assert!(stdout.contains("target: gommage-cli-v999.0.0"));
    assert!(stdout.contains("--bin-dir"));
    assert!(stdout.contains(bin_dir.to_str().unwrap()));
    assert!(stdout.contains("--with-skill"));
    assert!(stdout.contains("--skill-agent codex"));
    assert!(stdout.contains("--skill-agent claude"));
    assert!(stdout.contains("--verify"));
}

#[test]
fn upgrade_skill_only_dry_run_omits_binary_install_options() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage");

    let output = gommage(&home)
        .args([
            "upgrade",
            "--dry-run",
            "--skill-only",
            "--skill-agent",
            "all",
            "--no-prompt",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("mode: skill_only"));
    assert!(stdout.contains("--skill-only"));
    assert!(stdout.contains("--skill-agent all"));
    assert!(!stdout.contains("--version latest"));
    assert!(!stdout.contains("--bin-dir"));
}
