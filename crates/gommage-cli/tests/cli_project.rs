mod support;

use support::gommage;
use tempfile::tempdir;

#[test]
fn project_init_dry_run_and_write_creates_testable_project_policy() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage-home");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    assert!(gommage(&home).arg("init").status().unwrap().success());
    assert!(
        gommage(&home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );

    let dry_run = gommage(&home)
        .args([
            "project",
            "init",
            "--root",
            project.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_report: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_report["status"].as_str(), Some("pass"));
    assert_eq!(dry_report["dry_run"].as_bool(), Some(true));
    assert!(!project.join(".gommage/policy.d/20-project.yaml").exists());

    let write = gommage(&home)
        .args(["project", "init", "--root", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert!(project.join(".gommage/policy.d/20-project.yaml").exists());
    assert!(project.join(".gommage/policy-fixtures.yaml").exists());
    assert!(project.join(".gommage/README.md").exists());

    let fixture = project.join(".gommage/policy-fixtures.yaml");
    let output = gommage(&home)
        .env(
            "GOMMAGE_PROJECT_POLICY_DIR",
            project.join(".gommage/policy.d"),
        )
        .args(["policy", "test", fixture.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
}

#[test]
fn project_init_resolves_relative_root_before_writing_policy() {
    let temp = tempdir().unwrap();
    let home = temp.path().join(".gommage-home");

    let output = gommage(&home)
        .current_dir(temp.path())
        .args(["project", "init", "--root", "relative-project", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"].as_str(), Some("pass"));
    let policy = std::fs::read_to_string(
        temp.path()
            .join("relative-project/.gommage/policy.d/20-project.yaml"),
    )
    .unwrap();
    assert!(!policy.contains("fs.write:relative-project/.env"));
    assert!(policy.contains("/relative-project/.env"));
}
