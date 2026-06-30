use std::path::Path;
use std::process::Command;

#[test]
fn publish_crates_script_prints_workspace_versions() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();

    let output = Command::new("sh")
        .args(["scripts/publish-crates.sh", "--print-versions"])
        .current_dir(repo_root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.first(), Some(&"== local crate versions =="));

    let expected_packages = [
        "gommage-stdlib",
        "gommage-core",
        "gommage-audit",
        "gommage-cli",
        "gommage-daemon",
        "gommage-mcp",
    ];
    assert_eq!(lines.len(), expected_packages.len() + 1);

    for (line, package) in lines.iter().skip(1).zip(expected_packages) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 2, "{line}");
        assert_eq!(fields[0], package);
        assert!(!fields[1].is_empty(), "{line}");
        assert!(!fields[1].contains("path+file"), "{line}");
    }

    assert!(stdout.contains(&format!("gommage-cli {}", env!("CARGO_PKG_VERSION"))));
}
