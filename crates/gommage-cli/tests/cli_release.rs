use std::fs;
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

#[test]
fn publish_crates_script_parses_crates_io_rate_limit_retry_after() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();
    let log_path = std::env::temp_dir().join(format!(
        "gommage-crates-rate-limit-{}-{}.log",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    ));

    fs::write(
        &log_path,
        "the remote server responded with an error (status 429 Too Many Requests): \
         You have published too many new crates in a short period of time. \
         Please try again after Thu, 01 Jan 1970 00:00:10 GMT and see \
         https://crates.io/docs/rate-limits for more details.\n",
    )
    .unwrap();

    let output = Command::new("sh")
        .args([
            "scripts/publish-crates.sh",
            "--internal-retry-after-delay",
            log_path.to_str().unwrap(),
        ])
        .env("GOMMAGE_CRATES_IO_TEST_NOW_EPOCH", "0")
        .env("GOMMAGE_CRATES_IO_RETRY_PADDING_SECONDS", "0")
        .current_dir(repo_root)
        .output()
        .unwrap();

    let _ = fs::remove_file(&log_path);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "10");
}
