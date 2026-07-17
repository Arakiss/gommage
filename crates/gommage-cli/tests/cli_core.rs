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

#[path = "cli_core/basics.rs"]
mod basics;
#[path = "cli_core/hooks.rs"]
mod hooks;
#[path = "cli_core/mapping.rs"]
mod mapping;
#[path = "cli_core/posture.rs"]
mod posture;
