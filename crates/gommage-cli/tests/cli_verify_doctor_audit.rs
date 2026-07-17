mod support;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Output, Stdio},
};
use support::{doctor_check, gommage, workspace_path};
use tempfile::tempdir;

fn init_trace_home(home: &Path, policy: &str, mapper: &str) {
    assert!(gommage(home).arg("init").status().unwrap().success());
    assert!(
        gommage(home)
            .args(["policy", "init", "--stdlib"])
            .status()
            .unwrap()
            .success()
    );
    replace_yaml_dir(&home.join("policy.d"), "10-trace.yaml", policy);
    replace_yaml_dir(&home.join("capabilities.d"), "10-trace.yaml", mapper);
}

fn replace_yaml_dir(dir: &Path, file: &str, contents: &str) {
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(file), contents).unwrap();
}

fn emit_trace_probe(home: &Path, org: Option<&Path>, project: Option<&Path>) -> String {
    let mut command = gommage(home);
    command
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    set_policy_layer_env(&mut command, org, project);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"hook_event_name":"PreToolUse","tool_name":"TraceProbe","tool_input":{}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let audit = fs::read_to_string(home.join("audit.log")).unwrap();
    audit
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("tool").and_then(Value::as_str) == Some("TraceProbe"))
        .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_string))
        .unwrap()
}

fn explain_trace(
    home: &Path,
    id: &str,
    org: Option<&Path>,
    project: Option<&Path>,
    json: bool,
) -> Output {
    let mut command = gommage(home);
    command.args(["explain", id, "--trace"]);
    if json {
        command.arg("--json");
    }
    set_policy_layer_env(&mut command, org, project);
    command.output().unwrap()
}

fn set_policy_layer_env(
    command: &mut std::process::Command,
    org: Option<&Path>,
    project: Option<&Path>,
) {
    command.env_remove("GOMMAGE_ORG_POLICY_DIR");
    command.env_remove("GOMMAGE_PROJECT_POLICY_DIR");
    if let Some(org) = org {
        command.env("GOMMAGE_ORG_POLICY_DIR", org);
    }
    if let Some(project) = project {
        command.env("GOMMAGE_PROJECT_POLICY_DIR", project);
    }
}

fn provenance_for<'a>(report: &'a Value, field: &str, capability: &str) -> &'a Value {
    report[field]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["capability"].as_str() == Some(capability))
        .unwrap()
}

fn base64_standard_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[usize::from(first >> 2)] as char);
        encoded.push(ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[usize::from(third & 0x3f)] as char);
        }
    }
    encoded
}

fn write_signed_legacy_v1(home: &Path) -> &'static str {
    const ID: &str = "audit_legacy_cli";
    let key_bytes: [u8; 32] = fs::read(home.join("key.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&key_bytes);
    let canonical = br#"{"capabilities":["trace.a"],"decision":{"kind":"allow"},"expedition":null,"id":"audit_legacy_cli","input_hash":"sha256:input","matched_rule":null,"policy_version":"sha256:legacy","tool":"TraceProbe","ts":"2026-04-24T00:00:00Z","v":1}"#;
    let signature = key.sign(canonical);
    let line = serde_json::json!({
        "v": 1,
        "id": ID,
        "ts": "2026-04-24T00:00:00Z",
        "tool": "TraceProbe",
        "input_hash": "sha256:input",
        "capabilities": ["trace.a"],
        "decision": {"kind": "allow"},
        "matched_rule": null,
        "policy_version": "sha256:legacy",
        "expedition": null,
        "sig": format!(
            "ed25519:{}",
            base64_standard_no_pad(&signature.to_bytes())
        ),
    });
    fs::write(
        home.join("audit.log"),
        format!("{}\n", serde_json::to_string(&line).unwrap()),
    )
    .unwrap();
    ID
}

#[path = "cli_verify_doctor_audit/audit.rs"]
mod audit;
#[path = "cli_verify_doctor_audit/trace.rs"]
mod trace;
#[path = "cli_verify_doctor_audit/verify.rs"]
mod verify;
