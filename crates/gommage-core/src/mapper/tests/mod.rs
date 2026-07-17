use super::*;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn git_push_to_main() {
    let yaml = r#"
- name: bash-git-push
  tool: Bash
  match_input:
    command: "^git push(?:\\s+origin)?\\s+(?P<ref>\\S+)"
  emit:
    - "git.push:refs/heads/${ref}"
    - "net.out:github.com"
"#;
    let m = CapabilityMapper::from_yaml_string(yaml, "git.yaml").unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command": "git push origin main"}),
    };
    let caps = m.map(&call);
    assert_eq!(
        caps,
        vec![
            Capability::new("git.push:refs/heads/main"),
            Capability::new("net.out:github.com")
        ]
    );
}

#[test]
fn fs_write_template_from_input() {
    let yaml = r#"
- name: fs-write
  tool: Write
  emit:
    - "fs.write:${input.file_path}"
"#;
    let m = CapabilityMapper::from_yaml_string(yaml, "fs.yaml").unwrap();
    let call = ToolCall {
        tool: "Write".into(),
        input: json!({"file_path": "/tmp/x.txt", "content": "hi"}),
    };
    assert_eq!(m.map(&call), vec![Capability::new("fs.write:/tmp/x.txt")]);
}

#[test]
fn non_matching_tool_emits_nothing() {
    let yaml = r#"
- name: only-bash
  tool: Bash
  emit: ["proc.exec:${input.command}"]
"#;
    let m = CapabilityMapper::from_yaml_string(yaml, "x.yaml").unwrap();
    let call = ToolCall {
        tool: "Read".into(),
        input: json!({"file_path": "/tmp/x"}),
    };
    assert!(m.map(&call).is_empty());
}

#[test]
fn multiple_rules_fire_in_order() {
    let yaml = r#"
- name: a
  tool: Bash
  match_input: { command: "^echo" }
  emit: ["proc.exec:echo"]
- name: b
  tool: Bash
  match_input: { command: "^echo" }
  emit: ["net.out:unknown"]
"#;
    let m = CapabilityMapper::from_yaml_string(yaml, "x.yaml").unwrap();
    let call = ToolCall {
        tool: "Bash".into(),
        input: json!({"command": "echo hi"}),
    };
    assert_eq!(
        m.map(&call),
        vec![
            Capability::new("proc.exec:echo"),
            Capability::new("net.out:unknown")
        ]
    );
}

#[test]
fn tool_pattern_emits_actual_tool_name_and_captures() {
    let yaml = r#"
- name: mcp-read
  tool_pattern: "^mcp__(?P<server>.+)__read_.*$"
  emit:
    - "mcp.read:${tool}"
    - "mcp.server:${server}"
"#;
    let m = CapabilityMapper::from_yaml_string(yaml, "mcp.yaml").unwrap();
    let call = ToolCall {
        tool: "mcp__filesystem__read_file".into(),
        input: json!({"path": "/tmp/x"}),
    };
    assert_eq!(
        m.map(&call),
        vec![
            Capability::new("mcp.read:mcp__filesystem__read_file"),
            Capability::new("mcp.server:filesystem")
        ]
    );
}

#[test]
fn mapper_rule_requires_one_tool_matcher() {
    let yaml = r#"
- name: bad
  emit: ["x"]
"#;
    assert!(CapabilityMapper::from_yaml_string(yaml, "bad.yaml").is_err());
}

// --- Shell-aware (shape) mapping (R1 / R3) ------------------------------

/// A minimal mapper mirroring the shipped bash.yaml shapes relevant to the
/// shell-aware tests: whole-command proc.exec for audit + a per-segment
/// git.push rule.
fn shell_mapper() -> CapabilityMapper {
    let yaml = r#"
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
- name: bash-git-reset-hard
  tool: Bash
  match_input:
    command: "^\\s*git\\s+reset\\s+--hard\\b"
  emit:
    - "git.reset.hard:<any>"
"#;
    CapabilityMapper::from_yaml_string(yaml, "bash.yaml").unwrap()
}

fn typed_mapper() -> CapabilityMapper {
    CapabilityMapper::from_yaml_string(
        r#"
- name: bash-proc-exec
  tool: Bash
  emit: ["proc.exec:${input.command}"]
"#,
        "typed-bash.yaml",
    )
    .unwrap()
}

fn bash(cmd: &str) -> ToolCall {
    ToolCall {
        tool: "Bash".into(),
        input: json!({ "command": cmd }),
    }
}

fn caps_of(m: &CapabilityMapper, cmd: &str) -> Vec<String> {
    m.map(&bash(cmd))
        .into_iter()
        .map(|c| c.as_str().to_string())
        .collect()
}

fn caps_of_call(m: &CapabilityMapper, call: ToolCall) -> Vec<String> {
    m.map(&call)
        .into_iter()
        .map(|c| c.as_str().to_string())
        .collect()
}

mod gommage;
mod security;
mod shell_effects;
