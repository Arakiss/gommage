use super::*;
use serde_json::json;

#[test]
fn enriches_grep_with_hook_cwd_when_path_is_implicit() {
    let input = enrich_tool_input(
        "Grep",
        json!({"pattern": "fn main", "glob": "*.rs"}),
        Some("/tmp/proj"),
        None,
    )
    .unwrap();
    assert_eq!(input["__gommage_path"], "/tmp/proj");
    assert_eq!(input["__gommage_glob_path"], "/tmp/proj/*.rs");
}

#[test]
fn enriches_grep_relative_path_against_hook_cwd() {
    let input = enrich_tool_input(
        "Grep",
        json!({"pattern": "todo", "path": "src"}),
        Some("/tmp/proj"),
        None,
    )
    .unwrap();
    assert_eq!(input["__gommage_path"], "/tmp/proj/src");
}

#[test]
fn strips_and_recomputes_existing_reserved_fields() {
    let input = enrich_tool_input(
        "Grep",
        json!({"pattern": "todo", "__gommage_path": "/already"}),
        Some("/tmp/proj"),
        None,
    )
    .unwrap();
    assert_eq!(input["__gommage_path"], "/tmp/proj");
}

#[test]
fn strips_reserved_fields_even_without_cwd() {
    let input = enrich_tool_input(
        "Write",
        json!({"file_path": "src/lib.rs", "__gommage_file_path": "/spoofed"}),
        None,
        None,
    )
    .unwrap();
    assert!(input.get("__gommage_file_path").is_none());
}

#[test]
fn enriches_apply_patch_with_resolved_patch_paths() {
    let input = enrich_tool_input(
            "apply_patch",
            json!({
                "command": "*** Begin Patch\n*** Update File: src/lib.rs\n*** Delete File: old.rs\n*** End Patch\n"
            }),
            Some("/tmp/proj"),
            None,
        )
        .unwrap();
    assert_eq!(input["__gommage_patch_path_0"], "/tmp/proj/src/lib.rs");
    assert_eq!(input["__gommage_patch_path_1"], "/tmp/proj/old.rs");
}

#[test]
fn enriches_apply_patch_unparsed_when_command_is_missing() {
    let input = enrich_tool_input("apply_patch", json!({}), Some("/tmp/proj"), None).unwrap();
    assert_eq!(input["__gommage_patch_unparsed"], true);
}

#[test]
fn hook_session_hash_is_domain_separated_and_spoof_resistant() {
    let call = parse_hook_tool_call(
            r#"{"session_id":"session-a","tool_name":"mcp__node_repl__js","tool_input":{"code":"1 + 1","__gommage_session_hash":"sha256:spoofed"}}"#,
        )
        .unwrap();

    assert_eq!(
        call.input["__gommage_session_hash"],
        ToolCall::host_session_hash("session-a")
    );
    assert_ne!(
        call.input["__gommage_session_hash"],
        Value::String("sha256:spoofed".to_string())
    );
    assert_eq!(
        call.input_hash(),
        "sha256:caf2b377b4cd0bcce801a72468fd232cf08a2bc2b1141990a3fceeaafa6a11c9"
    );
    assert!(
        !serde_json::to_string(&call.input)
            .unwrap()
            .contains("session-a")
    );
}

#[test]
fn hook_session_changes_hash_but_absence_is_stable() {
    let payload = |session: Option<&str>| {
        let session_field = session
            .map(|session| format!(r#""session_id":"{session}","#))
            .unwrap_or_default();
        parse_hook_tool_call(&format!(
            r#"{{{session_field}"tool_name":"mcp__node_repl__js","tool_input":{{"code":"1 + 1"}}}}"#
        ))
        .unwrap()
    };

    assert_ne!(
        payload(Some("session-a")).input_hash(),
        payload(Some("session-b")).input_hash()
    );
    let without_session = payload(None);
    assert_eq!(without_session.input_hash(), payload(None).input_hash());
    assert!(
        without_session
            .input
            .get("__gommage_session_hash")
            .is_none()
    );
}

#[test]
fn hook_session_rejects_non_object_tool_input() {
    let error = parse_hook_tool_call(
        r#"{"session_id":"session-a","tool_name":"mcp__node_repl__js","tool_input":"1 + 1"}"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("tool_input must be an object"));
}

#[test]
fn hook_session_rejects_empty_or_non_string_identifiers() {
    for session_id in [r#""""#, "null", "42"] {
        let error = parse_hook_tool_call(&format!(
                r#"{{"session_id":{session_id},"tool_name":"mcp__node_repl__js","tool_input":{{"code":"1 + 1"}}}}"#
            ))
            .unwrap_err();

        assert!(error.to_string().contains("hook session_id must"));
    }
}
