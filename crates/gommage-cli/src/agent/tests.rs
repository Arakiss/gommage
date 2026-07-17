use super::*;

#[test]
fn owned_hook_parser_handles_escaped_arguments_conservatively() {
    assert!(hook_command_is_owned_by_gommage(
        r"gommage --home /tmp/gommage\ home hook --agent claude",
        AgentKind::Claude,
        None,
    ));
    assert!(!hook_command_is_owned_by_gommage(
        r"echo\ gommage hook --agent claude",
        AgentKind::Claude,
        None,
    ));
    assert!(!hook_command_is_owned_by_gommage(
        "gommage hook --agent claude && operator-command",
        AgentKind::Claude,
        None,
    ));
}

#[test]
fn broad_write_native_permissions_collapse_to_one_capability() {
    let rules = vec![
        "Write".to_string(),
        "Edit".to_string(),
        "NotebookEdit(*)".to_string(),
        "MultiEdit(**)".to_string(),
    ];

    let (translated, skipped) =
        translate_claude_native_rules(&rules, translate_claude_permission_allow);
    let grouped = group_native_permission_imports(&translated);

    assert!(skipped.is_empty());
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].capability, "fs.write:**");
    assert_eq!(
        grouped[0].raws,
        vec!["Write", "Edit", "NotebookEdit(*)", "MultiEdit(**)"]
    );
}

#[test]
fn native_star_path_is_normalized_to_recursive_glob() {
    assert_eq!(
        translate_claude_permission_allow("Read(*)").as_deref(),
        Some("fs.read:**")
    );
    assert_eq!(
        translate_claude_permission_allow("Write(*)").as_deref(),
        Some("fs.write:**")
    );
}

#[test]
fn agent_install_generates_posture_policy_that_parses() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = HomeLayout::at(tmp.path());
    layout.ensure().unwrap();

    write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();

    for name in ["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"] {
        assert!(
            layout.policy_dir.join(name).exists(),
            "expected generated posture file {name}"
        );
    }

    let mut env = std::collections::HashMap::new();
    env.insert("HOME".to_string(), "/home/test".to_string());
    env.insert("EXPEDITION_ROOT".to_string(), "/home/test/proj".to_string());
    let policy = gommage_core::Policy::load_from_dir(&layout.policy_dir, &env).unwrap();

    for rule in [
        "agent-config-writable-claude",
        "agent-config-writable-gommage",
        "agent-catch-all-proc-exec",
        "agent-catch-all-fs-write",
    ] {
        assert!(
            policy.rules.iter().any(|r| r.name == rule),
            "expected posture rule {rule}"
        );
    }
}

#[test]
fn agent_posture_dry_run_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = HomeLayout::at(tmp.path());
    layout.ensure().unwrap();

    write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, true).unwrap();

    assert!(
        !layout.policy_dir.join("95-agent-catch-all.yaml").exists(),
        "dry-run must not write posture files"
    );
}

#[test]
fn strict_posture_backs_up_and_removes_generated_relaxations() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = HomeLayout::at(tmp.path());
    layout.ensure().unwrap();
    write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();

    write_agent_posture_policy(&layout, AgentPolicyMode::Strict, false).unwrap();

    for name in ["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"] {
        assert!(!layout.policy_dir.join(name).exists(), "active {name}");
        let prefix = format!("{name}.gommage-bak-");
        assert!(
            std::fs::read_dir(&layout.policy_dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .any(|candidate| candidate.starts_with(&prefix)),
            "missing backup for {name}"
        );
    }
}

#[test]
fn strict_posture_preserves_all_files_when_a_reserved_layer_is_custom() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = HomeLayout::at(tmp.path());
    layout.ensure().unwrap();
    write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();
    let custom = layout.policy_dir.join("90-claude-allow-import.yaml");
    std::fs::write(&custom, "# operator-owned\n[]\n").unwrap();

    let error = write_agent_posture_policy(&layout, AgentPolicyMode::Strict, false)
        .expect_err("custom reserved layer must block strict migration");

    assert!(error.to_string().contains("custom or modified file"));
    assert_eq!(
        std::fs::read_to_string(&custom).unwrap(),
        "# operator-owned\n[]\n"
    );
    assert!(
        layout
            .policy_dir
            .join("06-agent-config-writable.yaml")
            .exists()
    );
    assert!(layout.policy_dir.join("95-agent-catch-all.yaml").exists());
}
