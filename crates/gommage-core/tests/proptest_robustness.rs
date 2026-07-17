//! Property-based robustness tests.
//!
//! These are not a proof of correctness — they are a proof that Gommage's
//! user-input-facing parsers and matchers do not panic on arbitrary input.
//! Signing things ourselves and then proving we can verify them is a
//! deterministic unit test. Proving we don't crash on hundreds of variations
//! of garbage the attacker can feed us is proptest territory.
//!
//! Targets:
//!
//! 1. `CapabilityMapper::map` on arbitrary `ToolCall` → never panics.
//! 2. `Policy::from_yaml_string` on arbitrary strings → returns `Ok` or a
//!    `GommageError`. Never panics, never hangs.
//! 3. `Picto::verify` on a correctly-shaped picto with a random 64-byte
//!    signature → never panics and rejects.
//! 4. `evaluate` on arbitrary capability lists → returns one of the three
//!    decision variants. Never panics.

use gommage_core::{
    Capability, CapabilityMapper, Decision, GommageError, Policy, ToolCall, evaluate,
    picto::{Picto, PictoBinding, PictoStatus},
};
use proptest::prelude::*;
use std::collections::HashMap;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ----------------------------------------------------------------------------
// 1. Capability mapper fuzz
// ----------------------------------------------------------------------------

fn arb_tool_name() -> impl Strategy<Value = String> {
    // 3 branches — well under the TupleUnion ceiling.
    prop_oneof![
        Just("Bash".to_string()),
        Just("Read".to_string()),
        Just("Write".to_string()),
    ]
}

fn arb_simple_input() -> impl Strategy<Value = serde_json::Value> {
    // Keep it flat — mappers walk via dot-path.
    prop_oneof![
        ".{0,200}".prop_map(|s| serde_json::json!({ "command": s })),
        ".{0,200}".prop_map(|s| serde_json::json!({ "file_path": s })),
        Just(serde_json::json!({})),
    ]
}

fn arb_tool_call() -> impl Strategy<Value = ToolCall> {
    (arb_tool_name(), arb_simple_input()).prop_map(|(tool, input)| ToolCall { tool, input })
}

fn shipped_mapper() -> CapabilityMapper {
    CapabilityMapper::load_from_dir(&repo_root().join("capabilities"))
        .expect("loading shipped mapper")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn mapper_never_panics_on_arbitrary_tool_call(call in arb_tool_call()) {
        let m = shipped_mapper();
        let _ = m.map(&call);
    }

}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn mapper_output_is_order_stable_and_duplicate_free(call in arb_tool_call()) {
        let mapper = shipped_mapper();
        let first = mapper.map(&call);
        let second = mapper.map(&call);
        prop_assert_eq!(&first, &second);

        let mut unique = first
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>();
        unique.sort_unstable();
        unique.dedup();
        prop_assert_eq!(unique.len(), first.len(), "caps: {:?}", first);
    }

    #[test]
    fn dynamic_destinations_always_emit_ambiguity(suffix in "[a-zA-Z0-9_./-]{0,40}") {
        let mapper = shipped_mapper();
        let call = ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({
                "command": format!("touch \"$DEST{suffix}\"")
            }),
        };
        let capabilities = mapper.map(&call);
        prop_assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str().starts_with("proc.exec.ambiguous:")),
            "caps: {:?}",
            capabilities
        );
        prop_assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str().starts_with("proc.exec:")),
            "raw execution capability must remain authoritative"
        );
    }

    #[test]
    fn malformed_shell_never_maps_as_only_permissive_execution(
        prefix in "[a-zA-Z0-9_ ./-]{0,80}",
    ) {
        let mapper = shipped_mapper();
        let call = ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({
                "command": format!("printf %s {prefix} '")
            }),
        };
        let capabilities = mapper.map(&call);
        prop_assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str().starts_with("proc.exec.ambiguous:")),
            "caps: {:?}",
            capabilities
        );
        prop_assert!(capabilities.iter().any(|cap| cap.as_str().starts_with("proc.exec:")));
    }

    #[test]
    fn transparent_wrappers_do_not_remove_write_effect(
        wrapper in prop::sample::select(vec![
            "command --",
            "exec",
            "env X=1",
            "sudo --",
            "doas --",
            "timeout 2",
            "time",
            "nice -n 1",
            "nohup",
            "stdbuf -o0",
            "setsid",
        ]),
        name in "[a-zA-Z0-9_][a-zA-Z0-9_-]{0,29}",
    ) {
        let mapper = shipped_mapper();
        let command = format!("{wrapper} touch {name}");
        let capabilities = mapper.map(&ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({"command": command, "__gommage_cwd": "/repo"}),
        });
        let expected = format!("fs.write:/repo/{name}");
        prop_assert!(
            capabilities.iter().any(|cap| cap.as_str() == expected),
            "wrapper {wrapper:?} removed {expected:?}; caps: {:?}",
            capabilities
        );
    }

    #[test]
    fn adding_a_compound_command_never_removes_existing_effect(
        name in "[a-zA-Z0-9_][a-zA-Z0-9_-]{0,29}",
        prefix in prop::sample::select(vec!["true", "echo ok", "printf ok"]),
    ) {
        let mapper = shipped_mapper();
        let base = ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({"command": format!("touch {name}"), "__gommage_cwd": "/repo"}),
        };
        let compound = ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({"command": format!("{prefix}; touch {name}"), "__gommage_cwd": "/repo"}),
        };
        let expected = format!("fs.write:/repo/{name}");
        prop_assert!(mapper.map(&base).iter().any(|cap| cap.as_str() == expected));
        prop_assert!(mapper.map(&compound).iter().any(|cap| cap.as_str() == expected));
    }

    #[test]
    fn quote_changes_preserve_home_alias_provenance(
        name in "[a-zA-Z0-9_][a-zA-Z0-9_-]{0,29}",
    ) {
        let mapper = shipped_mapper();
        let expanded = mapper.map(&ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({"command": format!("touch \"$HOME/{name}\"")}),
        });
        let literal = mapper.map(&ToolCall {
            tool: "Bash".to_string(),
            input: serde_json::json!({"command": format!("touch '$HOME/{name}'")}),
        });
        let expanded_expected = format!("fs.write:$HOME/{name}");
        let literal_expected = format!("fs.write:./$HOME/{name}");
        prop_assert!(expanded.iter().any(|cap| cap.as_str() == expanded_expected));
        prop_assert!(literal.iter().any(|cap| cap.as_str() == literal_expected));
        prop_assert_ne!(expanded, literal);
    }
}

// ----------------------------------------------------------------------------
// 1b. Home path spelling equivalence
// ----------------------------------------------------------------------------

fn shipped_policy(home: &str) -> Policy {
    let mut env = HashMap::<String, String>::new();
    env.insert("HOME".to_string(), home.to_string());
    env.insert(
        "EXPEDITION_ROOT".to_string(),
        "/__no_expedition__".to_string(),
    );
    Policy::load_from_dir(&repo_root().join("policies"), &env).expect("loading shipped policy")
}

fn bash_redirect_to(path: &str) -> ToolCall {
    ToolCall {
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": format!("printf x > {path}") }),
    }
}

fn decision_summary(eval: &gommage_core::EvalResult) -> (Decision, Option<String>) {
    (
        eval.decision.clone(),
        eval.matched_rule.as_ref().map(|rule| rule.name.clone()),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn home_path_spellings_decide_identically(
        suffix in prop::sample::select(vec![
            "/.gommage/policy.d/x.yaml",
            "/.gommage/capabilities.d/x.yaml",
            "/.gommage/key.ed25519",
            "/.claude/settings.json",
            "/.claude/hooks/pretool.sh",
            "/.codex/hooks.json",
            "/.codex/hooks/pretool.sh",
            "/.local/bin/gommage",
            "/.local/bin/gommage-daemon",
            "/.local/bin/gommage-mcp",
            "/.zshrc",
            "/notes.txt",
        ])
    ) {
        let home = "/__home__";
        let policy = shipped_policy(home);
        let mapper = shipped_mapper();
        let absolute = format!("{home}{suffix}");
        let expected = {
            let caps = mapper.map(&bash_redirect_to(&absolute));
            let eval = evaluate(&caps, &policy);
            decision_summary(&eval)
        };

        for spelling in [
            absolute.clone(),
            format!("~{suffix}"),
            format!("$HOME{suffix}"),
            format!("${{HOME}}{suffix}"),
        ] {
            let caps = mapper.map(&bash_redirect_to(&spelling));
            let eval = evaluate(&caps, &policy);
            prop_assert_eq!(
                decision_summary(&eval),
                expected.clone(),
                "home spelling {:?} diverged from absolute {:?}; caps: {:?}",
                spelling,
                absolute,
                eval.capabilities
            );
            prop_assert!(
                eval.capabilities
                    .iter()
                    .any(|cap| cap.as_str() == format!("fs.write:{absolute}")),
                "evaluation did not retain the canonical fs.write capability for {spelling:?}; caps: {:?}",
                eval.capabilities
            );
        }
    }
}

// ----------------------------------------------------------------------------
// 2. Policy YAML parser fuzz
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn policy_from_yaml_never_panics(yaml in ".{0,2000}") {
        let env = HashMap::<String, String>::new();
        let _ = Policy::from_yaml_string(&yaml, &env, "proptest.yaml");
    }
}

// ----------------------------------------------------------------------------
// 3. Picto signature tamper
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn picto_verify_rejects_random_64_bytes(
        sig in prop::collection::vec(any::<u8>(), 64..=64),
    ) {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        use base64::{Engine as _, engine::general_purpose};

        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let created_at = time::OffsetDateTime::from_unix_timestamp(
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .unwrap();

        let picto = Picto {
            id: "proptest".into(),
            scope: "any".into(),
            max_uses: 1,
            uses: 0,
            ttl_expires_at: created_at + time::Duration::seconds(60),
            created_at,
            status: PictoStatus::Active,
            reason: "proptest".into(),
            signature_b64: general_purpose::STANDARD_NO_PAD.encode(&sig),
            binding: PictoBinding::ScopeOnly,
        };

        prop_assert!(matches!(picto.verify(&vk), Err(GommageError::BadSignature)));
    }
}

// ----------------------------------------------------------------------------
// 4. Evaluator smoke
// ----------------------------------------------------------------------------

fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        "(fs\\.(read|write)|git\\.push|proc\\.exec|net\\.out):.{0,120}".prop_map(Capability::new),
        ".{0,200}".prop_map(Capability::new),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn evaluator_never_panics(
        caps in prop::collection::vec(arb_capability(), 0..20),
    ) {
        let env = HashMap::<String, String>::new();
        let pol = Policy::from_yaml_string(
            r#"
- name: always-deny
  decision: gommage
  match:
    any_capability: ["**"]
  reason: "proptest default"
"#,
            &env,
            "proptest.yaml",
        )
        .unwrap();

        let res = evaluate(&caps, &pol);
        match res.decision {
            Decision::Allow | Decision::Gommage { .. } | Decision::AskPicto { .. } => {}
        }
    }
}
