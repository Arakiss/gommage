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
//!    signature → never panics, almost always rejects.
//! 4. `evaluate` on arbitrary capability lists → returns one of the three
//!    decision variants. Never panics.

use gommage_core::{
    Capability, CapabilityMapper, Decision, Policy, ToolCall, evaluate,
    picto::{Picto, PictoStatus},
};
use proptest::prelude::*;
use std::collections::HashMap;

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
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    CapabilityMapper::load_from_dir(&repo_root.join("capabilities"))
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

        let picto = Picto {
            id: "proptest".into(),
            scope: "any".into(),
            max_uses: 1,
            uses: 0,
            ttl_expires_at: time::OffsetDateTime::now_utc() + time::Duration::seconds(60),
            created_at: time::OffsetDateTime::now_utc(),
            status: PictoStatus::Active,
            reason: "proptest".into(),
            signature_b64: general_purpose::STANDARD_NO_PAD.encode(&sig),
        };

        // Random 64-byte blob must not panic. It will almost always reject
        // (probability of a valid ed25519 signature is 2^-256).
        let _ = picto.verify(&vk);
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
