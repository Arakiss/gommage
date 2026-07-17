use super::*;
use proptest::prelude::*;

mod legacy_compat;

#[test]
fn authorization_context_rejects_raw_capability_fanout_before_normalization() {
    let capabilities = vec!["duplicate.capability".to_string(); MAX_CAPABILITIES + 1];
    let error = AuthorizationContextV2::new(
        "gommage-test-build".into(),
        "codex".into(),
        "Bash".into(),
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        capabilities,
    )
    .unwrap_err();
    assert!(
        matches!(error, AuthorityError::InvalidInput(message) if message.contains("input capabilities"))
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_utf8_request_fields_never_panic(
        integration in ".{0,300}",
        tool in ".{0,500}",
        scope in ".{0,800}",
        reason in ".{0,1400}",
        capabilities in prop::collection::vec(".{0,1200}", 0..12),
    ) {
        let context = AuthorizationContextV2::new(
            "gommage-property-build".into(),
            integration,
            tool,
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
            capabilities,
        );
        if let Ok(context) = context {
            let binding = PictoBinding::ExactInput {
                input_hash: context.input_hash().into(),
            };
            let command = CreateRequestCommand {
                request_id: "request_property".into(),
                event_id: "event_property".into(),
                created_at: 1_700_000_000,
                generation: AuthorityGenerationV2::new(
                    "1".into(),
                    "gommage-property-release".into(),
                    "gommage-property-build".into(),
                    format!("sha256:{}", "2".repeat(64)),
                    format!("sha256:{}", "3".repeat(64)),
                    "gommage-managed-v2".into(),
                )
                .unwrap(),
                context,
                binding,
                required_scope: scope,
                reason,
            };
            let _ = ApprovalRequestV2::from_command(&command);
        }
    }
}
