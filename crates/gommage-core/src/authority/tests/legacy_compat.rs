use super::super::*;
use crate::{Capability, Policy, ToolCall, evaluate};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

#[derive(Serialize)]
struct LegacyApprovalRequest<'a> {
    domain: &'static str,
    version: u8,
    request_id: &'a str,
    created_at: i64,
    context: &'a AuthorizationContextV2,
    generation: &'a AuthorityGenerationV2,
    required_scope: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct LegacyGrantClaim<'a> {
    domain: &'static str,
    version: u8,
    authority_instance: &'a str,
    authority_epoch: &'a str,
    grant_id: &'a str,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    max_uses: u8,
    required_scope: &'a str,
    input_hash: &'a str,
    approval_request_id: &'a str,
    request_hash: &'a str,
    operator_principal: &'a str,
    reason: &'a str,
    grant_key_id: &'a str,
}

impl KeyBound for LegacyGrantClaim<'_> {
    fn key_id(&self) -> &str {
        self.grant_key_id
    }
}

fn insert_legacy_approval(
    authority: &mut Authority,
    config: &AuthorityConfig,
    request: &ApprovalRequestV2,
    request_hash: &str,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> (SignedGrantClaimV2, SignedGrantStateV2) {
    let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
    let legacy_claim = LegacyGrantClaim {
        domain: "gommage.grant.claim",
        version: FORMAT_VERSION,
        authority_instance: &config.instance_id,
        authority_epoch: &config.epoch,
        grant_id: "legacy_grant",
        issued_at: 1_700_000_020,
        not_before: 1_700_000_020,
        expires_at: 1_700_000_620,
        max_uses: 1,
        required_scope: request.required_scope(),
        input_hash: request.input_hash(),
        approval_request_id: request.request_id(),
        request_hash,
        operator_principal: "uid:501",
        reason: "reviewed legacy request",
        grant_key_id: &grant_key_id,
    };
    let claim_jcs = canonicalize(&legacy_claim).unwrap();
    assert!(!String::from_utf8_lossy(&claim_jcs).contains("binding"));
    let claim: GrantClaimV2 = decode_canonical(&claim_jcs).unwrap();
    assert_eq!(canonicalize(&claim).unwrap(), claim_jcs);
    assert_eq!(
        claim.binding(),
        PictoBinding::ExactInput {
            input_hash: request.input_hash().into(),
        }
    );
    let signed_claim = SignedGrantClaimV2::sign(&claim, grant_key).unwrap();
    let active = GrantStateV2::active(
        &claim,
        signed_claim.claim_hash(),
        "legacy_activation".into(),
        1_700_000_020,
    )
    .unwrap();
    let signed_active = SignedGrantStateV2::sign(&active, grant_key).unwrap();

    let grant_vk = grant_key.verifying_key();
    let ledger_vk = ledger_key.verifying_key();
    let tx = authority
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    verify_all(&tx, config, &grant_vk, &ledger_vk, None).unwrap();
    tx.execute(
        "INSERT INTO approval_resolutions (
            request_id, outcome, operator_principal, reason, resolved_at, grant_id, event_id
         ) VALUES (?1, 'approved', ?2, ?3, ?4, ?5, ?6)",
        params![
            request.request_id(),
            "uid:501",
            "reviewed legacy request",
            1_700_000_020_i64,
            "legacy_grant",
            "legacy_resolution",
        ],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO grant_claims (
            grant_id, request_id, claim_jcs, signature_b64, claim_hash
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            "legacy_grant",
            request.request_id(),
            signed_claim.envelope().jcs(),
            signed_claim.envelope().signature_b64(),
            signed_claim.claim_hash(),
        ],
    )
    .unwrap();
    insert_state(&tx, &active, &signed_active).unwrap();
    assert_eq!(
        tx.execute(
            "DELETE FROM open_approvals WHERE request_id = ?1",
            [request.request_id()],
        )
        .unwrap(),
        1
    );
    append_ledger_entry(
        &tx,
        ledger_key,
        LedgerEventDraft {
            event_id: "legacy_resolution".into(),
            subject: request.request_id().into(),
            timestamp: 1_700_000_020,
            build_identity: Some(request.build_identity().into()),
            policy_identity: Some(request.policy_identity().into()),
            payload: LedgerPayloadV2::ApprovalResolved {
                request_id: request.request_id().into(),
                request_hash: request_hash.into(),
                outcome: "approved".into(),
                grant_id: Some("legacy_grant".into()),
                claim_hash: Some(signed_claim.claim_hash().into()),
                operator_principal: "uid:501".into(),
                reason: "reviewed legacy request".into(),
            },
        },
    )
    .unwrap();
    append_ledger_entry(
        &tx,
        ledger_key,
        LedgerEventDraft {
            event_id: "legacy_activation".into(),
            subject: "legacy_grant".into(),
            timestamp: 1_700_000_020,
            build_identity: Some(request.build_identity().into()),
            policy_identity: Some(request.policy_identity().into()),
            payload: LedgerPayloadV2::GrantStateChanged {
                grant_id: "legacy_grant".into(),
                claim_hash: signed_claim.claim_hash().into(),
                state_hash: signed_active.state_hash().into(),
                revision: active.revision().into(),
                status: GrantStatusV2::Active,
                operator_principal: None,
                reason: None,
            },
        },
    )
    .unwrap();
    verify_all(&tx, config, &grant_vk, &ledger_vk, None).unwrap();
    tx.commit().unwrap();
    (signed_claim, signed_active)
}

fn keys() -> (SigningKey, SigningKey) {
    (
        SigningKey::from_bytes(&[71; 32]),
        SigningKey::from_bytes(&[72; 32]),
    )
}

fn policy() -> Policy {
    Policy::from_yaml_string(
        r#"
- name: ask-legacy
  decision: ask_picto
  required_scope: "test.ask"
  bind_input: true
  match:
    any_capability: ["test.ask"]
  reason: legacy exact approval
- name: allow-new
  decision: allow
  match:
    any_capability: ["test.allow"]
  reason: ""
"#,
        &HashMap::new(),
        "legacy-compat.yaml",
    )
    .unwrap()
}

fn generation(policy_identity: &str) -> AuthorityGenerationV2 {
    AuthorityGenerationV2::new(
        "1".into(),
        "gommage-legacy-release".into(),
        "gommage-legacy-build".into(),
        policy_identity.into(),
        format!("sha256:{}", "7".repeat(64)),
        "gommage-managed-v2".into(),
    )
    .unwrap()
}

fn config(generation: AuthorityGenerationV2) -> AuthorityConfig {
    AuthorityConfig {
        instance_id: "authority_legacy_compat".into(),
        epoch: "1".into(),
        genesis_generation: generation,
        genesis_event_id: "event_genesis".into(),
        genesis_at: 1_700_000_000,
    }
}

#[test]
fn legacy_decision_allow_remains_byte_stable_inside_a_mixed_ledger() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = policy();
    let generation = generation(&policy.version_hash);
    let config = config(generation.clone());
    let (grant_key, ledger_key) = keys();
    let mut authority =
        Authority::open(&path, config.clone(), grant_key.clone(), ledger_key.clone()).unwrap();

    let ask_call = ToolCall {
        tool: "Bash".into(),
        input: json!({ "command": "protected-action" }),
    };
    let context = AuthorizationContextV2::new(
        generation.build_identity().into(),
        "codex".into(),
        ask_call.tool.clone(),
        ask_call.input_hash(),
        generation.policy_identity().into(),
        vec!["test.ask".into()],
    )
    .unwrap();
    let legacy_request = LegacyApprovalRequest {
        domain: REQUEST_DOMAIN,
        version: FORMAT_VERSION,
        request_id: "legacy_request",
        created_at: 1_700_000_010,
        context: &context,
        generation: &generation,
        required_scope: "test.ask",
        reason: "legacy exact approval",
    };
    let request_jcs = canonicalize(&legacy_request).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&request_jcs)),
        "dd74389af72c006676631d67b03296dcacd799e8f9c39fce585d48148bae3272"
    );
    let request: ApprovalRequestV2 = decode_canonical(&request_jcs).unwrap();
    request.validate().unwrap();
    assert!(matches!(request.binding(), PictoBinding::ExactInput { .. }));
    let request_hash = approval_request_hash(&request_jcs);
    let dedupe_jcs = canonicalize(&ApprovalDedupeV2 {
        domain: "gommage.approval.dedupe",
        version: FORMAT_VERSION,
        context: &context,
        generation: &generation,
        required_scope: "test.ask",
    })
    .unwrap();
    let dedupe_hash = approval_dedupe_hash(&dedupe_jcs);
    {
        let tx = authority
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "INSERT INTO approval_requests (
                request_id, dedupe_hash, request_jcs, request_hash, event_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.request_id(),
                dedupe_hash,
                String::from_utf8(request_jcs).unwrap(),
                request_hash,
                "legacy_request_event",
                request.created_at(),
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO open_approvals (dedupe_hash, request_id) VALUES (?1, ?2)",
            params![dedupe_hash, request.request_id()],
        )
        .unwrap();
        append_ledger_entry(
            &tx,
            &ledger_key,
            LedgerEventDraft {
                event_id: "legacy_request_event".into(),
                subject: request.request_id().into(),
                timestamp: request.created_at(),
                build_identity: Some(generation.build_identity().into()),
                policy_identity: Some(generation.policy_identity().into()),
                payload: LedgerPayloadV2::ApprovalRequested {
                    request_id: request.request_id().into(),
                    request_hash: request_hash.clone(),
                    dedupe_hash: dedupe_hash.clone(),
                },
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }

    let (legacy_claim, legacy_active) = insert_legacy_approval(
        &mut authority,
        &config,
        &request,
        &request_hash,
        &grant_key,
        &ledger_key,
    );
    assert_eq!(
        hex::encode(Sha256::digest(legacy_claim.envelope().jcs().as_bytes())),
        "50ce7f2404920a603ed9fbabc605a38ae323e9a801d8d5935980c47fc50da1a0"
    );
    assert_eq!(
        hex::encode(Sha256::digest(legacy_active.envelope().jcs().as_bytes())),
        "0cc1cf98b74abc17494604736e5eca5fcdd06ff5f14770904f2e465b208808fa"
    );

    {
        let grant_vk = grant_key.verifying_key();
        let ledger_vk = ledger_key.verifying_key();
        let tx = authority
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None).unwrap();
        let binding = PictoBinding::ExactInput {
            input_hash: context.input_hash().into(),
        };
        let (selected, _) = select_usable_grant(
            &tx,
            GrantSelectionInput {
                context: &context,
                generation: &generation,
                required_scope: "test.ask",
                binding: &binding,
                reason: "legacy exact approval",
                at: 1_700_000_030,
            },
            &grant_vk,
        )
        .unwrap();
        let spent = spend_grant(
            &tx,
            selected.unwrap(),
            SpendGrantInput {
                context: &context,
                consumed_at: 1_700_000_030,
                state_event_id: "legacy_spend",
            },
            &grant_key,
            &ledger_key,
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(spent.state.envelope().jcs().as_bytes())),
            "45a09aaf5ad0ec52cfeebeaf0df1c60a627888692cd9eb9ccd9a88af399a73f4"
        );
        append_ledger_entry(
            &tx,
            &ledger_key,
            LedgerEventDraft {
                event_id: "legacy_decision".into(),
                subject: "legacy_grant".into(),
                timestamp: 1_700_000_030,
                build_identity: Some(generation.build_identity().into()),
                policy_identity: Some(generation.policy_identity().into()),
                payload: LedgerPayloadV2::DecisionAllow {
                    grant_id: "legacy_grant".into(),
                    required_scope: "test.ask".into(),
                    input_hash: context.input_hash().into(),
                    context: context.clone(),
                    generation: generation.clone(),
                    state_hash: spent.state.state_hash().into(),
                },
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }

    let legacy_before: (String, String, String) = authority
        .conn
        .query_row(
            "SELECT entry_jcs, signature_b64, entry_hash
             FROM ledger_entries WHERE event_id = 'legacy_decision'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let legacy_jcs_digest = hex::encode(Sha256::digest(legacy_before.0.as_bytes()));
    assert_eq!(
        legacy_jcs_digest,
        "5cab755e09c059995ac02de7e10fd299044e2467acea6eaf0cb2c1151bccb1e6"
    );
    authority.verify_ledger(None).unwrap();

    let allow_call = ToolCall {
        tool: "Bash".into(),
        input: json!({ "command": "true" }),
    };
    authority
        .commit_decision(&CommitDecisionCommandV2 {
            evaluated_generation: generation.clone(),
            integration: "codex".into(),
            call: allow_call,
            evaluation: evaluate(&[Capability::new("test.allow")], &policy),
        })
        .unwrap();
    let checkpoint = authority
        .checkpoint("mixed_checkpoint", 2_000_000_000)
        .unwrap();
    assert!(matches!(
        authority
            .verify_ledger(Some(&checkpoint))
            .unwrap()
            .freshness,
        FreshnessVerdict::Anchored { .. }
    ));
    let first_page = authority.ledger_page(None, 3, Some(&checkpoint)).unwrap();
    let second_page = authority
        .ledger_page(first_page.next_cursor.as_ref(), 3, Some(&checkpoint))
        .unwrap();
    assert!(!first_page.entries.is_empty());
    assert!(!second_page.entries.is_empty());
    let legacy_after: (String, String, String) = authority
        .conn
        .query_row(
            "SELECT entry_jcs, signature_b64, entry_hash
             FROM ledger_entries WHERE event_id = 'legacy_decision'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(legacy_after, legacy_before);
    drop(authority);

    let reopened = Authority::open(&path, config, grant_key, ledger_key).unwrap();
    let verification = reopened.verify_ledger(Some(&checkpoint)).unwrap();
    assert!(
        verification.entries.iter().any(|entry| {
            matches!(entry.entry.payload(), LedgerPayloadV2::DecisionAllow { .. })
        })
    );
    assert!(verification.entries.iter().any(|entry| {
        matches!(
            entry.entry.payload(),
            LedgerPayloadV2::DecisionRecorded { .. }
        )
    }));
}
