use super::*;
use std::collections::HashMap;

fn decision_policy() -> Policy {
    Policy::from_yaml_string(
        r#"
- name: deny-test
  decision: gommage
  match:
    any_capability: ["test.deny"]
  reason: denied by test policy
- name: ask-test
  decision: ask_picto
  required_scope: "test.ask"
  bind_input: true
  match:
    any_capability: ["test.ask"]
  reason: reviewed test authorization required
- name: allow-test
  decision: allow
  match:
    any_capability: ["test.allow"]
  reason: allowed by test policy
"#,
        &HashMap::new(),
        "authority-decisions.yaml",
    )
    .unwrap()
}

fn scope_only_policy() -> Policy {
    Policy::from_yaml_string(
        r#"
- name: ask-by-scope
  decision: ask_picto
  required_scope: "test.ask"
  match:
    any_capability: ["test.ask"]
  reason: reviewed scope authorization required
"#,
        &HashMap::new(),
        "authority-scope-only.yaml",
    )
    .unwrap()
}

fn policy_generation(id: &str, policy_identity: &str) -> AuthorityGenerationV2 {
    AuthorityGenerationV2::new(
        id.into(),
        format!("gommage-release-{id}"),
        format!("gommage-build-{id}"),
        policy_identity.into(),
        hash('7'),
        "gommage-managed-v2".into(),
    )
    .unwrap()
}

fn policy_config(generation: AuthorityGenerationV2) -> AuthorityConfig {
    AuthorityConfig {
        instance_id: "authority_decision_test".into(),
        epoch: "1".into(),
        genesis_generation: generation,
        genesis_event_id: "event_genesis".into(),
        genesis_at: 1_700_000_000,
    }
}

fn open_policy_authority(path: &Path, generation: AuthorityGenerationV2) -> Authority {
    Authority::open_with_runtime_source(
        path,
        policy_config(generation),
        grant_key(),
        ledger_key(),
        Arc::new(DefaultTestRuntimeSource),
    )
    .unwrap()
}

fn evaluated_command(
    generation: &AuthorityGenerationV2,
    policy: &Policy,
    capability: &str,
    command: &str,
) -> CommitDecisionCommandV2 {
    CommitDecisionCommandV2 {
        evaluated_generation: generation.clone(),
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": command }),
        },
        evaluation: evaluate(&[Capability::new(capability)], policy),
    }
}

#[test]
fn every_policy_outcome_commits_one_normalized_decision_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());

    let allow = evaluated_command(&generation, &policy, "test.allow", "true");
    assert!(matches!(
        authority.commit_decision(&allow).unwrap(),
        CommittedDecisionV2::AllowedByPolicy { .. }
    ));
    let deny = evaluated_command(&generation, &policy, "test.deny", "false");
    assert!(matches!(
        authority.commit_decision(&deny).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    let unresolved = evaluated_command(&generation, &policy, "test.unresolved", "unknown");
    assert!(matches!(
        authority.commit_decision(&unresolved).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    let hard_stop = evaluated_command(&generation, &policy, "proc.exec:rm -rf /", "rm -rf /");
    assert!(matches!(
        authority.commit_decision(&hard_stop).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    let ask = evaluated_command(&generation, &policy, "test.ask", "protected-action");
    assert!(matches!(
        authority.commit_decision(&ask).unwrap(),
        CommittedDecisionV2::ApprovalRequired { created: true, .. }
    ));

    let verification = authority.verify_ledger(None).unwrap();
    assert_eq!(verification.head_seq, "7");
    let records: Vec<_> = verification
        .entries
        .iter()
        .filter_map(|entry| match entry.entry.payload() {
            LedgerPayloadV2::DecisionRecorded { record } => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), 5);
    assert!(matches!(
        records[0].outcome(),
        AuthorityDecisionOutcomeV2::AllowedByPolicy
    ));
    assert!(matches!(
        records[1].outcome(),
        AuthorityDecisionOutcomeV2::Denied
    ));
    assert_eq!(
        records[2].evaluation().provenance()[0].status(),
        CapabilityProvenanceStatus::Unresolved
    );
    assert_eq!(
        records[3].evaluation().provenance()[0].status(),
        CapabilityProvenanceStatus::HardStop
    );
    assert!(matches!(
        records[4].outcome(),
        AuthorityDecisionOutcomeV2::ApprovalRequired { .. }
    ));
    assert!(
        verification
            .entries
            .iter()
            .all(|entry| entry.entry.event_type() != "decision_allow")
    );
    drop(authority);

    let reopened = open_policy_authority(&path, generation);
    assert_eq!(reopened.verify_ledger(None).unwrap().head_seq, "7");
}

#[test]
fn every_stale_policy_outcome_fails_without_any_transition() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let first = policy_generation("1", &policy.version_hash);
    let second = policy_generation("2", &policy.version_hash);
    let mut authority = open_policy_authority(&path, first.clone());
    authority
        .activate_generation(&ActivateGenerationCommand {
            generation: second,
            event_id: "event_generation_2".into(),
            operator_principal: "uid:501".into(),
            reason: "activate successor".into(),
            activated_at: 1_700_000_020,
        })
        .unwrap();
    let head_before = authority.verify_ledger(None).unwrap().head_seq;

    for (capability, command) in [
        ("test.allow", "true"),
        ("test.ask", "protected-action"),
        ("test.deny", "false"),
        ("test.unresolved", "unknown"),
        ("proc.exec:rm -rf /", "rm -rf /"),
    ] {
        let decision = evaluated_command(&first, &policy, capability, command);
        assert!(matches!(
            authority.commit_decision(&decision),
            Err(AuthorityError::StaleGeneration {
                evaluated_generation_id,
                active_generation_id,
            }) if evaluated_generation_id == "1" && active_generation_id == "2"
        ));
    }
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
    let raw = Connection::open(&path).unwrap();
    let requests: i64 = raw
        .query_row("SELECT count(*) FROM approval_requests", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(requests, 0);
}

#[test]
fn compiled_hard_stop_never_selects_or_spends_matching_grants() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let command = evaluated_command(&generation, &policy, "proc.exec:rm -rf /", "rm -rf /");
    let seed = evaluated_command(&generation, &policy, "test.ask", "rm -rf /");
    let request = match authority.commit_decision(&seed).unwrap() {
        CommittedDecisionV2::ApprovalRequired { request, .. } => request,
        other => panic!("expected exact-call seed approval, got {other:?}"),
    };
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        77,
    );

    assert!(matches!(
        authority.commit_decision(&command).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    let state = authority
        .latest_state("grant_runtime_77")
        .unwrap()
        .unwrap()
        .verify(&grant_key().verifying_key())
        .unwrap();
    assert_eq!(state.status(), GrantStatusV2::Active);
    let verification = authority.verify_ledger(None).unwrap();
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "grant_spent")
            .count(),
        0
    );
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_recorded")
            .count(),
        2
    );
}

#[test]
fn scope_only_grant_authorizes_a_different_observed_input() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = scope_only_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let first = evaluated_command(&generation, &policy, "test.ask", "first-input");
    let first_hash = first.call.input_hash();
    let request = match authority.commit_decision(&first).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => request,
        other => panic!("expected first scope-only request, got {other:?}"),
    };
    assert_eq!(request.binding(), PictoBinding::ScopeOnly);
    let (claim, _) = approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        41,
    );
    assert_eq!(
        claim
            .verify(&grant_key().verifying_key())
            .unwrap()
            .binding(),
        PictoBinding::ScopeOnly
    );

    let second = evaluated_command(&generation, &policy, "test.ask", "different-input");
    let second_hash = second.call.input_hash();
    assert_ne!(first_hash, second_hash);
    assert!(matches!(
        authority.commit_decision(&second).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));

    let verification = authority.verify_ledger(None).unwrap();
    let record = verification
        .entries
        .iter()
        .rev()
        .find_map(|entry| match entry.entry.payload() {
            LedgerPayloadV2::DecisionRecorded { record } => Some(record),
            _ => None,
        })
        .unwrap();
    assert_eq!(record.context().input_hash(), second_hash);
    assert!(matches!(
        record.outcome(),
        AuthorityDecisionOutcomeV2::AllowedByGrant { .. }
    ));
}

#[test]
fn exact_input_grant_rejects_other_inputs_without_hidden_context_narrowing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let first = evaluated_command(&generation, &policy, "test.ask", "first-input");
    let request = match authority.commit_decision(&first).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => request,
        other => panic!("expected first exact-input request, got {other:?}"),
    };
    assert_eq!(
        request.binding(),
        PictoBinding::ExactInput {
            input_hash: first.call.input_hash(),
        }
    );
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        42,
    );

    let other_input = evaluated_command(&generation, &policy, "test.ask", "different-input");
    assert!(matches!(
        authority.commit_decision(&other_input).unwrap(),
        CommittedDecisionV2::ApprovalRequired { created: true, .. }
    ));
    let state = authority
        .latest_state("grant_runtime_42")
        .unwrap()
        .unwrap()
        .verify(&grant_key().verifying_key())
        .unwrap();
    assert_eq!(state.status(), GrantStatusV2::Active);

    let mut same_input = first;
    same_input.integration = "another-declared-host".into();
    assert!(matches!(
        authority.commit_decision(&same_input).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
}

#[test]
fn mismatched_policy_reason_never_commits_or_spends() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let original = evaluated_command(&generation, &policy, "test.ask", "protected-action");
    let request = match authority.commit_decision(&original).unwrap() {
        CommittedDecisionV2::ApprovalRequired { request, .. } => request,
        other => panic!("expected approval request, got {other:?}"),
    };
    let mut mismatch = original.clone();
    mismatch.evaluation = resolved_evaluation(
        &generation,
        Decision::AskPicto {
            required_scope: "test.ask".into(),
            reason: "different reason under the same claimed policy".into(),
            bind_input: true,
        },
        &["test.ask"],
    );

    let head_before = authority.verify_ledger(None).unwrap().head_seq;
    assert!(matches!(
        authority.commit_decision(&mismatch),
        Err(AuthorityError::InvalidInput(_))
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);

    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        43,
    );
    let head_before_spend = authority.verify_ledger(None).unwrap().head_seq;
    assert!(matches!(
        authority.commit_decision(&mismatch),
        Err(AuthorityError::InvalidInput(_))
    ));
    assert_eq!(
        authority.verify_ledger(None).unwrap().head_seq,
        head_before_spend
    );
    let state = authority
        .latest_state("grant_runtime_43")
        .unwrap()
        .unwrap()
        .verify(&grant_key().verifying_key())
        .unwrap();
    assert_eq!(state.status(), GrantStatusV2::Active);
    drop(authority);
    open_policy_authority(&path, generation)
        .verify_ledger(None)
        .unwrap();
}

#[test]
fn zero_capability_deny_commits_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let command = CommitDecisionCommandV2 {
        evaluated_generation: generation.clone(),
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": "" }),
        },
        evaluation: evaluate(&[], &policy),
    };
    assert!(matches!(
        authority.commit_decision(&command).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    let verification = authority.verify_ledger(None).unwrap();
    let record = match verification.entries[1].entry.payload() {
        LedgerPayloadV2::DecisionRecorded { record } => record,
        other => panic!("expected recorded deny, got {other:?}"),
    };
    assert!(record.evaluation().capabilities().is_empty());
    drop(authority);
    assert_eq!(
        open_policy_authority(&path, generation)
            .verify_ledger(None)
            .unwrap()
            .head_seq,
        "2"
    );
}

#[test]
fn many_large_picto_scopes_reduce_to_a_bounded_recordable_denial() {
    let mut yaml = String::new();
    let mut capabilities = Vec::new();
    for index in 0..9 {
        let capability = format!("test.scope.{index}");
        let scope = format!("scope.{index}.{}", "x".repeat(500));
        yaml.push_str(&format!(
            "- name: ask-{index}\n  decision: ask_picto\n  required_scope: \"{scope}\"\n  match:\n    any_capability: [\"{capability}\"]\n  reason: approval required\n"
        ));
        capabilities.push(Capability::new(capability));
    }
    let policy =
        Policy::from_yaml_string(&yaml, &std::collections::HashMap::new(), "many-scopes.yaml")
            .unwrap();
    let evaluation = evaluate(&capabilities, &policy);
    assert_eq!(
        evaluation.decision,
        Decision::Gommage {
            reason: "multiple Picto scopes required (9 distinct scopes); split the call before requesting authorization".into(),
            hard_stop: false,
        }
    );

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    assert!(matches!(
        authority
            .commit_decision(&CommitDecisionCommandV2 {
                evaluated_generation: generation.clone(),
                integration: "codex".into(),
                call: ToolCall {
                    tool: "MultiTool".into(),
                    input: json!({"operations": 9}),
                },
                evaluation,
            })
            .unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    drop(authority);
    assert_eq!(
        open_policy_authority(&path, generation)
            .verify_ledger(None)
            .unwrap()
            .head_seq,
        "2"
    );
}

#[test]
fn oversized_canonical_decision_is_rejected_before_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = open_policy_authority(&path, generation.clone());
    let matched_rule = MatchedRule {
        name: "bounded-large-rule".into(),
        file: "bounded-large-policy.yaml".into(),
        index: 0,
    };
    let contribution = RuleContribution {
        layer: "inline".into(),
        layer_index: 0,
        file_index: 0,
        rule: matched_rule.clone(),
        decision: Decision::Allow,
    };
    let capabilities: Vec<_> = (0..512)
        .map(|index| Capability::new(format!("bulk.{index:03}:{}", "x".repeat(980))))
        .collect();
    let evaluation = EvalResult {
        decision: Decision::Allow,
        matched_rule: Some(matched_rule),
        capability_provenance: capabilities
            .iter()
            .cloned()
            .map(|capability| CapabilityProvenance {
                capability,
                status: CapabilityProvenanceStatus::Resolved,
                effective_decision: Some(Decision::Allow),
                contributions: vec![contribution.clone()],
            })
            .collect(),
        capabilities,
        policy_version: generation.policy_identity().into(),
        authorization: None,
    };
    let command = CommitDecisionCommandV2 {
        evaluated_generation: generation,
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({ "command": "true" }),
        },
        evaluation,
    };
    assert!(matches!(
        authority.commit_decision(&command),
        Err(AuthorityError::InvalidInput(message))
            if message.contains("canonical decision evidence exceeds")
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "1");
}

#[test]
fn oversized_tool_call_is_rejected_before_time_or_transaction_access() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let generation = generation("1");
    let mut authority = Authority::open_with_runtime_source(
        &path,
        config(),
        grant_key(),
        ledger_key(),
        Arc::new(RejectRuntimeSource),
    )
    .unwrap();
    let command = CommitDecisionCommandV2 {
        evaluated_generation: generation.clone(),
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({"command": "x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES)}),
        },
        evaluation: resolved_evaluation(&generation, Decision::Allow, &["test.allow"]),
    };

    assert!(matches!(
        authority.commit_decision(&command),
        Err(AuthorityError::InvalidInput(message))
            if message.contains("canonical tool call exceeds")
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "1");
}

#[test]
fn oversized_hidden_decision_fields_are_rejected_before_runtime_access() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let generation = generation("1");
    let mut authority = Authority::open_with_runtime_source(
        &path,
        config(),
        grant_key(),
        ledger_key(),
        Arc::new(RejectRuntimeSource),
    )
    .unwrap();
    let base = CommitDecisionCommandV2 {
        evaluated_generation: generation.clone(),
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({"command": "true"}),
        },
        evaluation: resolved_evaluation(&generation, Decision::Allow, &["test.allow"]),
    };

    let mut oversized_integration = base.clone();
    oversized_integration.integration = "x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES);

    let mut oversized_effective_decision = base.clone();
    oversized_effective_decision
        .evaluation
        .capability_provenance[0]
        .effective_decision = Some(Decision::Gommage {
        reason: "x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES),
        hard_stop: false,
    });

    let mut oversized_matched_rule = base;
    oversized_matched_rule
        .evaluation
        .matched_rule
        .as_mut()
        .unwrap()
        .name = "x".repeat(MAX_CANONICAL_TOOL_CALL_BYTES);

    for command in [
        oversized_integration,
        oversized_effective_decision,
        oversized_matched_rule,
    ] {
        let error = authority.commit_decision(&command).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        assert!(!matches!(error, AuthorityError::RuntimeSource(_)));
        assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "1");
    }
}

#[test]
fn policy_allow_linearizes_before_or_fails_after_generation_activation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let first = policy_generation("1", &policy.version_hash);
    let second = policy_generation("2", &policy.version_hash);
    drop(open_policy_authority(&path, first.clone()));
    let barrier = Arc::new(Barrier::new(2));
    let commit_handle = {
        let path = path.clone();
        let policy = decision_policy();
        let first = first.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open_policy_authority(&path, first.clone());
            let command = evaluated_command(&first, &policy, "test.allow", "true");
            barrier.wait();
            authority.commit_decision(&command)
        })
    };
    let activation_handle = {
        let path = path.clone();
        let first = first.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open_policy_authority(&path, first);
            barrier.wait();
            authority.activate_generation(&ActivateGenerationCommand {
                generation: second,
                event_id: "event_generation_2".into(),
                operator_principal: "uid:501".into(),
                reason: "activate successor".into(),
                activated_at: 1_700_000_030,
            })
        })
    };
    let commit = commit_handle.join().unwrap();
    activation_handle.join().unwrap().unwrap();
    let verification = open_policy_authority(&path, first)
        .verify_ledger(None)
        .unwrap();
    let activation_index = verification
        .entries
        .iter()
        .position(|entry| entry.entry.event_type() == "generation_activated")
        .unwrap();
    let decision_index = verification
        .entries
        .iter()
        .position(|entry| entry.entry.event_type() == "decision_recorded");
    match commit {
        Ok(CommittedDecisionV2::AllowedByPolicy { .. }) => {
            assert!(decision_index.unwrap() < activation_index);
        }
        Err(AuthorityError::StaleGeneration { .. }) => assert!(decision_index.is_none()),
        other => panic!("unexpected concurrent policy allow result: {other:?}"),
    }
}

#[test]
fn decision_record_wire_digests_are_stable_for_every_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let policy = decision_policy();
    let generation = policy_generation("1", &policy.version_hash);
    let mut authority = Authority::open_with_runtime_source(
        &path,
        policy_config(generation.clone()),
        grant_key(),
        ledger_key(),
        Arc::new(FixedRuntimeSource {
            timestamp: AtomicI64::new(1_700_000_030),
            next_nonce: AtomicU64::new(1),
        }),
    )
    .unwrap();
    authority
        .commit_decision(&evaluated_command(
            &generation,
            &policy,
            "test.allow",
            "true",
        ))
        .unwrap();
    authority
        .commit_decision(&evaluated_command(
            &generation,
            &policy,
            "test.deny",
            "false",
        ))
        .unwrap();
    let ask = evaluated_command(&generation, &policy, "test.ask", "protected-action");
    let request = match authority.commit_decision(&ask).unwrap() {
        CommittedDecisionV2::ApprovalRequired { request, .. } => request,
        other => panic!("expected request, got {other:?}"),
    };
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        88,
    );
    authority.commit_decision(&ask).unwrap();

    let digests: Vec<_> = authority
        .verify_ledger(None)
        .unwrap()
        .entries
        .into_iter()
        .filter_map(|entry| {
            let LedgerPayloadV2::DecisionRecorded { record } = entry.entry.payload() else {
                return None;
            };
            let outcome = match record.outcome() {
                AuthorityDecisionOutcomeV2::AllowedByPolicy => "allowed_by_policy",
                AuthorityDecisionOutcomeV2::Denied => "denied",
                AuthorityDecisionOutcomeV2::ApprovalRequired { .. } => "approval_required",
                AuthorityDecisionOutcomeV2::AllowedByGrant { .. } => "allowed_by_grant",
            };
            Some((
                outcome,
                hex::encode(Sha256::digest(entry.envelope.jcs().as_bytes())),
            ))
        })
        .collect();
    assert_eq!(
        digests,
        vec![
            (
                "allowed_by_policy",
                "06007ddb1661f5dcde2e16f9440ed26a2b68f0974042ec9e2602c6cf16a6e63c".into(),
            ),
            (
                "denied",
                "771b017f57ba7fd549778212aee554ff63ed0663393653c947227384ecd1df9f".into(),
            ),
            (
                "approval_required",
                "1aa4cb764691eef27a9d2636a41c17724d2f8237786012cf90033d2491a1a7b9".into(),
            ),
            (
                "allowed_by_grant",
                "f746db2b7f144ae62864471c82895fb9288c0c2ee8c65a15598a887ebfba7978".into(),
            ),
        ]
    );
}
