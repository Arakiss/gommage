use super::*;

fn assert_active_matches(authority: &Authority, retention: &TestRetention) {
    let verification = authority.verify_ledger().unwrap();
    let CheckpointRetentionStateV2::Active(signed) = retention.state() else {
        panic!("ready Authority must have exactly one active retained checkpoint");
    };
    let checkpoint = signed.verify(&ledger_key().verifying_key()).unwrap();
    assert_eq!(checkpoint.head_seq(), verification.head_seq);
    assert_eq!(checkpoint.head_hash(), verification.head_hash);
    assert_eq!(
        checkpoint.checkpoint_id(),
        format!(
            "head:{}:{}",
            verification.head_seq,
            verification.head_hash.trim_start_matches("sha256:")
        )
    );
    assert_eq!(
        checkpoint.created_at(),
        verification.entries.last().unwrap().entry.timestamp()
    );
}

fn assert_one_checkpoint_transition(
    authority: &Authority,
    retention: &TestRetention,
    before: (usize, usize),
) {
    let after = retention.calls();
    assert_eq!(after, (before.0 + 1, before.1 + 1));
    assert_active_matches(authority, retention);
}

fn distinct_ask(authority: &mut Authority, command: &str) -> ApprovalRequestV2 {
    let mut decision = authorize_command();
    decision.call.input["command"] = json!(command);
    match authority.commit_decision(&decision).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => *request,
        other => panic!("expected distinct approval request, got {other:?}"),
    }
}

fn resign_checkpoint(
    signed: &SignedLedgerCheckpointV2,
    mutate: impl FnOnce(&mut Value),
) -> SignedLedgerCheckpointV2 {
    let mut value: Value = serde_json::from_str(signed.envelope().jcs()).unwrap();
    mutate(&mut value);
    let jcs =
        String::from_utf8(gommage_core::crypto_envelope::canonicalize(&value).unwrap()).unwrap();
    let mut message = b"GOMMAGE\0LEDGER_CHECKPOINT\0V2\0".to_vec();
    message.extend_from_slice(jcs.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(ledger_key().sign(&message).to_bytes());
    SignedLedgerCheckpointV2::from_stored(SignedJcs::from_stored(jcs, signature_b64))
}

#[test]
fn stage_rejection_rolls_back_and_keeps_the_instance_ready() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    let before = authority.verify_ledger().unwrap();
    let calls_before = retention.calls();
    retention.inject_stage(RetentionFault::Rejected);

    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Stage,
            outcome: CheckpointRetentionErrorV2::Rejected,
        })
    ));
    assert_eq!(authority.verify_ledger().unwrap(), before);
    assert_eq!(retention.calls(), (calls_before.0 + 1, calls_before.1));

    let calls_before = retention.calls();
    create_request(&mut authority);
    assert_one_checkpoint_transition(&authority, &retention, calls_before);
}

#[test]
fn indeterminate_stage_before_effect_poisons_but_reopen_can_recover() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    retention.inject_stage(RetentionFault::IndeterminateBefore);

    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Stage,
            outcome: CheckpointRetentionErrorV2::Indeterminate,
        })
    ));
    assert!(matches!(
        authority.verify_ledger(),
        Err(AuthorityError::Poisoned)
    ));
    assert!(matches!(
        authority.set_maintenance(&maintenance_command(true, 1, 1_700_000_031)),
        Err(AuthorityError::Poisoned)
    ));
    drop(authority);

    let reopened = open(&path);
    assert_eq!(reopened.verify_ledger().unwrap().head_seq, "1");
    assert_active_matches(&reopened, &retention);
}

#[test]
fn indeterminate_stage_after_effect_leaves_db_at_active_and_reopen_ambiguous() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    retention.inject_stage(RetentionFault::IndeterminateAfter);

    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Stage,
            outcome: CheckpointRetentionErrorV2::Indeterminate,
        })
    ));
    assert!(matches!(
        authority.verify_ledger(),
        Err(AuthorityError::Poisoned)
    ));
    let pending = retention.last_staged().unwrap();
    assert!(matches!(
        retention.state(),
        CheckpointRetentionStateV2::ActiveWithPending {
            pending: retained,
            ..
        } if retained == pending
    ));
    drop(authority);

    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RecoveryAmbiguous(message))
            if message.contains("database at the active head")
    ));
}

#[test]
fn promote_failure_poisons_and_active_with_pending_db_at_pending_recovers() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    retention.inject_promote(RetentionFault::Rejected);

    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            outcome: CheckpointRetentionErrorV2::Rejected,
        })
    ));
    assert!(matches!(
        authority.metadata(),
        Err(AuthorityError::Poisoned)
    ));
    assert!(matches!(
        retention.state(),
        CheckpointRetentionStateV2::ActiveWithPending { .. }
    ));
    drop(authority);

    let reopened = open(&path);
    assert_eq!(reopened.verify_ledger().unwrap().head_seq, "3");
    assert_active_matches(&reopened, &retention);
}

#[test]
fn promote_failure_during_live_reconciliation_poisons_that_instance() {
    let (_directory, path, mut writer) = fixture();
    let retention = retention_for(&path);
    let mut peer = open(&path);
    retention.inject_promote(RetentionFault::Rejected);
    assert!(matches!(
        writer.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            ..
        })
    ));

    retention.inject_promote(RetentionFault::Rejected);
    assert!(matches!(
        peer.set_maintenance(&maintenance_command(true, 1, 1_700_000_031)),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            outcome: CheckpointRetentionErrorV2::Rejected,
        })
    ));
    assert!(matches!(
        peer.verify_ledger(),
        Err(AuthorityError::Poisoned)
    ));
}

#[test]
fn indeterminate_promote_after_effect_poisons_but_active_reopen_is_safe() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    retention.inject_promote(RetentionFault::IndeterminateAfter);

    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            outcome: CheckpointRetentionErrorV2::Indeterminate,
        })
    ));
    assert!(matches!(
        authority.verify_ledger(),
        Err(AuthorityError::Poisoned)
    ));
    assert!(matches!(
        retention.state(),
        CheckpointRetentionStateV2::Active(_)
    ));
    drop(authority);

    let reopened = open(&path);
    assert_eq!(reopened.verify_ledger().unwrap().head_seq, "3");
    assert_active_matches(&reopened, &retention);
}

#[test]
fn bootstrap_pending_with_committed_genesis_promotes_on_open() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let retention = retention_for(&path);
    retention.inject_promote(RetentionFault::IndeterminateBefore);

    assert!(matches!(
        Authority::bootstrap(
            &path,
            config(),
            grant_key(),
            ledger_key(),
            Box::new(retention.clone()),
        ),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            outcome: CheckpointRetentionErrorV2::Indeterminate,
        })
    ));
    assert!(matches!(
        retention.state(),
        CheckpointRetentionStateV2::BootstrapPending(_)
    ));

    let authority = Authority::open(
        &path,
        config(),
        grant_key(),
        ledger_key(),
        Box::new(retention.clone()),
    )
    .unwrap();
    assert_eq!(authority.verify_ledger().unwrap().head_seq, "1");
    assert_active_matches(&authority, &retention);
}

#[test]
fn durable_state_that_is_behind_or_missing_the_db_head_fails_closed() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    let genesis_state = retention.state();
    create_request(&mut authority);
    drop(authority);

    retention.force_state(genesis_state);
    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RollbackDetected(_))
    ));

    retention.force_state(CheckpointRetentionStateV2::Empty);
    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RecoveryAmbiguous(message))
            if message.contains("empty retention")
    ));
}

#[test]
fn recovery_rejects_signed_but_non_authority_checkpoint_metadata() {
    let (_directory, path, authority) = fixture();
    let retention = retention_for(&path);
    let CheckpointRetentionStateV2::Active(active) = retention.state() else {
        panic!("bootstrap must retain its active checkpoint");
    };
    drop(authority);

    let forged_id = resign_checkpoint(&active, |checkpoint| {
        checkpoint["checkpoint_id"] = json!("caller_selected_checkpoint");
    });
    retention.force_state(CheckpointRetentionStateV2::Active(forged_id));
    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RollbackDetected(message))
            if message.contains("deterministic authority head id")
    ));

    let forged_time = resign_checkpoint(&active, |checkpoint| {
        checkpoint["created_at"] = json!(1_700_000_001_i64);
    });
    retention.force_state(CheckpointRetentionStateV2::Active(forged_time));
    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RollbackDetected(message))
            if message.contains("timestamp contradicts")
    ));
}

#[test]
fn every_mutation_family_promotes_its_checkpoint_before_returning() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);

    let generation = generation("1");
    let mut allow = authorize_command();
    allow.call.input["command"] = json!("true");
    allow.evaluation = resolved_evaluation(&generation, Decision::Allow, &["test.allow"]);
    let before = retention.calls();
    assert!(matches!(
        authority.commit_decision(&allow).unwrap(),
        CommittedDecisionV2::AllowedByPolicy { .. }
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let mut deny = authorize_command();
    deny.call.input["command"] = json!("false");
    deny.evaluation = resolved_evaluation(
        &generation,
        Decision::Gommage {
            reason: "denied by retained authority test".into(),
            hard_stop: false,
        },
        &["test.deny"],
    );
    let before = retention.calls();
    assert!(matches!(
        authority.commit_decision(&deny).unwrap(),
        CommittedDecisionV2::Denied { .. }
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let before = retention.calls();
    let first = distinct_ask(&mut authority, "protected-first");
    assert_one_checkpoint_transition(&authority, &retention, before);

    let before = retention.calls();
    let mut approve_first = approval_command(&first, 11);
    approve_first.resolved_at = first.created_at();
    assert!(matches!(
        authority.approve(&approve_first).unwrap(),
        ApproveResult::Approved { .. }
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let mut consume = authorize_command();
    consume.call.input["command"] = json!("protected-first");
    let before = retention.calls();
    assert!(matches!(
        authority.commit_decision(&consume).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let before = retention.calls();
    let second = distinct_ask(&mut authority, "protected-second");
    assert_one_checkpoint_transition(&authority, &retention, before);
    let before = retention.calls();
    assert!(matches!(
        authority
            .deny(&deny_command(second.request_id(), 12, second.created_at()))
            .unwrap(),
        DenyResult::Denied(_)
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let before = retention.calls();
    let third = distinct_ask(&mut authority, "protected-third");
    assert_one_checkpoint_transition(&authority, &retention, before);
    let approve_third = approval_command(&third, 13);
    let before = retention.calls();
    assert!(matches!(
        authority.approve(&approve_third).unwrap(),
        ApproveResult::Approved { .. }
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    let before = retention.calls();
    assert!(matches!(
        authority
            .revoke(&RevokeCommand {
                grant_id: "grant_13".into(),
                event_id: "event_revoke_13".into(),
                operator_principal: "uid:501".into(),
                reason: "Revoke the retained-checkpoint test grant".into(),
                revoked_at: 1_700_000_031,
                build_identity: "gommage-test-build".into(),
            })
            .unwrap(),
        RevokeResult::Revoked(_)
    ));
    assert_one_checkpoint_transition(&authority, &retention, before);

    for (enabled, index, timestamp) in [(true, 20, 1_700_000_040), (false, 21, 1_700_000_041)] {
        let before = retention.calls();
        authority
            .set_maintenance(&maintenance_command(enabled, index, timestamp))
            .unwrap();
        assert_one_checkpoint_transition(&authority, &retention, before);
    }

    let before = retention.calls();
    authority
        .activate_generation(&activate_command("2", 22, 1_700_000_042))
        .unwrap();
    assert_one_checkpoint_transition(&authority, &retention, before);
}

#[test]
fn idempotent_or_terminal_no_ops_do_not_create_successor_checkpoints() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    let request = create_request(&mut authority);
    let approve = approval_command(&request, 1);
    authority.approve(&approve).unwrap();

    let before = retention.calls();
    assert!(matches!(
        authority.approve(&approve).unwrap(),
        ApproveResult::AlreadyResolved(_)
    ));
    assert!(matches!(
        authority
            .deny(&deny_command(request.request_id(), 1, request.created_at()))
            .unwrap(),
        DenyResult::AlreadyResolved(_)
    ));
    assert!(matches!(
        authority
            .revoke(&RevokeCommand {
                grant_id: "missing_grant".into(),
                event_id: "event_revoke_missing".into(),
                operator_principal: "uid:501".into(),
                reason: "No matching grant".into(),
                revoked_at: 1_700_000_031,
                build_identity: "gommage-test-build".into(),
            })
            .unwrap(),
        RevokeResult::NotUsable(GrantNotUsableReason::Missing)
    ));
    assert!(matches!(
        authority.set_maintenance(&maintenance_command(false, 3, 1_700_000_032)),
        Err(AuthorityError::InvalidInput(_))
    ));
    assert_eq!(retention.calls(), before);
    assert_active_matches(&authority, &retention);

    authority
        .revoke(&RevokeCommand {
            grant_id: "grant_1".into(),
            event_id: "event_revoke_once".into(),
            operator_principal: "uid:501".into(),
            reason: "Revoke once".into(),
            revoked_at: 1_700_000_033,
            build_identity: "gommage-test-build".into(),
        })
        .unwrap();
    let before = retention.calls();
    assert!(matches!(
        authority
            .revoke(&RevokeCommand {
                grant_id: "grant_1".into(),
                event_id: "event_revoke_twice".into(),
                operator_principal: "uid:501".into(),
                reason: "Already terminal".into(),
                revoked_at: 1_700_000_034,
                build_identity: "gommage-test-build".into(),
            })
            .unwrap(),
        RevokeResult::NotUsable(GrantNotUsableReason::Terminal)
    ));
    assert_eq!(retention.calls(), before);
    assert_active_matches(&authority, &retention);
}
