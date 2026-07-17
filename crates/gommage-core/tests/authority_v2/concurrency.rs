use super::*;

#[test]
fn a_live_authority_fails_closed_after_another_instance_advances_the_head() {
    let (_directory, path, mut writer) = fixture();
    let stale = open(&path);

    create_request(&mut writer);
    assert!(matches!(
        stale.verify_ledger(),
        Err(AuthorityError::RollbackDetected(_))
    ));
    assert_eq!(writer.verify_ledger().unwrap().head_seq, "3");

    drop(stale);
    drop(writer);
    assert_eq!(open(&path).verify_ledger().unwrap().head_seq, "3");
}

#[test]
fn stale_reader_rejects_a_database_restored_to_its_cached_checkpoint() {
    let (directory, path, mut writer) = fixture();
    let snapshot = directory.path().join("genesis.snapshot.sqlite3");
    let stale = open(&path);
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    std::fs::copy(&path, &snapshot).unwrap();

    create_request(&mut writer);
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    std::fs::copy(&snapshot, &path).unwrap();

    assert!(matches!(
        stale.verify_ledger(),
        Err(AuthorityError::RollbackDetected(message))
            if message.contains("durable active checkpoint")
    ));
    drop(stale);
    drop(writer);
    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RollbackDetected(_))
    ));
}

#[test]
fn late_promote_cannot_rewind_a_newer_durable_checkpoint() {
    let (_directory, path, authority) = fixture();
    drop(authority);
    let retention = retention_for(&path);
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    retention.pause_next_promote(Arc::clone(&entered), Arc::clone(&release));

    let first_path = path.clone();
    let first = thread::spawn(move || {
        let mut authority = open(&first_path);
        authority.commit_decision(&authorize_command())
    });
    entered.wait();

    let mut second = open(&path);
    let mut allow = authorize_command();
    allow.call.input["command"] = json!("second-writer-after-recovery");
    allow.evaluation = resolved_evaluation(&generation("1"), Decision::Allow, &["test.allow"]);
    assert!(matches!(
        second.commit_decision(&allow).unwrap(),
        CommittedDecisionV2::AllowedByPolicy { .. }
    ));
    let newest = retention.state();

    release.wait();
    assert!(matches!(
        first.join().unwrap(),
        Err(AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Promote,
            outcome: CheckpointRetentionErrorV2::Rejected,
        })
    ));
    assert_eq!(retention.state(), newest);
    let verification = second.verify_ledger().unwrap();
    let CheckpointRetentionStateV2::Active(active) = retention.state() else {
        panic!("newest checkpoint must remain active");
    };
    let checkpoint = active.verify(&ledger_key().verifying_key()).unwrap();
    assert_eq!(checkpoint.head_seq(), verification.head_seq);
    assert_eq!(checkpoint.head_hash(), verification.head_hash);
}

#[test]
fn concurrent_decision_asks_share_one_request_but_record_every_attempt() {
    let (_directory, path, authority) = fixture();
    drop(authority);
    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.commit_decision(&authorize_command())
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                CommittedDecisionV2::ApprovalRequired { created: true, .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                CommittedDecisionV2::ApprovalRequired { created: false, .. }
            ))
            .count(),
        31
    );
    let authority = open(&path);
    let verification = authority.verify_ledger().unwrap();
    assert_eq!(verification.head_seq, "34");
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "approval_requested")
            .count(),
        1
    );
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_recorded")
            .count(),
        32
    );
}

#[test]
fn thirty_two_concurrent_approvers_create_exactly_one_grant() {
    let (_directory, path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let request_id = request.request_id().to_owned();
    let resolved_at = request.created_at();
    drop(authority);

    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let request_id = request_id.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                let mut command = approve_command(index);
                command.request_id = request_id;
                command.resolved_at = resolved_at;
                authority.approve(&command)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ApproveResult::Approved { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ApproveResult::AlreadyResolved(_)))
            .count(),
        31
    );
    let raw = Connection::open(&path).unwrap();
    let grants: i64 = raw
        .query_row("SELECT count(*) FROM grant_claims", [], |row| row.get(0))
        .unwrap();
    assert_eq!(grants, 1);
    open(&path).verify_ledger().unwrap();
}

#[test]
fn thirty_two_concurrent_decisions_yield_one_allow_and_record_every_retry() {
    let (_directory, path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    drop(authority);

    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.commit_decision(&consume_command(index))
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CommittedDecisionV2::AllowedByGrant { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CommittedDecisionV2::ApprovalRequired { .. }))
            .count(),
        31
    );
    let authority = open(&path);
    let allow_events = authority
        .verify_ledger()
        .unwrap()
        .entries
        .into_iter()
        .filter(|entry| entry.entry.event_type() == "decision_recorded")
        .count();
    assert_eq!(allow_events, 33);
}

#[test]
fn concurrent_runtime_retries_yield_one_allow_and_one_replacement_request() {
    let (_directory, path, mut authority) = fixture();
    let command = authorize_command();
    let request = match authority.commit_decision(&command).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => request,
        other => panic!("expected initial request, got {other:?}"),
    };
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        4,
    );
    drop(authority);

    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let command = command.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.commit_decision(&command)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CommittedDecisionV2::AllowedByGrant { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                CommittedDecisionV2::ApprovalRequired { created: true, .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                CommittedDecisionV2::ApprovalRequired { created: false, .. }
            ))
            .count(),
        30
    );
    let request_ids: Vec<_> = results
        .iter()
        .filter_map(|result| match result {
            CommittedDecisionV2::ApprovalRequired { request, .. } => Some(request.request_id()),
            _ => None,
        })
        .collect();
    assert_eq!(request_ids.len(), 31);
    assert!(
        request_ids
            .iter()
            .all(|request_id| *request_id == request_ids[0])
    );

    let authority = open(&path);
    let verification = authority.verify_ledger().unwrap();
    assert_eq!(verification.head_seq, "39");
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_recorded")
            .count(),
        33
    );
    let raw = Connection::open(&path).unwrap();
    let counts: (i64, i64, i64) = raw
        .query_row(
            "SELECT
                (SELECT count(*) FROM grant_claims),
                (SELECT count(*) FROM approval_requests),
                (SELECT count(*) FROM open_approvals)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 2, 1));
}

#[test]
fn approve_deny_and_consume_revoke_races_have_one_winner() {
    let (_directory, path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let request_id = request.request_id().to_owned();
    let resolved_at = request.created_at();
    drop(authority);
    let barrier = Arc::new(Barrier::new(2));
    let approve_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let request_id = request_id.clone();
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            let mut command = approve_command(1);
            command.request_id = request_id;
            command.resolved_at = resolved_at;
            authority.approve(&command).unwrap()
        })
    };
    let deny_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let request_id = request_id.clone();
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority
                .deny(&deny_command(&request_id, 1, resolved_at))
                .unwrap()
        })
    };
    let approve_result = approve_handle.join().unwrap();
    let deny_result = deny_handle.join().unwrap();
    assert_eq!(
        usize::from(matches!(approve_result, ApproveResult::Approved { .. }))
            + usize::from(matches!(deny_result, DenyResult::Denied(_))),
        1
    );
    open(&path).verify_ledger().unwrap();

    let (_terminal_directory, terminal_path, mut terminal_authority) = fixture();
    let terminal_request = create_request(&mut terminal_authority);
    approve(&mut terminal_authority, &terminal_request);
    drop(terminal_authority);

    let barrier = Arc::new(Barrier::new(2));
    let consume_handle = {
        let path = terminal_path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority.commit_decision(&consume_command(10)).unwrap()
        })
    };
    let revoke_handle = {
        let path = terminal_path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority
                .revoke(&RevokeCommand {
                    grant_id: "grant_1".into(),
                    event_id: "event_revoke".into(),
                    operator_principal: "uid:501".into(),
                    reason: "Operator revoked before use".into(),
                    revoked_at: 1_700_000_030,
                    build_identity: "gommage-test-build".into(),
                })
                .unwrap()
        })
    };
    let consume_result = consume_handle.join().unwrap();
    let revoke_result = revoke_handle.join().unwrap();
    assert_eq!(
        usize::from(matches!(
            consume_result,
            CommittedDecisionV2::AllowedByGrant { .. }
        )) + usize::from(matches!(revoke_result, RevokeResult::Revoked(_))),
        1
    );
    open(&terminal_path).verify_ledger().unwrap();
}
