use super::*;

#[test]
fn one_live_authority_excludes_every_other_cooperative_writer() {
    let (_directory, path, writer) = fixture();
    assert!(matches!(try_open(&path), Err(AuthorityError::WriterBusy)));
    assert_eq!(writer.verify_ledger().unwrap().head_seq, "1");

    drop(writer);
    assert_eq!(open(&path).verify_ledger().unwrap().head_seq, "1");
}

#[test]
fn live_authority_rejects_database_path_replacement() {
    let (directory, path, writer) = fixture();
    let replacement = directory.path().join("replacement.sqlite3");
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    std::fs::copy(&path, &replacement).unwrap();
    std::fs::rename(&replacement, &path).unwrap();

    assert!(matches!(
        writer.verify_ledger(),
        Err(AuthorityError::Storage(message)) if message.contains("changed identity")
    ));
    assert!(matches!(try_open(&path), Err(AuthorityError::WriterBusy)));
    drop(writer);
    assert_eq!(open(&path).verify_ledger().unwrap().head_seq, "1");
}

#[test]
fn late_promote_cannot_rewind_a_newer_durable_checkpoint() {
    let (_directory, path, mut authority) = fixture();
    let retention = retention_for(&path);
    let CheckpointRetentionStateV2::Active(genesis) = retention.state() else {
        panic!("bootstrap must leave genesis active");
    };
    create_request(&mut authority);
    let CheckpointRetentionStateV2::Active(first_successor) = retention.state() else {
        panic!("first mutation must leave one active successor");
    };
    authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_031))
        .unwrap();
    let newest = retention.state();

    let mut delayed_backend = retention.clone();
    assert!(matches!(
        delayed_backend.promote(Some(&genesis), &first_successor),
        Err(CheckpointRetentionErrorV2::Rejected)
    ));
    assert_eq!(retention.state(), newest);
    let verification = authority.verify_ledger().unwrap();
    let CheckpointRetentionStateV2::Active(active) = retention.state() else {
        panic!("newest checkpoint must remain active");
    };
    let checkpoint = active.verify(&ledger_key().verifying_key()).unwrap();
    assert_eq!(checkpoint.head_seq(), verification.head_seq);
    assert_eq!(checkpoint.head_hash(), verification.head_hash);
}

#[test]
fn concurrent_decision_asks_share_one_request_but_record_every_attempt() {
    let (_directory, _path, authority) = fixture();
    let (authority, results) = concurrently_on_authority(authority, 32, |_, authority| {
        authority.commit_decision(&authorize_command())
    });
    let results: Vec<_> = results.into_iter().map(Result::unwrap).collect();
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
    let verification = authority.lock().unwrap().verify_ledger().unwrap();
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
    let (authority, results) = concurrently_on_authority(authority, 32, move |index, authority| {
        let mut command = approve_command(index);
        command.request_id = request_id.clone();
        command.resolved_at = resolved_at;
        authority.approve(&command)
    });
    let results: Vec<_> = results.into_iter().map(Result::unwrap).collect();
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
    authority.lock().unwrap().verify_ledger().unwrap();
}

#[test]
fn thirty_two_concurrent_decisions_yield_one_allow_and_record_every_retry() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    let (authority, results) = concurrently_on_authority(authority, 32, |index, authority| {
        authority.commit_decision(&consume_command(index))
    });
    let results: Vec<_> = results.into_iter().map(Result::unwrap).collect();
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
    let allow_events = authority
        .lock()
        .unwrap()
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
    let (authority, results) = concurrently_on_authority(authority, 32, move |_, authority| {
        authority.commit_decision(&command)
    });
    let results: Vec<_> = results.into_iter().map(Result::unwrap).collect();
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

    let verification = authority.lock().unwrap().verify_ledger().unwrap();
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
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let request_id = request.request_id().to_owned();
    let resolved_at = request.created_at();
    let authority = Arc::new(Mutex::new(authority));
    let barrier = Arc::new(Barrier::new(2));
    let approve_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        let request_id = request_id.clone();
        thread::spawn(move || {
            barrier.wait();
            let mut command = approve_command(1);
            command.request_id = request_id;
            command.resolved_at = resolved_at;
            authority.lock().unwrap().approve(&command).unwrap()
        })
    };
    let deny_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        let request_id = request_id.clone();
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
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
    authority.lock().unwrap().verify_ledger().unwrap();

    let (_terminal_directory, _terminal_path, mut terminal_authority) = fixture();
    let terminal_request = create_request(&mut terminal_authority);
    approve(&mut terminal_authority, &terminal_request);
    let terminal_authority = Arc::new(Mutex::new(terminal_authority));

    let barrier = Arc::new(Barrier::new(2));
    let consume_handle = {
        let authority = Arc::clone(&terminal_authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
                .commit_decision(&consume_command(10))
                .unwrap()
        })
    };
    let revoke_handle = {
        let authority = Arc::clone(&terminal_authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
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
    terminal_authority.lock().unwrap().verify_ledger().unwrap();
}
