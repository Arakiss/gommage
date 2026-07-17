use super::*;

#[test]
fn concurrent_identical_requests_share_one_open_slot() {
    let (_directory, path, authority) = fixture();
    drop(authority);
    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.create_or_get_request(&request_command(
                    &format!("request_{index}"),
                    &format!("event_request_{index}"),
                ))
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
            .filter(|result| matches!(result, CreateRequestResult::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CreateRequestResult::Existing(_)))
            .count(),
        31
    );
    let raw = Connection::open(&path).unwrap();
    let counts: (i64, i64) = raw
        .query_row(
            "SELECT
                (SELECT count(*) FROM approval_requests),
                (SELECT count(*) FROM open_approvals)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
}

#[test]
fn thirty_two_concurrent_approvers_create_exactly_one_grant() {
    let (_directory, path, mut authority) = fixture();
    create_request(&mut authority);
    drop(authority);

    let barrier = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.approve(&approve_command(index))
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
    open(&path).verify_ledger(None).unwrap();
}

#[test]
fn one_hundred_concurrent_consumers_yield_one_allow() {
    let (_directory, path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    drop(authority);

    let barrier = Arc::new(Barrier::new(100));
    let handles: Vec<_> = (0..100)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            thread::spawn(move || {
                let mut authority = open(&path);
                barrier.wait();
                authority.consume_and_record_allow(&consume_command(index))
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
            .filter(|result| matches!(result, ConsumeResult::Consumed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    ConsumeResult::NotUsable(GrantNotUsableReason::Missing)
                )
            })
            .count(),
        99
    );
    let authority = open(&path);
    let allow_events = authority
        .verify_ledger(None)
        .unwrap()
        .entries
        .into_iter()
        .filter(|entry| entry.entry.event_type() == "decision_allow")
        .count();
    assert_eq!(allow_events, 1);
}

#[test]
fn concurrent_runtime_retries_yield_one_allow_and_one_replacement_request() {
    let (_directory, path, mut authority) = fixture();
    let command = authorize_command();
    let request = match authority.authorize_approval(&command).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
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
                authority.authorize_approval(&command)
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
            .filter(|result| matches!(result, AuthorizeApprovalResultV2::Allowed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                AuthorizeApprovalResultV2::ApprovalRequired { created: true, .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                AuthorizeApprovalResultV2::ApprovalRequired { created: false, .. }
            ))
            .count(),
        30
    );
    let request_ids: Vec<_> = results
        .iter()
        .filter_map(|result| match result {
            AuthorizeApprovalResultV2::ApprovalRequired { request, .. } => {
                Some(request.request_id())
            }
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
    let verification = authority.verify_ledger(None).unwrap();
    assert_eq!(verification.head_seq, "7");
    assert_eq!(
        verification
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_allow")
            .count(),
        1
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
    create_request(&mut authority);
    drop(authority);
    let barrier = Arc::new(Barrier::new(2));
    let approve_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority.approve(&approve_command(1)).unwrap()
        })
    };
    let deny_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority
                .deny(&deny_command("request_1", 1, 1_700_000_020))
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
    open(&path).verify_ledger(None).unwrap();

    let (_terminal_directory, terminal_path, mut terminal_authority) = fixture();
    create_request(&mut terminal_authority);
    approve(&mut terminal_authority);
    drop(terminal_authority);

    let barrier = Arc::new(Barrier::new(2));
    let consume_handle = {
        let path = terminal_path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority
                .consume_and_record_allow(&consume_command(10))
                .unwrap()
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
        usize::from(matches!(consume_result, ConsumeResult::Consumed { .. }))
            + usize::from(matches!(revoke_result, RevokeResult::Revoked(_))),
        1
    );
    open(&terminal_path).verify_ledger(None).unwrap();
}
