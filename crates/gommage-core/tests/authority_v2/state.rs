use super::*;

#[test]
fn stale_generation_creates_no_request_spends_no_grant_and_records_no_allow() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_025))
        .unwrap();
    let head_before = authority.verify_ledger(None).unwrap().head_seq;

    let stale_request = request_command("request_stale", "event_request_stale");
    assert!(matches!(
        authority.create_or_get_request(&stale_request),
        Err(AuthorityError::StaleGeneration {
            evaluated_generation_id,
            active_generation_id,
        }) if evaluated_generation_id == "1" && active_generation_id == "2"
    ));
    assert!(authority.request("request_stale").unwrap().is_none());
    assert!(matches!(
        authority.consume_and_record_allow(&consume_command(9)),
        Err(AuthorityError::StaleGeneration { .. })
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
    assert_eq!(
        authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Active
    );
    assert_eq!(
        authority
            .verify_ledger(None)
            .unwrap()
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_allow")
            .count(),
        0
    );
}

#[test]
fn stale_or_maintenance_generation_cannot_be_approved_without_mutation() {
    for blocked_by_maintenance in [false, true] {
        let (_directory, _path, mut authority) = fixture();
        create_request(&mut authority);
        if blocked_by_maintenance {
            authority
                .set_maintenance(&maintenance_command(true, 1, 1_700_000_015))
                .unwrap();
        } else {
            authority
                .activate_generation(&activate_command("2", 2, 1_700_000_015))
                .unwrap();
        }
        let head_before = authority.verify_ledger(None).unwrap().head_seq;

        let result = authority.approve(&approve_command(1));
        if blocked_by_maintenance {
            assert!(matches!(result, Err(AuthorityError::Maintenance)));
        } else {
            assert!(matches!(
                result,
                Err(AuthorityError::StaleGeneration {
                    evaluated_generation_id,
                    active_generation_id,
                }) if evaluated_generation_id == "1" && active_generation_id == "2"
            ));
        }
        assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
        assert!(authority.resolution("request_1").unwrap().is_none());
        assert!(authority.grant("grant_1").unwrap().is_none());
        assert!(authority.request("request_1").unwrap().is_some());
    }
}

#[test]
fn deny_and_revoke_remain_available_for_cleanup_during_maintenance() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);

    let mut second = request_command("request_2", "event_request_2");
    second.context = context_with(
        "gommage-test-build",
        "codex",
        "Bash",
        '4',
        '2',
        &["git.push:refs/heads/main", "proc.exec:git"],
    );
    assert!(matches!(
        authority.create_or_get_request(&second).unwrap(),
        CreateRequestResult::Created(request) if request.request_id() == "request_2"
    ));
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_025))
        .unwrap();
    authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_026))
        .unwrap();

    assert!(matches!(
        authority
            .deny(&deny_command("request_2", 2, 1_700_000_030))
            .unwrap(),
        DenyResult::Denied(resolution)
            if resolution.request_id == "request_2"
                && resolution.kind == gommage_core::ApprovalResolutionKindV2::Denied
    ));
    assert!(matches!(
        authority
            .revoke(&RevokeCommand {
                grant_id: "grant_1".into(),
                event_id: "event_revoke_maintenance".into(),
                operator_principal: "uid:501".into(),
                reason: "Revoke an obsolete active grant during maintenance".into(),
                revoked_at: 1_700_000_031,
                build_identity: "maintenance-admin-build".into(),
            })
            .unwrap(),
        RevokeResult::Revoked(_)
    ));
    assert!(authority.runtime_state().unwrap().maintenance());
    assert_eq!(
        authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Revoked
    );
    authority.verify_ledger(None).unwrap();
}

#[test]
fn generation_activation_linearizes_with_concurrent_approval() {
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
            authority.approve(&approve_command(1))
        })
    };
    let activate_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority.activate_generation(&activate_command("2", 2, 1_700_000_025))
        })
    };
    let approve_result = approve_handle.join().unwrap();
    activate_handle.join().unwrap().unwrap();

    let authority = open(&path);
    let verification = authority.verify_ledger(None).unwrap();
    let generation_seq = verification
        .entries
        .iter()
        .position(|entry| entry.entry.event_type() == "generation_activated")
        .unwrap();
    match approve_result {
        Ok(ApproveResult::Approved { .. }) => {
            let resolution_seq = verification
                .entries
                .iter()
                .position(|entry| entry.entry.event_type() == "approval_resolved")
                .unwrap();
            let grant_activation_seq = verification
                .entries
                .iter()
                .position(|entry| entry.entry.event_type() == "grant_activated")
                .unwrap();
            assert!(resolution_seq < grant_activation_seq);
            assert!(grant_activation_seq < generation_seq);
            assert!(authority.grant("grant_1").unwrap().is_some());
        }
        Err(AuthorityError::StaleGeneration { .. }) => {
            assert!(
                verification
                    .entries
                    .iter()
                    .all(|entry| entry.entry.event_type() != "approval_resolved")
            );
            assert!(authority.grant("grant_1").unwrap().is_none());
        }
        other => panic!("unexpected concurrent approval result: {other:?}"),
    }
}

#[test]
fn maintenance_blocks_decisions_without_mutation_until_signed_exit() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_025))
        .unwrap();
    let head_before = authority.verify_ledger(None).unwrap().head_seq;

    assert!(matches!(
        authority.create_or_get_request(&request_command(
            "request_maintenance",
            "event_request_maintenance",
        )),
        Err(AuthorityError::Maintenance)
    ));
    assert!(matches!(
        authority.consume_and_record_allow(&consume_command(9)),
        Err(AuthorityError::Maintenance)
    ));
    assert!(authority.request("request_maintenance").unwrap().is_none());
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
    assert_eq!(
        authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Active
    );

    authority
        .set_maintenance(&maintenance_command(false, 2, 1_700_000_026))
        .unwrap();
    assert!(matches!(
        authority
            .consume_and_record_allow(&consume_command(10))
            .unwrap(),
        ConsumeResult::Consumed { .. }
    ));
}

#[test]
fn generation_activation_linearizes_with_concurrent_allow() {
    let (_directory, path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    drop(authority);

    let barrier = Arc::new(Barrier::new(2));
    let consume_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority.consume_and_record_allow(&consume_command(20))
        })
    };
    let activate_handle = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut authority = open(&path);
            barrier.wait();
            authority.activate_generation(&activate_command("2", 2, 1_700_000_025))
        })
    };
    let consume_result = consume_handle.join().unwrap();
    let activated = activate_handle.join().unwrap().unwrap();
    assert_eq!(activated.active_generation(), &generation("2"));

    let verification = open(&path).verify_ledger(None).unwrap();
    let activation_seq = verification
        .entries
        .iter()
        .position(|entry| entry.entry.event_type() == "generation_activated")
        .unwrap();
    let allow_sequences: Vec<_> = verification
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry.entry.event_type() == "decision_allow").then_some(index)
        })
        .collect();
    match consume_result {
        Ok(ConsumeResult::Consumed { .. }) => {
            assert_eq!(allow_sequences.len(), 1);
            assert!(allow_sequences[0] < activation_seq);
        }
        Err(AuthorityError::StaleGeneration { .. }) => assert!(allow_sequences.is_empty()),
        other => panic!("unexpected concurrent consume result: {other:?}"),
    }
}

#[test]
fn consumption_requires_the_complete_approved_context_without_spending_on_mismatch() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);

    let mismatches = [
        context_with(
            "gommage-test-build",
            "claude-code",
            "Bash",
            '1',
            '2',
            &["git.push:refs/heads/main", "proc.exec:git"],
        ),
        context_with(
            "gommage-test-build",
            "codex",
            "Shell",
            '1',
            '2',
            &["git.push:refs/heads/main", "proc.exec:git"],
        ),
        context_with(
            "gommage-test-build",
            "codex",
            "Bash",
            '9',
            '2',
            &["git.push:refs/heads/main", "proc.exec:git"],
        ),
        context_with(
            "gommage-test-build",
            "codex",
            "Bash",
            '1',
            '2',
            &["git.push:refs/heads/main"],
        ),
    ];

    for (index, context) in mismatches.into_iter().enumerate() {
        let mut command = consume_command(index + 10);
        command.context = context;
        assert_eq!(
            authority.consume_and_record_allow(&command).unwrap(),
            ConsumeResult::NotUsable(GrantNotUsableReason::Missing)
        );
        let latest = authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap();
        assert_eq!(latest.status(), GrantStatusV2::Active);
    }
    for (index, context) in [
        context_with(
            "gommage-next-build",
            "codex",
            "Bash",
            '1',
            '2',
            &["git.push:refs/heads/main", "proc.exec:git"],
        ),
        context_with(
            "gommage-test-build",
            "codex",
            "Bash",
            '1',
            '9',
            &["git.push:refs/heads/main", "proc.exec:git"],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut command = consume_command(index + 30);
        command.context = context;
        assert!(matches!(
            authority.consume_and_record_allow(&command),
            Err(AuthorityError::InvalidInput(_))
        ));
    }
    let mut wrong_scope = consume_command(20);
    wrong_scope.required_scope = "git.push:refs/heads/release".into();
    assert_eq!(
        authority.consume_and_record_allow(&wrong_scope).unwrap(),
        ConsumeResult::NotUsable(GrantNotUsableReason::Missing)
    );
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "4");
    assert!(matches!(
        authority
            .consume_and_record_allow(&consume_command(99))
            .unwrap(),
        ConsumeResult::Consumed { .. }
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "6");
}

#[test]
fn sequential_grants_select_the_only_currently_usable_exact_match() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    assert!(matches!(
        authority
            .consume_and_record_allow(&consume_command(1))
            .unwrap(),
        ConsumeResult::Consumed { .. }
    ));

    create_second_request(&mut authority, 1_700_000_040);
    approve_second_request(&mut authority, 1_700_000_050);
    let mut command = consume_command(2);
    command.consumed_at = 1_700_000_060;
    let state = match authority.consume_and_record_allow(&command).unwrap() {
        ConsumeResult::Consumed { state, .. } => state,
        other => panic!("expected the second exact grant to be consumed, got {other:?}"),
    };
    assert_eq!(
        state
            .verify(&grant_key().verifying_key())
            .unwrap()
            .grant_id(),
        "grant_2"
    );
    assert_eq!(
        authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Spent
    );
}

#[test]
fn duplicate_usable_exact_grants_fail_closed_without_spending_either() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    create_second_request(&mut authority, 1_700_000_021);
    approve_second_request(&mut authority, 1_700_000_022);

    assert!(matches!(
        authority.consume_and_record_allow(&consume_command(1)),
        Err(AuthorityError::Corrupt(message))
            if message.contains("multiple usable grants match")
    ));
    for grant_id in ["grant_1", "grant_2"] {
        assert_eq!(
            authority
                .latest_state(grant_id)
                .unwrap()
                .unwrap()
                .verify(&grant_key().verifying_key())
                .unwrap()
                .status(),
            GrantStatusV2::Active
        );
    }
    let allow_events = authority
        .verify_ledger(None)
        .unwrap()
        .entries
        .into_iter()
        .filter(|entry| entry.entry.event_type() == "decision_allow")
        .count();
    assert_eq!(allow_events, 0);
}
