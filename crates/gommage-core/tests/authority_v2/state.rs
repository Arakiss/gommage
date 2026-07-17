use super::*;

#[test]
fn stale_generation_creates_no_request_spends_no_grant_and_records_no_allow() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_025))
        .unwrap();
    let head_before = authority.verify_ledger().unwrap().head_seq;

    let decisions_before = authority
        .verify_ledger()
        .unwrap()
        .entries
        .iter()
        .filter(|entry| entry.entry.event_type() == "decision_recorded")
        .count();
    assert!(matches!(
        authority.commit_decision(&consume_command(9)),
        Err(AuthorityError::StaleGeneration { .. })
    ));
    assert_eq!(authority.verify_ledger().unwrap().head_seq, head_before);
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
            .verify_ledger()
            .unwrap()
            .entries
            .iter()
            .filter(|entry| entry.entry.event_type() == "decision_recorded")
            .count(),
        decisions_before
    );
}

#[test]
fn stale_or_maintenance_generation_cannot_be_approved_without_mutation() {
    for blocked_by_maintenance in [false, true] {
        let (_directory, _path, mut authority) = fixture();
        let request = create_request(&mut authority);
        if blocked_by_maintenance {
            authority
                .set_maintenance(&maintenance_command(true, 1, 1_700_000_015))
                .unwrap();
        } else {
            authority
                .activate_generation(&activate_command("2", 2, 1_700_000_015))
                .unwrap();
        }
        let head_before = authority.verify_ledger().unwrap().head_seq;

        let result = authority.approve(&approval_command(&request, 1));
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
        assert_eq!(authority.verify_ledger().unwrap().head_seq, head_before);
        assert!(
            authority
                .resolution(request.request_id())
                .unwrap()
                .is_none()
        );
        assert!(authority.grant("grant_1").unwrap().is_none());
        assert!(authority.request(request.request_id()).unwrap().is_some());
    }
}

#[test]
fn deny_and_revoke_remain_available_for_cleanup_during_maintenance() {
    let (_directory, _path, mut authority) = fixture();
    let first = create_request(&mut authority);
    approve(&mut authority, &first);
    let second = create_second_request(&mut authority);
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_025))
        .unwrap();
    authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_026))
        .unwrap();

    assert!(matches!(
        authority
            .deny(&deny_command(second.request_id(), 2, 1_700_000_030))
            .unwrap(),
        DenyResult::Denied(resolution)
            if resolution.request_id == second.request_id()
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
    authority.verify_ledger().unwrap();
}

#[test]
fn generation_activation_linearizes_with_concurrent_approval() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let request_id = request.request_id().to_owned();
    let resolved_at = request.created_at();
    let authority = Arc::new(Mutex::new(authority));

    let barrier = Arc::new(Barrier::new(2));
    let approve_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let mut command = approve_command(1);
            command.request_id = request_id;
            command.resolved_at = resolved_at;
            authority.lock().unwrap().approve(&command)
        })
    };
    let activate_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
                .activate_generation(&activate_command("2", 2, 1_700_000_025))
        })
    };
    let approve_result = approve_handle.join().unwrap();
    activate_handle.join().unwrap().unwrap();

    let authority = authority.lock().unwrap();
    let verification = authority.verify_ledger().unwrap();
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
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_025))
        .unwrap();
    let head_before = authority.verify_ledger().unwrap().head_seq;

    assert!(matches!(
        authority.commit_decision(&consume_command(9)),
        Err(AuthorityError::Maintenance)
    ));
    assert_eq!(authority.verify_ledger().unwrap().head_seq, head_before);
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
        authority.commit_decision(&consume_command(10)).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
}

#[test]
fn generation_activation_linearizes_with_concurrent_allow() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    let authority = Arc::new(Mutex::new(authority));

    let barrier = Arc::new(Barrier::new(2));
    let consume_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
                .commit_decision(&consume_command(20))
        })
    };
    let activate_handle = {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            authority
                .lock()
                .unwrap()
                .activate_generation(&activate_command("2", 2, 1_700_000_025))
        })
    };
    let consume_result = consume_handle.join().unwrap();
    let activated = activate_handle.join().unwrap().unwrap();
    assert_eq!(activated.active_generation(), &generation("2"));

    let verification = authority.lock().unwrap().verify_ledger().unwrap();
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
            matches!(
                entry.entry.payload(),
                LedgerPayloadV2::DecisionRecorded { record }
                    if matches!(
                        record.outcome(),
                        AuthorityDecisionOutcomeV2::AllowedByGrant { .. }
                    )
            )
            .then_some(index)
        })
        .collect();
    match consume_result {
        Ok(CommittedDecisionV2::AllowedByGrant { .. }) => {
            assert_eq!(allow_sequences.len(), 1);
            assert!(allow_sequences[0] < activation_seq);
        }
        Err(AuthorityError::StaleGeneration { .. }) => assert!(allow_sequences.is_empty()),
        other => panic!("unexpected concurrent consume result: {other:?}"),
    }
}

#[test]
fn failure_between_spend_and_decision_rolls_back_the_whole_transition() {
    let (_directory, path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    let mut enter = maintenance_command(true, 91, request.created_at());
    enter.event_id = "decision_collision".into();
    authority.set_maintenance(&enter).unwrap();
    authority
        .set_maintenance(&maintenance_command(false, 92, request.created_at()))
        .unwrap();
    let head_before = authority.verify_ledger().unwrap().head_seq;
    drop(authority);

    let mut authority = open_with_source(
        &path,
        config(),
        Arc::new(CollidingDecisionRuntimeSource {
            identifiers: AtomicU64::new(0),
        }),
    );
    assert!(matches!(
        authority.commit_decision(&authorize_command()),
        Err(AuthorityError::Sqlite(_))
    ));
    drop(authority);

    let authority = open(&path);
    assert_eq!(authority.verify_ledger().unwrap().head_seq, head_before);
    let state = authority
        .latest_state("grant_1")
        .unwrap()
        .unwrap()
        .verify(&grant_key().verifying_key())
        .unwrap();
    assert_eq!(state.status(), GrantStatusV2::Active);
}

#[test]
fn exact_binding_requires_the_complete_tool_input_without_spending_on_mismatch() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    approve(&mut authority, &request);

    let mut tool_mismatch = consume_command(11);
    tool_mismatch.call.tool = "Shell".into();
    let mut input_mismatch = consume_command(12);
    input_mismatch.call.input["command"] = json!("git push origin release");
    for command in [tool_mismatch, input_mismatch] {
        assert!(matches!(
            authority.commit_decision(&command).unwrap(),
            CommittedDecisionV2::ApprovalRequired { created: true, .. }
        ));
        let latest = authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap();
        assert_eq!(latest.status(), GrantStatusV2::Active);
    }
    let mut stale_build = consume_command(30);
    stale_build.evaluated_generation = generation("2");
    stale_build.evaluation = ask_evaluation(&generation("2"));
    assert!(matches!(
        authority.commit_decision(&stale_build),
        Err(AuthorityError::StaleGeneration { .. })
    ));
    let mut policy_mismatch = consume_command(31);
    policy_mismatch.evaluation.policy_version = hash('9');
    assert!(matches!(
        authority.commit_decision(&policy_mismatch),
        Err(AuthorityError::InvalidInput(_))
    ));
    let mut wrong_scope = consume_command(20);
    wrong_scope.evaluation = resolved_evaluation(
        &generation("1"),
        Decision::AskPicto {
            required_scope: "git.push:refs/heads/release".into(),
            reason: "Release the reviewed commit".into(),
            bind_input: true,
        },
        &["git.push:refs/heads/main", "proc.exec:git"],
    );
    assert!(matches!(
        authority.commit_decision(&wrong_scope).unwrap(),
        CommittedDecisionV2::ApprovalRequired { created: true, .. }
    ));
    let head_before_allow = authority.verify_ledger().unwrap().head_seq;
    assert!(matches!(
        authority.commit_decision(&consume_command(99)).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
    assert_eq!(
        authority
            .verify_ledger()
            .unwrap()
            .head_seq
            .parse::<usize>()
            .unwrap(),
        head_before_allow.parse::<usize>().unwrap() + 2
    );
}

#[test]
fn sequential_grants_select_the_only_currently_usable_exact_match() {
    let (_directory, _path, mut authority) = fixture();
    let first = create_request(&mut authority);
    approve(&mut authority, &first);
    assert!(matches!(
        authority.commit_decision(&consume_command(1)).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));

    let second = create_request(&mut authority);
    approve_second_request(&mut authority, &second, second.created_at());
    let state = match authority.commit_decision(&consume_command(2)).unwrap() {
        CommittedDecisionV2::AllowedByGrant { state, .. } => state,
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
