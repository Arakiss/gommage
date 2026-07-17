use super::*;

#[test]
fn consume_command_api_has_no_client_selected_grant() {
    let ConsumeCommand {
        required_scope,
        context,
        generation: evaluated_generation,
        state_event_id,
        decision_event_id,
        consumed_at,
    } = consume_command(0);

    assert_eq!(required_scope, "git.push:refs/heads/main");
    assert_eq!(context, authorization_context());
    assert_eq!(evaluated_generation, generation("1"));
    assert_eq!(state_event_id, "event_spend_0");
    assert_eq!(decision_event_id, "event_allow_0");
    assert_eq!(consumed_at, 1_700_000_030);
}

#[test]
fn runtime_authorization_api_exposes_no_identity_time_or_event_controls() {
    let AuthorizeApprovalCommandV2 {
        integration,
        call,
        capabilities,
        required_scope,
        reason,
    } = authorize_command();

    assert_eq!(integration, "codex");
    assert_eq!(call.tool, "Bash");
    assert_eq!(call.input["command"], "git push origin main");
    assert_eq!(capabilities.len(), 3);
    assert_eq!(required_scope, "git.push:refs/heads/main");
    assert_eq!(reason, "Release the reviewed commit");
}

#[test]
fn trusted_open_time_and_identifier_source_owns_runtime_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let source = Arc::new(FixedRuntimeSource {
        timestamp: AtomicI64::new(1_800_000_000),
        next_nonce: AtomicU64::new(1),
    });
    let mut authority = Authority::open_with_runtime_source(
        &path,
        config(),
        grant_key(),
        ledger_key(),
        source.clone(),
    )
    .unwrap();
    let command = authorize_command();
    let request = match authority.authorize_approval(&command).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => request,
        other => panic!("expected source-owned request, got {other:?}"),
    };
    assert_eq!(request.created_at(), 1_800_000_000);
    assert_eq!(request.request_id(), "request_fixed0000000000000001");
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        8,
    );

    assert!(matches!(
        authority.authorize_approval(&command).unwrap(),
        AuthorizeApprovalResultV2::Allowed {
            decision_event_id,
            ..
        } if decision_event_id == "decision_allow_fixed0000000000000004"
    ));
    let head_before = authority.verify_ledger(None).unwrap().head_seq;
    source.timestamp.store(1_799_999_999, Ordering::SeqCst);
    assert!(matches!(
        authority.authorize_approval(&command),
        Err(AuthorityError::RuntimeSource(message))
            if message.contains("predates signed evidence time")
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
}

#[test]
fn resolution_commands_have_no_caller_controlled_build_identity() {
    let ApproveCommand {
        request_id,
        grant_id,
        resolution_event_id,
        activation_event_id,
        operator_principal,
        reason,
        resolved_at,
        ttl_seconds,
    } = approve_command(7);
    assert_eq!(request_id, "request_1");
    assert_eq!(grant_id, "grant_7");
    assert_eq!(resolution_event_id, "event_approve_7");
    assert_eq!(activation_event_id, "event_activate_7");
    assert_eq!(operator_principal, "uid:501");
    assert_eq!(reason, "Reviewed exact input and scope");
    assert_eq!(resolved_at, 1_700_000_020);
    assert_eq!(ttl_seconds, 600);

    let DenyCommand {
        request_id,
        event_id,
        operator_principal,
        reason,
        resolved_at,
    } = deny_command("request_2", 7, 1_700_000_021);
    assert_eq!(request_id, "request_2");
    assert_eq!(event_id, "event_deny_7");
    assert_eq!(operator_principal, "uid:501");
    assert_eq!(reason, "Denied after exact review");
    assert_eq!(resolved_at, 1_700_000_021);
}

#[test]
fn reference_lifecycle_is_atomic_exact_and_reopenable() {
    let (_directory, path, mut authority) = fixture();
    let initial = authority.verify_ledger(None).unwrap();
    assert_eq!(initial.head_seq, "1");
    assert_eq!(initial.freshness, FreshnessVerdict::Unanchored);
    assert_eq!(
        authority.metadata().unwrap().schema_version,
        2,
        "fresh v2 metadata is explicit"
    );

    create_request(&mut authority);
    let existing = authority
        .create_or_get_request(&request_command("request_duplicate", "event_duplicate"))
        .unwrap();
    match existing {
        CreateRequestResult::Existing(request) => {
            assert_eq!(request.request_id(), "request_1");
            assert_eq!(
                request.capabilities(),
                &["git.push:refs/heads/main", "proc.exec:git"]
            );
        }
        other => panic!("expected deduplication, got {other:?}"),
    }

    let (claim, active) = approve(&mut authority);
    assert_eq!(
        claim
            .verify(&grant_key().verifying_key())
            .unwrap()
            .max_uses(),
        1
    );
    assert_eq!(
        active
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Active
    );
    let mut mismatch = consume_command(0);
    mismatch.context = context_with(
        "gommage-test-build",
        "codex",
        "Bash",
        '9',
        '2',
        &["git.push:refs/heads/main", "proc.exec:git"],
    );
    assert_eq!(
        authority.consume_and_record_allow(&mismatch).unwrap(),
        ConsumeResult::NotUsable(GrantNotUsableReason::Missing)
    );
    let consumed = authority
        .consume_and_record_allow(&consume_command(1))
        .unwrap();
    assert!(matches!(consumed, ConsumeResult::Consumed { .. }));
    assert_eq!(
        authority
            .consume_and_record_allow(&consume_command(2))
            .unwrap(),
        ConsumeResult::NotUsable(GrantNotUsableReason::Missing)
    );
    let checkpoint = authority.checkpoint("checkpoint_1", 1_700_000_040).unwrap();
    let anchored = authority.verify_ledger(Some(&checkpoint)).unwrap();
    assert_eq!(anchored.head_seq, "6");
    assert_eq!(
        anchored.freshness,
        FreshnessVerdict::Anchored {
            checkpoint_seq: "6".into()
        }
    );
    drop(authority);

    let reopened = open(&path);
    let verification = reopened.verify_ledger(Some(&checkpoint)).unwrap();
    assert_eq!(verification.head_seq, "6");
    assert!(reopened.grant("grant_1").unwrap().is_some());
    assert_eq!(
        reopened
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Spent
    );

    let raw =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let journal: String = raw
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let application_id: i32 = raw
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .unwrap();
    let user_version: i32 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    assert_eq!(application_id, 0x474f_4d32);
    assert_eq!(user_version, 2);
}

#[test]
fn signed_ledger_pages_are_bounded_and_keep_one_snapshot_head() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);
    assert!(matches!(
        authority
            .consume_and_record_allow(&consume_command(1))
            .unwrap(),
        ConsumeResult::Consumed { .. }
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "6");

    let first = authority.ledger_page(None, 2, None).unwrap();
    assert_eq!(first.entries.len(), 2);
    assert_eq!(first.entries[0].entry.seq(), "1");
    assert_eq!(first.entries[1].entry.seq(), "2");
    assert_eq!(first.snapshot_head_seq, "6");
    assert_eq!(first.freshness, FreshnessVerdict::Unanchored);
    let first_cursor = first.next_cursor.unwrap();
    let verified_cursor = first_cursor.verify(&ledger_key().verifying_key()).unwrap();
    assert_eq!(verified_cursor.snapshot_head_seq(), "6");
    assert_eq!(verified_cursor.next_seq(), "3");

    let mut later = request_command("request_later", "event_request_later");
    later.context = context_with(
        "gommage-test-build",
        "codex",
        "Bash",
        '8',
        '2',
        &["git.push:refs/heads/main", "proc.exec:git"],
    );
    assert!(matches!(
        authority.create_or_get_request(&later).unwrap(),
        CreateRequestResult::Created(_)
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "7");

    let second = authority.ledger_page(Some(&first_cursor), 2, None).unwrap();
    assert_eq!(second.snapshot_head_seq, "6");
    assert_eq!(second.entries[0].entry.seq(), "3");
    assert_eq!(second.entries[1].entry.seq(), "4");
    let second_cursor = second.next_cursor.unwrap();
    let third = authority
        .ledger_page(Some(&second_cursor), 2, None)
        .unwrap();
    assert_eq!(third.snapshot_head_seq, "6");
    assert_eq!(third.entries[0].entry.seq(), "5");
    assert_eq!(third.entries[1].entry.seq(), "6");
    assert!(third.next_cursor.is_none());
    assert!(third.entries.iter().all(|entry| entry.entry.seq() != "7"));

    assert!(matches!(
        authority.ledger_page(None, 0, None),
        Err(AuthorityError::InvalidInput(_))
    ));
    assert!(matches!(
        authority.ledger_page(None, MAX_LEDGER_PAGE_ENTRIES + 1, None),
        Err(AuthorityError::InvalidInput(_))
    ));

    let tampered = SignedLedgerCursorV2::from_stored(SignedJcs::from_stored(
        format!("{} ", first_cursor.envelope().jcs()),
        first_cursor.envelope().signature_b64().to_owned(),
    ));
    assert!(authority.ledger_page(Some(&tampered), 2, None).is_err());
}

#[test]
fn ledger_cursor_issuance_rejects_runtime_clock_regression() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let source = Arc::new(FixedRuntimeSource {
        timestamp: AtomicI64::new(1_800_000_000),
        next_nonce: AtomicU64::new(1),
    });
    let mut authority = Authority::open_with_runtime_source(
        &path,
        config(),
        grant_key(),
        ledger_key(),
        source.clone(),
    )
    .unwrap();
    create_request(&mut authority);
    approve(&mut authority);

    let first = authority.ledger_page(None, 1, None).unwrap();
    let cursor = first.next_cursor.unwrap();
    assert_eq!(
        cursor
            .verify(&ledger_key().verifying_key())
            .unwrap()
            .issued_at(),
        1_800_000_000
    );
    source.timestamp.store(1_799_999_999, Ordering::SeqCst);
    assert!(matches!(
        authority.ledger_page(Some(&cursor), 1, None),
        Err(AuthorityError::RuntimeSource(message))
            if message.contains("predates signed evidence time")
    ));
}

#[test]
fn runtime_authorization_owns_identity_time_and_the_complete_retry_transaction() {
    let (_directory, _path, mut authority) = fixture();
    let command = authorize_command();

    let first = authority.authorize_approval(&command).unwrap();
    let (request_id, created_at) = match first {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => {
            assert!(request.request_id().starts_with("request_"));
            assert!(request.created_at() > config().genesis_at);
            assert_eq!(request.context().build_identity(), "gommage-test-build");
            assert_eq!(request.policy_identity(), hash('2'));
            assert_eq!(request.generation(), &generation("1"));
            assert_eq!(request.integration(), "codex");
            assert_eq!(request.tool(), "Bash");
            assert_eq!(request.input_hash(), command.call.input_hash());
            assert_eq!(
                request.capabilities(),
                &["git.push:refs/heads/main", "proc.exec:git"]
            );
            (request.request_id().to_owned(), request.created_at())
        }
        other => panic!("expected Authority-owned approval request, got {other:?}"),
    };
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "2");

    let duplicate = authority.authorize_approval(&command).unwrap();
    assert!(matches!(
        duplicate,
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: false,
        } if request.request_id() == request_id
    ));
    assert_eq!(
        authority.verify_ledger(None).unwrap().head_seq,
        "2",
        "deduplicating the exact retry must not grow the ledger"
    );

    approve_request_at(&mut authority, &request_id, created_at, 1);
    let allowed = authority.authorize_approval(&command).unwrap();
    match allowed {
        AuthorizeApprovalResultV2::Allowed {
            state,
            decision_event_id,
        } => {
            assert!(decision_event_id.starts_with("decision_allow_"));
            let state = state.verify(&grant_key().verifying_key()).unwrap();
            assert_eq!(state.status(), GrantStatusV2::Spent);
            assert!(state.transition_event_id().starts_with("state_spend_"));
        }
        other => panic!("expected exact one-use authorization, got {other:?}"),
    }
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "6");

    let replacement = authority.authorize_approval(&command).unwrap();
    assert!(matches!(
        replacement,
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } if request.request_id() != request_id
            && request.request_id().starts_with("request_")
    ));
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
}

#[test]
fn runtime_authorization_never_spends_for_input_scope_or_context_mismatch() {
    let (_directory, _path, mut authority) = fixture();
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
        2,
    );

    let mut input_mismatch = command.clone();
    input_mismatch.call.input["command"] = json!("git push origin release");
    let input_request_id = match authority.authorize_approval(&input_mismatch).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => request.request_id().to_owned(),
        other => panic!("input mismatch authorized unexpectedly: {other:?}"),
    };
    let mut scope_mismatch = command.clone();
    scope_mismatch.required_scope = "git.push:refs/heads/release".into();
    let scope_request_id = match authority.authorize_approval(&scope_mismatch).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => request.request_id().to_owned(),
        other => panic!("scope mismatch authorized unexpectedly: {other:?}"),
    };
    let mut context_mismatch = command.clone();
    context_mismatch.integration = "claude-code".into();
    let context_request_id = match authority.authorize_approval(&context_mismatch).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => request.request_id().to_owned(),
        other => panic!("context mismatch authorized unexpectedly: {other:?}"),
    };
    assert_ne!(input_request_id, scope_request_id);
    assert_ne!(input_request_id, context_request_id);
    assert_ne!(scope_request_id, context_request_id);
    assert_eq!(
        authority
            .latest_state("grant_runtime_2")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Active
    );

    assert!(matches!(
        authority.authorize_approval(&command).unwrap(),
        AuthorizeApprovalResultV2::Allowed { .. }
    ));
    assert_eq!(
        authority
            .latest_state("grant_runtime_2")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Spent
    );
    authority.verify_ledger(None).unwrap();
}

#[test]
fn runtime_authorization_derives_the_active_generation_and_fails_closed_in_maintenance() {
    let (_directory, _path, mut authority) = fixture();
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_010))
        .unwrap();

    let request = match authority.authorize_approval(&authorize_command()).unwrap() {
        AuthorizeApprovalResultV2::ApprovalRequired {
            request,
            created: true,
        } => request,
        other => panic!("expected request in active generation, got {other:?}"),
    };
    assert_eq!(request.generation(), &generation("2"));
    assert_eq!(request.build_identity(), "gommage-next-build");
    assert_eq!(request.policy_identity(), hash('9'));

    authority
        .set_maintenance(&maintenance_command(true, 7, request.created_at() + 1))
        .unwrap();
    let head_before = authority.verify_ledger(None).unwrap().head_seq;
    assert!(matches!(
        authority.authorize_approval(&authorize_command()),
        Err(AuthorityError::Maintenance)
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
}

#[test]
fn runtime_authorization_fails_closed_on_future_dated_grant_evidence() {
    let (_directory, _path, mut authority) = fixture();
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
        request.created_at() + 60,
        3,
    );
    let head_before = authority.verify_ledger(None).unwrap().head_seq;

    assert!(matches!(
        authority.authorize_approval(&command),
        Err(AuthorityError::RuntimeSource(message))
            if message.contains("predates signed evidence time")
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, head_before);
    assert_eq!(
        authority
            .latest_state("grant_runtime_3")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap()
            .status(),
        GrantStatusV2::Active
    );
}

#[test]
fn open_request_dedupe_binds_the_complete_active_generation() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    authority
        .activate_generation(&activate_command("2", 2, 1_700_000_011))
        .unwrap();

    let mut other_build = request_command("request_other_build", "event_other_build");
    other_build.generation = generation("2");
    other_build.context = authorization_context_for(&other_build.generation);
    assert!(matches!(
        authority.create_or_get_request(&other_build).unwrap(),
        CreateRequestResult::Created(request)
            if request.request_id() == "request_other_build"
                && request.build_identity() == "gommage-next-build"
                && request.generation() == &generation("2")
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "4");
}

#[test]
fn genesis_generation_and_admin_runtime_transitions_are_signed_state() {
    let (_directory, _path, mut authority) = fixture();
    let genesis = authority.runtime_state().unwrap();
    assert_eq!(genesis.revision(), "0");
    assert_eq!(genesis.active_generation(), &generation("1"));
    assert!(!genesis.maintenance());
    assert_eq!(genesis.transition_event_id(), "event_genesis");
    assert_eq!(
        authority.metadata().unwrap().genesis_generation,
        generation("1")
    );

    let activated = authority
        .activate_generation(&activate_command("2", 2, 1_700_000_010))
        .unwrap();
    assert_eq!(activated.revision(), "1");
    assert_eq!(activated.active_generation(), &generation("2"));
    assert!(!activated.maintenance());

    let entered = authority
        .set_maintenance(&maintenance_command(true, 1, 1_700_000_011))
        .unwrap();
    assert_eq!(entered.revision(), "2");
    assert!(entered.maintenance());
    let exited = authority
        .set_maintenance(&maintenance_command(false, 2, 1_700_000_012))
        .unwrap();
    assert_eq!(exited.revision(), "3");
    assert!(!exited.maintenance());

    let event_types: Vec<_> = authority
        .verify_ledger(None)
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.entry.event_type().to_string())
        .collect();
    assert_eq!(
        event_types,
        [
            "genesis",
            "generation_activated",
            "maintenance_entered",
            "maintenance_exited",
        ]
    );
}
