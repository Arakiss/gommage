use super::*;

#[test]
fn signed_claim_and_state_field_tampering_fails_closed() {
    let (_directory, _path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let (claim, active) = approve(&mut authority, &request);
    let claim_fields = [
        ("expires_at", serde_json::json!(1_700_000_021)),
        ("input_hash", serde_json::json!(hash('8'))),
        ("required_scope", serde_json::json!("other:scope")),
        ("request_hash", serde_json::json!(hash('7'))),
        (
            "grant_key_id",
            serde_json::json!(format!("ledger:sha256:{}", "0".repeat(64))),
        ),
    ];
    for (field, replacement) in claim_fields {
        let mut value: Value = serde_json::from_str(claim.envelope().jcs()).unwrap();
        value[field] = replacement;
        let tampered = SignedGrantClaimV2::from_stored(
            SignedJcs::from_stored(
                serde_json_canonicalizer::to_string(&value).unwrap(),
                claim.envelope().signature_b64().into(),
            ),
            claim.claim_hash().into(),
        );
        assert!(tampered.verify(&grant_key().verifying_key()).is_err());
    }

    let state_fields = [
        ("status", serde_json::json!("spent")),
        ("uses", serde_json::json!(1)),
        ("claim_hash", serde_json::json!(hash('6'))),
        ("revision", serde_json::json!("1")),
        ("previous_state_hash", serde_json::json!(hash('5'))),
        (
            "grant_key_id",
            serde_json::json!(format!("ledger:sha256:{}", "0".repeat(64))),
        ),
    ];
    for (field, replacement) in state_fields {
        let mut value: Value = serde_json::from_str(active.envelope().jcs()).unwrap();
        value[field] = replacement;
        let tampered = SignedGrantStateV2::from_stored(
            SignedJcs::from_stored(
                serde_json_canonicalizer::to_string(&value).unwrap(),
                active.envelope().signature_b64().into(),
            ),
            active.state_hash().into(),
        );
        assert!(tampered.verify(&grant_key().verifying_key()).is_err());
    }
}

#[test]
fn append_only_triggers_and_full_verification_reject_row_tampering() {
    let (_directory, path, mut authority) = fixture();
    let request = create_request(&mut authority);
    let request_id = request.request_id().to_owned();
    drop(authority);
    let raw = Connection::open(&path).unwrap();
    assert!(
        raw.execute("DELETE FROM ledger_entries WHERE seq = 2", [])
            .is_err()
    );
    assert!(
        raw.execute(
            "UPDATE approval_requests SET request_hash = ?1 WHERE request_id = ?2",
            rusqlite::params![hash('9'), request_id],
        )
        .is_err()
    );
    drop(raw);

    for mutation in ["delete", "reorder", "insert", "request_hash"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tampered.sqlite3");
        let mut authority = open(&path);
        let request = create_request(&mut authority);
        let request_id = request.request_id().to_owned();
        drop(authority);
        let raw = Connection::open(&path).unwrap();
        match mutation {
            "delete" => {
                raw.execute_batch(
                    "DROP TRIGGER ledger_entries_no_delete;
                     DELETE FROM ledger_entries WHERE seq = 2;",
                )
                .unwrap();
            }
            "reorder" => {
                raw.execute_batch(
                    "DROP TRIGGER ledger_entries_no_update;
                     UPDATE ledger_entries SET entry_jcs = replace(
                         entry_jcs, 'approval_requested', 'approval_resolved'
                     ) WHERE seq = 2;",
                )
                .unwrap();
            }
            "insert" => {
                raw.execute(
                    "INSERT INTO ledger_entries (
                        seq, event_id, entry_jcs, signature_b64, entry_hash
                     ) SELECT 4, 'event_forged', entry_jcs, signature_b64, ?1
                       FROM ledger_entries WHERE seq = 1",
                    [hash('f')],
                )
                .unwrap();
                raw.execute(
                    "UPDATE authority_meta SET head_seq = 4, head_hash = ?1 WHERE singleton = 1",
                    [hash('f')],
                )
                .unwrap();
            }
            "request_hash" => {
                raw.execute_batch("DROP TRIGGER approval_requests_no_update;")
                    .unwrap();
                raw.execute(
                    "UPDATE approval_requests SET request_hash = ?1 WHERE request_id = ?2",
                    rusqlite::params![hash('9'), request_id],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(raw);
        assert!(
            try_open(&path).is_err(),
            "offline {mutation} tampering must fail verification"
        );
    }

    let resolution_directory = tempfile::tempdir().unwrap();
    let resolution_path = resolution_directory
        .path()
        .join("resolution-tampered.sqlite3");
    let mut authority = open(&resolution_path);
    let request = create_request(&mut authority);
    authority
        .deny(&deny_command(
            request.request_id(),
            99,
            request.created_at(),
        ))
        .unwrap();
    let request_id = request.request_id().to_owned();
    drop(authority);
    let raw = Connection::open(&resolution_path).unwrap();
    raw.execute_batch("DROP TRIGGER approval_resolutions_no_update;")
        .unwrap();
    raw.execute(
        "UPDATE approval_resolutions SET operator_principal = 'uid:999'
         WHERE request_id = ?1",
        [request_id],
    )
    .unwrap();
    drop(raw);
    assert!(try_open(&resolution_path).is_err());
}

#[test]
fn full_verification_rejects_signed_resolution_and_activation_build_rebinding() {
    for mutation in [
        "denied_resolution",
        "approved_activation",
        "approved_resolution_and_activation",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{mutation}.sqlite3"));
        let mut authority = open(&path);
        let request = create_request(&mut authority);
        match mutation {
            "denied_resolution" => {
                authority
                    .deny(&deny_command(
                        request.request_id(),
                        50,
                        request.created_at(),
                    ))
                    .unwrap();
            }
            "approved_activation" | "approved_resolution_and_activation" => {
                approve(&mut authority, &request);
            }
            _ => unreachable!(),
        }
        drop(authority);

        let first_rebound_seq = if mutation == "approved_activation" {
            5
        } else {
            4
        };
        resign_ledger_suffix_with_build(&path, first_rebound_seq, "forged-signed-build");
        match try_open(&path) {
            Err(AuthorityError::Corrupt(_)) => {}
            Err(other) => panic!(
                "signed {mutation} rebinding reached the wrong verification layer: {other:?}"
            ),
            Ok(_) => panic!("signed {mutation} rebinding must fail relational verification"),
        }
    }
}

#[test]
fn full_verification_rejects_generation_and_runtime_state_tampering() {
    for mutation in ["generation", "runtime"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(format!("{mutation}-tampered.sqlite3"));
        let mut authority = open(&path);
        authority
            .activate_generation(&activate_command("2", 2, 1_700_000_010))
            .unwrap();
        drop(authority);

        let raw = Connection::open(&path).unwrap();
        match mutation {
            "generation" => {
                raw.execute_batch("DROP TRIGGER authority_generations_no_update;")
                    .unwrap();
                raw.execute(
                    "UPDATE authority_generations
                     SET generation_jcs = replace(
                         generation_jcs,
                         'gommage-release-2',
                         'gommage-release-x'
                     )
                     WHERE generation_id = '2'",
                    [],
                )
                .unwrap();
            }
            "runtime" => {
                raw.execute_batch("DROP TRIGGER authority_runtime_states_no_update;")
                    .unwrap();
                raw.execute(
                    "UPDATE authority_runtime_states SET maintenance = 1 WHERE revision = 1",
                    [],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(raw);
        assert!(
            try_open(&path).is_err(),
            "offline {mutation} tampering must fail runtime reconstruction"
        );
    }
}

#[test]
fn resigned_decision_record_tampering_fails_closed() {
    for mutation in ["outcome", "semantics", "provenance", "generation"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(format!("decision-{mutation}.sqlite3"));
        let mut authority = open(&path);
        let command = CommitDecisionCommandV2 {
            evaluated_generation: generation("1"),
            integration: "codex".into(),
            call: observed_call(),
            evaluation: resolved_evaluation(&generation("1"), Decision::Allow, &["test.allow"]),
        };
        authority.commit_decision(&command).unwrap();
        drop(authority);

        resign_ledger_suffix(&path, 2, |seq, entry| {
            if seq != 2 {
                return;
            }
            let record = &mut entry["payload"]["record"];
            match mutation {
                "outcome" => record["outcome"]["kind"] = json!("denied"),
                "semantics" => {
                    record["evaluation"]["semantics"] = json!("forged.reducer.v99");
                }
                "provenance" => {
                    record["evaluation"]["provenance"][0]["status"] = json!("unresolved");
                }
                "generation" => record["generation"]["generation_id"] = json!("2"),
                _ => unreachable!(),
            }
        });
        assert!(
            try_open(&path).is_err(),
            "re-signed decision {mutation} tampering must fail"
        );
    }
}

#[test]
fn resigned_request_and_spent_state_links_fail_closed() {
    let request_directory = tempfile::tempdir().unwrap();
    let request_path = request_directory.path().join("request-hash.sqlite3");
    let mut authority = open(&request_path);
    authority.commit_decision(&authorize_command()).unwrap();
    drop(authority);
    resign_ledger_suffix(&request_path, 3, |seq, entry| {
        if seq == 3 {
            entry["payload"]["record"]["outcome"]["request_hash"] = json!(hash('9'));
        }
    });
    assert!(try_open(&request_path).is_err());

    let state_directory = tempfile::tempdir().unwrap();
    let state_path = state_directory.path().join("state-hash.sqlite3");
    let mut authority = open(&state_path);
    let request = match authority.commit_decision(&authorize_command()).unwrap() {
        CommittedDecisionV2::ApprovalRequired { request, .. } => request,
        other => panic!("expected request, got {other:?}"),
    };
    approve_request_at(
        &mut authority,
        request.request_id(),
        request.created_at(),
        77,
    );
    assert!(matches!(
        authority.commit_decision(&authorize_command()).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
    drop(authority);
    resign_ledger_suffix(&state_path, 7, |seq, entry| {
        if seq == 7 {
            entry["payload"]["record"]["outcome"]["state_hash"] = json!(hash('8'));
        }
    });
    assert!(try_open(&state_path).is_err());
}

#[test]
fn trusted_checkpoint_detects_whole_store_rollback() {
    let older_directory = tempfile::tempdir().unwrap();
    let older_path = older_directory.path().join("older.sqlite3");
    let older = open(&older_path);
    assert_eq!(older.verify_ledger().unwrap().head_seq, "1");

    let newer_directory = tempfile::tempdir().unwrap();
    let newer_path = newer_directory.path().join("newer.sqlite3");
    let mut newer = open(&newer_path);
    create_request(&mut newer);
    assert_eq!(newer.verify_ledger().unwrap().head_seq, "3");
    let newer_retention = retention_for(&newer_path).state();
    drop(newer);
    drop(older);

    retention_for(&older_path).force_state(newer_retention);
    assert!(matches!(
        try_open(&older_path),
        Err(AuthorityError::RollbackDetected(_))
    ));
}

#[test]
fn durable_checkpoint_blocks_snapshot_rollback_on_live_commit_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let snapshot = directory.path().join("approved.snapshot.sqlite3");
    let source = Arc::new(FixedRuntimeSource {
        timestamp: AtomicI64::new(1_700_000_030),
        next_nonce: AtomicU64::new(1),
    });
    let mut authority = open_with_source(&path, config(), source.clone());
    let request = create_request(&mut authority);
    approve(&mut authority, &request);
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    std::fs::copy(&path, &snapshot).unwrap();

    assert!(matches!(
        authority.commit_decision(&consume_command(1)).unwrap(),
        CommittedDecisionV2::AllowedByGrant { .. }
    ));
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let nonce_before_rollback = source.next_nonce.load(Ordering::SeqCst);

    std::fs::copy(&snapshot, &path).unwrap();
    assert!(matches!(
        authority.request(request.request_id()),
        Err(AuthorityError::RollbackDetected(_))
    ));
    assert!(matches!(
        authority.commit_decision(&consume_command(1)),
        Err(AuthorityError::RollbackDetected(_))
    ));
    assert_eq!(
        source.next_nonce.load(Ordering::SeqCst),
        nonce_before_rollback
    );
    drop(authority);

    assert!(matches!(
        try_open(&path),
        Err(AuthorityError::RollbackDetected(_))
    ));
}

#[test]
fn fixed_commands_produce_byte_identical_signed_artifacts_and_order() {
    fn build(path: &Path) -> Vec<(String, String, String)> {
        let mut authority = open_with_source(
            path,
            config(),
            Arc::new(FixedRuntimeSource {
                timestamp: AtomicI64::new(1_700_000_030),
                next_nonce: AtomicU64::new(1),
            }),
        );
        let request = create_request(&mut authority);
        approve(&mut authority, &request);
        authority.commit_decision(&consume_command(1)).unwrap();
        drop(authority);
        let raw = Connection::open(path).unwrap();
        let mut statement = raw
            .prepare("SELECT entry_jcs, signature_b64, entry_hash FROM ledger_entries ORDER BY seq")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    let first_directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let first = build(&first_directory.path().join("first.sqlite3"));
    let second = build(&second_directory.path().join("second.sqlite3"));
    assert_eq!(first, second);
}
