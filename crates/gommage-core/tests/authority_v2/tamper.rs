use super::*;

#[test]
fn signed_claim_and_state_field_tampering_fails_closed() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    let (claim, active) = approve(&mut authority);
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
    create_request(&mut authority);
    drop(authority);
    let raw = Connection::open(&path).unwrap();
    assert!(
        raw.execute("DELETE FROM ledger_entries WHERE seq = 2", [])
            .is_err()
    );
    assert!(
        raw.execute(
            "UPDATE approval_requests SET request_hash = ?1 WHERE request_id = 'request_1'",
            [hash('9')],
        )
        .is_err()
    );
    drop(raw);

    for mutation in ["delete", "reorder", "insert", "request_hash"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tampered.sqlite3");
        let mut authority = open(&path);
        create_request(&mut authority);
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
                     ) SELECT 3, 'event_forged', entry_jcs, signature_b64, ?1
                       FROM ledger_entries WHERE seq = 1",
                    [hash('f')],
                )
                .unwrap();
                raw.execute(
                    "UPDATE authority_meta SET head_seq = 3, head_hash = ?1 WHERE singleton = 1",
                    [hash('f')],
                )
                .unwrap();
            }
            "request_hash" => {
                raw.execute_batch("DROP TRIGGER approval_requests_no_update;")
                    .unwrap();
                raw.execute(
                    "UPDATE approval_requests SET request_hash = ?1 WHERE request_id = 'request_1'",
                    [hash('9')],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(raw);
        assert!(
            Authority::open(&path, config(), grant_key(), ledger_key()).is_err(),
            "offline {mutation} tampering must fail verification"
        );
    }

    let resolution_directory = tempfile::tempdir().unwrap();
    let resolution_path = resolution_directory
        .path()
        .join("resolution-tampered.sqlite3");
    let mut authority = open(&resolution_path);
    create_request(&mut authority);
    authority
        .deny(&deny_command("request_1", 99, 1_700_000_020))
        .unwrap();
    drop(authority);
    let raw = Connection::open(&resolution_path).unwrap();
    raw.execute_batch("DROP TRIGGER approval_resolutions_no_update;")
        .unwrap();
    raw.execute(
        "UPDATE approval_resolutions SET operator_principal = 'uid:999'
         WHERE request_id = 'request_1'",
        [],
    )
    .unwrap();
    drop(raw);
    assert!(Authority::open(&resolution_path, config(), grant_key(), ledger_key()).is_err());
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
        create_request(&mut authority);
        match mutation {
            "denied_resolution" => {
                authority
                    .deny(&deny_command("request_1", 50, 1_700_000_020))
                    .unwrap();
            }
            "approved_activation" | "approved_resolution_and_activation" => {
                approve(&mut authority);
            }
            _ => unreachable!(),
        }
        drop(authority);

        let first_rebound_seq = if mutation == "approved_activation" {
            4
        } else {
            3
        };
        resign_ledger_suffix_with_build(&path, first_rebound_seq, "forged-signed-build");
        match Authority::open(&path, config(), grant_key(), ledger_key()) {
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
            Authority::open(&path, config(), grant_key(), ledger_key()).is_err(),
            "offline {mutation} tampering must fail runtime reconstruction"
        );
    }
}

#[test]
fn trusted_checkpoint_detects_whole_store_rollback() {
    let older_directory = tempfile::tempdir().unwrap();
    let older_path = older_directory.path().join("older.sqlite3");
    let older = open(&older_path);
    assert_eq!(older.verify_ledger(None).unwrap().head_seq, "1");

    let newer_directory = tempfile::tempdir().unwrap();
    let newer_path = newer_directory.path().join("newer.sqlite3");
    let mut newer = open(&newer_path);
    create_request(&mut newer);
    let checkpoint = newer.checkpoint("checkpoint_newer", 1_700_000_020).unwrap();
    assert_eq!(
        newer.verify_ledger(Some(&checkpoint)).unwrap().head_seq,
        "2"
    );

    assert!(matches!(
        older.verify_ledger(Some(&checkpoint)),
        Err(AuthorityError::RollbackDetected(_))
    ));
    assert_eq!(
        older.verify_ledger(None).unwrap().freshness,
        FreshnessVerdict::Unanchored
    );
}

#[test]
fn fixed_commands_produce_byte_identical_signed_artifacts_and_order() {
    fn build(path: &Path) -> Vec<(String, String, String)> {
        let mut authority = open(path);
        create_request(&mut authority);
        approve(&mut authority);
        authority
            .consume_and_record_allow(&consume_command(1))
            .unwrap();
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
