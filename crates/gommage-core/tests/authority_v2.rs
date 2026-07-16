use ed25519_dalek::SigningKey;
use gommage_core::{
    ApproveCommand, ApproveResult, Authority, AuthorityConfig, AuthorityError,
    AuthorizationContextV2, ConsumeCommand, ConsumeResult, CreateRequestCommand,
    CreateRequestResult, DenyCommand, DenyResult, FreshnessVerdict, GrantNotUsableReason,
    GrantStatusV2, RevokeCommand, RevokeResult, SignedGrantClaimV2, SignedGrantStateV2, SignedJcs,
};
use rusqlite::Connection;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};
use tempfile::TempDir;

fn grant_key() -> SigningKey {
    SigningKey::from_bytes(&[41; 32])
}

fn ledger_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn config() -> AuthorityConfig {
    AuthorityConfig {
        instance_id: "authority_test".into(),
        epoch: "1".into(),
        genesis_build_identity: "gommage-test-build".into(),
        genesis_event_id: "event_genesis".into(),
        genesis_at: 1_700_000_000,
    }
}

fn open(path: &Path) -> Authority {
    Authority::open(path, config(), grant_key(), ledger_key()).unwrap()
}

fn fixture() -> (TempDir, PathBuf, Authority) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let authority = open(&path);
    (directory, path, authority)
}

fn hash(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn context_with(
    build_identity: &str,
    integration: &str,
    tool: &str,
    input_hash: char,
    policy_identity: char,
    capabilities: &[&str],
) -> AuthorizationContextV2 {
    AuthorizationContextV2::new(
        build_identity.into(),
        integration.into(),
        tool.into(),
        hash(input_hash),
        hash(policy_identity),
        capabilities.iter().map(|value| (*value).into()).collect(),
    )
    .unwrap()
}

fn authorization_context() -> AuthorizationContextV2 {
    context_with(
        "gommage-test-build",
        "codex",
        "Bash",
        '1',
        '2',
        &[
            "git.push:refs/heads/main",
            "proc.exec:git",
            "git.push:refs/heads/main",
        ],
    )
}

fn request_command(request_id: &str, event_id: &str) -> CreateRequestCommand {
    CreateRequestCommand {
        request_id: request_id.into(),
        event_id: event_id.into(),
        created_at: 1_700_000_010,
        context: authorization_context(),
        required_scope: "git.push:refs/heads/main".into(),
        reason: "Release the reviewed commit".into(),
    }
}

fn create_request(authority: &mut Authority) {
    assert!(matches!(
        authority
            .create_or_get_request(&request_command("request_1", "event_request_1"))
            .unwrap(),
        CreateRequestResult::Created(_)
    ));
}

fn approve_command(index: usize) -> ApproveCommand {
    ApproveCommand {
        request_id: "request_1".into(),
        grant_id: format!("grant_{index}"),
        resolution_event_id: format!("event_approve_{index}"),
        activation_event_id: format!("event_activate_{index}"),
        operator_principal: "uid:501".into(),
        reason: "Reviewed exact input and scope".into(),
        resolved_at: 1_700_000_020,
        build_identity: "gommage-test-build".into(),
        ttl_seconds: 600,
    }
}

fn approve(authority: &mut Authority) -> (SignedGrantClaimV2, SignedGrantStateV2) {
    match authority.approve(&approve_command(1)).unwrap() {
        ApproveResult::Approved { claim, state } => (claim, state),
        other => panic!("expected a new grant, got {other:?}"),
    }
}

fn consume_command(index: usize, grant_id: &str) -> ConsumeCommand {
    ConsumeCommand {
        grant_id: grant_id.into(),
        required_scope: "git.push:refs/heads/main".into(),
        context: authorization_context(),
        state_event_id: format!("event_spend_{index}"),
        decision_event_id: format!("event_allow_{index}"),
        consumed_at: 1_700_000_030,
    }
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
    let mut mismatch = consume_command(0, "grant_1");
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
        ConsumeResult::NotUsable(GrantNotUsableReason::InputMismatch)
    );
    let consumed = authority
        .consume_and_record_allow(&consume_command(1, "grant_1"))
        .unwrap();
    assert!(matches!(consumed, ConsumeResult::Consumed { .. }));
    assert_eq!(
        authority
            .consume_and_record_allow(&consume_command(2, "grant_1"))
            .unwrap(),
        ConsumeResult::NotUsable(GrantNotUsableReason::Terminal)
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
fn open_request_dedupe_binds_the_observing_build() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);

    let mut other_build = request_command("request_other_build", "event_other_build");
    other_build.context = context_with(
        "gommage-next-build",
        "codex",
        "Bash",
        '1',
        '2',
        &["git.push:refs/heads/main", "proc.exec:git"],
    );
    assert!(matches!(
        authority.create_or_get_request(&other_build).unwrap(),
        CreateRequestResult::Created(request)
            if request.request_id() == "request_other_build"
                && request.build_identity() == "gommage-next-build"
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "3");
}

#[test]
fn consumption_requires_the_complete_approved_context_without_spending_on_mismatch() {
    let (_directory, _path, mut authority) = fixture();
    create_request(&mut authority);
    approve(&mut authority);

    let mismatches = [
        (
            context_with(
                "gommage-next-build",
                "codex",
                "Bash",
                '1',
                '2',
                &["git.push:refs/heads/main", "proc.exec:git"],
            ),
            GrantNotUsableReason::BuildIdentityMismatch,
        ),
        (
            context_with(
                "gommage-test-build",
                "claude-code",
                "Bash",
                '1',
                '2',
                &["git.push:refs/heads/main", "proc.exec:git"],
            ),
            GrantNotUsableReason::IntegrationMismatch,
        ),
        (
            context_with(
                "gommage-test-build",
                "codex",
                "Shell",
                '1',
                '2',
                &["git.push:refs/heads/main", "proc.exec:git"],
            ),
            GrantNotUsableReason::ToolMismatch,
        ),
        (
            context_with(
                "gommage-test-build",
                "codex",
                "Bash",
                '9',
                '2',
                &["git.push:refs/heads/main", "proc.exec:git"],
            ),
            GrantNotUsableReason::InputMismatch,
        ),
        (
            context_with(
                "gommage-test-build",
                "codex",
                "Bash",
                '1',
                '9',
                &["git.push:refs/heads/main", "proc.exec:git"],
            ),
            GrantNotUsableReason::PolicyMismatch,
        ),
        (
            context_with(
                "gommage-test-build",
                "codex",
                "Bash",
                '1',
                '2',
                &["git.push:refs/heads/main"],
            ),
            GrantNotUsableReason::CapabilityMismatch,
        ),
    ];

    for (index, (context, expected)) in mismatches.into_iter().enumerate() {
        let mut command = consume_command(index + 10, "grant_1");
        command.context = context;
        assert_eq!(
            authority.consume_and_record_allow(&command).unwrap(),
            ConsumeResult::NotUsable(expected)
        );
        let latest = authority
            .latest_state("grant_1")
            .unwrap()
            .unwrap()
            .verify(&grant_key().verifying_key())
            .unwrap();
        assert_eq!(latest.status(), GrantStatusV2::Active);
    }
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "4");
    assert!(matches!(
        authority
            .consume_and_record_allow(&consume_command(99, "grant_1"))
            .unwrap(),
        ConsumeResult::Consumed { .. }
    ));
    assert_eq!(authority.verify_ledger(None).unwrap().head_seq, "6");
}

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
                authority.consume_and_record_allow(&consume_command(index, "grant_1"))
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
                    ConsumeResult::NotUsable(GrantNotUsableReason::Terminal)
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
                .deny(&DenyCommand {
                    request_id: "request_1".into(),
                    event_id: "event_deny".into(),
                    operator_principal: "uid:501".into(),
                    reason: "Operator denied".into(),
                    resolved_at: 1_700_000_020,
                    build_identity: "gommage-test-build".into(),
                })
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
                .consume_and_record_allow(&consume_command(10, "grant_1"))
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
        .deny(&DenyCommand {
            request_id: "request_1".into(),
            event_id: "event_deny_tamper".into(),
            operator_principal: "uid:501".into(),
            reason: "Denied after review".into(),
            resolved_at: 1_700_000_020,
            build_identity: "gommage-test-build".into(),
        })
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
            .consume_and_record_allow(&consume_command(1, "grant_1"))
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
