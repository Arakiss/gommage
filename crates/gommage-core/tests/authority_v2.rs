use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use gommage_core::{
    ActivateGenerationCommand, ApproveCommand, ApproveResult, Authority, AuthorityConfig,
    AuthorityError, AuthorityGenerationV2, AuthorityRuntimeSource, AuthorizationContextV2,
    AuthorizeApprovalCommandV2, AuthorizeApprovalResultV2, ConsumeCommand, ConsumeResult,
    CreateRequestCommand, CreateRequestResult, DenyCommand, DenyResult, FreshnessVerdict,
    GrantNotUsableReason, GrantStatusV2, RevokeCommand, RevokeResult, SetMaintenanceCommand,
    SignedGrantClaimV2, SignedGrantStateV2, SignedJcs, ToolCall,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    thread,
};
use tempfile::TempDir;

struct FixedRuntimeSource {
    timestamp: AtomicI64,
    next_nonce: AtomicU64,
}

impl AuthorityRuntimeSource for FixedRuntimeSource {
    fn unix_timestamp(&self) -> Result<i64, AuthorityError> {
        Ok(self.timestamp.load(Ordering::SeqCst))
    }

    fn identifier_nonce(&self) -> Result<String, AuthorityError> {
        let nonce = self.next_nonce.fetch_add(1, Ordering::SeqCst);
        Ok(format!("fixed{nonce:016x}"))
    }
}

fn grant_key() -> SigningKey {
    SigningKey::from_bytes(&[41; 32])
}

fn ledger_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn generation(id: &str) -> AuthorityGenerationV2 {
    let (release, build, policy, mapper, protocol) = match id {
        "1" => (
            "gommage-release-1",
            "gommage-test-build",
            hash('2'),
            hash('3'),
            "gommage-managed-v2",
        ),
        "2" => (
            "gommage-release-2",
            "gommage-next-build",
            hash('9'),
            hash('8'),
            "gommage-managed-v2",
        ),
        other => panic!("unexpected test generation {other}"),
    };
    AuthorityGenerationV2::new(
        id.into(),
        release.into(),
        build.into(),
        policy,
        mapper,
        protocol.into(),
    )
    .unwrap()
}

fn config() -> AuthorityConfig {
    AuthorityConfig {
        instance_id: "authority_test".into(),
        epoch: "1".into(),
        genesis_generation: generation("1"),
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

fn resign_ledger_suffix_with_build(path: &Path, first_seq: i64, build_identity: &str) {
    let raw = Connection::open(path).unwrap();
    raw.execute_batch("DROP TRIGGER ledger_entries_no_update;")
        .unwrap();
    let mut previous_hash: String = raw
        .query_row(
            "SELECT entry_hash FROM ledger_entries WHERE seq = ?1",
            [first_seq - 1],
            |row| row.get(0),
        )
        .unwrap();
    let entries = {
        let mut statement = raw
            .prepare(
                "SELECT seq, entry_jcs FROM ledger_entries
                 WHERE seq >= ?1 ORDER BY seq",
            )
            .unwrap();
        statement
            .query_map([first_seq], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(!entries.is_empty());
    let key = ledger_key();
    for (seq, stored_jcs) in entries {
        let mut entry: Value = serde_json::from_str(&stored_jcs).unwrap();
        entry["previous_hash"] = serde_json::json!(previous_hash);
        entry["build_identity"] = serde_json::json!(build_identity);
        let jcs = String::from_utf8(gommage_core::crypto_envelope::canonicalize(&entry).unwrap())
            .unwrap();
        let mut message = b"GOMMAGE\0LEDGER_ENTRY\0V2\0".to_vec();
        message.extend_from_slice(jcs.as_bytes());
        let signature = key.sign(&message).to_bytes();
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
        let mut digest = Sha256::new();
        digest.update(b"GOMMAGE\0LEDGER_ENTRY_HASH\0V2\0");
        digest.update(jcs.as_bytes());
        digest.update(signature);
        let entry_hash = format!("sha256:{}", hex::encode(digest.finalize()));
        raw.execute(
            "UPDATE ledger_entries
             SET entry_jcs = ?1, signature_b64 = ?2, entry_hash = ?3
             WHERE seq = ?4",
            rusqlite::params![jcs, signature_b64, entry_hash, seq],
        )
        .unwrap();
        previous_hash = entry_hash;
    }
    raw.execute(
        "UPDATE authority_meta SET head_hash = ?1 WHERE singleton = 1",
        [previous_hash],
    )
    .unwrap();
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
    authorization_context_for(&generation("1"))
}

fn authorization_context_for(generation: &AuthorityGenerationV2) -> AuthorizationContextV2 {
    AuthorizationContextV2::new(
        generation.build_identity().into(),
        "codex".into(),
        "Bash".into(),
        hash('1'),
        generation.policy_identity().into(),
        vec![
            "git.push:refs/heads/main".into(),
            "proc.exec:git".into(),
            "git.push:refs/heads/main".into(),
        ],
    )
    .unwrap()
}

fn request_command(request_id: &str, event_id: &str) -> CreateRequestCommand {
    CreateRequestCommand {
        request_id: request_id.into(),
        event_id: event_id.into(),
        created_at: 1_700_000_010,
        context: authorization_context(),
        generation: generation("1"),
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
        ttl_seconds: 600,
    }
}

fn deny_command(request_id: &str, index: usize, resolved_at: i64) -> DenyCommand {
    DenyCommand {
        request_id: request_id.into(),
        event_id: format!("event_deny_{index}"),
        operator_principal: "uid:501".into(),
        reason: "Denied after exact review".into(),
        resolved_at,
    }
}

fn approve(authority: &mut Authority) -> (SignedGrantClaimV2, SignedGrantStateV2) {
    match authority.approve(&approve_command(1)).unwrap() {
        ApproveResult::Approved { claim, state } => (claim, state),
        other => panic!("expected a new grant, got {other:?}"),
    }
}

fn approve_request_at(
    authority: &mut Authority,
    request_id: &str,
    resolved_at: i64,
    index: usize,
) -> (SignedGrantClaimV2, SignedGrantStateV2) {
    let command = ApproveCommand {
        request_id: request_id.into(),
        grant_id: format!("grant_runtime_{index}"),
        resolution_event_id: format!("event_runtime_approve_{index}"),
        activation_event_id: format!("event_runtime_activate_{index}"),
        operator_principal: "uid:501".into(),
        reason: "Reviewed the exact Authority-owned request".into(),
        resolved_at,
        ttl_seconds: 600,
    };
    match authority.approve(&command).unwrap() {
        ApproveResult::Approved { claim, state } => (claim, state),
        other => panic!("expected a new runtime grant, got {other:?}"),
    }
}

fn consume_command(index: usize) -> ConsumeCommand {
    ConsumeCommand {
        required_scope: "git.push:refs/heads/main".into(),
        context: authorization_context(),
        generation: generation("1"),
        state_event_id: format!("event_spend_{index}"),
        decision_event_id: format!("event_allow_{index}"),
        consumed_at: 1_700_000_030,
    }
}

fn authorize_command() -> AuthorizeApprovalCommandV2 {
    AuthorizeApprovalCommandV2 {
        integration: "codex".into(),
        call: ToolCall {
            tool: "Bash".into(),
            input: json!({
                "command": "git push origin main",
                "timeout_ms": 120_000,
            }),
        },
        capabilities: vec![
            "proc.exec:git".into(),
            "git.push:refs/heads/main".into(),
            "proc.exec:git".into(),
        ],
        required_scope: "git.push:refs/heads/main".into(),
        reason: "Release the reviewed commit".into(),
    }
}

fn activate_command(id: &str, index: usize, activated_at: i64) -> ActivateGenerationCommand {
    ActivateGenerationCommand {
        generation: generation(id),
        event_id: format!("event_generation_{index}"),
        operator_principal: "uid:501".into(),
        reason: "Activate the reviewed immutable generation".into(),
        activated_at,
    }
}

fn maintenance_command(enabled: bool, index: usize, transitioned_at: i64) -> SetMaintenanceCommand {
    SetMaintenanceCommand {
        enabled,
        event_id: format!("event_maintenance_{index}"),
        operator_principal: "uid:501".into(),
        reason: "Perform a controlled authority transition".into(),
        transitioned_at,
    }
}

fn create_second_request(authority: &mut Authority, created_at: i64) {
    let mut command = request_command("request_2", "event_request_2");
    command.created_at = created_at;
    assert!(matches!(
        authority.create_or_get_request(&command).unwrap(),
        CreateRequestResult::Created(request) if request.request_id() == "request_2"
    ));
}

fn approve_second_request(authority: &mut Authority, resolved_at: i64) {
    let mut command = approve_command(2);
    command.request_id = "request_2".into();
    command.resolved_at = resolved_at;
    assert!(matches!(
        authority.approve(&command).unwrap(),
        ApproveResult::Approved { .. }
    ));
}

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
