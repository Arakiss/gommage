use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use gommage_core::{
    ActivateGenerationCommand, ApproveCommand, ApproveResult, Authority, AuthorityConfig,
    AuthorityError, AuthorityGenerationV2, AuthorityRuntimeSource, AuthorizationContextV2,
    AuthorizeApprovalCommandV2, AuthorizeApprovalResultV2, ConsumeCommand, ConsumeResult,
    CreateRequestCommand, CreateRequestResult, DenyCommand, DenyResult, FreshnessVerdict,
    GrantNotUsableReason, GrantStatusV2, MAX_LEDGER_PAGE_ENTRIES, RevokeCommand, RevokeResult,
    SetMaintenanceCommand, SignedGrantClaimV2, SignedGrantStateV2, SignedJcs, SignedLedgerCursorV2,
    ToolCall,
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

#[path = "authority_v2/concurrency.rs"]
mod concurrency;
#[path = "authority_v2/lifecycle.rs"]
mod lifecycle;
#[path = "authority_v2/state.rs"]
mod state;
#[path = "authority_v2/tamper.rs"]
mod tamper;
