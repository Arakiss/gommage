use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use gommage_core::{
    ActivateGenerationCommand, ApprovalRequestV2, ApproveCommand, ApproveResult, Authority,
    AuthorityConfig, AuthorityDecisionOutcomeV2, AuthorityError, AuthorityGenerationV2,
    AuthorityRuntimeSource, Capability, CapabilityProvenance, CapabilityProvenanceStatus,
    CommitDecisionCommandV2, CommittedDecisionV2, Decision, DenyCommand, DenyResult, EvalResult,
    FreshnessVerdict, GrantStatusV2, LedgerPayloadV2, MAX_CANONICAL_TOOL_CALL_BYTES,
    MAX_LEDGER_PAGE_ENTRIES, MatchedRule, PictoBinding, Policy, RevokeCommand, RevokeResult,
    RuleContribution, SetMaintenanceCommand, SignedGrantClaimV2, SignedGrantStateV2, SignedJcs,
    SignedLedgerCheckpointV2, SignedLedgerCursorV2, ToolCall, evaluate,
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

struct DefaultTestRuntimeSource;

struct CollidingDecisionRuntimeSource {
    identifiers: AtomicU64,
}

struct RejectRuntimeSource;

static NEXT_TEST_NONCE: AtomicU64 = AtomicU64::new(1);

impl AuthorityRuntimeSource for DefaultTestRuntimeSource {
    fn unix_timestamp(&self) -> Result<i64, AuthorityError> {
        Ok(1_700_000_030)
    }

    fn identifier_nonce(&self) -> Result<String, AuthorityError> {
        let nonce = NEXT_TEST_NONCE.fetch_add(1, Ordering::SeqCst);
        Ok(format!("test{nonce:016x}"))
    }
}

impl AuthorityRuntimeSource for CollidingDecisionRuntimeSource {
    fn unix_timestamp(&self) -> Result<i64, AuthorityError> {
        Ok(1_700_000_030)
    }

    fn identifier_nonce(&self) -> Result<String, AuthorityError> {
        match self.identifiers.fetch_add(1, Ordering::SeqCst) {
            0 => Ok("unique_state".into()),
            1 => Ok("collision".into()),
            _ => Err(AuthorityError::RuntimeSource(
                "unexpected extra identifier request".into(),
            )),
        }
    }
}

impl AuthorityRuntimeSource for RejectRuntimeSource {
    fn unix_timestamp(&self) -> Result<i64, AuthorityError> {
        Err(AuthorityError::RuntimeSource(
            "runtime source must not be consulted".into(),
        ))
    }

    fn identifier_nonce(&self) -> Result<String, AuthorityError> {
        Err(AuthorityError::RuntimeSource(
            "runtime source must not be consulted".into(),
        ))
    }
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
    open_with_source(path, config(), Arc::new(DefaultTestRuntimeSource))
}

fn try_open(path: &Path) -> Result<Authority, AuthorityError> {
    try_open_with_source(path, config(), Arc::new(DefaultTestRuntimeSource))
}

fn open_with_source(
    path: &Path,
    config: AuthorityConfig,
    runtime_source: Arc<dyn AuthorityRuntimeSource>,
) -> Authority {
    try_open_with_source(path, config, runtime_source).unwrap()
}

fn try_open_with_source(
    path: &Path,
    config: AuthorityConfig,
    runtime_source: Arc<dyn AuthorityRuntimeSource>,
) -> Result<Authority, AuthorityError> {
    let grant_key = grant_key();
    let ledger_key = ledger_key();
    let checkpoint = external_genesis_checkpoint(path, &config, &grant_key, &ledger_key);
    Authority::open_with_runtime_source(
        path,
        config,
        grant_key,
        ledger_key,
        checkpoint,
        runtime_source,
    )
}

fn external_genesis_checkpoint(
    path: &Path,
    config: &AuthorityConfig,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> SignedLedgerCheckpointV2 {
    if !path.exists() {
        return Authority::bootstrap(path, config, grant_key, ledger_key).unwrap();
    }
    let directory = tempfile::tempdir().unwrap();
    Authority::bootstrap(
        &directory.path().join("equivalent-authority.sqlite3"),
        config,
        grant_key,
        ledger_key,
    )
    .unwrap()
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
    resign_ledger_suffix(path, first_seq, |_, entry| {
        entry["build_identity"] = serde_json::json!(build_identity);
    });
}

fn resign_ledger_suffix(path: &Path, first_seq: i64, mut mutate: impl FnMut(i64, &mut Value)) {
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
        mutate(seq, &mut entry);
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

fn create_request(authority: &mut Authority) -> ApprovalRequestV2 {
    match authority.commit_decision(&authorize_command()).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => *request,
        other => panic!("expected a new Authority-owned request, got {other:?}"),
    }
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

fn approval_command(request: &ApprovalRequestV2, index: usize) -> ApproveCommand {
    let mut command = approve_command(index);
    command.request_id = request.request_id().into();
    command.resolved_at = request.created_at();
    command
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

fn approve(
    authority: &mut Authority,
    request: &ApprovalRequestV2,
) -> (SignedGrantClaimV2, SignedGrantStateV2) {
    match authority.approve(&approval_command(request, 1)).unwrap() {
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

fn observed_call() -> ToolCall {
    ToolCall {
        tool: "Bash".into(),
        input: json!({
            "command": "git push origin main",
            "timeout_ms": 120_000,
        }),
    }
}

fn resolved_evaluation(
    generation: &AuthorityGenerationV2,
    decision: Decision,
    capabilities: &[&str],
) -> EvalResult {
    let mut capabilities: Vec<Capability> = capabilities
        .iter()
        .map(|capability| Capability::new(*capability))
        .collect();
    capabilities.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    capabilities.dedup_by(|left, right| left.as_str() == right.as_str());
    let matched_rule = MatchedRule {
        name: "authority-test-rule".into(),
        file: "authority-test-policy.yaml".into(),
        index: 0,
    };
    let contribution = RuleContribution {
        layer: "inline".into(),
        layer_index: 0,
        file_index: 0,
        rule: matched_rule.clone(),
        decision: decision.clone(),
    };
    let capability_provenance = capabilities
        .iter()
        .cloned()
        .map(|capability| CapabilityProvenance {
            capability,
            status: CapabilityProvenanceStatus::Resolved,
            effective_decision: Some(decision.clone()),
            contributions: vec![contribution.clone()],
        })
        .collect();
    EvalResult {
        decision,
        matched_rule: Some(matched_rule),
        capabilities,
        policy_version: generation.policy_identity().into(),
        capability_provenance,
        authorization: None,
    }
}

fn ask_evaluation(generation: &AuthorityGenerationV2) -> EvalResult {
    resolved_evaluation(
        generation,
        Decision::AskPicto {
            required_scope: "git.push:refs/heads/main".into(),
            reason: "Release the reviewed commit".into(),
            bind_input: true,
        },
        &["git.push:refs/heads/main", "proc.exec:git"],
    )
}

fn authorize_command_for(generation: AuthorityGenerationV2) -> CommitDecisionCommandV2 {
    CommitDecisionCommandV2 {
        evaluation: ask_evaluation(&generation),
        evaluated_generation: generation,
        integration: "codex".into(),
        call: observed_call(),
    }
}

fn authorize_command() -> CommitDecisionCommandV2 {
    authorize_command_for(generation("1"))
}

fn consume_command(_index: usize) -> CommitDecisionCommandV2 {
    authorize_command()
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

fn create_second_request(authority: &mut Authority) -> ApprovalRequestV2 {
    let mut command = authorize_command();
    command.call.input["command"] = json!("git push origin second-review");
    match authority.commit_decision(&command).unwrap() {
        CommittedDecisionV2::ApprovalRequired {
            request,
            created: true,
            ..
        } => *request,
        other => panic!("expected a second Authority-owned request, got {other:?}"),
    }
}

fn approve_second_request(
    authority: &mut Authority,
    request: &ApprovalRequestV2,
    resolved_at: i64,
) {
    let mut command = approve_command(2);
    command.request_id = request.request_id().into();
    command.resolved_at = resolved_at;
    assert!(matches!(
        authority.approve(&command).unwrap(),
        ApproveResult::Approved { .. }
    ));
}

#[path = "authority_v2/concurrency.rs"]
mod concurrency;
#[path = "authority_v2/decisions.rs"]
mod decisions;
#[path = "authority_v2/lifecycle.rs"]
mod lifecycle;
#[path = "authority_v2/state.rs"]
mod state;
#[path = "authority_v2/tamper.rs"]
mod tamper;
