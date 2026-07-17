//! Transactional Authority v2 for the reference security profile.
//!
//! One SQLite writer boundary owns the active release/policy/mapper/protocol
//! generation, fail-closed maintenance, approval deduplication, exact single-use
//! grants, state transitions, and signed decision evidence. Every mutation is
//! serialized by `BEGIN IMMEDIATE` and returns an authorization result only after
//! the corresponding state and ledger entries commit.

use crate::{
    crypto_envelope::{
        CryptoEnvelopeError, EnvelopeDomain, KeyBound, KeyPurpose, SignedJcs, approval_dedupe_hash,
        approval_request_hash, canonicalize, decode_canonical, key_id, ledger_entry_hash,
        sign_payload, signature_bytes, verify_payload,
    },
    grant_v2::{
        GrantClaimFields, GrantClaimV2, GrantStateV2, GrantStatusV2, GrantV2Error,
        MAX_GRANT_TTL_SECONDS, SignedGrantClaimV2, SignedGrantStateV2, validate_decimal,
        validate_hash, validate_text, validate_token,
    },
    picto::PictoBinding,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    path::Path,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const APPLICATION_ID: i32 = 0x474f_4d32; // ASCII "GOM2".
const SCHEMA_VERSION: i32 = 2;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const REQUEST_DOMAIN: &str = "gommage.approval.request";
const GENERATION_DOMAIN: &str = "gommage.authority.generation";
const LEDGER_DOMAIN: &str = "gommage.ledger.entry";
const CHECKPOINT_DOMAIN: &str = "gommage.ledger.checkpoint";
const CURSOR_DOMAIN: &str = "gommage.ledger.cursor";
const GENESIS_CHECKPOINT_ID: &str = "genesis";
const FORMAT_VERSION: u8 = 2;
const MAX_INTEGRATION_BYTES: usize = 128;
const MAX_TOOL_BYTES: usize = 256;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_CAPABILITY_BYTES: usize = 1_024;
const MAX_CAPABILITIES: usize = 512;
/// Maximum number of verified ledger entries returned by one online page.
pub const MAX_LEDGER_PAGE_ENTRIES: usize = 100;
const CUTOVER_MARKER: &str = "fresh_v2_no_legacy_active_grants";

mod approvals;
mod common;
mod decision_types;
mod decision_verify;
mod decisions;
mod grants;
mod ledger_store;
mod ledger_types;
mod model;
mod ops;
mod schema;
mod state;
mod verify;

pub use decision_types::*;
pub use ledger_types::*;
pub use model::*;

use approvals::*;
use common::*;
use decision_verify::*;
use grants::*;
use ledger_store::*;
use schema::*;
use state::*;
use verify::*;

#[cfg(test)]
mod tests;

/// Integrity, schema, cryptographic, and invalid-command failures.
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// SQLite failed or rejected a constrained write.
    #[error("sqlite authority error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Canonical envelope parsing or signature verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoEnvelopeError),
    /// Grant claim/state validation or verification failed.
    #[error(transparent)]
    Grant(#[from] GrantV2Error),
    /// A caller command violates the bounded Authority v2 contract.
    #[error("invalid authority input: {0}")]
    InvalidInput(String),
    /// Stored rows, hashes, signatures, or links are inconsistent.
    #[error("authority integrity failure: {0}")]
    Corrupt(String),
    /// The database predates or contradicts a trusted external checkpoint.
    #[error("authority rollback detected: {0}")]
    RollbackDetected(String),
    /// The file is not the supported Authority v2 schema.
    #[error("unsupported authority schema: {0}")]
    Schema(String),
    /// A decision was evaluated against a generation that is no longer active.
    #[error(
        "stale authority generation: evaluated {evaluated_generation_id}, active {active_generation_id}"
    )]
    StaleGeneration {
        /// Generation declared by the decision.
        evaluated_generation_id: String,
        /// Generation active at the serialized admission point.
        active_generation_id: String,
    },
    /// Decision admission is disabled by authoritative maintenance state.
    #[error("authority decisions are disabled during maintenance")]
    Maintenance,
    /// Trusted runtime time or identifier generation failed closed.
    #[error("authority runtime source failure: {0}")]
    RuntimeSource(String),
}

/// Trusted source of wall-clock time and unique identifier entropy for Authority.
///
/// The source is selected only when the authority is opened. Runtime callers do
/// not receive it and cannot supply timestamps or evidence identifiers per call.
pub trait AuthorityRuntimeSource: Send + Sync {
    /// Return the current Unix timestamp in whole seconds.
    fn unix_timestamp(&self) -> Result<i64, AuthorityError>;

    /// Return one unique, token-safe nonce without a semantic prefix.
    fn identifier_nonce(&self) -> Result<String, AuthorityError>;
}

/// Operating-system runtime source used by [`Authority::open`].
#[derive(Debug, Default)]
pub struct SystemAuthorityRuntimeSource;

impl AuthorityRuntimeSource for SystemAuthorityRuntimeSource {
    fn unix_timestamp(&self) -> Result<i64, AuthorityError> {
        Ok(OffsetDateTime::now_utc().unix_timestamp())
    }

    fn identifier_nonce(&self) -> Result<String, AuthorityError> {
        Ok(Uuid::now_v7().simple().to_string())
    }
}

/// File-backed reference-profile authorization authority.
///
/// Every mutation verifies the full signed history before writing, so mutation
/// cost is linear in ledger length. This favors a simple fail-closed reference
/// boundary; long-lived deployments should benchmark and later add verified
/// checkpoints or incremental proof caching without weakening the invariant.
///
/// Approval requests have no public construction command; they are created
/// only as part of [`Authority::commit_decision`].
///
/// ```compile_fail
/// use gommage_core::CreateRequestCommand;
/// ```
pub struct Authority {
    conn: Connection,
    config: AuthorityConfig,
    grant_key: SigningKey,
    ledger_key: SigningKey,
    grant_key_id: String,
    ledger_key_id: String,
    retained_checkpoint: SignedLedgerCheckpointV2,
    runtime_source: Arc<dyn AuthorityRuntimeSource>,
}

impl Authority {
    /// Create a new Authority v2 database and return its signed genesis checkpoint.
    ///
    /// Bootstrap never returns a usable Authority. The caller must durably retain
    /// the returned checkpoint outside the database before calling [`Authority::open`].
    /// Existing databases are rejected so bootstrap cannot mint a replacement
    /// trust root for rolled-back state.
    pub fn bootstrap(
        path: &Path,
        config: &AuthorityConfig,
        grant_key: &SigningKey,
        ledger_key: &SigningKey,
    ) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
        validate_authority_inputs(path, config, grant_key, ledger_key)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                AuthorityError::InvalidInput(format!(
                    "bootstrap requires a new authority database path: {error}"
                ))
            })?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        // Failure after exclusive creation intentionally leaves the file in
        // place. Bootstrap never removes a path because it cannot safely prove
        // pathname identity after handing it to SQLite.
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        let current_application_id: i32 =
            conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let current_user_version: i32 =
            conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current_application_id != 0 || current_user_version != 0 {
            return Err(AuthorityError::Schema(
                "bootstrap path changed before schema initialization".into(),
            ));
        }
        initialize_schema(&mut conn, config, &grant_key_id, &ledger_key_id, ledger_key)?;
        let verification = verify_all(
            &conn,
            config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            None,
        )?;
        sign_checkpoint(
            config,
            &ledger_key_id,
            ledger_key,
            GENESIS_CHECKPOINT_ID,
            config.genesis_at,
            verification.head_seq,
            verification.head_hash,
        )
    }

    /// Open an initialized file-backed Authority v2 database under an external checkpoint.
    ///
    /// Keys, paths, and the externally retained checkpoint are supplied by the
    /// managed control plane; the core never infers filesystem ownership or
    /// permits an unanchored runtime Authority.
    pub fn open(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        retained_checkpoint: SignedLedgerCheckpointV2,
    ) -> Result<Self, AuthorityError> {
        Self::open_with_runtime_source(
            path,
            config,
            grant_key,
            ledger_key,
            retained_checkpoint,
            Arc::new(SystemAuthorityRuntimeSource),
        )
    }

    /// Open Authority with an explicitly selected trusted runtime source.
    ///
    /// This is a control-plane trust boundary intended for managed runtimes and
    /// deterministic tests. Untrusted IPC clients must never select this source.
    pub fn open_with_runtime_source(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        retained_checkpoint: SignedLedgerCheckpointV2,
        runtime_source: Arc<dyn AuthorityRuntimeSource>,
    ) -> Result<Self, AuthorityError> {
        validate_authority_inputs(path, &config, &grant_key, &ledger_key)?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        let current_application_id: i32 =
            conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let current_user_version: i32 =
            conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current_application_id != APPLICATION_ID || current_user_version != SCHEMA_VERSION {
            return Err(AuthorityError::Schema(format!(
                "expected application_id {APPLICATION_ID} and user_version {SCHEMA_VERSION}, got {current_application_id} and {current_user_version}"
            )));
        }
        let authority = Self {
            conn,
            config,
            grant_key,
            ledger_key,
            grant_key_id,
            ledger_key_id,
            retained_checkpoint,
            runtime_source,
        };
        authority.verify_metadata()?;
        authority.verify_ledger()?;
        Ok(authority)
    }

    /// Return verified schema, key, instance, and migration-boundary metadata.
    pub fn metadata(&self) -> Result<AuthorityMetadata, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            Some(&self.retained_checkpoint),
        )?;
        let metadata = read_metadata(&tx)?;
        tx.commit()?;
        Ok(metadata)
    }

    fn verify_metadata(&self) -> Result<(), AuthorityError> {
        verify_pragmas(&self.conn)?;
        let metadata = read_metadata(&self.conn)?;
        if metadata.instance_id != self.config.instance_id
            || metadata.epoch != self.config.epoch
            || metadata.genesis_generation != self.config.genesis_generation
            || metadata.grant_key_id != self.grant_key_id
            || metadata.ledger_key_id != self.ledger_key_id
            || metadata.cutover != CutoverStateV2::FreshV2NoLegacyActiveGrants
        {
            return Err(AuthorityError::Corrupt(
                "opened metadata does not match supplied instance, build, cutover, or keys".into(),
            ));
        }
        Ok(())
    }
}

fn validate_authority_inputs(
    path: &Path,
    config: &AuthorityConfig,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> Result<(), AuthorityError> {
    config.validate()?;
    let path_text = path.to_string_lossy();
    if path.as_os_str().is_empty() || path_text == ":memory:" || path_text.starts_with("file:") {
        return Err(AuthorityError::InvalidInput(
            "reference authority requires a regular file path".into(),
        ));
    }
    if grant_key.verifying_key() == ledger_key.verifying_key() {
        return Err(AuthorityError::InvalidInput(
            "grant and ledger keys must be distinct".into(),
        ));
    }
    Ok(())
}
