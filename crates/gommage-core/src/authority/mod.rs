//! Transactional Authority v2 for the reference security profile.
//!
//! One SQLite writer boundary owns the active release/policy/mapper/protocol
//! generation, fail-closed maintenance, approval deduplication, exact single-use
//! grants, state transitions, and signed decision evidence. Every mutation is
//! serialized by `BEGIN IMMEDIATE` and returns an authorization result only after
//! the corresponding state and ledger entries commit and their exact head
//! checkpoint is durably promoted.

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
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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
mod recovery;
mod retained_commit;
mod retention;
mod schema;
mod state;
mod storage;
mod verify;

pub use decision_types::*;
pub use ledger_types::*;
pub use model::*;
pub use retention::*;

use approvals::*;
use common::*;
use decision_verify::*;
use grants::*;
use ledger_store::*;
use retained_commit::*;
use schema::*;
use state::*;
use storage::*;
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
    /// The database predates or contradicts a durably retained checkpoint.
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
    /// Durable checkpoint retention failed with bounded operation context.
    #[error("checkpoint retention {operation} failed: {outcome}")]
    Retention {
        /// Retention operation that failed.
        operation: CheckpointRetentionOperationV2,
        /// Whether the failure guarantees no effects or has an unknown outcome.
        outcome: CheckpointRetentionErrorV2,
    },
    /// SQLite commit outcome cannot be proven and the live instance is fail-stop.
    #[error("authority commit outcome is indeterminate; instance is poisoned")]
    CommitOutcomeIndeterminate,
    /// Recovery state cannot be reconciled without operator intervention.
    #[error("authority recovery is ambiguous: {0}")]
    RecoveryAmbiguous(String),
    /// The live instance encountered an indeterminate retention/commit outcome.
    #[error("authority instance is poisoned")]
    Poisoned,
    /// Authority storage ownership, permissions, or pathname identity is unsafe.
    #[error("authority storage failure: {0}")]
    Storage(String),
    /// Another cooperative process owns the Authority writer lock.
    #[error("another authority writer already owns this database")]
    WriterBusy,
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

/// Operating-system runtime source used by Authority bootstrap and open.
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
/// One stable sibling lock file is held for the complete lifetime of an
/// Authority, so cooperative callers cannot open a second writer for the same
/// database. The database and lock must be regular, single-link, mode-0600
/// files owned by the effective UID inside a directory that is not group- or
/// world-writable. SQLite is opened without following the final path component,
/// and every operation verifies the retained database, directory, and lock
/// identities before returning. The stable lock file is intentionally never
/// unlinked.
///
/// These checks do not claim isolation from a hostile process running as the
/// same UID with write access to the database directory. That boundary requires
/// a separately protected service identity or operating-system sandbox.
///
/// Every mutation verifies the full signed history before writing, so mutation
/// cost is linear in ledger length. This favors a simple fail-closed reference
/// boundary; long-lived deployments should benchmark incremental proof caching
/// without weakening exact durable checkpoint retention.
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
    active_checkpoint: SignedLedgerCheckpointV2,
    retention: Box<dyn CheckpointRetentionV2>,
    health: AuthorityHealthV2,
    runtime_source: Arc<dyn AuthorityRuntimeSource>,
    // Must remain last: the SQLite connection and every other field drop before
    // the stable writer lock held by this guard.
    storage: AuthorityStorageGuard,
}

impl Authority {
    /// Return verified schema, key, instance, and migration-boundary metadata.
    pub fn metadata(&self) -> Result<AuthorityMetadata, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let metadata = read_metadata(&tx)?;
        tx.commit()?;
        self.storage.verify()?;
        Ok(metadata)
    }
}
