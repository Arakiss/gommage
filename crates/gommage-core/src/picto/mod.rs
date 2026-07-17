//! Picto store — signed, TTL'd, usage-bounded break-glass grants.
//!
//! A picto is **the only mechanism** that converts an `ask_picto` decision into
//! an `allow` at the daemon layer. Pictos are first-class citizens: if a picto
//! matches, the call passes. The only thing that can override a picto is the
//! hardcoded hardstop set (which is unbypassable by design).
//!
//! Pictos are signed with the daemon's ed25519 key so that a foreign process
//! cannot inject one via a tool-call payload.
//!
//! Picto v1 signs `id`, `scope`, `max_uses`, both timestamps, `reason`, and the
//! optional `input_hash`. `uses` and `status` remain mutable store state and
//! are not covered by that signature; binding them requires a transactional
//! protocol upgrade, not a compatible v1 encoding repair.

use crate::error::GommageError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use time::{OffsetDateTime, UtcOffset};

const MAX_PICTO_TTL_SECONDS: i64 = 86_400;
const MAX_PICTO_ID_BYTES: usize = 128;
const MAX_PICTO_SCOPE_BYTES: usize = 512;
const MAX_PICTO_REASON_BYTES: usize = 4 * 1024;
const ED25519_SIGNATURE_B64_BYTES: usize = 86;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PictoStatus {
    /// Created, ready to be consumed.
    Active,
    /// Created with `--require-confirmation`; awaiting human approval before first use.
    PendingConfirmation,
    /// All uses spent or explicitly revoked.
    Spent,
    Revoked,
    Expired,
}

impl PictoStatus {
    pub fn as_str(self) -> &'static str {
        status_str(self)
    }
}

/// The signed authority boundary carried by a Picto.
///
/// `ScopeOnly` is the legacy v1 shape. `ExactInput` appends the canonical
/// `ToolCall::input_hash` to the otherwise byte-identical v1 signing payload.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PictoBinding {
    /// Authorizes any matching call in the exact Picto scope.
    #[default]
    ScopeOnly,
    /// Authorizes only the exact canonical tool call whose hash was signed.
    ExactInput { input_hash: String },
}

impl PictoBinding {
    /// Return the canonical input hash when this Picto is exact-input bound.
    pub fn input_hash(&self) -> Option<&str> {
        match self {
            Self::ScopeOnly => None,
            Self::ExactInput { input_hash } => Some(input_hash),
        }
    }

    /// Whether this Picto is restricted to one canonical tool input.
    pub fn is_exact_input(&self) -> bool {
        matches!(self, Self::ExactInput { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Picto {
    pub id: String,
    pub scope: String,
    pub max_uses: u32,
    pub uses: u32,
    pub ttl_expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub status: PictoStatus,
    pub reason: String,
    pub signature_b64: String,
    /// Signed authority binding. Absent legacy JSON means scope-only.
    #[serde(default)]
    pub binding: PictoBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PictoLookup {
    None,
    Verified { picto: Picto },
    BadSignature { id: String, scope: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PictoConsume {
    Consumed { picto: Picto },
    NotUsable,
    BadSignature { id: String, scope: String },
}

impl Picto {
    /// Encode the legacy v1 signing payload after the caller has validated all
    /// fields with [`Self::validate_signing_fields`].
    ///
    /// Keeping the byte format stable preserves well-formed Pictos already on
    /// disk. The canonical field domain enforced at creation and verification
    /// makes the newline separators unambiguous.
    fn signing_payload_for_input_hash_unchecked(&self, input_hash: Option<&str>) -> Vec<u8> {
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.id,
            self.scope,
            self.max_uses,
            self.ttl_expires_at.unix_timestamp(),
            self.created_at.unix_timestamp(),
            self.reason,
        );
        match input_hash {
            Some(input_hash) => format!("{payload}\ninput_hash={input_hash}").into_bytes(),
            None => payload.into_bytes(),
        }
    }

    fn validate_signing_fields(&self, input_hash: Option<&str>) -> Result<(), String> {
        validate_picto_id(&self.id)?;
        validate_picto_scope(&self.scope)?;
        validate_picto_text_field("reason", &self.reason, true, MAX_PICTO_REASON_BYTES)?;

        if self.max_uses == 0 {
            return Err("max_uses must be greater than zero".to_string());
        }
        if self.created_at.offset() != UtcOffset::UTC
            || self.ttl_expires_at.offset() != UtcOffset::UTC
        {
            return Err("timestamps must use UTC".to_string());
        }
        if self.created_at.nanosecond() != 0 || self.ttl_expires_at.nanosecond() != 0 {
            return Err("timestamps must use whole seconds".to_string());
        }
        let lifetime = self
            .ttl_expires_at
            .unix_timestamp()
            .checked_sub(self.created_at.unix_timestamp())
            .ok_or_else(|| "picto lifetime is not representable".to_string())?;
        if !(1..=MAX_PICTO_TTL_SECONDS).contains(&lifetime) {
            return Err(format!(
                "ttl must be between 1 and {MAX_PICTO_TTL_SECONDS} seconds"
            ));
        }
        if input_hash.is_some_and(|hash| !is_canonical_input_hash(hash)) {
            return Err("input_hash must be a canonical sha256 ToolCall hash".to_string());
        }
        Ok(())
    }

    /// Verify this Picto against its visible signed binding.
    ///
    /// Legacy serialized Pictos omit `binding` and deserialize as scope-only,
    /// preserving their byte-identical v1 verification path.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), GommageError> {
        let input_hash = self.binding.input_hash();
        self.verify_binding_unchecked(input_hash, vk)
    }

    /// Verify that this Picto visibly carries the requested optional binding,
    /// then verify the signature over that binding.
    ///
    /// This compatibility method cannot reinterpret an exact-input Picto as a
    /// scope-only Picto, or vice versa.
    pub fn verify_for_input_hash(
        &self,
        input_hash: Option<&str>,
        vk: &VerifyingKey,
    ) -> Result<(), GommageError> {
        if self.binding.input_hash() != input_hash {
            return Err(GommageError::BadSignature);
        }
        self.verify_binding_unchecked(input_hash, vk)
    }

    fn verify_binding_unchecked(
        &self,
        input_hash: Option<&str>,
        vk: &VerifyingKey,
    ) -> Result<(), GommageError> {
        self.validate_signing_fields(input_hash)
            .map_err(|_| GommageError::BadSignature)?;
        if self.signature_b64.len() != ED25519_SIGNATURE_B64_BYTES {
            return Err(GommageError::BadSignature);
        }
        let sig_bytes = base64_decode(&self.signature_b64)?;
        if base64_encode(&sig_bytes) != self.signature_b64 {
            return Err(GommageError::BadSignature);
        }
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| GommageError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(
            &self.signing_payload_for_input_hash_unchecked(input_hash),
            &sig,
        )
        .map_err(|_| GommageError::BadSignature)
    }

    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.ttl_expires_at
    }

    /// A picto matches a required_scope iff the stored scope equals the requirement.
    /// In v0.1 we use exact scope equality — no globbing on the picto side. This
    /// is intentional: overly-broad pictos are a security smell.
    pub fn matches_scope(&self, required: &str) -> bool {
        self.scope == required
    }
}

pub struct PictoStore {
    conn: Connection,
}

/// Read-only access to an existing Picto database.
///
/// Unlike [`PictoStore::open`], this never changes SQLite journal settings,
/// runs migrations, or creates sidecar files. It is for diagnostics and
/// operator reporting only; authorization and mutation paths must use
/// [`PictoStore`].
pub struct PictoReadStore {
    conn: Connection,
}

impl PictoReadStore {
    /// Open an existing Picto database without allowing SQLite writes.
    pub fn open(path: &Path) -> Result<Self, GommageError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    pub fn list(&self) -> Result<Vec<Picto>, GommageError> {
        list_pictos(&self.conn)
    }
}

impl PictoStore {
    pub fn open(path: &Path) -> Result<Self, GommageError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = PictoStore { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, GommageError> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        let store = PictoStore { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), GommageError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS pictos (
                id              TEXT PRIMARY KEY,
                scope           TEXT NOT NULL,
                max_uses        INTEGER NOT NULL CHECK (max_uses > 0),
                uses            INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
                ttl_expires_at  INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                status          TEXT NOT NULL,
                reason          TEXT NOT NULL DEFAULT '',
                signature_b64   TEXT NOT NULL,
                input_hash      TEXT
            );
            CREATE INDEX IF NOT EXISTS pictos_scope_idx     ON pictos(scope);
            CREATE INDEX IF NOT EXISTS pictos_status_idx    ON pictos(status);
            CREATE INDEX IF NOT EXISTS pictos_expires_idx   ON pictos(ttl_expires_at);
            "#,
        )?;
        self.ensure_input_hash_column()?;
        Ok(())
    }

    fn ensure_input_hash_column(&self) -> Result<(), GommageError> {
        if has_input_hash_column(&self.conn)? {
            return Ok(());
        }
        self.conn
            .execute("ALTER TABLE pictos ADD COLUMN input_hash TEXT", [])?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        id: &str,
        scope: &str,
        max_uses: u32,
        ttl_seconds: i64,
        reason: &str,
        signing_key: &SigningKey,
        require_confirmation: bool,
    ) -> Result<Picto, GommageError> {
        self.create_with_input_hash(
            id,
            scope,
            None,
            max_uses,
            ttl_seconds,
            reason,
            signing_key,
            require_confirmation,
        )
    }

    /// Create a Picto that can only be consumed by a matching canonical
    /// `ToolCall::input_hash` as well as its exact scope.
    #[allow(clippy::too_many_arguments)]
    pub fn create_for_input(
        &self,
        id: &str,
        scope: &str,
        input_hash: &str,
        max_uses: u32,
        ttl_seconds: i64,
        reason: &str,
        signing_key: &SigningKey,
        require_confirmation: bool,
    ) -> Result<Picto, GommageError> {
        self.create_with_input_hash(
            id,
            scope,
            Some(input_hash),
            max_uses,
            ttl_seconds,
            reason,
            signing_key,
            require_confirmation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_with_input_hash(
        &self,
        id: &str,
        scope: &str,
        input_hash: Option<&str>,
        max_uses: u32,
        ttl_seconds: i64,
        reason: &str,
        signing_key: &SigningKey,
        require_confirmation: bool,
    ) -> Result<Picto, GommageError> {
        if max_uses == 0 {
            return Err(GommageError::InvalidPicto(
                "max_uses must be greater than zero".to_string(),
            ));
        }
        if !(1..=MAX_PICTO_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(GommageError::InvalidPicto(
                "ttl must be between 1 and 86400 seconds".to_string(),
            ));
        }

        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|error| GommageError::InvalidPicto(error.to_string()))?;
        let ttl_expires_at = now + time::Duration::seconds(ttl_seconds);
        let status = if require_confirmation {
            PictoStatus::PendingConfirmation
        } else {
            PictoStatus::Active
        };

        let mut picto = Picto {
            id: id.to_string(),
            scope: scope.to_string(),
            max_uses,
            uses: 0,
            ttl_expires_at,
            created_at: now,
            status,
            reason: reason.to_string(),
            signature_b64: String::new(),
            binding: input_hash.map_or(PictoBinding::ScopeOnly, |input_hash| {
                PictoBinding::ExactInput {
                    input_hash: input_hash.to_string(),
                }
            }),
        };
        picto
            .validate_signing_fields(input_hash)
            .map_err(GommageError::InvalidPicto)?;
        let sig = signing_key.sign(&picto.signing_payload_for_input_hash_unchecked(input_hash));
        picto.signature_b64 = base64_encode(sig.to_bytes().as_slice());

        self.conn.execute(
            r#"INSERT INTO pictos (id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash)
               VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            params![
                picto.id,
                picto.scope,
                picto.max_uses,
                picto.ttl_expires_at.unix_timestamp(),
                picto.created_at.unix_timestamp(),
                status_str(picto.status),
                picto.reason,
                picto.signature_b64,
                input_hash,
            ],
        )?;
        Ok(picto)
    }

    pub fn get(&self, id: &str) -> Result<Option<Picto>, GommageError> {
        Ok(self
            .conn
            .query_row("SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash FROM pictos WHERE id = ?1", params![id], row_to_picto)
            .optional()?)
    }

    pub fn list(&self) -> Result<Vec<Picto>, GommageError> {
        list_pictos(&self.conn)
    }

    pub fn revoke(&self, id: &str) -> Result<bool, GommageError> {
        let n = self.conn.execute(
            "UPDATE pictos SET status = 'revoked' WHERE id = ?1 AND status IN ('active', 'pending_confirmation')",
            params![id],
        )?;
        Ok(n > 0)
    }

    pub fn confirm(&self, id: &str) -> Result<bool, GommageError> {
        let n = self.conn.execute(
            "UPDATE pictos SET status = 'active' WHERE id = ?1 AND status = 'pending_confirmation'",
            params![id],
        )?;
        Ok(n > 0)
    }

    /// Find the newest currently-usable picto whose scope matches `required`.
    /// Does NOT consume it; call `consume` to burn a use.
    pub fn find_match(
        &self,
        required_scope: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Picto>, GommageError> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
               FROM pictos
               WHERE scope = ?1
                 AND status = 'active'
                 AND uses < max_uses
                 AND ttl_expires_at > ?2
                 AND input_hash IS NULL
               ORDER BY created_at DESC
               LIMIT 1"#,
        )?;
        Ok(stmt
            .query_row(params![required_scope, now.unix_timestamp()], row_to_picto)
            .optional()?)
    }

    /// Find a usable Picto for an exact canonical input hash.
    pub fn find_match_for_input(
        &self,
        required_scope: &str,
        input_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Picto>, GommageError> {
        if !is_canonical_input_hash(input_hash) {
            return Ok(None);
        }
        let mut statement = self.conn.prepare(
            r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
               FROM pictos
               WHERE scope = ?1
                 AND status = 'active'
                 AND uses < max_uses
                 AND ttl_expires_at > ?2
                 AND input_hash = ?3
               ORDER BY created_at DESC
               LIMIT 1"#,
        )?;
        Ok(statement
            .query_row(
                params![required_scope, now.unix_timestamp(), input_hash],
                row_to_picto,
            )
            .optional()?)
    }

    /// Find the newest usable picto and verify its signature before returning it.
    /// A bad signature is returned explicitly so callers can audit the rejection
    /// while preserving the original `ask_picto` decision.
    pub fn find_verified_match(
        &self,
        required_scope: &str,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoLookup, GommageError> {
        self.find_verified_match_for_optional_input(required_scope, None, now, verifying_key)
    }

    /// Find a signature-verified Picto that matches both exact scope and the
    /// canonical `ToolCall::input_hash`.
    pub fn find_verified_match_for_input(
        &self,
        required_scope: &str,
        input_hash: &str,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoLookup, GommageError> {
        if !is_canonical_input_hash(input_hash) {
            return Ok(PictoLookup::None);
        }
        self.find_verified_match_for_optional_input(
            required_scope,
            Some(input_hash),
            now,
            verifying_key,
        )
    }

    fn find_verified_match_for_optional_input(
        &self,
        required_scope: &str,
        input_hash: Option<&str>,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoLookup, GommageError> {
        let stored = match input_hash {
            Some(input_hash) => self
                .conn
                .query_row(
                    r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
                       FROM pictos
                       WHERE scope = ?1
                         AND status = 'active'
                         AND uses < max_uses
                         AND ttl_expires_at > ?2
                         AND input_hash = ?3
                       ORDER BY created_at DESC
                       LIMIT 1"#,
                    params![required_scope, now.unix_timestamp(), input_hash],
                    row_to_picto,
                )
                .optional()?,
            None => self
                .conn
                .query_row(
                    r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
                       FROM pictos
                       WHERE scope = ?1
                         AND status = 'active'
                         AND uses < max_uses
                         AND ttl_expires_at > ?2
                         AND input_hash IS NULL
                       ORDER BY created_at DESC
                       LIMIT 1"#,
                    params![required_scope, now.unix_timestamp()],
                    row_to_picto,
                )
                .optional()?,
        };
        let Some(picto) = stored else {
            return Ok(PictoLookup::None);
        };
        if picto.verify(verifying_key).is_ok() {
            return Ok(PictoLookup::Verified { picto });
        }
        Ok(PictoLookup::BadSignature {
            id: picto.id,
            scope: picto.scope,
        })
    }

    /// Atomically consume a legacy scope-only Picto after verifying its
    /// signature. Input-bound Pictos require [`Self::consume_verified_for_input`].
    pub fn consume_verified(
        &self,
        id: &str,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoConsume, GommageError> {
        self.consume_verified_for_optional_input(id, None, now, verifying_key)
    }

    /// Atomically consume a Picto only when its signed input binding equals
    /// `input_hash`.
    pub fn consume_verified_for_input(
        &self,
        id: &str,
        input_hash: &str,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoConsume, GommageError> {
        if !is_canonical_input_hash(input_hash) {
            return Ok(PictoConsume::NotUsable);
        }
        self.consume_verified_for_optional_input(id, Some(input_hash), now, verifying_key)
    }

    fn consume_verified_for_optional_input(
        &self,
        id: &str,
        input_hash: Option<&str>,
        now: OffsetDateTime,
        verifying_key: &VerifyingKey,
    ) -> Result<PictoConsume, GommageError> {
        // Reserve the writer slot before reading mutable usage state. A
        // deferred transaction permits concurrent readers to observe the same
        // remaining use; BEGIN IMMEDIATE linearizes the security transition.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let query = match input_hash {
            Some(_) => {
                r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
                   FROM pictos
                   WHERE id = ?1
                     AND status = 'active'
                     AND uses < max_uses
                     AND ttl_expires_at > ?2
                     AND input_hash = ?3"#
            }
            None => {
                r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash
                   FROM pictos
                   WHERE id = ?1
                     AND status = 'active'
                     AND uses < max_uses
                     AND ttl_expires_at > ?2
                     AND input_hash IS NULL"#
            }
        };
        let stored = match input_hash {
            Some(input_hash) => tx
                .query_row(
                    query,
                    params![id, now.unix_timestamp(), input_hash],
                    row_to_picto,
                )
                .optional()?,
            None => tx
                .query_row(query, params![id, now.unix_timestamp()], row_to_picto)
                .optional()?,
        };
        let Some(mut picto) = stored else {
            return Ok(PictoConsume::NotUsable);
        };
        if picto.verify(verifying_key).is_err() {
            return Ok(PictoConsume::BadSignature {
                id: picto.id,
                scope: picto.scope,
            });
        }

        let new_uses = picto.uses + 1;
        let new_status = if new_uses >= picto.max_uses {
            PictoStatus::Spent
        } else {
            PictoStatus::Active
        };
        let updated = match input_hash {
            Some(input_hash) => tx.execute(
                r#"UPDATE pictos
                   SET uses = ?1, status = ?2
                   WHERE id = ?3
                     AND uses = ?4
                     AND status = 'active'
                     AND uses < max_uses
                     AND ttl_expires_at > ?5
                     AND input_hash = ?6"#,
                params![
                    new_uses,
                    status_str(new_status),
                    id,
                    picto.uses,
                    now.unix_timestamp(),
                    input_hash,
                ],
            )?,
            None => tx.execute(
                r#"UPDATE pictos
                   SET uses = ?1, status = ?2
                   WHERE id = ?3
                     AND uses = ?4
                     AND status = 'active'
                     AND uses < max_uses
                     AND ttl_expires_at > ?5
                     AND input_hash IS NULL"#,
                params![
                    new_uses,
                    status_str(new_status),
                    id,
                    picto.uses,
                    now.unix_timestamp(),
                ],
            )?,
        };
        if updated != 1 {
            return Ok(PictoConsume::NotUsable);
        }
        tx.commit()?;
        picto.uses = new_uses;
        picto.status = new_status;
        Ok(PictoConsume::Consumed { picto })
    }

    /// Atomically burn one use from the picto. Returns `true` on success,
    /// `false` if the picto vanished / was revoked / exhausted in the meantime.
    pub fn consume(&self, id: &str) -> Result<bool, GommageError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                "SELECT max_uses, uses FROM pictos WHERE id = ?1 AND status = 'active'",
                params![id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)),
            )
            .optional()?;
        let Some((max_uses, uses)) = row else {
            return Ok(false);
        };
        if uses >= max_uses {
            return Ok(false);
        }
        let new_uses = uses + 1;
        let new_status = if new_uses >= max_uses {
            "spent"
        } else {
            "active"
        };
        let updated = tx.execute(
            r#"UPDATE pictos
               SET uses = ?1, status = ?2
               WHERE id = ?3 AND uses = ?4 AND status = 'active' AND uses < max_uses"#,
            params![new_uses, new_status, id, uses],
        )?;
        if updated != 1 {
            return Ok(false);
        }
        tx.commit()?;
        Ok(true)
    }

    /// Mark all expired pictos as expired. Call periodically or on daemon start.
    pub fn sweep_expired(&self, now: OffsetDateTime) -> Result<usize, GommageError> {
        let n = self.conn.execute(
            "UPDATE pictos SET status = 'expired' WHERE status IN ('active', 'pending_confirmation') AND ttl_expires_at <= ?1",
            params![now.unix_timestamp()],
        )?;
        Ok(n)
    }
}

fn list_pictos(conn: &Connection) -> Result<Vec<Picto>, GommageError> {
    let query = if has_input_hash_column(conn)? {
        "SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, input_hash FROM pictos ORDER BY created_at"
    } else {
        "SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64, NULL AS input_hash FROM pictos ORDER BY created_at"
    };
    let mut stmt = conn.prepare(query)?;
    let rows = stmt.query_map([], row_to_picto)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn has_input_hash_column(conn: &Connection) -> Result<bool, GommageError> {
    let mut statement = conn.prepare("PRAGMA table_info(pictos)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    Ok(columns
        .filter_map(Result::ok)
        .any(|name| name == "input_hash"))
}

fn row_to_picto(row: &rusqlite::Row<'_>) -> rusqlite::Result<Picto> {
    let status: String = row.get(6)?;
    let ttl: i64 = row.get(4)?;
    let created: i64 = row.get(5)?;
    let input_hash: Option<String> = row.get(9)?;
    Ok(Picto {
        id: row.get(0)?,
        scope: row.get(1)?,
        max_uses: row.get(2)?,
        uses: row.get(3)?,
        ttl_expires_at: timestamp_from_sql(ttl, 4)?,
        created_at: timestamp_from_sql(created, 5)?,
        status: parse_status(&status),
        reason: row.get(7)?,
        signature_b64: row.get(8)?,
        binding: input_hash.map_or(PictoBinding::ScopeOnly, |input_hash| {
            PictoBinding::ExactInput { input_hash }
        }),
    })
}

fn timestamp_from_sql(value: i64, column: usize) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn validate_picto_id(value: &str) -> Result<(), String> {
    validate_picto_visible_ascii("id", value, MAX_PICTO_ID_BYTES)
}

pub(crate) fn validate_picto_scope(value: &str) -> Result<(), String> {
    validate_picto_visible_ascii("scope", value, MAX_PICTO_SCOPE_BYTES)
}

fn validate_picto_visible_ascii(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    validate_picto_text_field(field, value, false, max_bytes)?;
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{field} must contain only visible ASCII bytes 0x21..=0x7e"
        ));
    }
    Ok(())
}

fn validate_picto_text_field(
    field: &str,
    value: &str,
    allow_empty: bool,
    max_bytes: usize,
) -> Result<(), String> {
    if !allow_empty && value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("{field} must not exceed {max_bytes} bytes"));
    }
    if let Some(character) = value.chars().find(|character| {
        character.is_control()
            || matches!(character, '\u{2028}' | '\u{2029}')
            || is_bidi_control(*character)
    }) {
        return Err(format!(
            "{field} contains forbidden control, line-separator, or bidirectional control character U+{:04X}",
            character as u32
        ));
    }
    Ok(())
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn is_canonical_input_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn status_str(s: PictoStatus) -> &'static str {
    match s {
        PictoStatus::Active => "active",
        PictoStatus::PendingConfirmation => "pending_confirmation",
        PictoStatus::Spent => "spent",
        PictoStatus::Revoked => "revoked",
        PictoStatus::Expired => "expired",
    }
}

fn parse_status(s: &str) -> PictoStatus {
    match s {
        "active" => PictoStatus::Active,
        "pending_confirmation" => PictoStatus::PendingConfirmation,
        "spent" => PictoStatus::Spent,
        "revoked" => PictoStatus::Revoked,
        "expired" => PictoStatus::Expired,
        _ => PictoStatus::Revoked,
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, GommageError> {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| GommageError::BadSignature)
}

#[cfg(test)]
mod tests;
