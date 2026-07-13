//! Picto store — signed, TTL'd, usage-bounded break-glass grants.
//!
//! A picto is **the only mechanism** that converts an `ask_picto` decision into
//! an `allow` at the daemon layer. Pictos are first-class citizens: if a picto
//! matches, the call passes. The only thing that can override a picto is the
//! hardcoded hardstop set (which is unbypassable by design).
//!
//! Pictos are signed with the daemon's ed25519 key so that a foreign process
//! cannot inject one via a tool-call payload.

use crate::error::GommageError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

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
}

#[derive(Debug, Clone)]
struct StoredPicto {
    picto: Picto,
    input_hash: Option<String>,
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
    fn signing_payload_for_input_hash(&self, input_hash: Option<&str>) -> Vec<u8> {
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

    /// Verify a legacy scope-only Picto signature.
    ///
    /// Approval-created Pictos with an input binding must be verified through
    /// [`PictoStore`], which reads the signed binding from the same SQLite row.
    /// This preserves verification of Pictos created before input binding
    /// existed.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), GommageError> {
        self.verify_for_input_hash(None, vk)
    }

    /// Verify a Picto signature with its optional canonical tool-call input
    /// hash binding.
    pub fn verify_for_input_hash(
        &self,
        input_hash: Option<&str>,
        vk: &VerifyingKey,
    ) -> Result<(), GommageError> {
        if input_hash.is_some_and(|hash| !is_canonical_input_hash(hash)) {
            return Err(GommageError::BadSignature);
        }
        let sig_bytes = base64_decode(&self.signature_b64)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| GommageError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&self.signing_payload_for_input_hash(input_hash), &sig)
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
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = PictoStore { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, GommageError> {
        let conn = Connection::open_in_memory()?;
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
        let mut statement = self.conn.prepare("PRAGMA table_info(pictos)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        if columns
            .filter_map(Result::ok)
            .any(|name| name == "input_hash")
        {
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
        if !(1..=86_400).contains(&ttl_seconds) {
            return Err(GommageError::InvalidPicto(
                "ttl must be between 1 and 86400 seconds".to_string(),
            ));
        }
        if input_hash.is_some_and(|hash| !is_canonical_input_hash(hash)) {
            return Err(GommageError::InvalidPicto(
                "input_hash must be a canonical sha256 ToolCall hash".to_string(),
            ));
        }

        let now = OffsetDateTime::now_utc();
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
        };
        let sig = signing_key.sign(&picto.signing_payload_for_input_hash(input_hash));
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
            .query_row("SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64 FROM pictos WHERE id = ?1", params![id], row_to_picto)
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
            r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64
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
            r#"SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64
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
                    row_to_stored_picto,
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
                    row_to_stored_picto,
                )
                .optional()?,
        };
        let Some(stored) = stored else {
            return Ok(PictoLookup::None);
        };
        if stored
            .picto
            .verify_for_input_hash(stored.input_hash.as_deref(), verifying_key)
            .is_ok()
        {
            return Ok(PictoLookup::Verified {
                picto: stored.picto,
            });
        }
        Ok(PictoLookup::BadSignature {
            id: stored.picto.id,
            scope: stored.picto.scope,
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
        let tx = self.conn.unchecked_transaction()?;
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
                    row_to_stored_picto,
                )
                .optional()?,
            None => tx
                .query_row(
                    query,
                    params![id, now.unix_timestamp()],
                    row_to_stored_picto,
                )
                .optional()?,
        };
        let Some(mut stored) = stored else {
            return Ok(PictoConsume::NotUsable);
        };
        if stored
            .picto
            .verify_for_input_hash(stored.input_hash.as_deref(), verifying_key)
            .is_err()
        {
            return Ok(PictoConsume::BadSignature {
                id: stored.picto.id,
                scope: stored.picto.scope,
            });
        }

        let new_uses = stored.picto.uses + 1;
        let new_status = if new_uses >= stored.picto.max_uses {
            PictoStatus::Spent
        } else {
            PictoStatus::Active
        };
        tx.execute(
            "UPDATE pictos SET uses = ?1, status = ?2 WHERE id = ?3",
            params![new_uses, status_str(new_status), id],
        )?;
        tx.commit()?;
        stored.picto.uses = new_uses;
        stored.picto.status = new_status;
        Ok(PictoConsume::Consumed {
            picto: stored.picto,
        })
    }

    /// Atomically burn one use from the picto. Returns `true` on success,
    /// `false` if the picto vanished / was revoked / exhausted in the meantime.
    pub fn consume(&self, id: &str) -> Result<bool, GommageError> {
        let tx = self.conn.unchecked_transaction()?;
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
        tx.execute(
            "UPDATE pictos SET uses = ?1, status = ?2 WHERE id = ?3",
            params![new_uses, new_status, id],
        )?;
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
    let mut stmt = conn.prepare(
        "SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64 FROM pictos ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], row_to_picto)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn row_to_picto(row: &rusqlite::Row<'_>) -> rusqlite::Result<Picto> {
    let status: String = row.get(6)?;
    let ttl: i64 = row.get(4)?;
    let created: i64 = row.get(5)?;
    Ok(Picto {
        id: row.get(0)?,
        scope: row.get(1)?,
        max_uses: row.get(2)?,
        uses: row.get(3)?,
        ttl_expires_at: OffsetDateTime::from_unix_timestamp(ttl)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        created_at: OffsetDateTime::from_unix_timestamp(created)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        status: parse_status(&status),
        reason: row.get(7)?,
        signature_b64: row.get(8)?,
    })
}

fn row_to_stored_picto(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredPicto> {
    Ok(StoredPicto {
        picto: row_to_picto(row)?,
        input_hash: row.get(9)?,
    })
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
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::fs;
    use tempfile::tempdir;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn input_hash(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn create_find_consume() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        let picto = store
            .create("p1", "git.push:main", 1, 600, "test", &sk, false)
            .unwrap();
        picto.verify(&sk.verifying_key()).unwrap();

        let found = store
            .find_match("git.push:main", OffsetDateTime::now_utc())
            .unwrap();
        assert!(found.is_some());
        assert!(store.consume("p1").unwrap());
        // second consume fails — use exhausted
        assert!(!store.consume("p1").unwrap());
        // after exhaustion, no match
        assert!(
            store
                .find_match("git.push:main", OffsetDateTime::now_utc())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_store_never_migrates_or_creates_sidecars() {
        let td = tempdir().unwrap();
        let path = td.path().join("pictos.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE pictos (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                uses INTEGER NOT NULL,
                ttl_expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                signature_b64 TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        drop(conn);
        let before = fs::read(&path).unwrap();

        let store = PictoReadStore::open(&path).unwrap();
        assert!(store.list().unwrap().is_empty());
        drop(store);

        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!path.with_extension("sqlite-wal").exists());
        assert!(!path.with_extension("sqlite-shm").exists());
    }

    #[test]
    fn verified_lookup_rejects_tampered_scope() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:feature", 1, 600, "test", &sk, false)
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE pictos SET scope = 'git.push:main' WHERE id = 'p1'",
                [],
            )
            .unwrap();

        let found = store
            .find_verified_match(
                "git.push:main",
                OffsetDateTime::now_utc(),
                &sk.verifying_key(),
            )
            .unwrap();
        assert!(matches!(found, PictoLookup::BadSignature { .. }));
    }

    #[test]
    fn verified_consume_rejects_tampered_scope() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:feature", 1, 600, "test", &sk, false)
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE pictos SET scope = 'git.push:main' WHERE id = 'p1'",
                [],
            )
            .unwrap();

        let consumed = store
            .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
            .unwrap();
        assert!(matches!(consumed, PictoConsume::BadSignature { .. }));
        assert_eq!(store.get("p1").unwrap().unwrap().uses, 0);
    }

    #[test]
    fn verified_consume_updates_uses_and_status() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:main", 1, 600, "test", &sk, false)
            .unwrap();

        let consumed = store
            .consume_verified("p1", OffsetDateTime::now_utc(), &sk.verifying_key())
            .unwrap();
        let PictoConsume::Consumed { picto } = consumed else {
            panic!("expected consumed picto");
        };
        assert_eq!(picto.uses, 1);
        assert_eq!(picto.status, PictoStatus::Spent);
        assert!(
            store
                .find_match("git.push:main", OffsetDateTime::now_utc())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn revoke_blocks_match() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:main", 2, 600, "x", &sk, false)
            .unwrap();
        assert!(store.revoke("p1").unwrap());
        assert!(
            store
                .find_match("git.push:main", OffsetDateTime::now_utc())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pending_confirmation_not_usable() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:main", 1, 600, "x", &sk, true)
            .unwrap();
        assert!(
            store
                .find_match("git.push:main", OffsetDateTime::now_utc())
                .unwrap()
                .is_none()
        );
        assert!(store.confirm("p1").unwrap());
        assert!(
            store
                .find_match("git.push:main", OffsetDateTime::now_utc())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn expired_ignored() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create("p1", "git.push:main", 1, 1, "x", &sk, false)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let now = OffsetDateTime::now_utc();
        store.sweep_expired(now).unwrap();
        assert!(store.find_match("git.push:main", now).unwrap().is_none());
    }

    #[test]
    fn signature_verifies_roundtrip() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        let picto = store.create("p1", "any", 1, 60, "r", &sk, false).unwrap();
        assert!(picto.verify(&sk.verifying_key()).is_ok());

        let wrong = SigningKey::generate(&mut OsRng);
        assert!(picto.verify(&wrong.verifying_key()).is_err());
    }

    #[test]
    fn input_bound_picto_matches_only_the_approved_input() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        let approved_input = input_hash('a');
        let other_input = input_hash('b');
        store
            .create_for_input(
                "p1",
                "deploy.production",
                &approved_input,
                1,
                600,
                "reviewed exact deployment",
                &sk,
                false,
            )
            .unwrap();

        assert!(matches!(
            store
                .find_verified_match_for_input(
                    "deploy.production",
                    &approved_input,
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoLookup::Verified { .. }
        ));
        assert!(matches!(
            store
                .find_verified_match_for_input(
                    "deploy.production",
                    &other_input,
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoLookup::None
        ));
        assert!(matches!(
            store
                .consume_verified_for_input(
                    "p1",
                    &other_input,
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoConsume::NotUsable
        ));
        assert_eq!(store.get("p1").unwrap().unwrap().uses, 0);

        assert!(matches!(
            store
                .consume_verified_for_input(
                    "p1",
                    &approved_input,
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoConsume::Consumed { .. }
        ));
    }

    #[test]
    fn input_binding_tampering_rejects_the_picto_signature() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        let approved_input = input_hash('a');
        let tampered_input = input_hash('b');
        store
            .create_for_input(
                "p1",
                "deploy.production",
                &approved_input,
                1,
                600,
                "reviewed exact deployment",
                &sk,
                false,
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE pictos SET input_hash = ?1 WHERE id = 'p1'",
                params![tampered_input],
            )
            .unwrap();

        assert!(matches!(
            store
                .find_verified_match_for_input(
                    "deploy.production",
                    &input_hash('b'),
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoLookup::BadSignature { .. }
        ));
    }

    #[test]
    fn scope_only_picto_cannot_satisfy_an_input_bound_lookup() {
        let store = PictoStore::open_in_memory().unwrap();
        let sk = key();
        store
            .create(
                "p1",
                "deploy.production",
                1,
                600,
                "explicit operator grant",
                &sk,
                false,
            )
            .unwrap();

        assert!(matches!(
            store
                .find_verified_match_for_input(
                    "deploy.production",
                    &input_hash('a'),
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoLookup::None
        ));
        assert!(matches!(
            store
                .find_verified_match(
                    "deploy.production",
                    OffsetDateTime::now_utc(),
                    &sk.verifying_key(),
                )
                .unwrap(),
            PictoLookup::Verified { .. }
        ));
    }

    #[test]
    fn opening_a_legacy_store_adds_the_input_hash_column() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pictos.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE pictos (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                uses INTEGER NOT NULL DEFAULT 0,
                ttl_expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                signature_b64 TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        drop(conn);

        let store = PictoStore::open(&path).unwrap();
        let mut statement = store.conn.prepare("PRAGMA table_info(pictos)").unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "input_hash"));
    }
}
