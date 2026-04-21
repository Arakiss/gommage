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
use rusqlite::{Connection, OptionalExtension, params};
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

impl Picto {
    /// Canonical bytes for signing: `{id}\n{scope}\n{max_uses}\n{ttl}\n{created_at}\n{reason}`.
    fn signing_payload(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.id,
            self.scope,
            self.max_uses,
            self.ttl_expires_at.unix_timestamp(),
            self.created_at.unix_timestamp(),
            self.reason,
        )
        .into_bytes()
    }

    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), GommageError> {
        let sig_bytes = base64_decode(&self.signature_b64)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| GommageError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&self.signing_payload(), &sig)
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
                signature_b64   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS pictos_scope_idx     ON pictos(scope);
            CREATE INDEX IF NOT EXISTS pictos_status_idx    ON pictos(status);
            CREATE INDEX IF NOT EXISTS pictos_expires_idx   ON pictos(ttl_expires_at);
            "#,
        )?;
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
        assert!(max_uses > 0, "max_uses must be > 0");
        assert!(
            ttl_seconds > 0 && ttl_seconds <= 86_400,
            "ttl must be in (0, 86400] seconds"
        );

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
        let sig = signing_key.sign(&picto.signing_payload());
        picto.signature_b64 = base64_encode(sig.to_bytes().as_slice());

        self.conn.execute(
            r#"INSERT INTO pictos (id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64)
               VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                picto.id,
                picto.scope,
                picto.max_uses,
                picto.ttl_expires_at.unix_timestamp(),
                picto.created_at.unix_timestamp(),
                status_str(picto.status),
                picto.reason,
                picto.signature_b64,
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
        let mut stmt = self.conn.prepare(
            "SELECT id, scope, max_uses, uses, ttl_expires_at, created_at, status, reason, signature_b64 FROM pictos ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], row_to_picto)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
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
               ORDER BY created_at DESC
               LIMIT 1"#,
        )?;
        Ok(stmt
            .query_row(params![required_scope, now.unix_timestamp()], row_to_picto)
            .optional()?)
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

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
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
}
