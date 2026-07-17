use super::*;

pub(super) fn query_strings(conn: &Connection, sql: &str) -> Result<Vec<String>, AuthorityError> {
    let mut statement = conn.prepare(sql)?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?)
}

pub(super) fn configure_connection(conn: &Connection) -> Result<(), AuthorityError> {
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

pub(super) fn verify_pragmas(conn: &Connection) -> Result<(), AuthorityError> {
    let journal: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i32 = conn.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let foreign_keys: i32 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let trusted_schema: i32 = conn.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let application_id: i32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || application_id != APPLICATION_ID
        || user_version != SCHEMA_VERSION
    {
        return Err(AuthorityError::Schema(format!(
            "unsafe pragmas: journal={journal}, synchronous={synchronous}, foreign_keys={foreign_keys}, trusted_schema={trusted_schema}, application_id={application_id}, user_version={user_version}"
        )));
    }
    Ok(())
}

pub(super) fn initialize_schema_in_transaction(
    conn: &Connection,
    config: &AuthorityConfig,
    grant_key_id: &str,
    ledger_key_id: &str,
    ledger_key: &SigningKey,
) -> Result<(), AuthorityError> {
    conn.pragma_update(None, "application_id", APPLICATION_ID)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    conn.execute_batch(SCHEMA_SQL)?;
    conn.execute(
        "INSERT INTO authority_meta (
            singleton, schema_version, instance_id, epoch, head_seq, head_hash,
            grant_key_id, ledger_key_id, genesis_generation_id, cutover_marker
         ) VALUES (1, ?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)",
        params![
            SCHEMA_VERSION,
            config.instance_id,
            config.epoch,
            ZERO_HASH,
            grant_key_id,
            ledger_key_id,
            config.genesis_generation.generation_id(),
            CUTOVER_MARKER,
        ],
    )?;
    insert_generation(
        conn,
        &config.genesis_generation,
        &config.genesis_event_id,
        config.genesis_at,
    )?;
    insert_runtime_state(
        conn,
        0,
        config.genesis_generation.generation_id(),
        false,
        &config.genesis_event_id,
        config.genesis_at,
    )?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id: config.genesis_event_id.clone(),
            subject: "authority".into(),
            timestamp: config.genesis_at,
            build_identity: Some(config.genesis_generation.build_identity().into()),
            policy_identity: Some(config.genesis_generation.policy_identity().into()),
            payload: LedgerPayloadV2::Genesis {
                instance_id: config.instance_id.clone(),
                epoch: config.epoch.clone(),
                schema_version: SCHEMA_VERSION as u8,
                grant_key_id: grant_key_id.into(),
                ledger_key_id: ledger_key_id.into(),
                semantic_version: env!("CARGO_PKG_VERSION").into(),
                generation: config.genesis_generation.clone(),
                cutover_marker: CUTOVER_MARKER.into(),
            },
        },
    )?;
    Ok(())
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE authority_meta (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version  INTEGER NOT NULL CHECK (schema_version = 2),
    instance_id     TEXT NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 160),
    epoch           TEXT NOT NULL CHECK (length(epoch) BETWEEN 1 AND 40),
    head_seq        INTEGER NOT NULL CHECK (head_seq >= 0),
    head_hash       TEXT NOT NULL CHECK (length(head_hash) = 71),
    grant_key_id    TEXT NOT NULL CHECK (length(grant_key_id) = 77),
    ledger_key_id   TEXT NOT NULL CHECK (length(ledger_key_id) = 78),
    genesis_generation_id TEXT NOT NULL CHECK (length(genesis_generation_id) BETWEEN 1 AND 40),
    cutover_marker  TEXT NOT NULL CHECK (cutover_marker = 'fresh_v2_no_legacy_active_grants')
) STRICT;

CREATE TABLE authority_generations (
    generation_id  TEXT PRIMARY KEY CHECK (length(generation_id) BETWEEN 1 AND 40),
    generation_jcs TEXT NOT NULL UNIQUE,
    event_id       TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    activated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE authority_runtime_states (
    revision        INTEGER PRIMARY KEY CHECK (revision >= 0),
    generation_id   TEXT NOT NULL REFERENCES authority_generations(generation_id),
    maintenance     INTEGER NOT NULL CHECK (maintenance IN (0, 1)),
    event_id        TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    transitioned_at INTEGER NOT NULL
) STRICT;

CREATE TABLE ledger_entries (
    seq             INTEGER PRIMARY KEY CHECK (seq > 0),
    event_id        TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    entry_jcs       TEXT NOT NULL,
    signature_b64   TEXT NOT NULL CHECK (length(signature_b64) = 86),
    entry_hash      TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 71)
) STRICT;

CREATE TABLE approval_requests (
    request_id      TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 160),
    dedupe_hash     TEXT NOT NULL CHECK (length(dedupe_hash) = 71),
    request_jcs     TEXT NOT NULL,
    request_hash    TEXT NOT NULL UNIQUE CHECK (length(request_hash) = 71),
    event_id        TEXT NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE open_approvals (
    dedupe_hash     TEXT PRIMARY KEY CHECK (length(dedupe_hash) = 71),
    request_id      TEXT NOT NULL UNIQUE REFERENCES approval_requests(request_id)
) STRICT;

CREATE TABLE approval_resolutions (
    request_id          TEXT PRIMARY KEY REFERENCES approval_requests(request_id),
    outcome             TEXT NOT NULL CHECK (outcome IN ('approved', 'denied')),
    operator_principal  TEXT NOT NULL CHECK (length(operator_principal) BETWEEN 1 AND 256),
    reason              TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    resolved_at         INTEGER NOT NULL,
    grant_id            TEXT UNIQUE,
    event_id            TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE grant_claims (
    grant_id        TEXT PRIMARY KEY CHECK (length(grant_id) BETWEEN 1 AND 160),
    request_id      TEXT NOT NULL UNIQUE REFERENCES approval_requests(request_id),
    claim_jcs       TEXT NOT NULL,
    signature_b64   TEXT NOT NULL CHECK (length(signature_b64) = 86),
    claim_hash      TEXT NOT NULL UNIQUE CHECK (length(claim_hash) = 71)
) STRICT;

CREATE TABLE grant_states (
    grant_id            TEXT NOT NULL REFERENCES grant_claims(grant_id),
    revision            INTEGER NOT NULL CHECK (revision IN (0, 1)),
    status              TEXT NOT NULL CHECK (status IN ('active', 'spent', 'revoked')),
    uses                INTEGER NOT NULL CHECK (uses IN (0, 1)),
    state_jcs           TEXT NOT NULL,
    signature_b64       TEXT NOT NULL CHECK (length(signature_b64) = 86),
    state_hash          TEXT NOT NULL UNIQUE CHECK (length(state_hash) = 71),
    transition_event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (grant_id, revision)
) STRICT;

CREATE INDEX approval_requests_dedupe_idx ON approval_requests(dedupe_hash);
CREATE INDEX grant_states_latest_idx ON grant_states(grant_id, revision DESC);

CREATE TRIGGER authority_generations_no_update BEFORE UPDATE ON authority_generations
BEGIN SELECT RAISE(ABORT, 'authority generations are immutable'); END;
CREATE TRIGGER authority_generations_no_delete BEFORE DELETE ON authority_generations
BEGIN SELECT RAISE(ABORT, 'authority generations are immutable'); END;
CREATE TRIGGER authority_runtime_states_no_update BEFORE UPDATE ON authority_runtime_states
BEGIN SELECT RAISE(ABORT, 'authority runtime states are append-only'); END;
CREATE TRIGGER authority_runtime_states_no_delete BEFORE DELETE ON authority_runtime_states
BEGIN SELECT RAISE(ABORT, 'authority runtime states are append-only'); END;

CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END;
CREATE TRIGGER ledger_entries_no_delete BEFORE DELETE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END;
CREATE TRIGGER approval_requests_no_update BEFORE UPDATE ON approval_requests
BEGIN SELECT RAISE(ABORT, 'approval requests are immutable'); END;
CREATE TRIGGER approval_requests_no_delete BEFORE DELETE ON approval_requests
BEGIN SELECT RAISE(ABORT, 'approval requests are immutable'); END;
CREATE TRIGGER approval_resolutions_no_update BEFORE UPDATE ON approval_resolutions
BEGIN SELECT RAISE(ABORT, 'approval resolutions are immutable'); END;
CREATE TRIGGER approval_resolutions_no_delete BEFORE DELETE ON approval_resolutions
BEGIN SELECT RAISE(ABORT, 'approval resolutions are immutable'); END;
CREATE TRIGGER grant_claims_no_update BEFORE UPDATE ON grant_claims
BEGIN SELECT RAISE(ABORT, 'grant claims are immutable'); END;
CREATE TRIGGER grant_claims_no_delete BEFORE DELETE ON grant_claims
BEGIN SELECT RAISE(ABORT, 'grant claims are immutable'); END;
CREATE TRIGGER grant_states_no_update BEFORE UPDATE ON grant_states
BEGIN SELECT RAISE(ABORT, 'grant states are append-only'); END;
CREATE TRIGGER grant_states_no_delete BEFORE DELETE ON grant_states
BEGIN SELECT RAISE(ABORT, 'grant states are append-only'); END;
"#;
