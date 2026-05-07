use anyhow::{Context, Result, bail};
use clap::Subcommand;
use gommage_audit::{
    Anomaly, AuditEntry, AuditEvent, AuditEventEntry, AuditStreamItem, explain_log,
};
use gommage_core::{Decision, runtime::HomeLayout};
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::ExitCode,
    time::UNIX_EPOCH,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const SCHEMA_VERSION: i64 = 1;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Subcommand)]
pub(crate) enum StateCmd {
    /// Rebuild state.sqlite from the signed JSONL audit ledger.
    Rebuild {
        /// Emit a stable machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Verify whether state.sqlite matches the current audit ledger.
    Verify {
        /// Emit a stable machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Show indexed audit counters from state.sqlite.
    Stats {
        /// Emit a stable machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Vacuum state.sqlite.
    Vacuum,
    /// Remove state.sqlite. The signed audit ledger is not touched.
    Reset {
        /// Show the deletion without removing the file.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct StateCounters {
    pub(crate) audit_entries: usize,
    pub(crate) decisions: usize,
    pub(crate) events: usize,
    pub(crate) allows: usize,
    pub(crate) asks: usize,
    pub(crate) denies: usize,
    pub(crate) hard_stops: usize,
    pub(crate) approval_requests: usize,
    pub(crate) approval_resolutions: usize,
    pub(crate) picto_creations: usize,
    pub(crate) picto_consumptions: usize,
    pub(crate) picto_rejections: usize,
    pub(crate) webhook_dead_letters: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StateReadiness {
    pub(crate) status: String,
    pub(crate) current: bool,
    pub(crate) reason: String,
    pub(crate) state_db: String,
    pub(crate) audit_log: String,
    pub(crate) indexed_size_bytes: Option<u64>,
    pub(crate) current_size_bytes: u64,
    pub(crate) indexed_sha256: Option<String>,
    pub(crate) current_sha256: Option<String>,
    pub(crate) entries_indexed: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct StateRebuildReport {
    status: &'static str,
    state_db: String,
    audit_log: String,
    source_of_truth: &'static str,
    rebuilt_at: String,
    audit_size_bytes: u64,
    audit_sha256: String,
    indexed: StateCounters,
    forensic_anomalies: usize,
    non_blocking_anomalies: usize,
}

#[derive(Debug, Clone, Serialize)]
struct StateStatsReport {
    status: String,
    current: bool,
    reason: String,
    state_db: String,
    audit_log: String,
    source_of_truth: &'static str,
    counters: StateCounters,
}

#[derive(Debug, Clone)]
struct AuditFingerprint {
    size_bytes: u64,
    modified_unix_nanos: String,
    sha256: String,
}

#[derive(Debug, Clone)]
struct IndexedRecord {
    line: usize,
    id: String,
    ts: String,
    record_kind: String,
    summary: String,
    detail: String,
    tool: Option<String>,
    input_hash: Option<String>,
    decision_kind: Option<String>,
    hard_stop: bool,
    required_scope: Option<String>,
    matched_rule_name: Option<String>,
    matched_rule_file: Option<String>,
    matched_rule_index: Option<usize>,
    policy_version: Option<String>,
    expedition: Option<String>,
    event_type: Option<String>,
    event_subject_id: Option<String>,
    capabilities: Vec<String>,
    raw_json: String,
}

pub(crate) fn cmd_state(sub: StateCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        StateCmd::Rebuild { json } => {
            layout.ensure()?;
            let report = rebuild_state(&layout)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("ok state rebuilt at {}", report.state_db);
                println!("source: {}", report.source_of_truth);
                println!("audit: {} entries indexed", report.indexed.audit_entries);
                println!(
                    "counters: {} decisions, {} events, {} ask, {} deny, {} hard-stop",
                    report.indexed.decisions,
                    report.indexed.events,
                    report.indexed.asks,
                    report.indexed.denies,
                    report.indexed.hard_stops
                );
                if report.non_blocking_anomalies > 0 {
                    println!(
                        "warn: {} non-blocking forensic anomaly marker(s) recorded by audit explain",
                        report.non_blocking_anomalies
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        StateCmd::Verify { json } => {
            let report = verify_state(&layout, true)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("state: {} - {}", report.status, report.reason);
                println!("state_db: {}", report.state_db);
                println!("audit_log: {}", report.audit_log);
            }
            if report.status == "fail" {
                Ok(ExitCode::from(1))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        StateCmd::Stats { json } => {
            let readiness = verify_state(&layout, false)?;
            let counters = load_counters(&layout).unwrap_or_default();
            let report = StateStatsReport {
                status: readiness.status,
                current: readiness.current,
                reason: readiness.reason,
                state_db: readiness.state_db,
                audit_log: readiness.audit_log,
                source_of_truth: "audit.log",
                counters,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("state: {} - {}", report.status, report.reason);
                println!(
                    "audit: {} entries ({} decisions, {} events)",
                    report.counters.audit_entries,
                    report.counters.decisions,
                    report.counters.events
                );
                println!(
                    "decisions: {} allow, {} ask, {} deny, {} hard-stop",
                    report.counters.allows,
                    report.counters.asks,
                    report.counters.denies,
                    report.counters.hard_stops
                );
                println!(
                    "events: {} approval request(s), {} approval resolution(s), {} picto creation(s), {} picto consumption(s), {} picto rejection(s), {} webhook dead-letter(s)",
                    report.counters.approval_requests,
                    report.counters.approval_resolutions,
                    report.counters.picto_creations,
                    report.counters.picto_consumptions,
                    report.counters.picto_rejections,
                    report.counters.webhook_dead_letters
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        StateCmd::Vacuum => {
            let conn = open_existing_state(&layout.state_db)?;
            conn.execute_batch("VACUUM;")?;
            println!("ok state vacuumed at {}", layout.state_db.display());
            Ok(ExitCode::SUCCESS)
        }
        StateCmd::Reset { dry_run } => {
            if dry_run {
                println!("dry-run: would remove {}", layout.state_db.display());
            } else {
                let mut removed = 0usize;
                for path in state_storage_paths(&layout.state_db) {
                    if path.exists() {
                        fs::remove_file(&path)
                            .with_context(|| format!("removing {}", path.display()))?;
                        removed += 1;
                    }
                }
                if removed > 0 {
                    println!("ok state reset; audit log preserved");
                } else {
                    println!("ok state already absent");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub(crate) fn load_counters_if_quick_current(layout: &HomeLayout) -> Option<StateCounters> {
    if !quick_current(layout) {
        return None;
    }
    load_counters(layout).ok()
}

pub(crate) fn recent_items_if_quick_current(
    layout: &HomeLayout,
    limit: usize,
) -> Option<Vec<AuditStreamItem>> {
    if !quick_current(layout) {
        return None;
    }
    load_recent_items(layout, limit).ok()
}

fn rebuild_state(layout: &HomeLayout) -> Result<StateRebuildReport> {
    let fingerprint = audit_fingerprint(&layout.audit_log)?;
    let verify_report = if layout.audit_log.exists() {
        let vk = layout.load_verifying_key()?;
        Some(explain_log(&layout.audit_log, &vk).context("verifying audit before indexing")?)
    } else {
        None
    };
    let forensic_anomalies = verify_report
        .as_ref()
        .map(|report| critical_anomaly_count(&report.anomalies))
        .unwrap_or(0);
    if forensic_anomalies > 0 {
        bail!(
            "audit log has {forensic_anomalies} critical forensic anomaly marker(s); run `gommage audit-verify --explain` before rebuilding state"
        );
    }
    let non_blocking_anomalies = verify_report
        .as_ref()
        .map(|report| report.anomalies.len().saturating_sub(forensic_anomalies))
        .unwrap_or(0);

    let records = read_indexed_records(&layout.audit_log)?;
    let counters = counters_from_records(&records);
    let rebuilt_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let mut conn = open_state_for_write(&layout.state_db)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM audit_capabilities", [])?;
    tx.execute("DELETE FROM audit_records", [])?;
    tx.execute("DELETE FROM state_meta", [])?;
    {
        let mut record_stmt = tx.prepare(
            r#"
            INSERT INTO audit_records (
                line, id, ts, record_kind, summary, detail, tool, input_hash,
                decision_kind, hard_stop, required_scope, matched_rule_name,
                matched_rule_file, matched_rule_index, policy_version, expedition,
                event_type, event_subject_id, raw_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
            "#,
        )?;
        let mut cap_stmt = tx.prepare(
            "INSERT INTO audit_capabilities (audit_line, position, capability) VALUES (?1, ?2, ?3)",
        )?;
        for record in &records {
            record_stmt.execute(params![
                record.line as i64,
                &record.id,
                &record.ts,
                &record.record_kind,
                &record.summary,
                &record.detail,
                record.tool.as_deref(),
                record.input_hash.as_deref(),
                record.decision_kind.as_deref(),
                record.hard_stop,
                record.required_scope.as_deref(),
                record.matched_rule_name.as_deref(),
                record.matched_rule_file.as_deref(),
                record.matched_rule_index.map(|value| value as i64),
                record.policy_version.as_deref(),
                record.expedition.as_deref(),
                record.event_type.as_deref(),
                record.event_subject_id.as_deref(),
                &record.raw_json,
            ])?;
            for (index, capability) in record.capabilities.iter().enumerate() {
                cap_stmt.execute(params![record.line as i64, index as i64, capability])?;
            }
        }
    }
    write_meta(&tx, "schema_version", SCHEMA_VERSION.to_string())?;
    write_meta(&tx, "source_of_truth", "audit.log")?;
    write_meta(&tx, "rebuilt_at", &rebuilt_at)?;
    write_meta(&tx, "audit_path", path_string(&layout.audit_log))?;
    write_meta(&tx, "audit_size_bytes", fingerprint.size_bytes.to_string())?;
    write_meta(
        &tx,
        "audit_modified_unix_nanos",
        &fingerprint.modified_unix_nanos,
    )?;
    write_meta(&tx, "audit_sha256", &fingerprint.sha256)?;
    write_meta(&tx, "audit_entries", counters.audit_entries.to_string())?;
    write_meta(&tx, "audit_decisions", counters.decisions.to_string())?;
    write_meta(&tx, "audit_events", counters.events.to_string())?;
    tx.commit()?;

    Ok(StateRebuildReport {
        status: "ok",
        state_db: path_string(&layout.state_db),
        audit_log: path_string(&layout.audit_log),
        source_of_truth: "audit.log",
        rebuilt_at,
        audit_size_bytes: fingerprint.size_bytes,
        audit_sha256: fingerprint.sha256,
        indexed: counters,
        forensic_anomalies,
        non_blocking_anomalies,
    })
}

fn verify_state(layout: &HomeLayout, strong_hash: bool) -> Result<StateReadiness> {
    let fingerprint = audit_fingerprint(&layout.audit_log)?;
    if !layout.state_db.exists() {
        return Ok(StateReadiness {
            status: "warn".to_string(),
            current: false,
            reason: "state.sqlite is missing; run `gommage state rebuild`".to_string(),
            state_db: path_string(&layout.state_db),
            audit_log: path_string(&layout.audit_log),
            indexed_size_bytes: None,
            current_size_bytes: fingerprint.size_bytes,
            indexed_sha256: None,
            current_sha256: if strong_hash {
                Some(fingerprint.sha256)
            } else {
                None
            },
            entries_indexed: None,
        });
    }

    let conn = match open_state_readonly(&layout.state_db) {
        Ok(conn) => conn,
        Err(error) => {
            return Ok(StateReadiness {
                status: "fail".to_string(),
                current: false,
                reason: format!("state.sqlite cannot be opened: {error}"),
                state_db: path_string(&layout.state_db),
                audit_log: path_string(&layout.audit_log),
                indexed_size_bytes: None,
                current_size_bytes: fingerprint.size_bytes,
                indexed_sha256: None,
                current_sha256: if strong_hash {
                    Some(fingerprint.sha256)
                } else {
                    None
                },
                entries_indexed: None,
            });
        }
    };
    let meta = read_meta(&conn)?;
    let indexed_size = meta
        .get("audit_size_bytes")
        .and_then(|value| value.parse::<u64>().ok());
    let indexed_sha = meta.get("audit_sha256").cloned();
    let entries_indexed = meta
        .get("audit_entries")
        .and_then(|value| value.parse::<usize>().ok());
    let schema_ok = meta
        .get("schema_version")
        .and_then(|value| value.parse::<i64>().ok())
        == Some(SCHEMA_VERSION);
    let source_ok = meta.get("source_of_truth").map(String::as_str) == Some("audit.log");
    let path_ok = meta
        .get("audit_path")
        .is_some_and(|path| path == &path_string(&layout.audit_log));
    let size_ok = indexed_size == Some(fingerprint.size_bytes);
    let hash_ok = !strong_hash || indexed_sha.as_deref() == Some(fingerprint.sha256.as_str());
    let current = schema_ok && source_ok && path_ok && size_ok && hash_ok;
    let (status, reason) = if current {
        ("ok", "state.sqlite matches the current audit ledger")
    } else if !schema_ok {
        (
            "warn",
            "state.sqlite schema is missing or outdated; run `gommage state rebuild`",
        )
    } else if !source_ok {
        (
            "warn",
            "state.sqlite source metadata is invalid; run `gommage state rebuild`",
        )
    } else if !path_ok {
        (
            "warn",
            "state.sqlite was built for a different audit path; run `gommage state rebuild`",
        )
    } else if !size_ok {
        (
            "warn",
            "audit.log changed after state.sqlite was built; run `gommage state rebuild`",
        )
    } else {
        (
            "warn",
            "audit.log hash differs from state.sqlite; run `gommage state rebuild`",
        )
    };

    Ok(StateReadiness {
        status: status.to_string(),
        current,
        reason: reason.to_string(),
        state_db: path_string(&layout.state_db),
        audit_log: path_string(&layout.audit_log),
        indexed_size_bytes: indexed_size,
        current_size_bytes: fingerprint.size_bytes,
        indexed_sha256: indexed_sha,
        current_sha256: if strong_hash {
            Some(fingerprint.sha256)
        } else {
            None
        },
        entries_indexed,
    })
}

fn quick_current(layout: &HomeLayout) -> bool {
    let Ok(fingerprint) = audit_fingerprint_quick(&layout.audit_log) else {
        return false;
    };
    let Ok(conn) = open_state_readonly(&layout.state_db) else {
        return false;
    };
    let Ok(meta) = read_meta(&conn) else {
        return false;
    };
    meta.get("schema_version")
        .and_then(|value| value.parse::<i64>().ok())
        == Some(SCHEMA_VERSION)
        && meta.get("source_of_truth").map(String::as_str) == Some("audit.log")
        && meta
            .get("audit_path")
            .is_some_and(|path| path == &path_string(&layout.audit_log))
        && meta
            .get("audit_size_bytes")
            .and_then(|value| value.parse::<u64>().ok())
            == Some(fingerprint.size_bytes)
        && meta
            .get("audit_modified_unix_nanos")
            .is_some_and(|value| value == &fingerprint.modified_unix_nanos)
}

fn load_counters(layout: &HomeLayout) -> Result<StateCounters> {
    let conn = open_state_readonly(&layout.state_db)?;
    let mut counters = StateCounters::default();
    counters.audit_entries = scalar_usize(&conn, "SELECT COUNT(*) FROM audit_records")?;
    counters.decisions = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE record_kind = 'decision'",
    )?;
    counters.events = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE record_kind = 'event'",
    )?;
    counters.allows = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'allow'",
    )?;
    counters.asks = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'ask_picto'",
    )?;
    counters.denies = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'gommage'",
    )?;
    counters.hard_stops = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE hard_stop = 1",
    )?;
    counters.approval_requests = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_requested'",
    )?;
    counters.approval_resolutions = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_resolved'",
    )?;
    counters.picto_creations = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_created'",
    )?;
    counters.picto_consumptions = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_consumed'",
    )?;
    counters.picto_rejections = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_rejected'",
    )?;
    counters.webhook_dead_letters = scalar_usize(
        &conn,
        "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_webhook_dead_lettered'",
    )?;
    Ok(counters)
}

fn load_recent_items(layout: &HomeLayout, limit: usize) -> Result<Vec<AuditStreamItem>> {
    let conn = open_state_readonly(&layout.state_db)?;
    let limit = limit.clamp(1, 100) as i64;
    let mut stmt = conn.prepare(
        "SELECT line, id, ts, record_kind, summary, detail FROM audit_records ORDER BY line DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |row| {
        Ok(AuditStreamItem {
            line: row.get::<_, i64>(0)? as usize,
            id: row.get(1)?,
            ts: row.get(2)?,
            kind: row.get(3)?,
            summary: row.get(4)?,
            detail: row.get(5)?,
        })
    })?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    items.reverse();
    Ok(items)
}

fn open_state_for_write(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    migrate(&conn)?;
    Ok(conn)
}

fn open_existing_state(path: &Path) -> Result<Connection> {
    if !path.exists() {
        bail!("state.sqlite is missing; run `gommage state rebuild` first");
    }
    let conn = Connection::open(path)?;
    migrate(&conn)?;
    Ok(conn)
}

fn open_state_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA user_version = 1;
        CREATE TABLE IF NOT EXISTS state_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_records (
            line INTEGER PRIMARY KEY,
            id TEXT NOT NULL,
            ts TEXT NOT NULL,
            record_kind TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            tool TEXT,
            input_hash TEXT,
            decision_kind TEXT,
            hard_stop INTEGER NOT NULL DEFAULT 0,
            required_scope TEXT,
            matched_rule_name TEXT,
            matched_rule_file TEXT,
            matched_rule_index INTEGER,
            policy_version TEXT,
            expedition TEXT,
            event_type TEXT,
            event_subject_id TEXT,
            raw_json TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS audit_records_id_idx ON audit_records(id);
        CREATE INDEX IF NOT EXISTS audit_records_ts_idx ON audit_records(ts);
        CREATE INDEX IF NOT EXISTS audit_records_decision_idx ON audit_records(decision_kind);
        CREATE INDEX IF NOT EXISTS audit_records_event_idx ON audit_records(event_type);
        CREATE INDEX IF NOT EXISTS audit_records_policy_idx ON audit_records(policy_version);
        CREATE TABLE IF NOT EXISTS audit_capabilities (
            audit_line INTEGER NOT NULL,
            position INTEGER NOT NULL,
            capability TEXT NOT NULL,
            PRIMARY KEY (audit_line, position),
            FOREIGN KEY (audit_line) REFERENCES audit_records(line) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS audit_capabilities_capability_idx ON audit_capabilities(capability);
        "#,
    )?;
    Ok(())
}

fn write_meta(tx: &rusqlite::Transaction<'_>, key: &str, value: impl ToString) -> Result<()> {
    tx.execute(
        "INSERT INTO state_meta (key, value) VALUES (?1, ?2)",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn read_meta(conn: &Connection) -> Result<BTreeMap<String, String>> {
    let mut stmt = conn.prepare("SELECT key, value FROM state_meta")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut meta = BTreeMap::new();
    for row in rows {
        let (key, value) = row?;
        meta.insert(key, value);
    }
    Ok(meta)
}

fn scalar_usize(conn: &Connection, sql: &str) -> Result<usize> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))? as usize)
}

fn audit_fingerprint(path: &Path) -> Result<AuditFingerprint> {
    if !path.exists() {
        return Ok(AuditFingerprint {
            size_bytes: 0,
            modified_unix_nanos: "0".to_string(),
            sha256: EMPTY_SHA256.to_string(),
        });
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut fingerprint = audit_fingerprint_quick(path)?;
    fingerprint.sha256 = hex::encode(hasher.finalize());
    Ok(fingerprint)
}

fn audit_fingerprint_quick(path: &Path) -> Result<AuditFingerprint> {
    if !path.exists() {
        return Ok(AuditFingerprint {
            size_bytes: 0,
            modified_unix_nanos: "0".to_string(),
            sha256: EMPTY_SHA256.to_string(),
        });
    }
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|| "0".to_string());
    Ok(AuditFingerprint {
        size_bytes: metadata.len(),
        modified_unix_nanos,
        sha256: String::new(),
    })
}

fn read_indexed_records(path: &Path) -> Result<Vec<IndexedRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line_no = index + 1;
        let line = line.with_context(|| format!("reading audit line {line_no}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).with_context(|| format!("parsing audit line {line_no}"))?;
        if value.get("kind").and_then(|kind| kind.as_str()) == Some("event") {
            let entry: AuditEventEntry = serde_json::from_value(value)
                .with_context(|| format!("parsing audit event line {line_no}"))?;
            records.push(index_event(line_no, entry, line));
        } else {
            let entry: AuditEntry = serde_json::from_value(value)
                .with_context(|| format!("parsing audit decision line {line_no}"))?;
            records.push(index_decision(line_no, entry, line));
        }
    }
    Ok(records)
}

fn index_decision(line: usize, entry: AuditEntry, raw_json: String) -> IndexedRecord {
    let (decision_kind, hard_stop, required_scope) = match &entry.decision {
        Decision::Allow => ("allow".to_string(), false, None),
        Decision::AskPicto { required_scope, .. } => {
            ("ask_picto".to_string(), false, Some(required_scope.clone()))
        }
        Decision::Gommage { hard_stop, .. } => ("gommage".to_string(), *hard_stop, None),
    };
    let summary = if hard_stop {
        format!("deny hard-stop {}", entry.tool)
    } else {
        format!("decision {decision_kind} {}", entry.tool)
    };
    let detail = format!(
        "input={} policy={} capabilities={}",
        entry.input_hash,
        entry.policy_version,
        entry.capabilities.len()
    );
    let capabilities = entry
        .capabilities
        .iter()
        .map(|capability| capability.as_str().to_string())
        .collect();
    IndexedRecord {
        line,
        id: entry.id,
        ts: entry.ts,
        record_kind: "decision".to_string(),
        summary,
        detail,
        tool: Some(entry.tool),
        input_hash: Some(entry.input_hash),
        decision_kind: Some(decision_kind),
        hard_stop,
        required_scope,
        matched_rule_name: entry.matched_rule.as_ref().map(|rule| rule.name.clone()),
        matched_rule_file: entry.matched_rule.as_ref().map(|rule| rule.file.clone()),
        matched_rule_index: entry.matched_rule.as_ref().map(|rule| rule.index),
        policy_version: Some(entry.policy_version),
        expedition: entry.expedition,
        event_type: None,
        event_subject_id: None,
        capabilities,
        raw_json,
    }
}

fn index_event(line: usize, entry: AuditEventEntry, raw_json: String) -> IndexedRecord {
    let (event_type, subject, summary, detail) = event_index_fields(&entry.event);
    IndexedRecord {
        line,
        id: entry.id,
        ts: entry.ts,
        record_kind: "event".to_string(),
        summary,
        detail,
        tool: None,
        input_hash: None,
        decision_kind: None,
        hard_stop: false,
        required_scope: None,
        matched_rule_name: None,
        matched_rule_file: None,
        matched_rule_index: None,
        policy_version: None,
        expedition: None,
        event_type: Some(event_type.to_string()),
        event_subject_id: subject,
        capabilities: Vec::new(),
        raw_json,
    }
}

fn event_index_fields(event: &AuditEvent) -> (&'static str, Option<String>, String, String) {
    match event {
        AuditEvent::PictoCreated { id, scope, .. } => (
            "picto_created",
            Some(id.clone()),
            format!("picto created {id}"),
            format!("scope={scope}"),
        ),
        AuditEvent::PictoConfirmed { id } => (
            "picto_confirmed",
            Some(id.clone()),
            format!("picto confirmed {id}"),
            String::new(),
        ),
        AuditEvent::PictoRevoked { id } => (
            "picto_revoked",
            Some(id.clone()),
            format!("picto revoked {id}"),
            String::new(),
        ),
        AuditEvent::PictoConsumed {
            id, scope, status, ..
        } => (
            "picto_consumed",
            Some(id.clone()),
            format!("picto consumed {id}"),
            format!("scope={scope} status={status}"),
        ),
        AuditEvent::PictoRejected { id, scope, reason } => (
            "picto_rejected",
            Some(id.clone()),
            format!("picto rejected {id}"),
            format!("scope={scope} reason={reason}"),
        ),
        AuditEvent::ApprovalRequested {
            id,
            tool,
            input_hash,
            required_scope,
            ..
        } => (
            "approval_requested",
            Some(id.clone()),
            format!("approval requested {id}"),
            format!("tool={tool} scope={required_scope} input={input_hash}"),
        ),
        AuditEvent::ApprovalResolved {
            id,
            status,
            picto_id,
            ..
        } => (
            "approval_resolved",
            Some(id.clone()),
            format!("approval {status} {id}"),
            format!("picto={}", picto_id.as_deref().unwrap_or("none")),
        ),
        AuditEvent::ApprovalWebhookDelivered {
            id,
            status,
            attempts,
            source,
            signature,
            ..
        } => (
            "approval_webhook_delivered",
            Some(id.clone()),
            format!("webhook delivered {id}"),
            format!(
                "http={} attempts={} source={} signed={}",
                status.map_or_else(|| "unknown".to_string(), |status| status.to_string()),
                attempts,
                source,
                signature.is_some()
            ),
        ),
        AuditEvent::ApprovalWebhookFailed {
            id,
            error,
            attempts,
            source,
            signature,
            ..
        } => (
            "approval_webhook_failed",
            Some(id.clone()),
            format!("webhook failed {id}"),
            format!(
                "attempts={} source={} signed={} error={error}",
                attempts,
                source,
                signature.is_some()
            ),
        ),
        AuditEvent::ApprovalWebhookDeadLettered {
            id,
            dead_letter_id,
            provider,
            attempts,
            source,
            error,
            ..
        } => (
            "approval_webhook_dead_lettered",
            Some(id.clone()),
            format!("webhook dead-lettered {id}"),
            format!(
                "dlq={} provider={} attempts={} source={} error={error}",
                dead_letter_id, provider, attempts, source
            ),
        ),
        AuditEvent::PictosExpired { count } => (
            "pictos_expired",
            None,
            "pictos expired".to_string(),
            format!("count={count}"),
        ),
        AuditEvent::PolicyReloaded {
            source,
            rules,
            mapper_rules,
            policy_version,
        } => (
            "policy_reloaded",
            None,
            "policy reloaded".to_string(),
            format!(
                "source={source} rules={rules} mapper_rules={mapper_rules} policy={policy_version}"
            ),
        ),
        AuditEvent::BypassActivated {
            tool,
            hard_stop,
            bypass_decision,
            ..
        } => (
            "bypass_activated",
            None,
            format!("bypass {bypass_decision} {tool}"),
            format!("hard_stop={hard_stop}"),
        ),
    }
}

fn counters_from_records(records: &[IndexedRecord]) -> StateCounters {
    let mut counters = StateCounters {
        audit_entries: records.len(),
        ..StateCounters::default()
    };
    for record in records {
        match record.record_kind.as_str() {
            "decision" => {
                counters.decisions += 1;
                match record.decision_kind.as_deref() {
                    Some("allow") => counters.allows += 1,
                    Some("ask_picto") => counters.asks += 1,
                    Some("gommage") => counters.denies += 1,
                    _ => {}
                }
                if record.hard_stop {
                    counters.hard_stops += 1;
                }
            }
            "event" => {
                counters.events += 1;
                match record.event_type.as_deref() {
                    Some("approval_requested") => counters.approval_requests += 1,
                    Some("approval_resolved") => counters.approval_resolutions += 1,
                    Some("picto_created") => counters.picto_creations += 1,
                    Some("picto_consumed") => counters.picto_consumptions += 1,
                    Some("picto_rejected") => counters.picto_rejections += 1,
                    Some("approval_webhook_dead_lettered") => counters.webhook_dead_letters += 1,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    counters
}

fn critical_anomaly_count(anomalies: &[Anomaly]) -> usize {
    anomalies
        .iter()
        .filter(|anomaly| {
            matches!(
                anomaly,
                Anomaly::MalformedEntry { .. }
                    | Anomaly::BadSignature { .. }
                    | Anomaly::HardStopBypassAttempt { .. }
            )
        })
        .count()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn state_storage_paths(path: &Path) -> Vec<std::path::PathBuf> {
    vec![
        path.to_path_buf(),
        path.with_file_name(format!(
            "{}-wal",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state.sqlite")
        )),
        path.with_file_name(format!(
            "{}-shm",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state.sqlite")
        )),
    ]
}
