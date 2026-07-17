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

const SCHEMA_VERSION: i64 = 2;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Subcommand)]
pub(crate) enum StateCmd {
    /// Rebuild state.sqlite from the available authenticated audit records.
    Rebuild {
        /// Emit a stable machine-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Verify whether state.sqlite matches the current audit log snapshot.
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
    /// Remove state.sqlite. The authenticated audit record file is not touched.
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
    source_log: &'static str,
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
    source_log: &'static str,
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
                println!("source_log: {}", report.source_log);
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
                source_log: "audit.log",
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
    write_meta(&tx, "source_log", "audit.log")?;
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
        source_log: "audit.log",
        rebuilt_at,
        audit_size_bytes: fingerprint.size_bytes,
        audit_sha256: fingerprint.sha256,
        indexed: counters,
        forensic_anomalies,
        non_blocking_anomalies,
    })
}

pub(crate) fn build_state_readiness(
    layout: &HomeLayout,
    strong_hash: bool,
) -> Result<StateReadiness> {
    verify_state(layout, strong_hash)
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
    let source_ok = meta.get("source_log").map(String::as_str) == Some("audit.log");
    let path_ok = meta
        .get("audit_path")
        .is_some_and(|path| path == &path_string(&layout.audit_log));
    let size_ok = indexed_size == Some(fingerprint.size_bytes);
    let hash_ok = !strong_hash || indexed_sha.as_deref() == Some(fingerprint.sha256.as_str());
    let current = schema_ok && source_ok && path_ok && size_ok && hash_ok;
    let (status, reason) = if current {
        ("ok", "state.sqlite matches the current audit log snapshot")
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
        && meta.get("source_log").map(String::as_str) == Some("audit.log")
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
    Ok(StateCounters {
        audit_entries: scalar_usize(&conn, "SELECT COUNT(*) FROM audit_records")?,
        decisions: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE record_kind = 'decision'",
        )?,
        events: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE record_kind = 'event'",
        )?,
        allows: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'allow'",
        )?,
        asks: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'ask_picto'",
        )?,
        denies: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE decision_kind = 'gommage'",
        )?,
        hard_stops: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE hard_stop = 1",
        )?,
        approval_requests: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_requested'",
        )?,
        approval_resolutions: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_resolved'",
        )?,
        picto_creations: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_created'",
        )?,
        picto_consumptions: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_consumed'",
        )?,
        picto_rejections: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'picto_rejected'",
        )?,
        webhook_dead_letters: scalar_usize(
            &conn,
            "SELECT COUNT(*) FROM audit_records WHERE event_type = 'approval_webhook_dead_lettered'",
        )?,
    })
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

mod store;

use store::*;
