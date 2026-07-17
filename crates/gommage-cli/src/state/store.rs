use super::*;

pub(super) fn open_state_for_write(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    migrate(&conn)?;
    Ok(conn)
}

pub(super) fn open_existing_state(path: &Path) -> Result<Connection> {
    if !path.exists() {
        bail!("state.sqlite is missing; run `gommage state rebuild` first");
    }
    let conn = Connection::open(path)?;
    migrate(&conn)?;
    Ok(conn)
}

pub(super) fn open_state_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok(conn)
}

pub(super) fn migrate(conn: &Connection) -> Result<()> {
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

pub(super) fn write_meta(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    value: impl ToString,
) -> Result<()> {
    tx.execute(
        "INSERT INTO state_meta (key, value) VALUES (?1, ?2)",
        params![key, value.to_string()],
    )?;
    Ok(())
}

pub(super) fn read_meta(conn: &Connection) -> Result<BTreeMap<String, String>> {
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

pub(super) fn scalar_usize(conn: &Connection, sql: &str) -> Result<usize> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))? as usize)
}

pub(super) fn audit_fingerprint(path: &Path) -> Result<AuditFingerprint> {
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

pub(super) fn audit_fingerprint_quick(path: &Path) -> Result<AuditFingerprint> {
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

pub(super) fn read_indexed_records(path: &Path) -> Result<Vec<IndexedRecord>> {
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

pub(super) fn index_decision(line: usize, entry: AuditEntry, raw_json: String) -> IndexedRecord {
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

pub(super) fn index_event(line: usize, entry: AuditEventEntry, raw_json: String) -> IndexedRecord {
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

pub(super) fn event_index_fields(
    event: &AuditEvent,
) -> (&'static str, Option<String>, String, String) {
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

pub(super) fn counters_from_records(records: &[IndexedRecord]) -> StateCounters {
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

pub(super) fn critical_anomaly_count(anomalies: &[Anomaly]) -> usize {
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

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub(super) fn state_storage_paths(path: &Path) -> Vec<std::path::PathBuf> {
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
