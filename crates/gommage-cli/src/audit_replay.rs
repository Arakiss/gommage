use anyhow::{Context, Result};
use gommage_audit::{AuditEntry, AuditEventEntry};
use gommage_core::Decision;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Debug)]
pub(crate) struct AuditDecisionScan {
    pub(crate) decisions: Vec<AuditDecisionLine>,
    pub(crate) skipped_events: usize,
    pub(crate) skipped_blank_lines: usize,
}

#[derive(Debug)]
pub(crate) struct AuditDecisionLine {
    pub(crate) line: usize,
    pub(crate) entry: AuditEntry,
}

pub(crate) fn read_audit_decisions(audit_path: &Path) -> Result<AuditDecisionScan> {
    let file = File::open(audit_path)
        .with_context(|| format!("opening audit {}", audit_path.display()))?;
    let reader = BufReader::new(file);

    let mut decisions = Vec::new();
    let mut skipped_events = 0usize;
    let mut skipped_blank_lines = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line_no = index + 1;
        let line = line.with_context(|| format!("reading audit line {line_no}"))?;
        if line.trim().is_empty() {
            skipped_blank_lines += 1;
            continue;
        }

        let value: serde_json::Value =
            serde_json::from_str(&line).with_context(|| format!("parsing audit line {line_no}"))?;
        if value.get("kind").and_then(|kind| kind.as_str()) == Some("event") {
            let _event: AuditEventEntry = serde_json::from_value(value)
                .with_context(|| format!("parsing audit event line {line_no}"))?;
            skipped_events += 1;
            continue;
        }

        let entry: AuditEntry = serde_json::from_value(value)
            .with_context(|| format!("parsing audit decision line {line_no}"))?;
        decisions.push(AuditDecisionLine {
            line: line_no,
            entry,
        });
    }

    Ok(AuditDecisionScan {
        decisions,
        skipped_events,
        skipped_blank_lines,
    })
}

pub(crate) fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::AskPicto { required_scope, .. } => format!("ask_picto:{required_scope}"),
        Decision::Gommage { hard_stop, .. } => {
            if *hard_stop {
                "gommage:hard_stop".to_string()
            } else {
                "gommage".to_string()
            }
        }
    }
}
