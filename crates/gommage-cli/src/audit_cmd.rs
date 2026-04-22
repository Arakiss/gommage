use anyhow::{Context, Result};
use clap::ValueEnum;
use gommage_audit::{
    Anomaly, AuditEntry, AuditEventEntry, VerifyReport as AuditVerifyReport, verify_log,
};
use gommage_core::runtime::HomeLayout;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AuditExplainFormat {
    Json,
    Human,
}

pub(crate) fn cmd_audit_verify(
    layout: HomeLayout,
    explain: bool,
    format: Option<AuditExplainFormat>,
) -> Result<ExitCode> {
    let vk = layout.load_verifying_key()?;
    if explain {
        let report =
            gommage_audit::explain_log(&layout.audit_log, &vk).context("explaining audit log")?;
        match format.unwrap_or(AuditExplainFormat::Json) {
            AuditExplainFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            AuditExplainFormat::Human => print_audit_verify_report(&report),
        }
        if !report.anomalies.is_empty() {
            return Ok(ExitCode::from(1));
        }
    } else {
        let n = verify_log(&layout.audit_log, &vk).context("verifying audit log")?;
        println!("ok {n} entries verified");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_explain(layout: HomeLayout, id: &str, json: bool) -> Result<ExitCode> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(&layout.audit_log).context("opening audit log")?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let value: serde_json::Value = serde_json::from_str(&line)?;
        if value.get("id").and_then(|v| v.as_str()) != Some(id) {
            continue;
        }
        if json {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
            let entry: AuditEventEntry = serde_json::from_value(value)?;
            print_event_explain(&entry)?;
        } else {
            let entry: AuditEntry = serde_json::from_value(value)?;
            print_decision_explain(&entry)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("no audit entry with id {id}");
    Ok(ExitCode::from(1))
}

fn print_decision_explain(entry: &AuditEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: decision");
    println!("tool: {}", entry.tool);
    println!("input_hash: {}", entry.input_hash);
    println!("decision: {}", serde_json::to_string(&entry.decision)?);
    if let Some(rule) = &entry.matched_rule {
        println!("matched_rule: {} ({}:{})", rule.name, rule.file, rule.index);
    } else {
        println!("matched_rule: <none>");
    }
    println!("policy_version: {}", entry.policy_version);
    if let Some(expedition) = &entry.expedition {
        println!("expedition: {expedition}");
    }
    println!("capabilities:");
    for cap in &entry.capabilities {
        println!("  - {}", cap.as_str());
    }
    Ok(())
}

fn print_event_explain(entry: &AuditEventEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: event");
    println!("event: {}", serde_json::to_string(&entry.event)?);
    Ok(())
}

fn print_audit_verify_report(report: &AuditVerifyReport) {
    let status = if report.anomalies.is_empty() {
        "ok"
    } else {
        "anomaly"
    };

    println!("audit verification report");
    println!("status: {status}");
    println!(
        "entries: {} total, {} verified",
        report.entries_total, report.entries_verified
    );
    println!("key_fingerprint: {}", report.key_fingerprint);
    println!("bypass_activations: {}", report.bypass_activations);
    println!(
        "hard_stop_bypass_attempts: {}",
        report.hard_stop_bypass_attempts
    );
    print_string_list("policy_versions", &report.policy_versions_seen);
    print_string_list("expeditions", &report.expeditions_seen);

    if report.anomalies.is_empty() {
        println!("anomalies: none");
    } else {
        println!("anomalies:");
        for anomaly in &report.anomalies {
            println!("  - {}", format_anomaly(anomaly));
        }
    }
}

fn print_string_list(label: &str, values: &[String]) {
    if values.is_empty() {
        println!("{label}: none");
        return;
    }

    println!("{label}:");
    for value in values {
        println!("  - {value}");
    }
}

fn format_anomaly(anomaly: &Anomaly) -> String {
    match anomaly {
        Anomaly::MalformedEntry { line, error } => {
            format!("line {line}: malformed_entry error={error}")
        }
        Anomaly::BadSignature { line, entry_id } => {
            format!("line {line}: bad_signature entry_id={entry_id}")
        }
        Anomaly::TimestampOutOfOrder {
            line,
            previous_ts,
            current_ts,
        } => format!(
            "line {line}: timestamp_out_of_order previous_ts={previous_ts} current_ts={current_ts}"
        ),
        Anomaly::PolicyVersionChanged { line, from, to } => {
            format!("line {line}: policy_version_changed from={from} to={to}")
        }
        Anomaly::HardStopBypassAttempt {
            line,
            tool,
            original_reason,
        } => format!(
            "line {line}: hard_stop_bypass_attempt tool={tool} original_reason={original_reason}"
        ),
    }
}

pub(crate) fn print_log(path: &std::path::Path) -> Result<()> {
    use std::io::{BufRead, BufReader};
    if !path.exists() {
        println!("(no audit log yet at {})", path.display());
        return Ok(());
    }
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        println!("{}", line?);
    }
    Ok(())
}
