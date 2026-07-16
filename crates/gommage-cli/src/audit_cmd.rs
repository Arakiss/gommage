use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use gommage_audit::{
    Anomaly, AuditEntry, AuditEventEntry, VerifyReport as AuditVerifyReport, verify_log,
};
use gommage_core::{
    Capability, CapabilityProvenance, CapabilityProvenanceStatus, Decision, MatchedRule, evaluate,
    runtime::{Expedition, HomeLayout, default_policy_env, load_active_policy},
};
use serde::Serialize;
use std::process::ExitCode;

use crate::{audit_replay::decision_summary, util::path_display};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AuditExplainFormat {
    Json,
    Human,
}

pub(crate) fn cmd_audit_verify(
    layout: HomeLayout,
    explain: bool,
    format: Option<AuditExplainFormat>,
    json: bool,
) -> Result<ExitCode> {
    if json && matches!(format, Some(AuditExplainFormat::Human)) {
        bail!("--json cannot be combined with --format human");
    }

    let vk = layout.load_verifying_key()?;
    if explain {
        let report =
            gommage_audit::explain_log(&layout.audit_log, &vk).context("explaining audit log")?;
        let format = if json {
            AuditExplainFormat::Json
        } else {
            format.unwrap_or(AuditExplainFormat::Json)
        };
        match format {
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

pub(crate) fn cmd_explain(
    layout: HomeLayout,
    id: &str,
    json: bool,
    trace: bool,
) -> Result<ExitCode> {
    use std::io::{BufRead, BufReader};
    let verifying_key = layout.load_verifying_key()?;
    let file = std::fs::File::open(&layout.audit_log).context("opening audit log")?;
    let reader = BufReader::new(file);
    for (line_index, line) in reader.lines().enumerate() {
        let line = line?;
        let value: serde_json::Value = serde_json::from_str(&line)?;
        if value.get("id").and_then(|v| v.as_str()) != Some(id) {
            continue;
        }
        verify_selected_record(&layout, &verifying_key, line_index + 1, id)?;
        if trace {
            if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
                let entry: AuditEventEntry = serde_json::from_value(value)?;
                if json {
                    let report = ExplainEventTraceReport {
                        kind: "event",
                        entry,
                        signature_verified: true,
                        trace_available: false,
                        reason: "policy traces are only available for audit decision entries",
                    };
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print_event_explain(&entry)?;
                    println!("trace_available: false");
                    println!(
                        "trace_reason: policy traces are only available for audit decision entries"
                    );
                }
            } else {
                let entry: AuditEntry = serde_json::from_value(value)?;
                let report = build_decision_trace_report(&layout, &entry)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print_decision_trace_report(&report);
                }
            }
        } else if json {
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

#[derive(Debug, Serialize)]
struct ExplainEventTraceReport {
    kind: &'static str,
    entry: AuditEventEntry,
    signature_verified: bool,
    trace_available: bool,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
struct ExplainDecisionTraceReport {
    audit_id: String,
    timestamp: String,
    kind: &'static str,
    audit_schema_version: u32,
    signature_verified: bool,
    tool: String,
    input_hash: String,
    canonical_input: Option<serde_json::Value>,
    input_available: bool,
    input_note: &'static str,
    audited_capabilities: Vec<Capability>,
    active_capabilities: Vec<Capability>,
    audited_decision: Decision,
    audited_primary_matched_rule: Option<MatchedRule>,
    audited_capability_provenance: Option<Vec<CapabilityProvenance>>,
    audited_provenance_note: &'static str,
    audit_policy_version: String,
    expedition: Option<String>,
    active_policy_version: String,
    active_decision: Decision,
    active_primary_matched_rule: Option<MatchedRule>,
    active_capability_provenance: Vec<CapabilityProvenance>,
    primary_matched_rule_note: &'static str,
    policy_version_matches_audit: bool,
    decision_matches_audit: bool,
    fixture_hints: Vec<String>,
}

fn build_decision_trace_report(
    layout: &HomeLayout,
    entry: &AuditEntry,
) -> Result<ExplainDecisionTraceReport> {
    let expedition = Expedition::load(&layout.expedition_file)?;
    let env = expedition
        .as_ref()
        .map(Expedition::policy_env)
        .unwrap_or_else(default_policy_env);
    let policy = load_active_policy(layout, expedition.as_ref(), &env)
        .context("loading active policy for explain trace")?;
    let active_eval = evaluate(&entry.capabilities, &policy);
    let audited_capability_provenance =
        (entry.version >= 2).then(|| entry.capability_provenance.clone());
    let audited_provenance_note = if audited_capability_provenance.is_some() {
        "signed per-capability provenance from the audited decision"
    } else {
        "unavailable: audit schema v1 did not contain signed per-capability provenance"
    };

    Ok(ExplainDecisionTraceReport {
        audit_id: entry.id.clone(),
        timestamp: entry.ts.clone(),
        kind: "decision",
        audit_schema_version: entry.version,
        signature_verified: true,
        tool: entry.tool.clone(),
        input_hash: entry.input_hash.clone(),
        canonical_input: None,
        input_available: false,
        input_note: "audit decision entries store input_hash and capabilities, not raw tool input",
        audited_capabilities: entry.capabilities.clone(),
        active_capabilities: active_eval.capabilities.clone(),
        audited_decision: entry.decision.clone(),
        audited_primary_matched_rule: entry.matched_rule.clone(),
        audited_capability_provenance,
        audited_provenance_note,
        audit_policy_version: entry.policy_version.clone(),
        expedition: entry.expedition.clone(),
        active_policy_version: active_eval.policy_version.clone(),
        active_decision: active_eval.decision.clone(),
        active_primary_matched_rule: active_eval.matched_rule.clone(),
        active_capability_provenance: active_eval.capability_provenance,
        primary_matched_rule_note:
            "primary compatibility summary only; per-capability provenance is authoritative",
        policy_version_matches_audit: entry.policy_version == active_eval.policy_version,
        decision_matches_audit: entry.decision == active_eval.decision,
        fixture_hints: vec![
            "original tool input is not stored in the audit log; use `gommage policy snapshot --name <case>` with a captured ToolCall to create a fixture".to_string(),
            format!(
                "replay this audit log with `gommage replay --audit {} --policy <dir> --json`",
                path_display(&layout.audit_log)
            ),
            format!(
                "compare candidate policy with `gommage policy diff --from {} --to <dir> --against {} --json`",
                path_display(&layout.policy_dir),
                path_display(&layout.audit_log)
            ),
        ],
    })
}

fn verify_selected_record(
    layout: &HomeLayout,
    verifying_key: &ed25519_dalek::VerifyingKey,
    line_number: usize,
    id: &str,
) -> Result<()> {
    let report = gommage_audit::explain_log(&layout.audit_log, verifying_key)
        .context("verifying selected audit record")?;
    for anomaly in report.anomalies {
        match anomaly {
            Anomaly::MalformedEntry { line, error } if line == line_number => {
                bail!("audit entry {id} at line {line} failed schema verification: {error}");
            }
            Anomaly::BadSignature { line, .. } if line == line_number => {
                bail!("audit entry {id} at line {line} failed signature verification");
            }
            _ => {}
        }
    }
    Ok(())
}

fn print_decision_trace_report(report: &ExplainDecisionTraceReport) {
    println!("audit_id: {}", report.audit_id);
    println!("timestamp: {}", report.timestamp);
    println!("kind: decision");
    println!("audit_schema_version: {}", report.audit_schema_version);
    println!("signature_verified: {}", report.signature_verified);
    println!("tool: {}", report.tool);
    println!("input_hash: {}", report.input_hash);
    println!("input_available: {}", report.input_available);
    println!("input_note: {}", report.input_note);
    println!(
        "audited_decision: {}",
        decision_summary(&report.audited_decision)
    );
    println!("audit_policy_version: {}", report.audit_policy_version);
    println!("active_policy_version: {}", report.active_policy_version);
    println!(
        "policy_version_matches_audit: {}",
        report.policy_version_matches_audit
    );
    println!(
        "active_decision: {}",
        decision_summary(&report.active_decision)
    );
    println!("decision_matches_audit: {}", report.decision_matches_audit);
    println!(
        "primary_matched_rule_note: {}",
        report.primary_matched_rule_note
    );
    if let Some(rule) = &report.audited_primary_matched_rule {
        println!(
            "audited_primary_matched_rule: {} ({}:{})",
            rule.name, rule.file, rule.index
        );
    } else {
        println!("audited_primary_matched_rule: <none>");
    }
    if let Some(rule) = &report.active_primary_matched_rule {
        println!(
            "active_primary_matched_rule: {} ({}:{})",
            rule.name, rule.file, rule.index
        );
    } else {
        println!("active_primary_matched_rule: <none>");
    }
    if let Some(expedition) = &report.expedition {
        println!("expedition: {expedition}");
    }
    println!("audited_capabilities:");
    for cap in &report.audited_capabilities {
        println!("  - {}", cap.as_str());
    }
    println!("active_capabilities:");
    for cap in &report.active_capabilities {
        println!("  - {}", cap.as_str());
    }
    println!(
        "audited_provenance_note: {}",
        report.audited_provenance_note
    );
    print_capability_provenance(
        "audited_capability_provenance",
        report.audited_capability_provenance.as_deref(),
    );
    print_capability_provenance(
        "active_capability_provenance",
        Some(&report.active_capability_provenance),
    );
    println!("fixture_hints:");
    for hint in &report.fixture_hints {
        println!("  - {hint}");
    }
}

fn print_capability_provenance(label: &str, provenance: Option<&[CapabilityProvenance]>) {
    let Some(provenance) = provenance else {
        println!("{label}: unavailable");
        return;
    };
    if provenance.is_empty() {
        println!("{label}: none");
        return;
    }

    println!("{label}:");
    for capability in provenance {
        let effective = capability
            .effective_decision
            .as_ref()
            .map_or_else(|| "none".to_string(), decision_summary);
        println!(
            "  - capability={} status={} effective_decision={effective}",
            capability.capability,
            provenance_status(capability.status)
        );
        if capability.contributions.is_empty() {
            println!("    contributions: none");
        } else {
            println!("    contributions:");
            for contribution in &capability.contributions {
                println!(
                    "      - layer={} layer_index={} file_index={} rule={} ({}:{}) decision={}",
                    contribution.layer,
                    contribution.layer_index,
                    contribution.file_index,
                    contribution.rule.name,
                    contribution.rule.file,
                    contribution.rule.index,
                    decision_summary(&contribution.decision)
                );
            }
        }
    }
}

const fn provenance_status(status: CapabilityProvenanceStatus) -> &'static str {
    match status {
        CapabilityProvenanceStatus::Resolved => "resolved",
        CapabilityProvenanceStatus::Unresolved => "unresolved",
        CapabilityProvenanceStatus::HardStop => "hard_stop",
        CapabilityProvenanceStatus::SkippedDueToHardStop => "skipped_due_to_hard_stop",
        CapabilityProvenanceStatus::PolicyBypassed => "policy_bypassed",
    }
}

fn print_decision_explain(entry: &AuditEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: decision");
    println!("audit_schema_version: {}", entry.version);
    println!("signature_verified: true");
    println!("tool: {}", entry.tool);
    println!("input_hash: {}", entry.input_hash);
    println!("decision: {}", serde_json::to_string(&entry.decision)?);
    if let Some(rule) = &entry.matched_rule {
        println!(
            "primary_matched_rule: {} ({}:{}) [compatibility summary]",
            rule.name, rule.file, rule.index
        );
    } else {
        println!("primary_matched_rule: <none> [compatibility summary]");
    }
    println!("policy_version: {}", entry.policy_version);
    if let Some(expedition) = &entry.expedition {
        println!("expedition: {expedition}");
    }
    println!("capabilities:");
    for cap in &entry.capabilities {
        println!("  - {}", cap.as_str());
    }
    if entry.version >= 2 {
        print_capability_provenance(
            "audited_capability_provenance",
            Some(&entry.capability_provenance),
        );
    } else {
        println!("audited_capability_provenance: unavailable (audit schema v1)");
    }
    Ok(())
}

fn print_event_explain(entry: &AuditEventEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: event");
    println!("signature_verified: true");
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
