use anyhow::{Context, Result};
use clap::ValueEnum;
use gommage_audit::{
    Anomaly, AuditEntry, AuditEventEntry, VerifyReport as AuditVerifyReport, verify_log,
};
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, Rule, RuleDecision, evaluate, hardstop,
    runtime::{Expedition, HomeLayout, default_policy_env},
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

pub(crate) fn cmd_explain(
    layout: HomeLayout,
    id: &str,
    json: bool,
    trace: bool,
) -> Result<ExitCode> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(&layout.audit_log).context("opening audit log")?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let value: serde_json::Value = serde_json::from_str(&line)?;
        if value.get("id").and_then(|v| v.as_str()) != Some(id) {
            continue;
        }
        if trace {
            if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
                let entry: AuditEventEntry = serde_json::from_value(value)?;
                if json {
                    let report = ExplainEventTraceReport {
                        kind: "event",
                        entry,
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
    trace_available: bool,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
struct ExplainDecisionTraceReport {
    audit_id: String,
    timestamp: String,
    kind: &'static str,
    tool: String,
    input_hash: String,
    canonical_input: Option<serde_json::Value>,
    input_available: bool,
    input_note: &'static str,
    capabilities: Vec<Capability>,
    audited_decision: Decision,
    audited_matched_rule: Option<MatchedRule>,
    audit_policy_version: String,
    expedition: Option<String>,
    active_policy_version: String,
    active_decision: Decision,
    active_matched_rule: Option<MatchedRule>,
    policy_version_matches_audit: bool,
    decision_matches_audit: bool,
    hard_stop: Option<HardStopTrace>,
    rules: Vec<RuleTrace>,
    shadowed_rules: Vec<RuleTrace>,
    fixture_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleTrace {
    order: usize,
    name: String,
    file: String,
    index: usize,
    decision: RuleDecision,
    required_scope: Option<String>,
    hard_stop: bool,
    reason: String,
    matched_by_capabilities: bool,
    evaluated: bool,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct HardStopTrace {
    name: String,
    pattern: String,
    capability: Capability,
}

fn build_decision_trace_report(
    layout: &HomeLayout,
    entry: &AuditEntry,
) -> Result<ExplainDecisionTraceReport> {
    let env = Expedition::load(&layout.expedition_file)?
        .map(|e| e.policy_env())
        .unwrap_or_else(default_policy_env);
    let policy = Policy::load_from_dir(&layout.policy_dir, &env)
        .context("loading active policy for explain trace")?;
    let active_eval = evaluate(&entry.capabilities, &policy);
    let hard_stop = hardstop::check(&entry.capabilities);
    let hard_stop_trace = hard_stop.as_ref().map(|hit| HardStopTrace {
        name: hit.name.to_string(),
        pattern: hit.pattern.to_string(),
        capability: hit.capability.clone(),
    });
    let rules = build_rule_trace(&policy, &entry.capabilities, hard_stop.is_some());
    let shadowed_rules = rules
        .iter()
        .filter(|rule| rule.outcome == "shadowed")
        .cloned()
        .collect();

    Ok(ExplainDecisionTraceReport {
        audit_id: entry.id.clone(),
        timestamp: entry.ts.clone(),
        kind: "decision",
        tool: entry.tool.clone(),
        input_hash: entry.input_hash.clone(),
        canonical_input: None,
        input_available: false,
        input_note: "audit decision entries store input_hash and capabilities, not raw tool input",
        capabilities: entry.capabilities.clone(),
        audited_decision: entry.decision.clone(),
        audited_matched_rule: entry.matched_rule.clone(),
        audit_policy_version: entry.policy_version.clone(),
        expedition: entry.expedition.clone(),
        active_policy_version: active_eval.policy_version.clone(),
        active_decision: active_eval.decision.clone(),
        active_matched_rule: active_eval.matched_rule.clone(),
        policy_version_matches_audit: entry.policy_version == active_eval.policy_version,
        decision_matches_audit: entry.decision == active_eval.decision,
        hard_stop: hard_stop_trace,
        rules,
        shadowed_rules,
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

fn build_rule_trace(
    policy: &Policy,
    capabilities: &[Capability],
    hard_stop: bool,
) -> Vec<RuleTrace> {
    let winning_index = if hard_stop {
        None
    } else {
        policy
            .rules
            .iter()
            .position(|rule| rule.r#match.matches(capabilities))
    };

    policy
        .rules
        .iter()
        .enumerate()
        .map(|(order, rule)| trace_rule(order, rule, capabilities, hard_stop, winning_index))
        .collect()
}

fn trace_rule(
    order: usize,
    rule: &Rule,
    capabilities: &[Capability],
    hard_stop: bool,
    winning_index: Option<usize>,
) -> RuleTrace {
    let matched_by_capabilities = rule.r#match.matches(capabilities);
    let evaluated = !hard_stop && winning_index.is_none_or(|winner| order <= winner);
    let outcome = if hard_stop {
        "not_evaluated_hard_stop"
    } else if winning_index == Some(order) {
        "matched"
    } else if evaluated {
        "not_matched"
    } else if matched_by_capabilities {
        "shadowed"
    } else {
        "not_evaluated_after_match"
    };

    RuleTrace {
        order,
        name: rule.name.clone(),
        file: path_display(&rule.source.file),
        index: rule.source.index,
        decision: rule.decision,
        required_scope: rule.required_scope.clone(),
        hard_stop: rule.hard_stop,
        reason: rule.reason.clone(),
        matched_by_capabilities,
        evaluated,
        outcome,
    }
}

fn print_decision_trace_report(report: &ExplainDecisionTraceReport) {
    println!("audit_id: {}", report.audit_id);
    println!("timestamp: {}", report.timestamp);
    println!("kind: decision");
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
    if let Some(rule) = &report.audited_matched_rule {
        println!(
            "audited_matched_rule: {} ({}:{})",
            rule.name, rule.file, rule.index
        );
    } else {
        println!("audited_matched_rule: <none>");
    }
    if let Some(rule) = &report.active_matched_rule {
        println!(
            "active_matched_rule: {} ({}:{})",
            rule.name, rule.file, rule.index
        );
    } else {
        println!("active_matched_rule: <none>");
    }
    if let Some(hard_stop) = &report.hard_stop {
        println!(
            "hard_stop: {} pattern={} capability={}",
            hard_stop.name, hard_stop.pattern, hard_stop.capability
        );
    } else {
        println!("hard_stop: none");
    }
    if let Some(expedition) = &report.expedition {
        println!("expedition: {expedition}");
    }
    println!("capabilities:");
    for cap in &report.capabilities {
        println!("  - {}", cap.as_str());
    }
    println!("rule_trace:");
    for rule in &report.rules {
        println!(
            "  - #{} {} [{}] matched={} evaluated={} decision={:?}",
            rule.order,
            rule.name,
            rule.outcome,
            rule.matched_by_capabilities,
            rule.evaluated,
            rule.decision
        );
    }
    if report.shadowed_rules.is_empty() {
        println!("shadowed_rules: none");
    } else {
        println!("shadowed_rules:");
        for rule in &report.shadowed_rules {
            println!("  - #{} {} ({})", rule.order, rule.name, rule.file);
        }
    }
    println!("fixture_hints:");
    for hint in &report.fixture_hints {
        println!("  - {hint}");
    }
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
