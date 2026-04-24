use anyhow::{Context, Result};
use gommage_audit::{AuditEntry, AuditEventEntry};
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, evaluate, runtime::default_policy_env,
};
use serde::Serialize;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::util::path_display;

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct ReplayOptions {
    /// Audit JSONL file to replay.
    #[arg(long, value_name = "FILE")]
    pub audit: PathBuf,
    /// Candidate policy directory to evaluate against.
    #[arg(long, value_name = "DIR")]
    pub policy: PathBuf,
    /// Emit stable machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    status: ReplayStatus,
    audit: String,
    policy: String,
    replay_policy_version: String,
    summary: ReplaySummary,
    entries: Vec<ReplayEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplayStatus {
    Unchanged,
    Changed,
}

impl ReplayStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct ReplaySummary {
    decisions: usize,
    changed: usize,
    unchanged: usize,
    skipped_events: usize,
    skipped_blank_lines: usize,
}

#[derive(Debug, Serialize)]
struct ReplayEntry {
    line: usize,
    audit_id: String,
    timestamp: String,
    tool: String,
    input_hash: String,
    capabilities: Vec<Capability>,
    original_decision: Decision,
    replayed_decision: Decision,
    changed: bool,
    change: ReplayStatus,
    original_matched_rule: Option<MatchedRule>,
    replayed_matched_rule: Option<MatchedRule>,
    matched_rule_changed: bool,
    original_policy_version: String,
    replayed_policy_version: String,
    policy_version_changed: bool,
    expedition: Option<String>,
}

pub(crate) fn cmd_replay(options: ReplayOptions) -> Result<ExitCode> {
    let report = build_replay_report(&options.audit, &options.policy)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_replay_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn build_replay_report(audit_path: &Path, policy_path: &Path) -> Result<ReplayReport> {
    let env = default_policy_env();
    let policy = Policy::load_from_dir(policy_path, &env)
        .with_context(|| format!("loading candidate policy {}", policy_path.display()))?;
    let file = File::open(audit_path)
        .with_context(|| format!("opening audit {}", audit_path.display()))?;
    let reader = BufReader::new(file);

    let mut summary = ReplaySummary::default();
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_no = index + 1;
        let line = line.with_context(|| format!("reading audit line {line_no}"))?;
        if line.trim().is_empty() {
            summary.skipped_blank_lines += 1;
            continue;
        }

        let value: serde_json::Value =
            serde_json::from_str(&line).with_context(|| format!("parsing audit line {line_no}"))?;
        if value.get("kind").and_then(|kind| kind.as_str()) == Some("event") {
            let _event: AuditEventEntry = serde_json::from_value(value)
                .with_context(|| format!("parsing audit event line {line_no}"))?;
            summary.skipped_events += 1;
            continue;
        }

        let entry: AuditEntry = serde_json::from_value(value)
            .with_context(|| format!("parsing audit decision line {line_no}"))?;
        let replay = evaluate(&entry.capabilities, &policy);
        let changed = entry.decision != replay.decision;
        let change = if changed {
            summary.changed += 1;
            ReplayStatus::Changed
        } else {
            summary.unchanged += 1;
            ReplayStatus::Unchanged
        };
        summary.decisions += 1;

        entries.push(ReplayEntry {
            line: line_no,
            audit_id: entry.id,
            timestamp: entry.ts,
            tool: entry.tool,
            input_hash: entry.input_hash,
            capabilities: entry.capabilities,
            original_decision: entry.decision,
            replayed_decision: replay.decision,
            changed,
            change,
            matched_rule_changed: entry.matched_rule != replay.matched_rule,
            original_matched_rule: entry.matched_rule,
            replayed_matched_rule: replay.matched_rule,
            policy_version_changed: entry.policy_version != replay.policy_version,
            original_policy_version: entry.policy_version,
            replayed_policy_version: replay.policy_version,
            expedition: entry.expedition,
        });
    }

    let status = if summary.changed > 0 {
        ReplayStatus::Changed
    } else {
        ReplayStatus::Unchanged
    };

    Ok(ReplayReport {
        status,
        audit: path_display(audit_path),
        policy: path_display(policy_path),
        replay_policy_version: policy.version_hash,
        summary,
        entries,
    })
}

fn print_replay_report(report: &ReplayReport) {
    println!("Gommage replay");
    println!("status: {}", report.status.as_str());
    println!("audit: {}", report.audit);
    println!("policy: {}", report.policy);
    println!("replay_policy_version: {}", report.replay_policy_version);
    println!(
        "summary: {} decision(s), {} changed, {} unchanged, {} event(s) skipped",
        report.summary.decisions,
        report.summary.changed,
        report.summary.unchanged,
        report.summary.skipped_events
    );
    for entry in &report.entries {
        println!(
            "- line {} {} [{}] {} -> {}",
            entry.line,
            entry.audit_id,
            entry.change.as_str(),
            decision_summary(&entry.original_decision),
            decision_summary(&entry.replayed_decision)
        );
    }
}

fn decision_summary(decision: &Decision) -> String {
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
