use anyhow::{Context, Result};
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, evaluate, runtime::default_policy_env,
};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    audit_replay::{decision_summary, read_audit_decisions},
    util::path_display,
};

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct PolicyDiffOptions {
    /// Baseline policy directory.
    #[arg(long, value_name = "DIR")]
    pub from: PathBuf,
    /// Candidate policy directory.
    #[arg(long, value_name = "DIR")]
    pub to: PathBuf,
    /// Audit JSONL file to evaluate both policies against.
    #[arg(long, value_name = "FILE")]
    pub against: PathBuf,
    /// Emit stable machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct PolicyDiffReport {
    status: PolicyDiffStatus,
    audit: String,
    from_policy: String,
    to_policy: String,
    from_policy_version: String,
    to_policy_version: String,
    policy_version_changed: bool,
    summary: PolicyDiffSummary,
    entries: Vec<PolicyDiffEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyDiffStatus {
    Unchanged,
    Changed,
}

impl PolicyDiffStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct PolicyDiffSummary {
    decisions: usize,
    changed: usize,
    unchanged: usize,
    decision_changed: usize,
    matched_rule_changed: usize,
    allow_to_gommage: usize,
    gommage_to_allow: usize,
    allow_to_ask_picto: usize,
    ask_picto_to_allow: usize,
    gommage_to_ask_picto: usize,
    ask_picto_to_gommage: usize,
    ask_scope_changed: usize,
    skipped_events: usize,
    skipped_blank_lines: usize,
}

#[derive(Debug, Serialize)]
struct PolicyDiffEntry {
    line: usize,
    audit_id: String,
    timestamp: String,
    tool: String,
    input_hash: String,
    capabilities: Vec<Capability>,
    audit_decision: Decision,
    from_decision: Decision,
    to_decision: Decision,
    changed: bool,
    decision_changed: bool,
    matched_rule_changed: bool,
    change: PolicyDiffStatus,
    audit_matched_rule: Option<MatchedRule>,
    from_matched_rule: Option<MatchedRule>,
    to_matched_rule: Option<MatchedRule>,
    audit_policy_version: String,
    from_policy_version: String,
    to_policy_version: String,
    expedition: Option<String>,
}

pub(crate) fn cmd_policy_diff(options: PolicyDiffOptions) -> Result<ExitCode> {
    let report = build_policy_diff_report(&options.against, &options.from, &options.to)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_policy_diff_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn build_policy_diff_report(
    audit_path: &Path,
    from_policy_path: &Path,
    to_policy_path: &Path,
) -> Result<PolicyDiffReport> {
    let env = default_policy_env();
    let from_policy = Policy::load_from_dir(from_policy_path, &env)
        .with_context(|| format!("loading baseline policy {}", from_policy_path.display()))?;
    let to_policy = Policy::load_from_dir(to_policy_path, &env)
        .with_context(|| format!("loading candidate policy {}", to_policy_path.display()))?;
    let scan = read_audit_decisions(audit_path)?;

    let from_policy_version = from_policy.version_hash.clone();
    let to_policy_version = to_policy.version_hash.clone();
    let mut summary = PolicyDiffSummary {
        skipped_events: scan.skipped_events,
        skipped_blank_lines: scan.skipped_blank_lines,
        ..PolicyDiffSummary::default()
    };
    let mut entries = Vec::new();

    for record in scan.decisions {
        let from_eval = evaluate(&record.entry.capabilities, &from_policy);
        let to_eval = evaluate(&record.entry.capabilities, &to_policy);
        let decision_changed = from_eval.decision != to_eval.decision;
        let matched_rule_changed = from_eval.matched_rule != to_eval.matched_rule;
        let changed = decision_changed || matched_rule_changed;
        let change = if changed {
            summary.changed += 1;
            PolicyDiffStatus::Changed
        } else {
            summary.unchanged += 1;
            PolicyDiffStatus::Unchanged
        };
        if decision_changed {
            summary.decision_changed += 1;
        }
        if matched_rule_changed {
            summary.matched_rule_changed += 1;
        }
        classify_transition(&from_eval.decision, &to_eval.decision, &mut summary);
        summary.decisions += 1;

        entries.push(PolicyDiffEntry {
            line: record.line,
            audit_id: record.entry.id,
            timestamp: record.entry.ts,
            tool: record.entry.tool,
            input_hash: record.entry.input_hash,
            capabilities: record.entry.capabilities,
            audit_decision: record.entry.decision,
            from_decision: from_eval.decision,
            to_decision: to_eval.decision,
            changed,
            decision_changed,
            matched_rule_changed,
            change,
            audit_matched_rule: record.entry.matched_rule,
            from_matched_rule: from_eval.matched_rule,
            to_matched_rule: to_eval.matched_rule,
            audit_policy_version: record.entry.policy_version,
            from_policy_version: from_eval.policy_version,
            to_policy_version: to_eval.policy_version,
            expedition: record.entry.expedition,
        });
    }

    let status = if summary.changed > 0 || from_policy_version != to_policy_version {
        PolicyDiffStatus::Changed
    } else {
        PolicyDiffStatus::Unchanged
    };

    Ok(PolicyDiffReport {
        status,
        audit: path_display(audit_path),
        from_policy: path_display(from_policy_path),
        to_policy: path_display(to_policy_path),
        policy_version_changed: from_policy_version != to_policy_version,
        from_policy_version,
        to_policy_version,
        summary,
        entries,
    })
}

fn print_policy_diff_report(report: &PolicyDiffReport) {
    println!("Gommage policy diff");
    println!("status: {}", report.status.as_str());
    println!("audit: {}", report.audit);
    println!("from_policy: {}", report.from_policy);
    println!("to_policy: {}", report.to_policy);
    println!("from_policy_version: {}", report.from_policy_version);
    println!("to_policy_version: {}", report.to_policy_version);
    println!(
        "summary: {} decision(s), {} changed, {} unchanged, {} decision change(s), {} rule change(s), {} event(s) skipped",
        report.summary.decisions,
        report.summary.changed,
        report.summary.unchanged,
        report.summary.decision_changed,
        report.summary.matched_rule_changed,
        report.summary.skipped_events
    );
    println!(
        "transitions: {} allow->gommage, {} gommage->allow, {} allow->ask_picto, {} ask_picto->allow, {} gommage->ask_picto, {} ask_picto->gommage, {} ask scope change(s)",
        report.summary.allow_to_gommage,
        report.summary.gommage_to_allow,
        report.summary.allow_to_ask_picto,
        report.summary.ask_picto_to_allow,
        report.summary.gommage_to_ask_picto,
        report.summary.ask_picto_to_gommage,
        report.summary.ask_scope_changed
    );
    for entry in &report.entries {
        println!(
            "- line {} {} [{}] {} -> {}",
            entry.line,
            entry.audit_id,
            entry.change.as_str(),
            decision_summary(&entry.from_decision),
            decision_summary(&entry.to_decision)
        );
    }
}

fn classify_transition(from: &Decision, to: &Decision, summary: &mut PolicyDiffSummary) {
    match (from, to) {
        (Decision::Allow, Decision::Gommage { .. }) => summary.allow_to_gommage += 1,
        (Decision::Gommage { .. }, Decision::Allow) => summary.gommage_to_allow += 1,
        (Decision::Allow, Decision::AskPicto { .. }) => summary.allow_to_ask_picto += 1,
        (Decision::AskPicto { .. }, Decision::Allow) => summary.ask_picto_to_allow += 1,
        (Decision::Gommage { .. }, Decision::AskPicto { .. }) => {
            summary.gommage_to_ask_picto += 1;
        }
        (Decision::AskPicto { .. }, Decision::Gommage { .. }) => {
            summary.ask_picto_to_gommage += 1;
        }
        (
            Decision::AskPicto {
                required_scope: from_scope,
                ..
            },
            Decision::AskPicto {
                required_scope: to_scope,
                ..
            },
        ) if from_scope != to_scope => summary.ask_scope_changed += 1,
        _ => {}
    }
}
