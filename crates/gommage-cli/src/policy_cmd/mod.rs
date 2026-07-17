use anyhow::{Context, Result};
use clap::Subcommand;
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, RuleDecision, ToolCall, evaluate,
    policy::{RawMatch, RawRule, substitute_env},
    runtime::{
        Expedition, HomeLayout, active_policy_layers, default_policy_env, load_active_policy,
    },
};
use gommage_stdlib::{
    CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES, StdlibFile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    agent::{preflight_generated_relaxation_removal, remove_generated_relaxation_layers},
    audit_replay::{
        AuditDecisionLine, decision_summary as audit_decision_summary, read_audit_decisions,
    },
    daemon::{recover_recorded_daemon_runtime, reload_policy_runtime},
    input::read_tool_call_from_stdin,
    policy_diff::{PolicyDiffOptions, cmd_policy_diff},
    smoke::{SmokeStatus, SmokeSummary},
    util::{
        InstallTransaction, TransactionFile, backup_and_remove_file, ensure_home, path_display,
        write_text,
    },
};

const POLICY_FIXTURE_SCHEMA: &str = include_str!("../../schemas/policy-fixture.schema.json");
const LOCAL_RELAXATION_POLICY_FILES: &[&str] = &[
    "14-operator-allow-agent-tools.yaml",
    "19-operator-main-push.yaml",
];

#[derive(Subcommand)]
pub(crate) enum PolicyCmd {
    /// Initialize policy.d/ and capabilities.d/ from the embedded stdlib.
    Init {
        #[arg(long)]
        stdlib: bool,
        #[arg(long)]
        force: bool,
        /// Remove known local allow layers that relax stdlib friction gates.
        #[arg(long)]
        remove_local_relaxations: bool,
    },
    /// Parse and compile every policy file under policy.d/.
    Check,
    /// Print the active policy layer order.
    Layers {
        /// Emit a stable machine-readable layer report.
        #[arg(long)]
        json: bool,
    },
    /// Parse policy files and optionally run strict authoring checks.
    Lint {
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Detect duplicate names, empty matches, shadowed exact-match rules, and weak metadata.
        #[arg(long)]
        strict: bool,
        /// Emit a stable machine-readable lint report.
        #[arg(long)]
        json: bool,
    },
    /// Print the JSON Schema for policy test fixture files.
    Schema,
    /// Run YAML policy regression fixtures against the active home.
    Test {
        file: PathBuf,
        /// Emit a stable machine-readable fixture report.
        #[arg(long)]
        json: bool,
    },
    /// Compare two policy directories against historical audit decisions.
    Diff(PolicyDiffOptions),
    /// Suggest advisory policy rules and fixture drafts from audit decisions.
    Suggest {
        /// Audit JSONL file to inspect.
        #[arg(long, value_name = "FILE")]
        audit: PathBuf,
        /// Emit a stable machine-readable suggestion report.
        #[arg(long)]
        json: bool,
    },
    /// Capture a tool call from stdin as a YAML policy fixture.
    #[command(alias = "capture")]
    Snapshot {
        /// Stable fixture case name to write into the YAML output.
        #[arg(long)]
        name: String,
        /// Optional human-readable fixture description.
        #[arg(long)]
        description: Option<String>,
        /// Emit only the YAML case list, useful when appending to an existing file.
        #[arg(long)]
        case_only: bool,
        /// Read a PreToolUse hook payload (`tool_name` / `tool_input`) instead of a ToolCall.
        #[arg(long)]
        hook: bool,
    },
    /// Print the policy version hash.
    Hash,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PolicyTestDocument {
    Wrapped(PolicyTestFile),
    Cases(Vec<PolicyTestCase>),
}

impl PolicyTestDocument {
    fn into_parts(self) -> (Option<u32>, Vec<PolicyTestCase>) {
        match self {
            Self::Wrapped(file) => (file.version, file.cases),
            Self::Cases(cases) => (None, cases),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestFile {
    #[serde(default)]
    version: Option<u32>,
    cases: Vec<PolicyTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCase {
    name: String,
    #[serde(default)]
    description: Option<String>,
    tool: String,
    #[serde(default = "empty_json_object")]
    input: serde_json::Value,
    expect: PolicyTestExpectation,
}

fn empty_json_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyTestExpectation {
    decision: PolicyTestDecision,
    #[serde(default)]
    hard_stop: Option<bool>,
    #[serde(default)]
    required_scope: Option<String>,
    #[serde(default)]
    matched_rule: Option<String>,
}

impl PolicyTestExpectation {
    fn label(&self) -> String {
        let mut parts = vec![self.decision.as_str().to_string()];
        if let Some(hard_stop) = self.hard_stop {
            parts.push(format!("hard_stop={hard_stop}"));
        }
        if let Some(scope) = &self.required_scope {
            parts.push(format!("scope={scope}"));
        }
        if let Some(rule) = &self.matched_rule {
            parts.push(format!("matched_rule={rule}"));
        }
        parts.join(" ")
    }

    fn mismatch_errors(&self, eval: &gommage_core::EvalResult) -> Vec<String> {
        let mut errors = Vec::new();
        let actual = PolicyTestDecision::from_decision(&eval.decision);
        if self.decision != actual {
            errors.push(format!(
                "expected decision {}, got {}",
                self.decision.as_str(),
                actual.as_str()
            ));
        }

        if let Some(expected) = self.hard_stop {
            match &eval.decision {
                Decision::Gommage { hard_stop, .. } if *hard_stop == expected => {}
                Decision::Gommage { hard_stop, .. } => errors.push(format!(
                    "expected hard_stop={expected}, got hard_stop={hard_stop}"
                )),
                _ => errors.push(format!(
                    "expected hard_stop={expected}, but actual decision is {}",
                    actual.as_str()
                )),
            }
        }

        if let Some(expected) = &self.required_scope {
            match &eval.decision {
                Decision::AskPicto { required_scope, .. } if required_scope == expected => {}
                Decision::AskPicto { required_scope, .. } => errors.push(format!(
                    "expected required_scope={expected}, got required_scope={required_scope}"
                )),
                _ => errors.push(format!(
                    "expected required_scope={expected}, but actual decision is {}",
                    actual.as_str()
                )),
            }
        }

        if let Some(expected) = &self.matched_rule {
            match &eval.matched_rule {
                Some(rule) if &rule.name == expected => {}
                Some(rule) => errors.push(format!(
                    "expected matched_rule={expected}, got matched_rule={}",
                    rule.name
                )),
                None => errors.push(format!(
                    "expected matched_rule={expected}, but no rule matched"
                )),
            }
        }

        errors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyTestDecision {
    Allow,
    Gommage,
    AskPicto,
}

impl PolicyTestDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Gommage => "gommage",
            Self::AskPicto => "ask_picto",
        }
    }

    fn from_decision(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Gommage { .. } => Self::Gommage,
            Decision::AskPicto { .. } => Self::AskPicto,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyTestReport {
    pub(crate) status: SmokeStatus,
    pub(crate) fixture_file: String,
    pub(crate) home: String,
    pub(crate) policy_version: String,
    pub(crate) mapper_rules: usize,
    pub(crate) summary: SmokeSummary,
    pub(crate) cases: Vec<PolicyTestCaseResult>,
}

#[derive(Debug, Serialize)]
struct PolicyLayerReport {
    status: SmokeStatus,
    policy_version: String,
    layers: Vec<PolicyLayerEntry>,
}

#[derive(Debug, Serialize)]
struct PolicyLayerEntry {
    name: String,
    dir: String,
    files: usize,
    rules: usize,
}

impl PolicyTestReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.failed == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyTestCaseResult {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) status: SmokeStatus,
    pub(crate) expected: PolicyTestExpectation,
    pub(crate) actual: Decision,
    pub(crate) errors: Vec<String>,
    pub(crate) tool: String,
    pub(crate) input: serde_json::Value,
    pub(crate) input_hash: String,
    pub(crate) capabilities: Vec<Capability>,
    pub(crate) matched_rule: Option<MatchedRule>,
}

#[derive(Debug, Serialize)]
struct PolicyLintReport {
    status: SmokeStatus,
    target: String,
    strict: bool,
    files: usize,
    rules: usize,
    summary: PolicyLintSummary,
    issues: Vec<PolicyLintIssue>,
}

impl PolicyLintReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.errors == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct PolicyLintSummary {
    errors: usize,
    warnings: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyLintSeverity {
    Error,
    Warning,
}

impl PolicyLintSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicyLintIssue {
    severity: PolicyLintSeverity,
    code: &'static str,
    message: String,
    file: String,
    rule_name: Option<String>,
    rule_index: Option<usize>,
}

struct RawPolicyRuleRecord {
    file: PathBuf,
    file_display: String,
    index: usize,
    rule: RawRule,
}

#[derive(Debug, Serialize)]
struct PolicySnapshotDocument {
    version: u32,
    cases: Vec<PolicySnapshotCase>,
}

#[derive(Debug, Serialize)]
struct PolicySnapshotCase {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    tool: String,
    input: serde_json::Value,
    expect: PolicySnapshotExpectation,
}

#[derive(Debug, Clone, Serialize)]
struct PolicySnapshotExpectation {
    decision: PolicyTestDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    hard_stop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<String>,
}

impl PolicySnapshotExpectation {
    fn from_decision(decision: &Decision, matched_rule: Option<String>) -> Self {
        let (hard_stop, required_scope) = match decision {
            Decision::Allow => (None, None),
            Decision::Gommage { hard_stop, .. } => (Some(*hard_stop), None),
            Decision::AskPicto { required_scope, .. } => (None, Some(required_scope.clone())),
        };

        Self {
            decision: PolicyTestDecision::from_decision(decision),
            hard_stop,
            required_scope,
            matched_rule,
        }
    }

    fn from_eval(eval: &gommage_core::EvalResult) -> Self {
        Self::from_decision(
            &eval.decision,
            eval.matched_rule.as_ref().map(|rule| rule.name.clone()),
        )
    }
}

#[derive(Debug, Serialize)]
struct PolicySuggestReport {
    status: PolicySuggestStatus,
    audit: String,
    home: String,
    active_policy_version: String,
    mutated: bool,
    summary: PolicySuggestSummary,
    suggestions: Vec<PolicySuggestion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicySuggestStatus {
    Empty,
    Suggestions,
}

impl PolicySuggestStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Suggestions => "suggestions",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct PolicySuggestSummary {
    decisions: usize,
    suggestions: usize,
    evidence: usize,
    covered_by_active_policy: usize,
    skipped_empty_capabilities: usize,
    skipped_events: usize,
    skipped_blank_lines: usize,
}

#[derive(Debug, Serialize)]
struct PolicySuggestion {
    id: String,
    advisory: bool,
    review_required: bool,
    reason: String,
    warnings: Vec<String>,
    rule: RawRule,
    rule_yaml: String,
    fixture_case: PolicySuggestedFixtureCase,
    fixture_yaml: String,
    evidence: Vec<PolicySuggestionEvidence>,
}

#[derive(Debug, Serialize)]
struct PolicySuggestedFixtureCase {
    name: String,
    description: String,
    tool: String,
    input_available: bool,
    input_hash: String,
    usable: bool,
    input_note: String,
    expect: PolicySnapshotExpectation,
}

#[derive(Debug, Serialize)]
struct PolicySuggestionEvidence {
    line: usize,
    audit_id: String,
    timestamp: String,
    tool: String,
    input_hash: String,
    capabilities: Vec<Capability>,
    audited_decision: Decision,
    audited_matched_rule: Option<MatchedRule>,
    audited_policy_version: String,
    active_decision: Decision,
    active_matched_rule: Option<MatchedRule>,
    active_policy_version: String,
    expedition: Option<String>,
}

fn build_policy_snapshot_case(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
    env: &std::collections::HashMap<String, String>,
    name: String,
    description: Option<String>,
    call: ToolCall,
) -> Result<PolicySnapshotCase> {
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for policy snapshot")?;
    let policy = load_active_policy(layout, expedition, env)
        .context("loading policy for policy snapshot")?;
    let capabilities = mapper.map(&call);
    let eval = evaluate(&capabilities, &policy);

    Ok(PolicySnapshotCase {
        name,
        description,
        tool: call.tool,
        input: call.input,
        expect: PolicySnapshotExpectation::from_eval(&eval),
    })
}

fn build_policy_suggest_report(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
    env: &HashMap<String, String>,
    audit_path: &Path,
) -> Result<PolicySuggestReport> {
    let policy = load_active_policy(layout, expedition, env)
        .context("loading active policy for policy suggest")?;
    let scan = read_audit_decisions(audit_path)?;
    let mut summary = PolicySuggestSummary {
        skipped_events: scan.skipped_events,
        skipped_blank_lines: scan.skipped_blank_lines,
        ..PolicySuggestSummary::default()
    };
    let mut suggestions: Vec<PolicySuggestion> = Vec::new();
    let mut suggestion_by_key: HashMap<String, usize> = HashMap::new();

    for record in scan.decisions {
        summary.decisions += 1;
        if record.entry.capabilities.is_empty() {
            summary.skipped_empty_capabilities += 1;
            continue;
        }

        let active_eval = evaluate(&record.entry.capabilities, &policy);
        if active_eval.matched_rule.is_some() {
            summary.covered_by_active_policy += 1;
            continue;
        }

        let key = suggestion_key(
            &record.entry.tool,
            &record.entry.decision,
            &record.entry.capabilities,
        );
        let evidence = PolicySuggestionEvidence::from_record(
            &record,
            active_eval,
            policy.version_hash.clone(),
        );
        if let Some(index) = suggestion_by_key.get(&key) {
            suggestions[*index].evidence.push(evidence);
            continue;
        }

        let suggestion = build_policy_suggestion(&record, evidence)?;
        suggestion_by_key.insert(key, suggestions.len());
        suggestions.push(suggestion);
    }

    summary.suggestions = suggestions.len();
    summary.evidence = suggestions
        .iter()
        .map(|suggestion| suggestion.evidence.len())
        .sum();
    let status = if suggestions.is_empty() {
        PolicySuggestStatus::Empty
    } else {
        PolicySuggestStatus::Suggestions
    };

    Ok(PolicySuggestReport {
        status,
        audit: path_display(audit_path),
        home: path_display(&layout.root),
        active_policy_version: policy.version_hash,
        mutated: false,
        summary,
        suggestions,
    })
}

impl PolicySuggestionEvidence {
    fn from_record(
        record: &AuditDecisionLine,
        active_eval: gommage_core::EvalResult,
        active_policy_version: String,
    ) -> Self {
        Self {
            line: record.line,
            audit_id: record.entry.id.clone(),
            timestamp: record.entry.ts.clone(),
            tool: record.entry.tool.clone(),
            input_hash: record.entry.input_hash.clone(),
            capabilities: record.entry.capabilities.clone(),
            audited_decision: record.entry.decision.clone(),
            audited_matched_rule: record.entry.matched_rule.clone(),
            audited_policy_version: record.entry.policy_version.clone(),
            active_decision: active_eval.decision,
            active_matched_rule: active_eval.matched_rule,
            active_policy_version,
            expedition: record.entry.expedition.clone(),
        }
    }
}

fn build_policy_suggestion(
    record: &AuditDecisionLine,
    evidence: PolicySuggestionEvidence,
) -> Result<PolicySuggestion> {
    let entry = &record.entry;
    let rule = advisory_rule_from_audit(entry, record.line);
    let fixture_case = suggested_fixture_case(entry, &rule);
    let warnings = suggestion_warnings(&rule);
    let rule_yaml = serde_yaml::to_string(std::slice::from_ref(&rule))?
        .trim_end()
        .to_string();
    let fixture_yaml = suggested_fixture_yaml(&fixture_case)?;

    Ok(PolicySuggestion {
        id: rule.name.clone(),
        advisory: true,
        review_required: true,
        reason: format!(
            "Active policy has no matching rule for audit {} line {}; review before adding.",
            entry.id, record.line
        ),
        warnings,
        rule,
        rule_yaml,
        fixture_case,
        fixture_yaml,
        evidence: vec![evidence],
    })
}

fn advisory_rule_from_audit(entry: &gommage_audit::AuditEntry, line: usize) -> RawRule {
    let capability_patterns = sorted_capability_patterns(&entry.capabilities);
    let name = format!(
        "advisory-{}-{}-{}",
        slugify(&entry.tool),
        slugify(&audit_decision_summary(&entry.decision)),
        slugify(&entry.id)
    );
    let (decision, hard_stop, required_scope) = match &entry.decision {
        Decision::Allow => (RuleDecision::Allow, false, None),
        Decision::Gommage { hard_stop, .. } => (RuleDecision::Gommage, *hard_stop, None),
        Decision::AskPicto { required_scope, .. } => {
            (RuleDecision::AskPicto, false, Some(required_scope.clone()))
        }
    };

    RawRule {
        name,
        decision,
        hard_stop,
        required_scope,
        required_scope_from_capability: None,
        bind_input: false,
        r#match: RawMatch {
            all_capability: capability_patterns,
            ..RawMatch::default()
        },
        reason: format!(
            "Advisory suggestion from audit {} line {}; observed {} with input hash {}. Review and add a usable fixture before enabling.",
            entry.id,
            line,
            audit_decision_summary(&entry.decision),
            entry.input_hash
        ),
    }
}

fn suggested_fixture_case(
    entry: &gommage_audit::AuditEntry,
    rule: &RawRule,
) -> PolicySuggestedFixtureCase {
    PolicySuggestedFixtureCase {
        name: format!("{}_fixture", rule.name.replace('-', "_")),
        description: format!(
            "Draft fixture for {}; replace input with the captured tool payload that hashes to {}.",
            rule.name, entry.input_hash
        ),
        tool: entry.tool.clone(),
        input_available: false,
        input_hash: entry.input_hash.clone(),
        usable: false,
        input_note: "Audit decisions store input_hash and capabilities, not raw input. Capture the original tool payload with policy snapshot before using this fixture.".to_string(),
        expect: PolicySnapshotExpectation::from_decision(
            &entry.decision,
            Some(rule.name.clone()),
        ),
    }
}

fn suggested_fixture_yaml(fixture_case: &PolicySuggestedFixtureCase) -> Result<String> {
    let document = PolicySnapshotDocument {
        version: 1,
        cases: vec![PolicySnapshotCase {
            name: fixture_case.name.clone(),
            description: Some(fixture_case.description.clone()),
            tool: fixture_case.tool.clone(),
            input: serde_json::json!({
                "__replace_with_captured_input_for_hash": fixture_case.input_hash,
            }),
            expect: fixture_case.expect.clone(),
        }],
    };

    Ok(serde_yaml::to_string(&document)?.trim_end().to_string())
}

fn suggestion_key(tool: &str, decision: &Decision, capabilities: &[Capability]) -> String {
    let capabilities = sorted_capability_patterns(capabilities).join("\n");
    format!(
        "{tool}\n{}\n{capabilities}",
        audit_decision_summary(decision)
    )
}

fn sorted_capability_patterns(capabilities: &[Capability]) -> Vec<String> {
    let mut patterns: Vec<String> = capabilities
        .iter()
        .map(|capability| capability.as_str().to_string())
        .collect();
    patterns.sort();
    patterns.dedup();
    patterns
}

fn suggestion_warnings(rule: &RawRule) -> Vec<String> {
    let mut warnings = vec![
        "Generated from audited capabilities only; the audit log does not contain raw tool input."
            .to_string(),
        "all_capability rules still match calls with additional capabilities; review before enabling."
            .to_string(),
    ];

    if rule
        .r#match
        .all_capability
        .iter()
        .any(|capability| contains_glob_meta(capability))
    {
        warnings.push(
            "At least one observed capability contains glob metacharacters; tighten the pattern manually if needed."
                .to_string(),
        );
    }

    warnings
}

fn contains_glob_meta(value: &str) -> bool {
    value
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
    }

    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        slug.push_str("entry");
    }
    if slug.len() > 64 {
        slug.truncate(64);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    slug
}

mod analysis;
mod commands;

use analysis::*;
pub(crate) use analysis::{build_policy_test_report, print_policy_test_report};
use commands::*;
pub(crate) use commands::{cmd_policy, install_stdlib};
