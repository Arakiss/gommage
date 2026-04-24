use anyhow::{Context, Result};
use clap::Subcommand;
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, default_policy_env},
};
use gommage_stdlib::{
    CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES, StdlibFile,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    input::read_tool_call_from_stdin,
    policy_diff::{PolicyDiffOptions, cmd_policy_diff},
    smoke::{SmokeStatus, SmokeSummary},
    util::path_display,
};

const POLICY_FIXTURE_SCHEMA: &str = include_str!("../schemas/policy-fixture.schema.json");

#[derive(Subcommand)]
pub(crate) enum PolicyCmd {
    /// Initialize policy.d/ and capabilities.d/ from the embedded stdlib.
    Init {
        #[arg(long)]
        stdlib: bool,
        #[arg(long)]
        force: bool,
    },
    /// Parse and compile every policy file under policy.d/.
    Check,
    /// Parse a single file.
    Lint { file: PathBuf },
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

#[derive(Debug, Serialize)]
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
    fn from_eval(eval: &gommage_core::EvalResult) -> Self {
        let (hard_stop, required_scope) = match &eval.decision {
            Decision::Allow => (None, None),
            Decision::Gommage { hard_stop, .. } => (Some(*hard_stop), None),
            Decision::AskPicto { required_scope, .. } => (None, Some(required_scope.clone())),
        };

        Self {
            decision: PolicyTestDecision::from_decision(&eval.decision),
            hard_stop,
            required_scope,
            matched_rule: eval.matched_rule.as_ref().map(|rule| rule.name.clone()),
        }
    }
}

fn build_policy_snapshot_case(
    layout: &HomeLayout,
    env: &std::collections::HashMap<String, String>,
    name: String,
    description: Option<String>,
    call: ToolCall,
) -> Result<PolicySnapshotCase> {
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for policy snapshot")?;
    let policy = Policy::load_from_dir(&layout.policy_dir, env)
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

pub(crate) fn build_policy_test_report(
    layout: &HomeLayout,
    env: &std::collections::HashMap<String, String>,
    file: &Path,
) -> Result<PolicyTestReport> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("reading policy test fixture {}", file.display()))?;
    let document: PolicyTestDocument = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing policy test fixture {}", file.display()))?;
    let (version, cases) = document.into_parts();
    if let Some(version) = version
        && version != 1
    {
        anyhow::bail!("unsupported policy test fixture version {version}; expected 1");
    }
    if cases.is_empty() {
        anyhow::bail!("policy test fixture {} has no cases", file.display());
    }

    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for policy test")?;
    let policy =
        Policy::load_from_dir(&layout.policy_dir, env).context("loading policy for policy test")?;

    let mut results = Vec::new();
    let mut summary = SmokeSummary::default();
    for case in cases {
        let call = ToolCall {
            tool: case.tool,
            input: case.input,
        };
        let capabilities = mapper.map(&call);
        let eval = evaluate(&capabilities, &policy);
        let input_hash = call.input_hash();
        let errors = case.expect.mismatch_errors(&eval);
        let status = if errors.is_empty() {
            summary.passed += 1;
            SmokeStatus::Pass
        } else {
            summary.failed += 1;
            SmokeStatus::Fail
        };

        results.push(PolicyTestCaseResult {
            name: case.name,
            description: case.description,
            status,
            expected: case.expect,
            actual: eval.decision,
            errors,
            tool: call.tool,
            input: call.input,
            input_hash,
            capabilities: eval.capabilities,
            matched_rule: eval.matched_rule,
        });
    }

    Ok(PolicyTestReport {
        status: if summary.failed == 0 {
            SmokeStatus::Pass
        } else {
            SmokeStatus::Fail
        },
        fixture_file: path_display(file),
        home: path_display(&layout.root),
        policy_version: policy.version_hash,
        mapper_rules: mapper.rule_count(),
        summary,
        cases: results,
    })
}

pub(crate) fn print_policy_test_report(report: &PolicyTestReport) {
    for case in &report.cases {
        println!(
            "{} {}: expected {}, got {}",
            case.status.as_str(),
            case.name,
            case.expected.label(),
            decision_summary(&case.actual)
        );
        for error in &case.errors {
            println!("  - {error}");
        }
    }
    println!(
        "summary: {} passed, {} failed ({}; {} mapper rules)",
        report.summary.passed, report.summary.failed, report.policy_version, report.mapper_rules
    );
}

pub(crate) fn cmd_policy(sub: PolicyCmd, layout: HomeLayout) -> Result<ExitCode> {
    let sub = match sub {
        PolicyCmd::Schema => {
            println!("{}", POLICY_FIXTURE_SCHEMA.trim_end());
            return Ok(ExitCode::SUCCESS);
        }
        PolicyCmd::Diff(options) => return cmd_policy_diff(options),
        sub => sub,
    };

    layout.ensure()?;
    let env = Expedition::load(&layout.expedition_file)?
        .map(|e| e.policy_env())
        .unwrap_or_else(default_policy_env);
    match sub {
        PolicyCmd::Init { stdlib, force } => {
            if !stdlib {
                anyhow::bail!("policy init currently requires --stdlib");
            }
            let installed = install_stdlib(&layout, force)?;
            println!(
                "ok stdlib installed: {} policy files, {} capability files",
                installed.0, installed.1
            );
        }
        PolicyCmd::Check => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("ok {} rules loaded", pol.rules.len());
            println!("version: {}", pol.version_hash);
        }
        PolicyCmd::Lint { file } => {
            let raw = std::fs::read_to_string(&file)?;
            let _ = Policy::from_yaml_string(&raw, &env, &file.to_string_lossy())?;
            println!("ok {}", file.display());
        }
        PolicyCmd::Schema => unreachable!("policy schema returns before home validation"),
        PolicyCmd::Diff(_) => unreachable!("policy diff returns before home validation"),
        PolicyCmd::Test { file, json } => {
            let report = build_policy_test_report(&layout, &env, &file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_test_report(&report);
            }
            return Ok(report.exit_code());
        }
        PolicyCmd::Snapshot {
            name,
            description,
            case_only,
            hook,
        } => {
            let call = read_tool_call_from_stdin(hook)?;
            let case = build_policy_snapshot_case(&layout, &env, name, description, call)?;
            if case_only {
                println!("{}", serde_yaml::to_string(&[case])?.trim_end());
            } else {
                let document = PolicySnapshotDocument {
                    version: 1,
                    cases: vec![case],
                };
                println!("{}", serde_yaml::to_string(&document)?.trim_end());
            }
        }
        PolicyCmd::Hash => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("{}", pol.version_hash);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn install_stdlib(layout: &HomeLayout, force: bool) -> Result<(usize, usize)> {
    let policies = install_embedded_files(&layout.policy_dir, STDLIB_POLICIES, force)?;
    let capabilities =
        install_embedded_files(&layout.capabilities_dir, STDLIB_CAPABILITIES, force)?;
    Ok((policies, capabilities))
}

fn install_embedded_files(dir: &Path, files: &[StdlibFile], force: bool) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut installed = 0usize;
    for file in files {
        let path = dir.join(file.name);
        if path.exists() && !force {
            continue;
        }
        std::fs::write(path, file.contents)?;
        installed += 1;
    }
    Ok(installed)
}

fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::AskPicto { required_scope, .. } => format!("ask:{required_scope}"),
        Decision::Gommage {
            hard_stop, reason, ..
        } => {
            if *hard_stop {
                format!("hard_stop:{reason}")
            } else {
                format!("gommage:{reason}")
            }
        }
    }
}
