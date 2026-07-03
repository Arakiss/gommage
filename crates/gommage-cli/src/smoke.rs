use anyhow::{Context, Result};
use gommage_core::{
    Capability, Decision, MatchedRule, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, default_policy_env},
};
use serde::Serialize;
use std::process::ExitCode;

use crate::{input::bash_call, util::path_display};

pub(crate) fn cmd_smoke(layout: HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_smoke_report(&layout)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_smoke_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SmokeStatus {
    Pass,
    Warn,
    Fail,
}

impl SmokeStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SmokeReport {
    pub(crate) status: SmokeStatus,
    home: String,
    policy_version: String,
    pub(crate) mapper_rules: usize,
    pub(crate) summary: SmokeSummary,
    checks: Vec<SmokeCheck>,
}

impl SmokeReport {
    fn exit_code(&self) -> ExitCode {
        if self.status != SmokeStatus::Fail {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct SmokeSummary {
    pub(crate) passed: usize,
    pub(crate) warnings: usize,
    pub(crate) failed: usize,
}

#[derive(Debug, Serialize)]
struct SmokeCheck {
    name: &'static str,
    description: &'static str,
    status: SmokeStatus,
    expected: String,
    actual: Decision,
    tool: String,
    input: serde_json::Value,
    input_hash: String,
    capabilities: Vec<Capability>,
    matched_rule: Option<MatchedRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

struct SmokeFixture {
    name: &'static str,
    description: &'static str,
    call: ToolCall,
    expectation: SmokeExpectation,
    allow_local_relaxation: bool,
}

enum SmokeExpectation {
    Allow,
    Gommage { hard_stop: Option<bool> },
    AskPicto { scope: &'static str },
}

impl SmokeExpectation {
    fn label(&self) -> String {
        match self {
            Self::Allow => "allow".to_string(),
            Self::Gommage {
                hard_stop: Some(value),
            } => format!("gommage hard_stop={value}"),
            Self::Gommage { hard_stop: None } => "gommage".to_string(),
            Self::AskPicto { scope } => format!("ask_picto scope={scope}"),
        }
    }

    fn matches(&self, decision: &Decision) -> bool {
        match (self, decision) {
            (Self::Allow, Decision::Allow) => true,
            (
                Self::Gommage {
                    hard_stop: expected,
                },
                Decision::Gommage { hard_stop, .. },
            ) => expected.is_none_or(|expected| expected == *hard_stop),
            (Self::AskPicto { scope }, Decision::AskPicto { required_scope, .. }) => {
                required_scope == scope
            }
            _ => false,
        }
    }

    fn local_relaxation_warning(
        &self,
        decision: &Decision,
        matched_rule: Option<&MatchedRule>,
    ) -> Option<String> {
        match (self, decision, matched_rule) {
            (Self::AskPicto { scope }, Decision::Allow, Some(rule)) => Some(format!(
                "local policy relaxed the stdlib gate for {scope} via rule {} ({}:{})",
                rule.name, rule.file, rule.index
            )),
            _ => None,
        }
    }
}

pub(crate) fn build_smoke_report(layout: &HomeLayout) -> Result<SmokeReport> {
    let env = Expedition::load(&layout.expedition_file)?
        .map(|expedition| expedition.policy_env())
        .unwrap_or_else(default_policy_env);
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for smoke tests")?;
    let policy = Policy::load_from_dir(&layout.policy_dir, &env)
        .context("loading policy for smoke tests")?;

    let mut checks = Vec::new();
    let mut summary = SmokeSummary::default();
    for fixture in smoke_fixtures() {
        let capabilities = mapper.map(&fixture.call);
        let eval = evaluate(&capabilities, &policy);
        let warning = if fixture.allow_local_relaxation {
            fixture
                .expectation
                .local_relaxation_warning(&eval.decision, eval.matched_rule.as_ref())
        } else {
            None
        };
        let status = if fixture.expectation.matches(&eval.decision) {
            summary.passed += 1;
            SmokeStatus::Pass
        } else if warning.is_some() {
            summary.warnings += 1;
            SmokeStatus::Warn
        } else {
            summary.failed += 1;
            SmokeStatus::Fail
        };

        checks.push(SmokeCheck {
            name: fixture.name,
            description: fixture.description,
            status,
            expected: fixture.expectation.label(),
            actual: eval.decision,
            tool: fixture.call.tool.clone(),
            input: fixture.call.input.clone(),
            input_hash: fixture.call.input_hash(),
            capabilities: eval.capabilities,
            matched_rule: eval.matched_rule,
            warning,
        });
    }

    Ok(SmokeReport {
        status: if summary.failed > 0 {
            SmokeStatus::Fail
        } else if summary.warnings > 0 {
            SmokeStatus::Warn
        } else {
            SmokeStatus::Pass
        },
        home: path_display(&layout.root),
        policy_version: policy.version_hash,
        mapper_rules: mapper.rule_count(),
        summary,
        checks,
    })
}

fn smoke_fixtures() -> Vec<SmokeFixture> {
    vec![
        SmokeFixture {
            name: "hardstop_rm_root",
            description: "compiled hard-stop blocks destructive root deletion",
            call: bash_call("rm -rf /"),
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(true),
            },
            allow_local_relaxation: false,
        },
        SmokeFixture {
            name: "fail_closed_unmapped_tool",
            description: "unmapped tools deny when no capability or policy rule matches",
            call: ToolCall {
                tool: "UnknownTool".to_string(),
                input: serde_json::json!({}),
            },
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(false),
            },
            allow_local_relaxation: false,
        },
        SmokeFixture {
            name: "allow_feature_push",
            description: "feature-style branch pushes are allowed by stdlib policy",
            call: bash_call("git push origin chore/test-branch"),
            expectation: SmokeExpectation::Allow,
            allow_local_relaxation: false,
        },
        SmokeFixture {
            name: "ask_main_push",
            description: "main branch pushes require a git.push:main picto",
            call: bash_call("git push origin main"),
            expectation: SmokeExpectation::AskPicto {
                scope: "git.push:main",
            },
            allow_local_relaxation: true,
        },
        SmokeFixture {
            name: "gate_force_push",
            description: "force pushes are deny-by-default but unlockable with a git.push.force picto",
            call: bash_call("git push --force origin main"),
            expectation: SmokeExpectation::AskPicto {
                scope: "git.push.force",
            },
            allow_local_relaxation: false,
        },
        SmokeFixture {
            name: "ask_web_fetch",
            description: "agent-native WebFetch crosses the local trust boundary",
            call: ToolCall {
                tool: "WebFetch".to_string(),
                input: serde_json::json!({ "url": "https://example.com/docs" }),
            },
            expectation: SmokeExpectation::AskPicto { scope: "net.fetch" },
            allow_local_relaxation: true,
        },
        SmokeFixture {
            name: "ask_mcp_write",
            description: "write-like MCP tools require explicit approval",
            call: ToolCall {
                tool: "mcp__github__create_issue".to_string(),
                input: serde_json::json!({ "title": "smoke" }),
            },
            expectation: SmokeExpectation::AskPicto { scope: "mcp.write" },
            allow_local_relaxation: true,
        },
        SmokeFixture {
            name: "deny_unparsed_apply_patch",
            description: "unparsed Codex apply_patch payloads fail closed",
            call: ToolCall {
                tool: "apply_patch".to_string(),
                input: serde_json::json!({ "__gommage_patch_unparsed": true }),
            },
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(false),
            },
            allow_local_relaxation: false,
        },
    ]
}

fn print_smoke_report(report: &SmokeReport) {
    for check in &report.checks {
        println!(
            "{} {}: expected {}, got {}",
            check.status.as_str(),
            check.name,
            check.expected,
            decision_summary(&check.actual)
        );
        if let Some(warning) = &check.warning {
            println!("  warning: {warning}");
        }
    }
    println!(
        "summary: {} passed, {} warnings, {} failed ({}; {} mapper rules)",
        report.summary.passed,
        report.summary.warnings,
        report.summary.failed,
        report.policy_version,
        report.mapper_rules
    );
}

fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::Gommage { hard_stop, reason } => {
            format!("gommage hard_stop={hard_stop} reason={reason:?}")
        }
        Decision::AskPicto {
            required_scope,
            reason,
        } => {
            format!("ask_picto scope={required_scope} reason={reason:?}")
        }
    }
}
