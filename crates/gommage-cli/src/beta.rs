use anyhow::Result;
use clap::Subcommand;
use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env};
use serde::Serialize;
use std::{path::PathBuf, process::ExitCode};

use crate::{
    agent::AgentKind,
    agent_status::{AgentStatus, build_agent_status_report},
    doctor::{DoctorStatus, build_doctor_report},
    gestral::{UiTone, color_enabled, paint},
    policy_cmd::build_policy_test_report,
    smoke::{SmokeStatus, build_smoke_report},
    util::path_display,
};

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum BetaCmd {
    /// Run the beta-readiness gate without mutating host configuration.
    Check {
        /// Agent integrations to validate. Defaults to claude.
        #[arg(long = "agent", value_enum)]
        agents: Vec<AgentKind>,
        /// Include repository-owned policy regression fixtures.
        #[arg(long = "policy-test", value_name = "FILE")]
        policy_tests: Vec<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn cmd_beta(cmd: BetaCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        BetaCmd::Check {
            agents,
            policy_tests,
            json,
        } => beta_check(layout, agents, policy_tests, json),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BetaStatus {
    Pass,
    Warn,
    Skip,
    Fail,
}

impl BetaStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Skip => "skip",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
struct BetaReport {
    status: BetaStatus,
    version: String,
    home: String,
    summary: BetaSummary,
    checks: Vec<BetaCheck>,
    next: Vec<String>,
}

impl BetaReport {
    fn exit_code(&self) -> ExitCode {
        if self.status == BetaStatus::Fail {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct BetaSummary {
    passed: usize,
    warnings: usize,
    skipped: usize,
    failed: usize,
}

#[derive(Debug, Serialize)]
struct BetaCheck {
    name: String,
    status: BetaStatus,
    message: String,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

fn beta_check(
    layout: HomeLayout,
    agents: Vec<AgentKind>,
    policy_tests: Vec<PathBuf>,
    json: bool,
) -> Result<ExitCode> {
    let report = build_beta_report(&layout, agents, &policy_tests);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_beta_report(&report);
    }
    Ok(report.exit_code())
}

fn build_beta_report(
    layout: &HomeLayout,
    agents: Vec<AgentKind>,
    policy_tests: &[PathBuf],
) -> BetaReport {
    let mut checks = Vec::new();
    let doctor = build_doctor_report(layout);
    checks.push(BetaCheck {
        name: "doctor".to_string(),
        status: beta_status_from_doctor(doctor.status),
        message: format!(
            "{} failure(s), {} warning(s)",
            doctor.summary.failures, doctor.summary.warnings
        ),
        command: "gommage doctor --json".to_string(),
        details: Some(serde_json::json!({
            "status": doctor.status,
            "failures": doctor.summary.failures,
            "warnings": doctor.summary.warnings,
        })),
    });

    if doctor.status == DoctorStatus::Fail {
        checks.push(BetaCheck {
            name: "smoke".to_string(),
            status: BetaStatus::Skip,
            message: "skipped because doctor failed".to_string(),
            command: "gommage smoke --json".to_string(),
            details: None,
        });
    } else {
        match build_smoke_report(layout) {
            Ok(smoke) => checks.push(BetaCheck {
                name: "smoke".to_string(),
                status: beta_status_from_smoke(smoke.status),
                message: format!(
                    "{} passed, {} failed, {} mapper rules",
                    smoke.summary.passed, smoke.summary.failed, smoke.mapper_rules
                ),
                command: "gommage smoke --json".to_string(),
                details: Some(serde_json::json!({
                    "status": smoke.status,
                    "passed": smoke.summary.passed,
                    "failed": smoke.summary.failed,
                    "mapper_rules": smoke.mapper_rules,
                })),
            }),
            Err(error) => checks.push(BetaCheck {
                name: "smoke".to_string(),
                status: BetaStatus::Fail,
                message: error.to_string(),
                command: "gommage smoke --json".to_string(),
                details: None,
            }),
        }
    }

    for agent in normalize_agents(agents) {
        let report = build_agent_status_report(agent, layout);
        checks.push(BetaCheck {
            name: format!("agent {}", agent.as_str()),
            status: beta_status_from_agent(report.status()),
            message: format!(
                "{} failure(s), {} warning(s)",
                report.failures(),
                report.warnings()
            ),
            command: format!("gommage agent status {} --json", agent.as_str()),
            details: Some(serde_json::json!({
                "status": report.status(),
                "failures": report.failures(),
                "warnings": report.warnings(),
            })),
        });
    }

    push_policy_fixture_checks(layout, policy_tests, &mut checks);

    checks.push(BetaCheck {
        name: "operator dashboard".to_string(),
        status: BetaStatus::Pass,
        message: "snapshot, watch, and stream commands are available".to_string(),
        command: "gommage tui --snapshot --view all".to_string(),
        details: Some(serde_json::json!({
            "watch": "gommage tui --watch --watch-ticks 2 --view approvals",
            "stream": "gommage tui --stream --stream-ticks 3",
        })),
    });

    let summary = summarize(&checks);
    let status = overall_status(&summary);
    let next = beta_next_actions(&checks, status);

    BetaReport {
        status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        home: path_display(&layout.root),
        summary,
        checks,
        next,
    }
}

fn push_policy_fixture_checks(
    layout: &HomeLayout,
    policy_tests: &[PathBuf],
    checks: &mut Vec<BetaCheck>,
) {
    if policy_tests.is_empty() {
        checks.push(BetaCheck {
            name: "policy fixtures".to_string(),
            status: BetaStatus::Skip,
            message: "no --policy-test fixtures provided".to_string(),
            command: "gommage beta check --policy-test examples/policy-fixtures.yaml --json"
                .to_string(),
            details: None,
        });
        return;
    }

    let env = Expedition::load(&layout.expedition_file)
        .map(|expedition| {
            expedition
                .map(|expedition| expedition.policy_env())
                .unwrap_or_else(default_policy_env)
        })
        .map_err(|error| format!("loading expedition policy environment: {error}"));

    for file in policy_tests {
        let (status, message, details) = match &env {
            Ok(env) => match build_policy_test_report(layout, env, file) {
                Ok(report) => (
                    beta_status_from_smoke(report.status),
                    format!(
                        "{} passed, {} failed",
                        report.summary.passed, report.summary.failed
                    ),
                    Some(serde_json::json!({
                        "status": report.status,
                        "passed": report.summary.passed,
                        "failed": report.summary.failed,
                    })),
                ),
                Err(error) => (BetaStatus::Fail, error.to_string(), None),
            },
            Err(error) => (BetaStatus::Fail, error.clone(), None),
        };
        checks.push(BetaCheck {
            name: format!("policy fixture {}", path_display(file)),
            status,
            message,
            command: format!("gommage policy test {} --json", path_display(file)),
            details,
        });
    }
}

fn normalize_agents(mut agents: Vec<AgentKind>) -> Vec<AgentKind> {
    if agents.is_empty() {
        agents.push(AgentKind::Claude);
    }
    agents.sort_by_key(|agent| agent.as_str());
    agents.dedup();
    agents
}

fn beta_status_from_doctor(status: DoctorStatus) -> BetaStatus {
    match status {
        DoctorStatus::Ok => BetaStatus::Pass,
        DoctorStatus::Warn => BetaStatus::Warn,
        DoctorStatus::Fail => BetaStatus::Fail,
    }
}

fn beta_status_from_smoke(status: SmokeStatus) -> BetaStatus {
    match status {
        SmokeStatus::Pass => BetaStatus::Pass,
        SmokeStatus::Fail => BetaStatus::Fail,
    }
}

fn beta_status_from_agent(status: AgentStatus) -> BetaStatus {
    match status {
        AgentStatus::Ok => BetaStatus::Pass,
        AgentStatus::Warn => BetaStatus::Warn,
        AgentStatus::Fail => BetaStatus::Fail,
    }
}

fn summarize(checks: &[BetaCheck]) -> BetaSummary {
    let mut summary = BetaSummary::default();
    for check in checks {
        match check.status {
            BetaStatus::Pass => summary.passed += 1,
            BetaStatus::Warn => summary.warnings += 1,
            BetaStatus::Skip => summary.skipped += 1,
            BetaStatus::Fail => summary.failed += 1,
        }
    }
    summary
}

fn overall_status(summary: &BetaSummary) -> BetaStatus {
    if summary.failed > 0 {
        BetaStatus::Fail
    } else if summary.warnings > 0 || summary.skipped > 0 {
        BetaStatus::Warn
    } else {
        BetaStatus::Pass
    }
}

fn beta_next_actions(checks: &[BetaCheck], status: BetaStatus) -> Vec<String> {
    let mut actions = Vec::new();
    if status == BetaStatus::Pass {
        actions.push("gommage tui --stream --stream-ticks 3".to_string());
        return actions;
    }
    if checks
        .iter()
        .any(|check| check.name == "doctor" && check.status == BetaStatus::Fail)
    {
        actions.push("gommage quickstart --agent claude --daemon --self-test".to_string());
    }
    for check in checks
        .iter()
        .filter(|check| check.status == BetaStatus::Fail)
    {
        actions.push(check.command.clone());
    }
    if checks.iter().any(|check| check.status == BetaStatus::Warn) {
        actions.push("gommage doctor --json".to_string());
    }
    if checks.iter().any(|check| check.status == BetaStatus::Skip) {
        actions.push(
            "gommage beta check --policy-test examples/policy-fixtures.yaml --json".to_string(),
        );
    }
    actions.push("gommage tui --snapshot --view all".to_string());
    actions.sort();
    actions.dedup();
    actions.truncate(6);
    actions
}

fn print_beta_report(report: &BetaReport) {
    let colors = color_enabled();
    println!("Gommage beta readiness");
    println!(
        "status: {}",
        paint(
            report.status.as_str(),
            beta_tone(report.status),
            true,
            colors
        )
    );
    println!("version: {}", report.version);
    println!("home: {}", report.home);
    println!(
        "summary: {} pass, {} warn, {} skip, {} fail",
        report.summary.passed,
        report.summary.warnings,
        report.summary.skipped,
        report.summary.failed
    );
    println!("checks:");
    for check in &report.checks {
        println!(
            "- {} [{}] {}",
            check.name,
            paint(check.status.as_str(), beta_tone(check.status), true, colors),
            check.message
        );
    }
    if !report.next.is_empty() {
        println!("next:");
        for (index, action) in report.next.iter().enumerate() {
            println!("{}. {action}", index + 1);
        }
    }
}

fn beta_tone(status: BetaStatus) -> UiTone {
    match status {
        BetaStatus::Pass => UiTone::Green,
        BetaStatus::Warn => UiTone::Gold,
        BetaStatus::Skip => UiTone::Muted,
        BetaStatus::Fail => UiTone::Red,
    }
}
