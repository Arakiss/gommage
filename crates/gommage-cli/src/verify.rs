use anyhow::Result;
use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env};
use serde::Serialize;
use std::{path::PathBuf, process::ExitCode};

use crate::{
    doctor::{DoctorReport, DoctorStatus, build_doctor_report},
    gestral::{UiTone, color_enabled, paint},
    policy_cmd::{PolicyTestReport, build_policy_test_report},
    smoke::{SmokeReport, SmokeStatus, build_smoke_report},
    util::path_display,
};

pub(crate) fn cmd_verify(
    layout: HomeLayout,
    json: bool,
    policy_tests: Vec<PathBuf>,
) -> Result<ExitCode> {
    let report = build_verify_report(&layout, &policy_tests);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_verify_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerifyStatus {
    Pass,
    Warn,
    Skip,
    Fail,
}

impl VerifyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Skip => "skip",
            Self::Fail => "fail",
        }
    }

    fn from_doctor(status: DoctorStatus) -> Self {
        match status {
            DoctorStatus::Ok => Self::Pass,
            DoctorStatus::Warn => Self::Warn,
            DoctorStatus::Fail => Self::Fail,
        }
    }

    fn from_smoke(status: SmokeStatus) -> Self {
        match status {
            SmokeStatus::Pass => Self::Pass,
            SmokeStatus::Fail => Self::Fail,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyReport {
    status: VerifyStatus,
    home: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    summary: VerifySummary,
    doctor: VerifySection<DoctorReport>,
    smoke: VerifySection<SmokeReport>,
    policy_tests: Vec<VerifyPolicyTestSection>,
}

impl VerifyReport {
    fn exit_code(&self) -> ExitCode {
        if self.status == VerifyStatus::Fail {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct VerifySummary {
    failures: usize,
    warnings: usize,
    policy_tests: usize,
}

#[derive(Debug, Serialize)]
struct VerifySection<T: Serialize> {
    status: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyPolicyTestSection {
    file: String,
    status: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<PolicyTestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub(crate) fn build_verify_report(
    layout: &HomeLayout,
    policy_test_files: &[PathBuf],
) -> VerifyReport {
    let mut summary = VerifySummary {
        policy_tests: policy_test_files.len(),
        ..VerifySummary::default()
    };

    let doctor_report = build_doctor_report(layout);
    let doctor_status = VerifyStatus::from_doctor(doctor_report.status);
    push_verify_status(&mut summary, doctor_status);
    let doctor = VerifySection {
        status: doctor_status,
        report: Some(doctor_report),
        error: None,
    };

    let hint = preinit_hint(layout, doctor_status);
    let smoke = if doctor_status == VerifyStatus::Fail {
        VerifySection {
            status: VerifyStatus::Skip,
            report: None,
            error: Some(format!(
                "skipped: doctor failed{}",
                hint.as_ref()
                    .map(|hint| format!("; {hint}"))
                    .unwrap_or_default()
            )),
        }
    } else {
        match build_smoke_report(layout) {
            Ok(report) => {
                let status = VerifyStatus::from_smoke(report.status);
                push_verify_status(&mut summary, status);
                VerifySection {
                    status,
                    report: Some(report),
                    error: None,
                }
            }
            Err(error) => {
                push_verify_status(&mut summary, VerifyStatus::Fail);
                VerifySection {
                    status: VerifyStatus::Fail,
                    report: None,
                    error: Some(error.to_string()),
                }
            }
        }
    };

    let policy_context = Expedition::load(&layout.expedition_file)
        .map(|expedition| {
            let env = expedition
                .as_ref()
                .map(Expedition::policy_env)
                .unwrap_or_else(default_policy_env);
            (expedition, env)
        })
        .map_err(|error| format!("loading expedition policy environment: {error}"));

    let mut policy_tests = Vec::new();
    for file in policy_test_files {
        let section = match &policy_context {
            Ok((expedition, env)) => {
                match build_policy_test_report(layout, expedition.as_ref(), env, file) {
                    Ok(report) => {
                        let status = VerifyStatus::from_smoke(report.status);
                        VerifyPolicyTestSection {
                            file: path_display(file),
                            status,
                            report: Some(report),
                            error: None,
                        }
                    }
                    Err(error) => VerifyPolicyTestSection {
                        file: path_display(file),
                        status: VerifyStatus::Fail,
                        report: None,
                        error: Some(error.to_string()),
                    },
                }
            }
            Err(error) => VerifyPolicyTestSection {
                file: path_display(file),
                status: VerifyStatus::Fail,
                report: None,
                error: Some(error.clone()),
            },
        };
        push_verify_status(&mut summary, section.status);
        policy_tests.push(section);
    }

    VerifyReport {
        status: if summary.failures > 0 {
            VerifyStatus::Fail
        } else if summary.warnings > 0 {
            VerifyStatus::Warn
        } else {
            VerifyStatus::Pass
        },
        home: path_display(&layout.root),
        hint,
        summary,
        doctor,
        smoke,
        policy_tests,
    }
}

fn push_verify_status(summary: &mut VerifySummary, status: VerifyStatus) {
    match status {
        VerifyStatus::Pass => {}
        VerifyStatus::Warn => summary.warnings += 1,
        VerifyStatus::Skip => {}
        VerifyStatus::Fail => summary.failures += 1,
    }
}

fn preinit_hint(layout: &HomeLayout, doctor_status: VerifyStatus) -> Option<String> {
    if doctor_status != VerifyStatus::Fail {
        return None;
    }
    if !layout.root.exists() || !layout.policy_dir.exists() || !layout.key_file.exists() {
        Some("run 'gommage init' or 'gommage quickstart' first".to_string())
    } else {
        None
    }
}

fn print_verify_report(report: &VerifyReport) {
    let colors = color_enabled();
    println!("Gommage verify");
    println!(
        "status: {}",
        paint(
            report.status.as_str(),
            verify_tone(report.status),
            true,
            colors
        )
    );
    println!("home: {}", report.home);
    if let Some(hint) = &report.hint {
        println!("hint: {hint}");
    }
    println!();

    println!(
        "{} doctor: {} failure(s), {} warning(s)",
        status_text(report.doctor.status, colors),
        report
            .doctor
            .report
            .as_ref()
            .map(|doctor| doctor.summary.failures)
            .unwrap_or(1),
        report
            .doctor
            .report
            .as_ref()
            .map(|doctor| doctor.summary.warnings)
            .unwrap_or(0)
    );

    match (&report.smoke.report, &report.smoke.error) {
        (Some(smoke), _) => println!(
            "{} smoke: {} passed, {} failed",
            status_text(report.smoke.status, colors),
            smoke.summary.passed,
            smoke.summary.failed
        ),
        (None, Some(error)) => println!(
            "{} smoke: {error}",
            status_text(report.smoke.status, colors)
        ),
        (None, None) => println!(
            "{} smoke: missing report",
            status_text(report.smoke.status, colors)
        ),
    }

    for section in &report.policy_tests {
        match (&section.report, &section.error) {
            (Some(policy), _) => println!(
                "{} policy test {}: {} passed, {} failed",
                status_text(section.status, colors),
                section.file,
                policy.summary.passed,
                policy.summary.failed
            ),
            (None, Some(error)) => println!("fail policy test {}: {error}", section.file),
            (None, None) => println!("fail policy test {}: missing report", section.file),
        }
    }

    println!(
        "summary: {} failure(s), {} warning(s), {} policy test file(s)",
        report.summary.failures, report.summary.warnings, report.summary.policy_tests
    );

    let next = verify_next_actions(report);
    if !next.is_empty() {
        println!();
        println!("{}", paint("next:", UiTone::Gold, true, colors));
        for (index, action) in next.iter().enumerate() {
            println!("{}. {action}", index + 1);
        }
    }
}

fn status_text(status: VerifyStatus, colors: bool) -> String {
    paint(status.as_str(), verify_tone(status), true, colors)
}

fn verify_tone(status: VerifyStatus) -> UiTone {
    match status {
        VerifyStatus::Pass => UiTone::Green,
        VerifyStatus::Warn => UiTone::Gold,
        VerifyStatus::Skip => UiTone::Muted,
        VerifyStatus::Fail => UiTone::Red,
    }
}

fn verify_next_actions(report: &VerifyReport) -> Vec<String> {
    let mut actions = Vec::new();
    if report.status == VerifyStatus::Pass {
        return actions;
    }
    if report.doctor.status == VerifyStatus::Fail {
        actions.push(
            report
                .hint
                .as_ref()
                .map(|_| "gommage quickstart --agent claude --daemon --self-test".to_string())
                .unwrap_or_else(|| "gommage doctor --json".to_string()),
        );
    }
    if report.smoke.status == VerifyStatus::Fail {
        actions.push("gommage smoke --json".to_string());
    }
    if report
        .policy_tests
        .iter()
        .any(|test| test.status == VerifyStatus::Fail)
    {
        actions.push("gommage policy test <fixture.yaml> --json".to_string());
    }
    if report.status == VerifyStatus::Warn {
        actions.push("gommage doctor --json".to_string());
    }
    actions.push("gommage tui --snapshot".to_string());
    actions.sort();
    actions.dedup();
    actions.truncate(4);
    actions
}
