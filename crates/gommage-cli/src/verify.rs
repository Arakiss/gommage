use anyhow::Result;
use gommage_core::runtime::{Expedition, HomeLayout, default_policy_env};
use serde::Serialize;
use std::{path::PathBuf, process::ExitCode};

use crate::{
    doctor::{DoctorReport, DoctorStatus, build_doctor_report},
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
enum VerifyStatus {
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
struct VerifyReport {
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

fn build_verify_report(layout: &HomeLayout, policy_test_files: &[PathBuf]) -> VerifyReport {
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

    let policy_env = Expedition::load(&layout.expedition_file)
        .map(|expedition| {
            expedition
                .map(|expedition| expedition.policy_env())
                .unwrap_or_else(default_policy_env)
        })
        .map_err(|error| format!("loading expedition policy environment: {error}"));

    let mut policy_tests = Vec::new();
    for file in policy_test_files {
        let section = match &policy_env {
            Ok(env) => match build_policy_test_report(layout, env, file) {
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
            },
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
    println!(
        "{} doctor: {} failure(s), {} warning(s)",
        report.doctor.status.as_str(),
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
            report.smoke.status.as_str(),
            smoke.summary.passed,
            smoke.summary.failed
        ),
        (None, Some(error)) => println!("{} smoke: {error}", report.smoke.status.as_str()),
        (None, None) => println!("{} smoke: missing report", report.smoke.status.as_str()),
    }

    for section in &report.policy_tests {
        match (&section.report, &section.error) {
            (Some(policy), _) => println!(
                "{} policy test {}: {} passed, {} failed",
                section.status.as_str(),
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
}
