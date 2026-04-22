use anyhow::Result;
use gommage_audit::verify_log;
use gommage_core::{
    Policy,
    runtime::{Expedition, HomeLayout, default_policy_env},
};
use serde::Serialize;
use std::{path::Path, process::ExitCode};

use crate::util::{path_details, path_display};

pub(crate) fn cmd_doctor(layout: HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_doctor_report(&layout);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_doctor_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) status: DoctorStatus,
    home: String,
    pub(crate) summary: DoctorSummary,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new(layout: &HomeLayout) -> Self {
        Self {
            status: DoctorStatus::Ok,
            home: path_display(&layout.root),
            summary: DoctorSummary::default(),
            checks: Vec::new(),
        }
    }

    fn push(
        &mut self,
        name: impl Into<String>,
        status: DoctorStatus,
        message: impl Into<String>,
        details: Option<serde_json::Value>,
    ) {
        match status {
            DoctorStatus::Ok => {}
            DoctorStatus::Warn => self.summary.warnings += 1,
            DoctorStatus::Fail => self.summary.failures += 1,
        }
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            message: message.into(),
            details,
        });
        self.status = if self.summary.failures > 0 {
            DoctorStatus::Fail
        } else if self.summary.warnings > 0 {
            DoctorStatus::Warn
        } else {
            DoctorStatus::Ok
        };
    }

    fn exit_code(&self) -> ExitCode {
        if self.summary.failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct DoctorSummary {
    pub(crate) failures: usize,
    pub(crate) warnings: usize,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

pub(crate) fn build_doctor_report(layout: &HomeLayout) -> DoctorReport {
    let mut report = DoctorReport::new(layout);

    push_path_check(&mut report, "home", &layout.root);
    push_path_check(&mut report, "policy_dir", &layout.policy_dir);
    push_path_check(&mut report, "capabilities_dir", &layout.capabilities_dir);

    match layout.load_key() {
        Ok(_) => report.push(
            "key",
            DoctorStatus::Ok,
            format!("{} is loadable", layout.key_file.display()),
            Some(path_details(&layout.key_file)),
        ),
        Err(e) => report.push(
            "key",
            DoctorStatus::Fail,
            format!("could not load key: {e}"),
            Some(path_details(&layout.key_file)),
        ),
    }

    let env = match Expedition::load(&layout.expedition_file) {
        Ok(Some(expedition)) => {
            let details = serde_json::json!({
                "path": path_display(&layout.expedition_file),
                "name": expedition.name,
                "root": path_display(&expedition.root),
                "started_at": expedition.started_at.to_string(),
            });
            let env = expedition.policy_env();
            report.push(
                "expedition",
                DoctorStatus::Ok,
                "active expedition loaded",
                Some(details),
            );
            env
        }
        Ok(None) => {
            report.push(
                "expedition",
                DoctorStatus::Ok,
                "no active expedition",
                Some(path_details(&layout.expedition_file)),
            );
            default_policy_env()
        }
        Err(e) => {
            report.push(
                "expedition",
                DoctorStatus::Fail,
                format!("could not load expedition state: {e}"),
                Some(path_details(&layout.expedition_file)),
            );
            default_policy_env()
        }
    };

    match Policy::load_from_dir(&layout.policy_dir, &env) {
        Ok(policy) => report.push(
            "policy",
            DoctorStatus::Ok,
            format!("{} rules ({})", policy.rules.len(), policy.version_hash),
            Some(serde_json::json!({
                "path": path_display(&layout.policy_dir),
                "rules": policy.rules.len(),
                "version": policy.version_hash,
            })),
        ),
        Err(e) => report.push(
            "policy",
            DoctorStatus::Fail,
            format!("could not load policy: {e}"),
            Some(path_details(&layout.policy_dir)),
        ),
    }

    match gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir) {
        Ok(mapper) => report.push(
            "capabilities",
            DoctorStatus::Ok,
            format!("{} rules", mapper.rule_count()),
            Some(serde_json::json!({
                "path": path_display(&layout.capabilities_dir),
                "rules": mapper.rule_count(),
            })),
        ),
        Err(e) => report.push(
            "capabilities",
            DoctorStatus::Fail,
            format!("could not load capabilities: {e}"),
            Some(path_details(&layout.capabilities_dir)),
        ),
    }

    if layout.audit_log.exists() {
        match layout
            .load_verifying_key()
            .ok()
            .and_then(|vk| verify_log(&layout.audit_log, &vk).ok())
        {
            Some(count) => report.push(
                "audit",
                DoctorStatus::Ok,
                format!("{count} entries verified"),
                Some(serde_json::json!({
                    "path": path_display(&layout.audit_log),
                    "entries": count,
                })),
            ),
            None => report.push(
                "audit",
                DoctorStatus::Fail,
                format!("could not verify {}", layout.audit_log.display()),
                Some(path_details(&layout.audit_log)),
            ),
        }
    } else {
        report.push(
            "audit",
            DoctorStatus::Warn,
            "no audit log yet",
            Some(path_details(&layout.audit_log)),
        );
    }

    if layout.socket.exists() {
        report.push(
            "daemon",
            DoctorStatus::Ok,
            format!("socket exists at {}", layout.socket.display()),
            Some(serde_json::json!({
                "socket": path_display(&layout.socket),
            })),
        );
    } else {
        report.push(
            "daemon",
            DoctorStatus::Warn,
            "socket not found; hook adapter will use audited fallback",
            Some(serde_json::json!({
                "socket": path_display(&layout.socket),
            })),
        );
    }

    report
}

fn push_path_check(report: &mut DoctorReport, name: &str, path: &Path) {
    if path.exists() {
        report.push(
            name,
            DoctorStatus::Ok,
            format!("{} exists", path.display()),
            Some(path_details(path)),
        );
    } else {
        report.push(
            name,
            DoctorStatus::Fail,
            "missing",
            Some(path_details(path)),
        );
    }
}

fn print_doctor_report(report: &DoctorReport) {
    for check in &report.checks {
        println!(
            "{} {}: {}",
            check.status.as_str(),
            check.name,
            check.message
        );
    }
    println!(
        "summary: {} failure(s), {} warning(s)",
        report.summary.failures, report.summary.warnings
    );
}
