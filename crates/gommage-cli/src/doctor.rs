use anyhow::Result;
use gommage_audit::verify_log;
use gommage_core::{
    Policy,
    runtime::{Expedition, HomeLayout, default_policy_env},
};
use serde::Serialize;
use std::{
    env,
    path::Path,
    process::{Command, ExitCode},
};

use crate::self_update::UpdateStatus;
use crate::update_cache;
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

    push_companion_binary_check(&mut report, "gommage-daemon");
    push_companion_binary_check(&mut report, "gommage-mcp");

    push_update_check(&mut report, layout);

    report
}

/// Surface the cached new-version check. This is a pure local read — no network
/// I/O — so doctor never blocks or fails on a transient outage. An available
/// upgrade is a `Warn` (informational), not a `Fail`, so it never flips the
/// doctor/verify exit code.
fn push_update_check(report: &mut DoctorReport, layout: &HomeLayout) {
    let running_version = env!("CARGO_PKG_VERSION");
    match update_cache::read_cache(&update_cache::cache_path(layout)) {
        Some(cache) if cache.current_version != running_version => {
            report.push(
                "update",
                DoctorStatus::Ok,
                "update check stale for current binary — run `gommage update`",
                Some(serde_json::json!({
                    "cached_current_version": cache.current_version,
                    "running_version": running_version,
                    "latest_tag": cache.latest_tag,
                    "latest_version": cache.latest_version,
                    "checked_at": cache.checked_at.to_string(),
                })),
            );
        }
        Some(cache) if cache.status == UpdateStatus::UpgradeAvailable => {
            report.push(
                "update",
                DoctorStatus::Warn,
                format!(
                    "gommage {} available — run `gommage upgrade`",
                    cache.latest_version
                ),
                Some(serde_json::json!({
                    "latest_tag": cache.latest_tag,
                    "latest_version": cache.latest_version,
                    "checked_at": cache.checked_at.to_string(),
                })),
            );
        }
        Some(cache) => report.push(
            "update",
            DoctorStatus::Ok,
            "latest",
            Some(serde_json::json!({
                "latest_tag": cache.latest_tag,
                "latest_version": cache.latest_version,
                "checked_at": cache.checked_at.to_string(),
            })),
        ),
        None => report.push(
            "update",
            DoctorStatus::Ok,
            "update check not run yet — run `gommage update`",
            None,
        ),
    }
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

fn push_companion_binary_check(report: &mut DoctorReport, binary: &str) {
    let check_name = format!("companion_{}", binary.replace('-', "_"));
    let Some(path) = current_exe_sibling(binary) else {
        report.push(
            check_name,
            DoctorStatus::Warn,
            format!("could not resolve installed {binary} path"),
            None,
        );
        return;
    };

    if !path.exists() {
        report.push(
            check_name,
            DoctorStatus::Warn,
            format!("{binary} not found next to gommage"),
            Some(path_details(&path)),
        );
        return;
    }

    match Command::new(&path).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            report.push(
                check_name,
                DoctorStatus::Ok,
                format!("{binary} responds: {version}"),
                Some(serde_json::json!({
                    "path": path_display(&path),
                    "version": version,
                })),
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            report.push(
                check_name,
                DoctorStatus::Fail,
                format!("{binary} --version failed"),
                Some(serde_json::json!({
                    "path": path_display(&path),
                    "status": output.status.code(),
                    "stderr": stderr,
                })),
            );
        }
        Err(e) => {
            report.push(
                check_name,
                DoctorStatus::Fail,
                format!("could not run {binary} --version: {e}"),
                Some(path_details(&path)),
            );
        }
    }
}

fn current_exe_sibling(binary: &str) -> Option<std::path::PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(binary)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_cache::UpdateCheckCache;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    fn find_update_check(report: &DoctorReport) -> &DoctorCheck {
        report
            .checks
            .iter()
            .find(|check| check.name == "update")
            .expect("doctor report must contain an `update` check")
    }

    fn write_update_cache_with_versions(
        layout: &HomeLayout,
        status: UpdateStatus,
        current_version: &str,
        latest_version: &str,
    ) {
        let cache = UpdateCheckCache {
            checked_at: OffsetDateTime::now_utc(),
            current_version: current_version.to_string(),
            latest_tag: format!("gommage-cli-v{latest_version}"),
            latest_version: latest_version.to_string(),
            status,
        };
        let bytes = serde_json::to_vec_pretty(&cache).unwrap();
        std::fs::write(&layout.update_check, bytes).unwrap();
    }

    fn write_update_cache(layout: &HomeLayout, status: UpdateStatus) {
        write_update_cache_with_versions(layout, status, env!("CARGO_PKG_VERSION"), "999.0.0");
    }

    #[test]
    fn doctor_surfaces_upgrade_available() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        write_update_cache(&layout, UpdateStatus::UpgradeAvailable);

        let report = build_doctor_report(&layout);
        let check = find_update_check(&report);
        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(check.message.contains("available"));
        assert!(check.message.contains("gommage upgrade"));
    }

    #[test]
    fn doctor_update_ok_when_latest() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        write_update_cache_with_versions(
            &layout,
            UpdateStatus::UpToDate,
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_VERSION"),
        );

        let report = build_doctor_report(&layout);
        let check = find_update_check(&report);
        assert_eq!(check.status, DoctorStatus::Ok);
        assert_eq!(check.message, "latest");
    }

    #[test]
    fn doctor_ignores_upgrade_available_cache_for_previous_binary() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        write_update_cache_with_versions(
            &layout,
            UpdateStatus::UpgradeAvailable,
            "0.39.0-beta.1",
            env!("CARGO_PKG_VERSION"),
        );

        let report = build_doctor_report(&layout);
        let check = find_update_check(&report);
        assert_eq!(check.status, DoctorStatus::Ok);
        assert!(check.message.contains("stale"));
    }

    #[test]
    fn doctor_update_missing_cache_is_ok() {
        let td = tempdir().unwrap();
        let layout = HomeLayout::at(td.path());
        layout.ensure().unwrap();
        // No cache file written.

        let report = build_doctor_report(&layout);
        let check = find_update_check(&report);
        assert_eq!(check.status, DoctorStatus::Ok);
        // A missing cache must never flip doctor's exit code.
        assert_eq!(report.summary.failures, 0);
    }
}
