use anyhow::Result;
use clap::Subcommand;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use crate::{
    agent::AgentKind,
    agent_status::{AgentStatus, build_agent_status_report},
    util::path_display,
};

#[derive(Subcommand)]
pub(crate) enum ManagedCmd {
    /// Inspect shipped user-mode deployment signals and their isolation limit.
    Status {
        /// Emit a stable machine-readable deployment report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct ManagedStatusReport {
    status: AgentStatus,
    mode: ManagedMode,
    status_requires_root: bool,
    isolation: &'static str,
    tamper_resistance: &'static str,
    reference_ready: bool,
    home: String,
    summary: ManagedSummary,
    checks: Vec<ManagedCheck>,
    notes: Vec<String>,
}

impl ManagedStatusReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedMode {
    UserServiceFilePresent,
    UserLevel,
    Unconfigured,
}

impl ManagedMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::UserServiceFilePresent => "user_service_file_present",
            Self::UserLevel => "user_level",
            Self::Unconfigured => "unconfigured",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct ManagedSummary {
    ok: usize,
    warnings: usize,
    failures: usize,
}

#[derive(Debug, Serialize)]
struct ManagedCheck {
    name: &'static str,
    status: AgentStatus,
    message: String,
    details: serde_json::Value,
}

pub(crate) fn cmd_managed(cmd: ManagedCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        ManagedCmd::Status { json } => {
            let report = build_managed_status_report(&layout);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_managed_status_report(&report);
            }
            Ok(report.exit_code())
        }
    }
}

fn build_managed_status_report(layout: &HomeLayout) -> ManagedStatusReport {
    let mut checks = Vec::new();
    push_path_mode_check(&mut checks, "home_permissions", &layout.root, 0o700);
    push_path_mode_check(&mut checks, "policy_permissions", &layout.policy_dir, 0o700);
    push_path_mode_check(
        &mut checks,
        "capability_permissions",
        &layout.capabilities_dir,
        0o700,
    );
    push_path_mode_check(&mut checks, "key_permissions", &layout.key_file, 0o600);
    push_service_file_check(&mut checks);
    push_socket_check(&mut checks, &layout.socket);
    push_agent_check(&mut checks, AgentKind::Codex, layout);
    push_agent_check(&mut checks, AgentKind::Claude, layout);
    push_bypass_env_check(&mut checks);

    let mut summary = ManagedSummary::default();
    for check in &checks {
        match check.status {
            AgentStatus::Ok => summary.ok += 1,
            AgentStatus::Warn => summary.warnings += 1,
            AgentStatus::Fail => summary.failures += 1,
        }
    }
    let user_service_file_present = checks
        .iter()
        .any(|check| check.name == "user_daemon_service_file" && check.status == AgentStatus::Ok);
    let mode = if summary.failures > 0 {
        ManagedMode::Unconfigured
    } else if user_service_file_present {
        ManagedMode::UserServiceFilePresent
    } else {
        ManagedMode::UserLevel
    };
    let status = if summary.failures > 0 {
        AgentStatus::Fail
    } else if summary.warnings > 0 {
        AgentStatus::Warn
    } else {
        AgentStatus::Ok
    };
    ManagedStatusReport {
        status,
        mode,
        status_requires_root: false,
        isolation: "none",
        tamper_resistance: "none",
        reference_ready: false,
        home: path_display(&layout.root),
        summary,
        checks,
        notes: vec![
            "This command inspects user-owned path modes, user-service file presence, socket presence, hooks, and the current process environment only."
                .to_string(),
            "These checks do not verify ownership, service process identity, socket peer credentials, a distinct authority principal, or resistance to the current UID."
                .to_string(),
            "A protected reference-mode authority is not shipped in this release."
                .to_string(),
        ],
    }
}

fn push_path_mode_check(
    checks: &mut Vec<ManagedCheck>,
    name: &'static str,
    path: &Path,
    expected_mode: u32,
) {
    if !path.exists() {
        checks.push(ManagedCheck {
            name,
            status: AgentStatus::Fail,
            message: format!("{} is missing", path.display()),
            details: serde_json::json!({ "path": path_display(path) }),
        });
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match std::fs::metadata(path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(error) => {
                checks.push(ManagedCheck {
                    name,
                    status: AgentStatus::Fail,
                    message: format!("could not inspect {}: {error}", path.display()),
                    details: serde_json::json!({ "path": path_display(path) }),
                });
                return;
            }
        };
        let status = if mode == expected_mode {
            AgentStatus::Ok
        } else if mode & 0o077 == 0 {
            AgentStatus::Warn
        } else {
            AgentStatus::Fail
        };
        checks.push(ManagedCheck {
            name,
            status,
            message: format!(
                "{} mode {:o}; expected {:o}",
                path.display(),
                mode,
                expected_mode
            ),
            details: serde_json::json!({
                "path": path_display(path),
                "mode": format!("{:o}", mode),
                "expected_mode": format!("{:o}", expected_mode),
            }),
        });
    }
    #[cfg(not(unix))]
    {
        checks.push(ManagedCheck {
            name,
            status: AgentStatus::Warn,
            message: "permission-mode checks are only implemented on Unix hosts".to_string(),
            details: serde_json::json!({ "path": path_display(path) }),
        });
    }
}

fn push_service_file_check(checks: &mut Vec<ManagedCheck>) {
    let path = service_file_path();
    let status = if path.exists() {
        AgentStatus::Ok
    } else {
        AgentStatus::Warn
    };
    checks.push(ManagedCheck {
        name: "user_daemon_service_file",
        status,
        message: if path.exists() {
            format!("user daemon service file exists at {}", path.display())
        } else {
            format!("user daemon service file not found at {}", path.display())
        },
        details: serde_json::json!({
            "path": path_display(&path),
            "evidence_limit": "presence_only"
        }),
    });
}

fn push_socket_check(checks: &mut Vec<ManagedCheck>, socket: &Path) {
    checks.push(ManagedCheck {
        name: "daemon_socket",
        status: if socket.exists() {
            AgentStatus::Ok
        } else {
            AgentStatus::Warn
        },
        message: if socket.exists() {
            format!("user daemon socket exists at {}", socket.display())
        } else {
            format!("user daemon socket not found at {}", socket.display())
        },
        details: serde_json::json!({ "path": path_display(socket) }),
    });
}

fn push_agent_check(checks: &mut Vec<ManagedCheck>, agent: AgentKind, layout: &HomeLayout) {
    let report = build_agent_status_report(agent, layout);
    let status = if report.failures() > 0 {
        AgentStatus::Fail
    } else if report.warnings() > 0 {
        AgentStatus::Warn
    } else {
        AgentStatus::Ok
    };
    checks.push(ManagedCheck {
        name: match agent {
            AgentKind::Codex => "codex_hook_integrity",
            AgentKind::Claude => "claude_hook_integrity",
        },
        status,
        message: format!(
            "{} hook status: {} failure(s), {} warning(s)",
            agent.as_str(),
            report.failures(),
            report.warnings()
        ),
        details: serde_json::json!({ "agent_status": report }),
    });
}

fn push_bypass_env_check(checks: &mut Vec<ManagedCheck>) {
    let active = std::env::var("GOMMAGE_BYPASS")
        .map(|value| value == "1")
        .unwrap_or(false);
    checks.push(ManagedCheck {
        name: "bypass_env",
        status: if active {
            AgentStatus::Warn
        } else {
            AgentStatus::Ok
        },
        message: if active {
            "GOMMAGE_BYPASS=1 is active in this process environment".to_string()
        } else {
            "GOMMAGE_BYPASS is not active in this process environment".to_string()
        },
        details: serde_json::json!({ "active": active }),
    });
}

fn service_file_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents/dev.gommage.daemon.plist")
    } else {
        home.join(".config/systemd/user/gommage-daemon.service")
    }
}

fn print_managed_status_report(report: &ManagedStatusReport) {
    println!(
        "deployment status: {} [{}]",
        report.mode.as_str(),
        report.status.as_str()
    );
    println!("home: {}", report.home);
    println!("status requires root: {}", report.status_requires_root);
    println!("isolation: {}", report.isolation);
    println!("tamper resistance: {}", report.tamper_resistance);
    println!("reference ready: {}", report.reference_ready);
    for check in &report.checks {
        println!(
            "{} {}: {}",
            check.status.as_str(),
            check.name,
            check.message
        );
    }
    for note in &report.notes {
        println!("note: {note}");
    }
}
