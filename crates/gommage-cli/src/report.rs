use anyhow::{Context, Result, bail};
use clap::Subcommand;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};
use time::OffsetDateTime;

use crate::{
    agent::AgentKind,
    agent_status::build_agent_status_report,
    daemon::{ServiceManager, daemon_dry_run_plan},
    doctor::build_doctor_report,
    util::path_display,
    verify::build_verify_report,
};

#[derive(Subcommand)]
pub(crate) enum ReportCmd {
    /// Create a redacted diagnostic bundle for support and issue reports.
    Bundle {
        /// Redact home paths and secret-like environment values. Required.
        #[arg(long)]
        redact: bool,
        /// Output JSON file.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
}

pub(crate) fn cmd_report(sub: ReportCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        ReportCmd::Bundle {
            redact,
            output,
            force,
        } => report_bundle(&layout, redact, &output, force),
    }
}

fn report_bundle(
    layout: &HomeLayout,
    redact: bool,
    output: &Path,
    force: bool,
) -> Result<ExitCode> {
    if !redact {
        bail!("report bundle requires --redact");
    }
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        );
    }
    let mut value = serde_json::to_value(build_report_bundle(layout, redact)?)?;
    redact_json(&mut value);

    let mut raw = serde_json::to_string_pretty(&value)?;
    raw.push('\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(output, raw).with_context(|| format!("writing {}", output.display()))?;
    println!("ok report bundle: {}", output.display());
    Ok(ExitCode::SUCCESS)
}

fn build_report_bundle(layout: &HomeLayout, redacted: bool) -> Result<ReportBundle> {
    let doctor = serde_json::to_value(build_doctor_report(layout))?;
    let verify = serde_json::to_value(build_verify_report(layout, &[]))?;
    let agents = [AgentKind::Claude, AgentKind::Codex]
        .into_iter()
        .map(|agent| {
            Ok(AgentBundle {
                agent,
                report: serde_json::to_value(build_agent_status_report(agent, layout))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ReportBundle {
        schema_version: 1,
        generated_at: OffsetDateTime::now_utc().to_string(),
        redacted,
        cli: CliBundle {
            version: env!("CARGO_PKG_VERSION"),
        },
        host: HostBundle {
            os: env::consts::OS,
            arch: env::consts::ARCH,
            family: env::consts::FAMILY,
        },
        home: HomeBundle {
            root: path_display(&layout.root),
            policy_dir: path_display(&layout.policy_dir),
            capabilities_dir: path_display(&layout.capabilities_dir),
            key_file: path_display(&layout.key_file),
            audit_log: path_display(&layout.audit_log),
            socket: path_display(&layout.socket),
        },
        environment: environment_hints(),
        inventory: InventoryBundle {
            policies: directory_inventory(&layout.policy_dir),
            capabilities: directory_inventory(&layout.capabilities_dir),
        },
        daemon: vec![
            serde_json::to_value(daemon_dry_run_plan(ServiceManager::Systemd, false, true)?)?,
            serde_json::to_value(daemon_dry_run_plan(ServiceManager::Launchd, false, true)?)?,
        ],
        doctor,
        verify,
        agents,
    })
}

#[derive(Debug, Serialize)]
struct ReportBundle {
    schema_version: u32,
    generated_at: String,
    redacted: bool,
    cli: CliBundle,
    host: HostBundle,
    home: HomeBundle,
    environment: Vec<EnvHint>,
    inventory: InventoryBundle,
    daemon: Vec<serde_json::Value>,
    doctor: serde_json::Value,
    verify: serde_json::Value,
    agents: Vec<AgentBundle>,
}

#[derive(Debug, Serialize)]
struct CliBundle {
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct HostBundle {
    os: &'static str,
    arch: &'static str,
    family: &'static str,
}

#[derive(Debug, Serialize)]
struct HomeBundle {
    root: String,
    policy_dir: String,
    capabilities_dir: String,
    key_file: String,
    audit_log: String,
    socket: String,
}

#[derive(Debug, Serialize)]
struct EnvHint {
    name: &'static str,
    present: bool,
    value: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct InventoryBundle {
    policies: DirectoryInventory,
    capabilities: DirectoryInventory,
}

#[derive(Debug, Serialize)]
struct DirectoryInventory {
    path: String,
    exists: bool,
    files: Vec<FileInventory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct FileInventory {
    name: String,
    path: String,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct AgentBundle {
    agent: AgentKind,
    report: serde_json::Value,
}

fn environment_hints() -> Vec<EnvHint> {
    [
        "GOMMAGE_HOME",
        "GOMMAGE_BIN_DIR",
        "GOMMAGE_CLAUDE_SETTINGS",
        "GOMMAGE_CODEX_HOOKS",
        "GOMMAGE_CODEX_CONFIG",
        "GOMMAGE_DAEMON_BIN",
        "GOMMAGE_SYSTEMD_USER_DIR",
        "GOMMAGE_LAUNCHD_DIR",
        "GOMMAGE_COSIGN",
        "GOMMAGE_GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ]
    .into_iter()
    .map(|name| EnvHint {
        name,
        present: env::var_os(name).is_some(),
        value: env::var_os(name).map(|_| "<redacted>"),
    })
    .collect()
}

fn directory_inventory(path: &Path) -> DirectoryInventory {
    if !path.exists() {
        return DirectoryInventory {
            path: path_display(path),
            exists: false,
            files: Vec::new(),
            error: None,
        };
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            return DirectoryInventory {
                path: path_display(path),
                exists: true,
                files: Vec::new(),
                error: Some(error.to_string()),
            };
        }
    };

    let mut files = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some(FileInventory {
                name: entry.file_name().to_string_lossy().to_string(),
                path: path_display(&entry.path()),
                bytes: metadata.len(),
            })
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.name.cmp(&right.name));

    DirectoryInventory {
        path: path_display(path),
        exists: true,
        files,
        error: None,
    }
}

fn redact_json(value: &mut serde_json::Value) {
    let home = dirs::home_dir().map(|path| path_display(&path));
    redact_value(value, home.as_deref());
}

fn redact_value(value: &mut serde_json::Value, home: Option<&str>) {
    match value {
        serde_json::Value::String(raw) => {
            if let Some(home) = home.filter(|home| !home.is_empty()) {
                *raw = raw.replace(home, "$HOME");
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_value(item, home);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                redact_value(value, home);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}
