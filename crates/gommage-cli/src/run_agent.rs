use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{
    path::PathBuf,
    process::{Command, ExitCode},
};

use crate::{
    agent::AgentKind,
    agent_status::{AgentStatus, AgentStatusReport, build_codex_status_report_at},
    util::path_display,
};

#[derive(Subcommand)]
pub(crate) enum RunCmd {
    /// Run Codex through a verified Gommage-wired home and explicit sandbox.
    Codex {
        /// Codex sandbox mode for this run.
        #[arg(long, value_enum, default_value_t = CodexSandbox::WorkspaceWrite)]
        sandbox: CodexSandbox,
        /// Print the launch plan without running Codex.
        #[arg(long)]
        dry_run: bool,
        /// Emit a stable machine-readable launch plan.
        #[arg(long)]
        json: bool,
        /// Prompt/arguments passed to `codex exec`. Use `--` before the task.
        #[arg(last = true, required = true)]
        task: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CodexSandbox {
    #[value(name = "read-only")]
    ReadOnly,
    #[value(name = "workspace-write")]
    WorkspaceWrite,
    #[value(name = "danger-full-access")]
    DangerFullAccess,
}

impl CodexSandbox {
    fn as_arg(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }
}

#[derive(Debug, Serialize)]
struct RunPlan {
    status: AgentStatus,
    agent: AgentKind,
    dry_run: bool,
    executable: String,
    argv: Vec<String>,
    sandbox: CodexSandbox,
    gommage_home: String,
    agent_home: String,
    hook_report: AgentStatusReport,
    warnings: Vec<String>,
}

impl RunPlan {
    fn exit_code(&self) -> ExitCode {
        if self.hook_report.failures() == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

pub(crate) fn cmd_run(cmd: RunCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        RunCmd::Codex {
            sandbox,
            dry_run,
            json,
            task,
        } => run_codex(layout, sandbox, dry_run, json, task),
    }
}

fn run_codex(
    layout: HomeLayout,
    sandbox: CodexSandbox,
    dry_run: bool,
    json: bool,
    task: Vec<String>,
) -> Result<ExitCode> {
    let plan = build_codex_run_plan(&layout, sandbox, dry_run, task);
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_run_plan(&plan);
    }
    if dry_run || plan.exit_code() != ExitCode::SUCCESS {
        return Ok(plan.exit_code());
    }

    let status = Command::new(&plan.executable)
        .args(&plan.argv)
        .env("GOMMAGE_HOME", &layout.root)
        .status()
        .with_context(|| format!("running {}", plan.executable))?;
    Ok(status
        .code()
        .map(|code| ExitCode::from(code.clamp(0, 255) as u8))
        .unwrap_or(ExitCode::from(1)))
}

fn build_codex_run_plan(
    layout: &HomeLayout,
    sandbox: CodexSandbox,
    dry_run: bool,
    task: Vec<String>,
) -> RunPlan {
    let agent_home = codex_home();
    let hook_report = build_codex_status_report_at(
        layout,
        &agent_home.join("hooks.json"),
        &agent_home.join("config.toml"),
    );
    let mut warnings = Vec::new();
    if sandbox == CodexSandbox::DangerFullAccess {
        warnings.push(
            "danger-full-access leaves OS-level confinement to the operator; Gommage only governs matched hook events."
                .to_string(),
        );
    }
    if hook_report.failures() > 0 {
        warnings.push(
            "Codex home is not Gommage-wired; run `gommage agent install codex --dry-run` before launching."
                .to_string(),
        );
    }
    let status = if hook_report.failures() > 0 {
        AgentStatus::Fail
    } else if hook_report.warnings() > 0 || !warnings.is_empty() {
        AgentStatus::Warn
    } else {
        AgentStatus::Ok
    };
    let mut argv = vec![
        "exec".to_string(),
        "--sandbox".to_string(),
        sandbox.as_arg().to_string(),
    ];
    argv.extend(task);
    RunPlan {
        status,
        agent: AgentKind::Codex,
        dry_run,
        executable: "codex".to_string(),
        argv,
        sandbox,
        gommage_home: path_display(&layout.root),
        agent_home: path_display(&agent_home),
        hook_report,
        warnings,
    }
}

fn codex_home() -> PathBuf {
    if let Ok(value) = std::env::var("CODEX_HOME")
        && !value.trim().is_empty()
    {
        return PathBuf::from(value);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".codex")
}

fn print_run_plan(plan: &RunPlan) {
    println!("run {}: {}", plan.agent.as_str(), plan.status.as_str());
    println!("home: {}", plan.agent_home);
    println!("gommage home: {}", plan.gommage_home);
    println!("command: {} {}", plan.executable, plan.argv.join(" "));
    for warning in &plan.warnings {
        println!("warning: {warning}");
    }
    if plan.dry_run {
        println!("dry-run: command not executed");
    }
}
