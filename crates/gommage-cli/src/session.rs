use anyhow::{Context, Result};
use clap::Subcommand;
use gommage_core::runtime::HomeLayout;
use serde::Serialize;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use crate::{
    agent::AgentKind,
    agent_status::{
        AgentStatus, AgentStatusReport, build_claude_status_report_at, build_codex_status_report_at,
    },
    util::path_display,
};

#[derive(Subcommand)]
pub(crate) enum SessionCmd {
    /// Inspect live Claude/Codex-like processes and their Gommage hook posture.
    Doctor {
        /// Emit a stable machine-readable session report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct SessionDoctorReport {
    status: AgentStatus,
    summary: SessionSummary,
    process_source: String,
    default_homes: Vec<SessionHomeReport>,
    processes: Vec<SessionProcessReport>,
    notes: Vec<String>,
}

impl SessionDoctorReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct SessionSummary {
    processes_seen: usize,
    agent_processes: usize,
    protected_processes: usize,
    warnings: usize,
    failures: usize,
}

#[derive(Debug, Serialize)]
struct SessionHomeReport {
    agent: AgentKind,
    home: String,
    source: String,
    hook_status: AgentStatus,
    hook_report: AgentStatusReport,
}

#[derive(Debug, Serialize)]
struct SessionProcessReport {
    pid: u32,
    agent: AgentKind,
    command: String,
    home: String,
    home_source: String,
    hook_status: AgentStatus,
    hook_report: AgentStatusReport,
}

struct ProcessRow {
    pid: u32,
    command: String,
}

pub(crate) fn cmd_session(cmd: SessionCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        SessionCmd::Doctor { json } => {
            let report = build_session_doctor_report(&layout)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_session_doctor_report(&report);
            }
            Ok(report.exit_code())
        }
    }
}

fn build_session_doctor_report(layout: &HomeLayout) -> Result<SessionDoctorReport> {
    let (process_source, rows) = process_rows().context("reading process table")?;
    let mut summary = SessionSummary {
        processes_seen: rows.len(),
        ..SessionSummary::default()
    };
    let default_homes = vec![
        session_home_report(
            AgentKind::Codex,
            default_agent_home(AgentKind::Codex),
            "default",
            layout,
        ),
        session_home_report(
            AgentKind::Claude,
            default_agent_home(AgentKind::Claude),
            "default",
            layout,
        ),
    ];
    let mut counted_home_status = HashSet::new();
    for home in &default_homes {
        count_unique_home_status(
            &mut summary,
            &mut counted_home_status,
            home.agent,
            &home.home,
            &home.hook_report,
        );
    }

    let mut processes = Vec::new();
    for row in rows {
        let Some(agent) = detect_agent(&row.command) else {
            continue;
        };
        summary.agent_processes += 1;
        let (home, home_source) = infer_agent_home(agent, &row.command);
        let hook_report = hook_report_for_home(agent, &home, layout);
        let hook_status = hook_report.status();
        if hook_report.failures() == 0 {
            summary.protected_processes += 1;
        }
        count_unique_home_status(
            &mut summary,
            &mut counted_home_status,
            agent,
            &path_display(&home),
            &hook_report,
        );
        processes.push(SessionProcessReport {
            pid: row.pid,
            agent,
            command: row.command,
            home: path_display(&home),
            home_source,
            hook_status,
            hook_report,
        });
    }

    let status = if summary.failures > 0 {
        AgentStatus::Fail
    } else if summary.warnings > 0 {
        AgentStatus::Warn
    } else {
        AgentStatus::Ok
    };
    Ok(SessionDoctorReport {
        status,
        summary,
        process_source,
        default_homes,
        processes,
        notes: vec![
            "Session detection is advisory: it inspects process command lines and agent home files, not kernel execution paths.".to_string(),
            "Nested agents are protected only when the inner process uses a Gommage-wired agent home and emits covered hook events.".to_string(),
        ],
    })
}

fn count_unique_home_status(
    summary: &mut SessionSummary,
    counted: &mut HashSet<String>,
    agent: AgentKind,
    home: &str,
    hook_report: &AgentStatusReport,
) {
    let key = format!("{}:{home}", agent.as_str());
    if !counted.insert(key) {
        return;
    }
    summary.failures += hook_report.failures();
    summary.warnings += hook_report.warnings();
}

fn session_home_report(
    agent: AgentKind,
    home: PathBuf,
    source: impl Into<String>,
    layout: &HomeLayout,
) -> SessionHomeReport {
    let hook_report = hook_report_for_home(agent, &home, layout);
    let hook_status = hook_report.status();
    SessionHomeReport {
        agent,
        home: path_display(&home),
        source: source.into(),
        hook_status,
        hook_report,
    }
}

fn hook_report_for_home(agent: AgentKind, home: &Path, layout: &HomeLayout) -> AgentStatusReport {
    match agent {
        AgentKind::Codex => {
            build_codex_status_report_at(&home.join("hooks.json"), &home.join("config.toml"))
        }
        AgentKind::Claude => build_claude_status_report_at(layout, &home.join("settings.json")),
    }
}

fn process_rows() -> Result<(String, Vec<ProcessRow>)> {
    if let Ok(raw) = std::env::var("GOMMAGE_SESSION_PROCESS_TABLE") {
        return Ok((
            "GOMMAGE_SESSION_PROCESS_TABLE".to_string(),
            parse_process_rows(&raw),
        ));
    }
    let output = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .context("running ps -axo pid=,command=")?;
    let raw = String::from_utf8_lossy(&output.stdout);
    Ok((
        "ps -axo pid=,command=".to_string(),
        parse_process_rows(&raw),
    ))
}

fn parse_process_rows(raw: &str) -> Vec<ProcessRow> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (pid, command) = trimmed.split_once(char::is_whitespace)?;
            let pid = pid.parse::<u32>().ok()?;
            let command = command.trim().to_string();
            if command.is_empty() {
                return None;
            }
            Some(ProcessRow { pid, command })
        })
        .collect()
}

fn detect_agent(command: &str) -> Option<AgentKind> {
    let lower = command.to_ascii_lowercase();
    if lower.contains("gommage") {
        return None;
    }
    if looks_like_codex_process(command, &lower) {
        Some(AgentKind::Codex)
    } else if looks_like_claude_process(command, &lower) {
        Some(AgentKind::Claude)
    } else {
        None
    }
}

fn looks_like_codex_process(command: &str, lower: &str) -> bool {
    lower.contains("codex")
        && (env_assignment(command, "CODEX_HOME").is_some()
            || command_tokens_include_basename(command, "codex")
            || lower.contains("@openai/codex"))
}

fn looks_like_claude_process(command: &str, lower: &str) -> bool {
    if !lower.contains("claude") || looks_like_claude_desktop_helper(lower) {
        return false;
    }
    env_assignment(command, "CLAUDE_HOME").is_some()
        || command_tokens_include_basename(command, "claude")
        || lower.contains("/.local/share/claude/versions/")
        || lower.contains("/.claude/local/")
}

fn looks_like_claude_desktop_helper(lower: &str) -> bool {
    lower.contains("/applications/claude.app/")
        || lower.contains("claude helper")
        || (lower.contains("chrome_crashpad_handler") && lower.contains("claude"))
}

fn command_tokens_include_basename(command: &str, basename: &str) -> bool {
    command
        .split_whitespace()
        .map(command_token_basename)
        .any(|token| token == basename)
}

fn command_token_basename(token: &str) -> String {
    let trimmed = token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\'' | ',' | ';' | ':' | '[' | ']' | '{' | '}' | '(' | ')'
        )
    });
    Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

fn infer_agent_home(agent: AgentKind, command: &str) -> (PathBuf, String) {
    let var = match agent {
        AgentKind::Codex => "CODEX_HOME",
        AgentKind::Claude => "CLAUDE_HOME",
    };
    if let Some(value) = env_assignment(command, var) {
        return (PathBuf::from(value), format!("{var}= command assignment"));
    }
    (default_agent_home(agent), "default".to_string())
}

fn default_agent_home(agent: AgentKind) -> PathBuf {
    let var = match agent {
        AgentKind::Codex => "CODEX_HOME",
        AgentKind::Claude => "CLAUDE_HOME",
    };
    if let Ok(value) = std::env::var(var)
        && !value.trim().is_empty()
    {
        return PathBuf::from(value);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(match agent {
            AgentKind::Codex => ".codex",
            AgentKind::Claude => ".claude",
        })
}

fn env_assignment(command: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    command.split_whitespace().find_map(|token| {
        token
            .strip_prefix(&needle)
            .map(|value| value.trim_matches(['"', '\'']).to_string())
            .filter(|value| !value.is_empty())
    })
}

fn print_session_doctor_report(report: &SessionDoctorReport) {
    println!("session doctor: {}", report.status.as_str());
    println!(
        "processes: {} seen, {} agent-like, {} protected",
        report.summary.processes_seen,
        report.summary.agent_processes,
        report.summary.protected_processes
    );
    println!("source: {}", report.process_source);
    println!();
    println!("default homes:");
    for home in &report.default_homes {
        println!(
            "  - {} [{}] {}",
            home.agent.as_str(),
            home.hook_status.as_str(),
            home.home
        );
    }
    if report.processes.is_empty() {
        println!();
        println!("live agent processes: none detected");
    } else {
        println!();
        println!("live agent processes:");
        for process in &report.processes {
            println!(
                "  - pid={} {} [{}] home={} ({})",
                process.pid,
                process.agent.as_str(),
                process.hook_status.as_str(),
                process.home,
                process.home_source
            );
            println!("    {}", process.command);
        }
    }
    println!();
    for note in &report.notes {
        println!("note: {note}");
    }
}
