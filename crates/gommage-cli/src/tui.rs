use anyhow::{Context, Result};
use gommage_core::runtime::HomeLayout;
use std::{
    io::{self, IsTerminal, Read, Write},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    agent::AgentKind,
    agent_status::build_agent_status_report,
    doctor::{DoctorStatus, build_doctor_report},
    gestral::{UiStatus, color_enabled, truncate_plain},
    smoke::{SmokeStatus, build_smoke_report},
    tui_actions::{ApprovalDraft, PendingTuiAction, execute_tui_action},
    tui_render::{RenderState, render_lines},
    tui_stream::print_stream,
    tui_views::{TuiView, build_view_report, pending_approval_ids},
    util::path_display,
};

#[derive(Debug, Clone)]
pub(crate) struct TuiOptions {
    pub(crate) agents: Vec<AgentKind>,
    pub(crate) view: TuiView,
    pub(crate) snapshot: bool,
    pub(crate) watch: bool,
    pub(crate) watch_ticks: Option<u32>,
    pub(crate) stream: bool,
    pub(crate) stream_ticks: Option<u32>,
    pub(crate) stream_limit: usize,
    pub(crate) refresh_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Dashboard {
    pub(crate) version: &'static str,
    pub(crate) home: String,
    pub(crate) rows: Vec<StatusRow>,
    pub(crate) next_actions: Vec<String>,
    pub(crate) updated: String,
}

#[derive(Debug, Clone)]
pub(crate) struct StatusRow {
    pub(crate) label: String,
    pub(crate) status: UiStatus,
    pub(crate) summary: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DashboardSummary {
    pub(crate) total: usize,
    pub(crate) ok: usize,
    pub(crate) warn: usize,
    pub(crate) fail: usize,
    pub(crate) skip: usize,
}

pub(crate) fn cmd_tui(layout: HomeLayout, options: TuiOptions) -> Result<ExitCode> {
    let agents = normalize_agents(options.agents);
    if options.stream || options.stream_ticks.is_some() {
        print_stream(
            &layout,
            Duration::from_millis(options.refresh_ms),
            options.stream_ticks,
            options.stream_limit,
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    if options.watch || options.watch_ticks.is_some() {
        print_watch(
            &layout,
            &agents,
            options.view,
            Duration::from_millis(options.refresh_ms),
            options.watch_ticks,
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    if options.snapshot || !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        let dashboard = build_dashboard(&layout, &agents)?;
        print_snapshot(&layout, &dashboard, options.view)?;
        return Ok(ExitCode::SUCCESS);
    }

    match run_interactive(
        &layout,
        &agents,
        options.view,
        Duration::from_millis(options.refresh_ms),
    ) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            eprintln!("gommage tui: interactive mode unavailable: {error:#}");
            eprintln!("gommage tui: printing snapshot instead.");
            let dashboard = build_dashboard(&layout, &agents)?;
            print_snapshot(&layout, &dashboard, options.view)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn build_dashboard(layout: &HomeLayout, agents: &[AgentKind]) -> Result<Dashboard> {
    let mut rows = Vec::new();
    let doctor = build_doctor_report(layout);
    rows.push(StatusRow {
        label: "doctor".to_string(),
        status: from_doctor_status(doctor.status),
        summary: format!(
            "{} failure(s), {} warning(s)",
            doctor.summary.failures, doctor.summary.warnings
        ),
        detail: doctor_hint(doctor.status),
    });

    if doctor.status == DoctorStatus::Fail {
        rows.push(StatusRow {
            label: "smoke".to_string(),
            status: UiStatus::Skip,
            summary: "not run".to_string(),
            detail: "doctor failed; fix installation health first".to_string(),
        });
    } else {
        rows.push(match build_smoke_report(layout) {
            Ok(smoke) => StatusRow {
                label: "smoke".to_string(),
                status: from_smoke_status(smoke.status),
                summary: format!(
                    "{} passed, {} failed",
                    smoke.summary.passed, smoke.summary.failed
                ),
                detail: format!("{} mapper rule(s)", smoke.mapper_rules),
            },
            Err(error) => StatusRow {
                label: "smoke".to_string(),
                status: UiStatus::Fail,
                summary: "could not run".to_string(),
                detail: error.to_string(),
            },
        });
    }

    for agent in agents {
        rows.push(agent_row(*agent, layout)?);
    }

    Ok(Dashboard {
        version: env!("CARGO_PKG_VERSION"),
        home: path_display(&layout.root),
        next_actions: next_actions(&rows),
        rows,
        updated: time::OffsetDateTime::now_utc().to_string(),
    })
}

fn agent_row(agent: AgentKind, layout: &HomeLayout) -> Result<StatusRow> {
    let report = build_agent_status_report(agent, layout);
    let value = serde_json::to_value(&report)?;
    let status = match value.pointer("/status").and_then(|value| value.as_str()) {
        Some("ok") => UiStatus::Ok,
        Some("warn") => UiStatus::Warn,
        Some("fail") => UiStatus::Fail,
        _ => UiStatus::Fail,
    };
    let failures = value
        .pointer("/summary/failures")
        .and_then(|value| value.as_u64())
        .unwrap_or(1);
    let warnings = value
        .pointer("/summary/warnings")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    Ok(StatusRow {
        label: format!("agent {}", agent_name(agent)),
        status,
        summary: format!("{failures} failure(s), {warnings} warning(s)"),
        detail: first_agent_detail(&value),
    })
}

fn first_agent_detail(value: &serde_json::Value) -> String {
    value
        .pointer("/checks")
        .and_then(|checks| checks.as_array())
        .and_then(|checks| {
            checks.iter().find(|check| {
                check.pointer("/status").and_then(|status| status.as_str()) != Some("ok")
            })
        })
        .and_then(|check| {
            check
                .pointer("/message")
                .and_then(|message| message.as_str())
        })
        .unwrap_or("integration wiring looks healthy")
        .to_string()
}

fn print_snapshot(layout: &HomeLayout, dashboard: &Dashboard, view: TuiView) -> Result<()> {
    println!("Gommage dashboard");
    println!("version: {}", dashboard.version);
    println!("home: {}", dashboard.home);
    println!("status: {}", dashboard.overall_status().label());
    println!("summary: {}", dashboard.summary().describe());
    if let Some(row) = dashboard.primary_row() {
        println!(
            "focus: {} [{}] {} - {}",
            row.label,
            row.status.label(),
            row.summary,
            row.detail
        );
    }
    println!();
    println!("readiness:");
    for row in &dashboard.rows {
        println!(
            "- {} [{}] {} - {}",
            row.label,
            row.status.label(),
            row.summary,
            row.detail
        );
    }
    println!();
    println!("next:");
    for (index, action) in dashboard.next_actions.iter().enumerate() {
        println!("{}. {action}", index + 1);
    }
    if view != TuiView::Dashboard {
        println!();
        print_view_snapshot(layout, view)?;
    }
    Ok(())
}

fn print_view_snapshot(layout: &HomeLayout, view: TuiView) -> Result<()> {
    let views = if view == TuiView::All {
        TuiView::interactive_views().to_vec()
    } else {
        vec![view]
    };
    for view in views.into_iter().filter(|view| *view != TuiView::Dashboard) {
        let report = build_view_report(layout, view)?;
        println!("{}:", report.title);
        for line in report.lines {
            println!("- {line}");
        }
        if !report.next_actions.is_empty() {
            println!("next {}:", report.title);
            for (index, action) in report.next_actions.iter().enumerate() {
                println!("{}. {action}", index + 1);
            }
        }
        println!();
    }
    Ok(())
}

fn print_watch(
    layout: &HomeLayout,
    agents: &[AgentKind],
    view: TuiView,
    refresh: Duration,
    ticks: Option<u32>,
) -> Result<()> {
    let refresh = refresh.clamp(Duration::from_millis(250), Duration::from_millis(10_000));
    let limit = ticks.unwrap_or(u32::MAX);
    let mut stdout = io::stdout();
    for frame in 0..limit {
        if frame > 0 {
            thread::sleep(refresh);
            writeln!(stdout)?;
        }
        let dashboard = build_dashboard(layout, agents)?;
        writeln!(
            stdout,
            "--- gommage tui frame {} at {} ---",
            frame + 1,
            dashboard.updated
        )?;
        print_snapshot(layout, &dashboard, view)?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(unix)]
fn run_interactive(
    layout: &HomeLayout,
    agents: &[AgentKind],
    initial_view: TuiView,
    refresh: Duration,
) -> Result<()> {
    let refresh = refresh.clamp(Duration::from_millis(250), Duration::from_millis(10_000));
    let _session = TerminalSession::enter()?;
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let colors = color_enabled();
    let mut dashboard = build_dashboard(layout, agents)?;
    let mut selected = dashboard.primary_row_index().unwrap_or(0);
    let mut selected_approval = 0usize;
    let mut view = normalize_interactive_view(initial_view);
    let mut notice: Option<String> = None;
    let mut confirm: Option<PendingTuiAction> = None;
    let mut approval_draft = ApprovalDraft::default();
    let confirm_prompt = confirm.as_ref().map(PendingTuiAction::prompt);
    draw_dashboard(
        &mut stdout,
        layout,
        &dashboard,
        colors,
        RenderState {
            selected,
            selected_approval,
            view,
            approval_uses: approval_draft.uses,
            approval_ttl: approval_draft.ttl_label(),
            notice: notice.as_deref(),
            confirm: confirm_prompt.as_deref(),
        },
    )?;
    let mut last_refresh = Instant::now();
    let mut input = [0_u8; 1];

    loop {
        match stdin.read(&mut input) {
            Ok(0) => {}
            Ok(_) => {
                if let Some(action) = confirm.take() {
                    match input[0] {
                        b'y' | b'Y' => {
                            notice = Some(execute_tui_action(layout, action));
                            dashboard = build_dashboard(layout, agents)?;
                            selected = selected.min(dashboard.rows.len().saturating_sub(1));
                            selected_approval = clamp_approval_selection(layout, selected_approval);
                            last_refresh = Instant::now();
                        }
                        b'n' | b'N' | 27 => {
                            notice = Some("cancelled approval action".to_string());
                        }
                        other => {
                            confirm = Some(action);
                            notice = Some(format!(
                                "press y to confirm or n to cancel; ignored {:?}",
                                other as char
                            ));
                        }
                    }
                } else {
                    match input[0] {
                        b'q' | 27 => break,
                        b'j' | b'J' => {
                            if view == TuiView::Approvals {
                                selected_approval =
                                    (selected_approval + 1).min(pending_approval_max(layout));
                            } else {
                                selected =
                                    (selected + 1).min(dashboard.rows.len().saturating_sub(1));
                            }
                            notice = None;
                        }
                        b'k' | b'K' => {
                            if view == TuiView::Approvals {
                                selected_approval = selected_approval.saturating_sub(1);
                            } else {
                                selected = selected.saturating_sub(1);
                            }
                            notice = None;
                        }
                        b'r' | b'R' => {
                            dashboard = build_dashboard(layout, agents)?;
                            selected = selected.min(dashboard.rows.len().saturating_sub(1));
                            selected_approval = clamp_approval_selection(layout, selected_approval);
                            notice = Some("refreshed".to_string());
                            last_refresh = Instant::now();
                        }
                        b'1' => view = TuiView::Dashboard,
                        b'2' => view = TuiView::Approvals,
                        b'3' => view = TuiView::Policies,
                        b'4' => view = TuiView::Audit,
                        b'5' => view = TuiView::Capabilities,
                        b'6' => view = TuiView::Recovery,
                        b't' if view == TuiView::Approvals => {
                            approval_draft.cycle_ttl(false);
                            notice = Some(format!(
                                "approval ttl set to {}",
                                approval_draft.ttl_label()
                            ));
                        }
                        b'T' if view == TuiView::Approvals => {
                            approval_draft.cycle_ttl(true);
                            notice = Some(format!(
                                "approval ttl set to {}",
                                approval_draft.ttl_label()
                            ));
                        }
                        b'u' if view == TuiView::Approvals => {
                            approval_draft.cycle_uses(false);
                            notice = Some(format!("approval uses set to {}", approval_draft.uses));
                        }
                        b'U' if view == TuiView::Approvals => {
                            approval_draft.cycle_uses(true);
                            notice = Some(format!("approval uses set to {}", approval_draft.uses));
                        }
                        b'A' if view == TuiView::Approvals => {
                            if let Some(id) = selected_approval_id(layout, selected_approval) {
                                confirm =
                                    Some(PendingTuiAction::Approve(id, approval_draft.clone()));
                                notice = None;
                            } else {
                                notice = Some("no pending approval selected".to_string());
                            }
                        }
                        b'D' if view == TuiView::Approvals => {
                            if let Some(id) = selected_approval_id(layout, selected_approval) {
                                confirm = Some(PendingTuiAction::Deny(id));
                                notice = None;
                            } else {
                                notice = Some("no pending approval selected".to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("reading terminal input"),
        }

        if last_refresh.elapsed() >= refresh {
            dashboard = build_dashboard(layout, agents)?;
            selected = selected.min(dashboard.rows.len().saturating_sub(1));
            selected_approval = clamp_approval_selection(layout, selected_approval);
            last_refresh = Instant::now();
        }
        let confirm_prompt = confirm.as_ref().map(PendingTuiAction::prompt);
        draw_dashboard(
            &mut stdout,
            layout,
            &dashboard,
            colors,
            RenderState {
                selected,
                selected_approval,
                view,
                approval_uses: approval_draft.uses,
                approval_ttl: approval_draft.ttl_label(),
                notice: notice.as_deref(),
                confirm: confirm_prompt.as_deref(),
            },
        )?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn run_interactive(
    _layout: &HomeLayout,
    _agents: &[AgentKind],
    _initial_view: TuiView,
    _refresh: Duration,
) -> Result<()> {
    anyhow::bail!("interactive TUI is currently available on Unix terminals only")
}

#[cfg(unix)]
struct TerminalSession {
    stty_state: String,
}

#[cfg(unix)]
impl TerminalSession {
    fn enter() -> Result<Self> {
        let state = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::inherit())
            .output()
            .context("capturing terminal mode with stty -g")?;
        if !state.status.success() {
            anyhow::bail!("stty -g failed");
        }
        let stty_state = String::from_utf8(state.stdout)
            .context("decoding stty state")?
            .trim()
            .to_string();
        let status = Command::new("stty")
            .args(["raw", "-echo", "min", "0", "time", "1"])
            .stdin(Stdio::inherit())
            .status()
            .context("entering raw terminal mode")?;
        if !status.success() {
            anyhow::bail!("stty raw -echo failed");
        }
        let mut stdout = io::stdout();
        write!(stdout, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")?;
        stdout.flush()?;
        Ok(Self { stty_state })
    }
}

#[cfg(unix)]
impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = Command::new("stty")
            .arg(&self.stty_state)
            .stdin(Stdio::inherit())
            .status();
        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[0m\x1b[?25h\x1b[2J\x1b[H\x1b[?1049l");
        let _ = stdout.flush();
    }
}

fn draw_dashboard(
    stdout: &mut impl Write,
    layout: &HomeLayout,
    dashboard: &Dashboard,
    colors: bool,
    state: RenderState<'_>,
) -> io::Result<()> {
    let (cols, rows) = terminal_size();
    let width = cols.clamp(40, 120);
    let height = rows.max(12);
    let lines = render_lines(layout, dashboard, width, colors, state);
    write!(stdout, "\x1b[H\x1b[2J")?;
    for line in lines.into_iter().take(height) {
        writeln!(stdout, "{}", truncate_plain(&line, width))?;
    }
    stdout.flush()
}

fn selected_approval_id(layout: &HomeLayout, selected: usize) -> Option<String> {
    pending_approval_ids(layout).into_iter().nth(selected)
}

fn pending_approval_max(layout: &HomeLayout) -> usize {
    pending_approval_ids(layout).len().saturating_sub(1)
}

fn clamp_approval_selection(layout: &HomeLayout, selected: usize) -> usize {
    selected.min(pending_approval_max(layout))
}

fn terminal_size() -> (usize, usize) {
    if let (Ok(cols), Ok(lines)) = (std::env::var("COLUMNS"), std::env::var("LINES"))
        && let (Ok(cols), Ok(lines)) = (cols.parse::<usize>(), lines.parse::<usize>())
    {
        return (cols, lines);
    }
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("stty")
            .arg("size")
            .stdin(Stdio::inherit())
            .output()
            && output.status.success()
            && let Ok(size) = String::from_utf8(output.stdout)
        {
            let mut parts = size.split_whitespace();
            if let (Some(lines), Some(cols)) = (parts.next(), parts.next())
                && let (Ok(lines), Ok(cols)) = (lines.parse::<usize>(), cols.parse::<usize>())
            {
                return (cols, lines);
            }
        }
    }
    (80, 24)
}

fn next_actions(rows: &[StatusRow]) -> Vec<String> {
    let mut actions = Vec::new();
    if rows
        .iter()
        .any(|row| row.label == "doctor" && row.status == UiStatus::Fail)
    {
        actions.push("gommage quickstart --agent claude --daemon --self-test".to_string());
        actions.push("gommage verify --json".to_string());
        return actions;
    }
    if rows
        .iter()
        .any(|row| row.label.starts_with("agent ") && row.status == UiStatus::Fail)
    {
        actions.push("gommage agent status claude --json".to_string());
        actions.push("gommage agent status codex --json".to_string());
    }
    if rows
        .iter()
        .any(|row| row.label == "smoke" && row.status == UiStatus::Fail)
    {
        actions.push("gommage smoke --json".to_string());
    }
    actions.push("gommage verify --json".to_string());
    actions.truncate(4);
    actions
}

fn normalize_agents(agents: Vec<AgentKind>) -> Vec<AgentKind> {
    if agents.is_empty() {
        return vec![AgentKind::Claude, AgentKind::Codex];
    }
    let mut normalized = Vec::new();
    for agent in agents {
        if !normalized.contains(&agent) {
            normalized.push(agent);
        }
    }
    normalized
}

fn normalize_interactive_view(view: TuiView) -> TuiView {
    if view == TuiView::All {
        TuiView::Dashboard
    } else {
        view
    }
}

fn from_doctor_status(status: DoctorStatus) -> UiStatus {
    match status {
        DoctorStatus::Ok => UiStatus::Ok,
        DoctorStatus::Warn => UiStatus::Warn,
        DoctorStatus::Fail => UiStatus::Fail,
    }
}

fn from_smoke_status(status: SmokeStatus) -> UiStatus {
    match status {
        SmokeStatus::Pass => UiStatus::Ok,
        SmokeStatus::Fail => UiStatus::Fail,
    }
}

fn doctor_hint(status: DoctorStatus) -> String {
    match status {
        DoctorStatus::Ok => "home, policy, mapper, audit, and companions are readable".to_string(),
        DoctorStatus::Warn => "operable, but review warnings before trusting a hook".to_string(),
        DoctorStatus::Fail => "run 'gommage init' or 'gommage quickstart' first".to_string(),
    }
}

fn agent_name(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Claude => "claude",
        AgentKind::Codex => "codex",
    }
}

impl Dashboard {
    pub(crate) fn overall_status(&self) -> UiStatus {
        self.rows
            .iter()
            .map(|row| row.status)
            .max_by_key(|status| status.rank())
            .unwrap_or(UiStatus::Skip)
    }

    pub(crate) fn summary(&self) -> DashboardSummary {
        let mut summary = DashboardSummary {
            total: self.rows.len(),
            ok: 0,
            warn: 0,
            fail: 0,
            skip: 0,
        };
        for row in &self.rows {
            match row.status {
                UiStatus::Ok => summary.ok += 1,
                UiStatus::Warn => summary.warn += 1,
                UiStatus::Fail => summary.fail += 1,
                UiStatus::Skip => summary.skip += 1,
            }
        }
        summary
    }

    fn primary_row(&self) -> Option<&StatusRow> {
        self.primary_row_index()
            .and_then(|index| self.rows.get(index))
    }

    fn primary_row_index(&self) -> Option<usize> {
        let overall = self.overall_status();
        self.rows.iter().position(|row| row.status == overall)
    }
}

impl DashboardSummary {
    pub(crate) fn ready_percent(self) -> usize {
        self.ok
            .saturating_mul(100)
            .checked_div(self.total)
            .unwrap_or(0)
    }

    pub(crate) fn describe(self) -> String {
        format!(
            "{} check(s): {} ok, {} warn, {} fail, {} skip",
            self.total, self.ok, self.warn, self.fail, self.skip
        )
    }
}
