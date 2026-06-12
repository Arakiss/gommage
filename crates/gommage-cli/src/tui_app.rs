//! Interactive operator dashboard rendered with ratatui.
//!
//! This module owns ONLY the full-screen interactive path. The non-interactive
//! `--snapshot` / `--watch` / `--stream` contract lives in `tui.rs` and is byte
//! identical; nothing here is reachable from those code paths.

use anyhow::Result;
use gommage_core::runtime::HomeLayout;
use std::time::{Duration, Instant};

use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Tabs, Wrap,
    },
};

use crate::{
    agent::AgentKind,
    gestral::{UiTone, color_enabled},
    tui::{Dashboard, build_dashboard, normalize_interactive_view},
    tui_actions::{ApprovalDraft, PendingTuiAction, execute_tui_action},
    tui_views::{TuiView, build_approvals_report, build_view_report, pending_approval_ids},
};

const TAB_TITLES: [&str; 8] = [
    "1 readiness",
    "2 approvals",
    "3 policies",
    "4 audit",
    "5 capabilities",
    "6 recovery",
    "7 onboarding",
    "8 metrics",
];

/// Lines moved per PageUp/PageDown.
const PAGE_STEP: u16 = 10;
/// Lines moved per mouse-wheel notch.
const WHEEL_STEP: u16 = 3;

/// Interactive dashboard state. Owns a reconstructed `HomeLayout` and the agent
/// filter so `draw`/`handle_key` stay self-contained and unit-testable without a
/// terminal.
pub(crate) struct App {
    layout: HomeLayout,
    agents: Vec<AgentKind>,
    dashboard: Dashboard,
    selected: usize,
    selected_approval: usize,
    view: TuiView,
    approval_draft: ApprovalDraft,
    notice: Option<String>,
    confirm: Option<PendingTuiAction>,
    scroll: u16,
    show_help: bool,
    last_refresh: Instant,
    refresh: Duration,
    colors: bool,
    quit: bool,
}

impl App {
    pub(crate) fn new(
        layout: &HomeLayout,
        agents: &[AgentKind],
        initial_view: TuiView,
        refresh: Duration,
    ) -> Result<Self> {
        let dashboard = build_dashboard(layout, agents)?;
        let selected = dashboard.primary_row_index().unwrap_or(0);
        Ok(Self {
            layout: HomeLayout::at(&layout.root),
            agents: agents.to_vec(),
            dashboard,
            selected,
            selected_approval: 0,
            view: normalize_interactive_view(initial_view),
            approval_draft: ApprovalDraft::default(),
            notice: None,
            confirm: None,
            scroll: 0,
            show_help: false,
            last_refresh: Instant::now(),
            refresh,
            colors: color_enabled(),
            quit: false,
        })
    }

    /// Rebuild the dashboard and re-clamp the selections. Leaves `notice` and
    /// `scroll` untouched so callers decide their own messaging.
    fn rebuild(&mut self) -> Result<()> {
        self.dashboard = build_dashboard(&self.layout, &self.agents)?;
        self.selected = self
            .selected
            .min(self.dashboard.rows.len().saturating_sub(1));
        self.selected_approval = clamp_approval_selection(&self.layout, self.selected_approval);
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn move_selection(&mut self, down: bool) {
        if self.view == TuiView::Approvals {
            let max = pending_approval_max(&self.layout);
            self.selected_approval = step(self.selected_approval, down, max);
        } else {
            let max = self.dashboard.rows.len().saturating_sub(1);
            self.selected = step(self.selected, down, max);
        }
        self.notice = None;
    }

    fn set_view(&mut self, view: TuiView) {
        if self.view != view {
            self.view = view;
            self.scroll = 0;
        }
    }
}

fn step(current: usize, down: bool, max: usize) -> usize {
    if down {
        (current + 1).min(max)
    } else {
        current.saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// Event loop + terminal lifecycle (Unix only — matches the daemon posture).
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) fn run_interactive(
    layout: &HomeLayout,
    agents: &[AgentKind],
    initial_view: TuiView,
    refresh: Duration,
) -> Result<()> {
    use anyhow::Context;

    let refresh = refresh.clamp(Duration::from_millis(250), Duration::from_millis(10_000));
    let mut app = App::new(layout, agents, initial_view, refresh)?;
    let mut guard = TerminalGuard::enter()?;
    let result = run_loop(&mut guard, &mut app);
    // `guard` restores the terminal on drop; surface the loop error afterwards.
    drop(guard);
    result.context("interactive event loop")
}

#[cfg(not(unix))]
pub(crate) fn run_interactive(
    _layout: &HomeLayout,
    _agents: &[AgentKind],
    _initial_view: TuiView,
    _refresh: Duration,
) -> Result<()> {
    anyhow::bail!("interactive TUI is currently available on Unix terminals only")
}

#[cfg(unix)]
fn run_loop(guard: &mut TerminalGuard, app: &mut App) -> Result<()> {
    use anyhow::Context;
    use ratatui::crossterm::event::{self, Event, KeyEventKind};

    guard.terminal.draw(|frame| draw(frame, app))?;
    while !app.quit {
        if event::poll(app.refresh).context("polling terminal events")? {
            match event::read().context("reading terminal event")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key)?,
                Event::Mouse(mouse) => handle_mouse(app, mouse),
                _ => {}
            }
        }
        if app.last_refresh.elapsed() >= app.refresh {
            app.rebuild()?;
        }
        guard.terminal.draw(|frame| draw(frame, app))?;
    }
    Ok(())
}

#[cfg(unix)]
struct TerminalGuard {
    terminal: ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
}

#[cfg(unix)]
impl TerminalGuard {
    fn enter() -> Result<Self> {
        use anyhow::Context;
        use ratatui::{
            Terminal,
            backend::CrosstermBackend,
            crossterm::{
                event::EnableMouseCapture,
                execute,
                terminal::{EnterAlternateScreen, enable_raw_mode},
            },
        };

        install_panic_hook();
        enable_raw_mode().context("enabling raw terminal mode")?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .context("entering alternate screen")?;
        let terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))
            .context("initializing terminal backend")?;
        Ok(Self { terminal })
    }
}

#[cfg(unix)]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = restore_terminal();
    }
}

/// Best-effort terminal restore. Idempotent, so the panic hook and `Drop` can
/// both fire without corrupting the terminal.
#[cfg(unix)]
fn restore_terminal() -> std::io::Result<()> {
    use ratatui::crossterm::{
        event::DisableMouseCapture,
        execute,
        terminal::{LeaveAlternateScreen, disable_raw_mode},
    };

    let mut stdout = std::io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    disable_raw_mode()
}

/// The release profile is `panic = "abort"`, so `Drop` never runs on panic.
/// This hook is the real safety net: restore the terminal, then chain whatever
/// hook was installed before us (so the default panic message still prints).
#[cfg(unix)]
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        previous(info);
    }));
}

#[cfg(unix)]
fn handle_mouse(app: &mut App, mouse: ratatui::crossterm::event::MouseEvent) {
    use ratatui::crossterm::event::MouseEventKind;

    if app.confirm.is_some() || app.show_help {
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollDown => app.scroll = app.scroll.saturating_add(WHEEL_STEP),
        MouseEventKind::ScrollUp => app.scroll = app.scroll.saturating_sub(WHEEL_STEP),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Keyboard protocol — preserved exactly, plus additive help/scroll bindings.
// ---------------------------------------------------------------------------

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    // Help overlay swallows input; only its own keys close it.
    if app.show_help {
        if matches!(
            key.code,
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q')
        ) {
            app.show_help = false;
        }
        return Ok(());
    }

    // Confirm popup: y/n/Esc, identical notice strings to the old renderer.
    if let Some(action) = app.confirm.take() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let message = execute_tui_action(&app.layout, action);
                app.notice = Some(message);
                app.rebuild()?;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.notice = Some("cancelled approval action".to_string());
            }
            other => {
                app.confirm = Some(action);
                app.notice = Some(ignored_confirm_message(other));
            }
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Down => app.move_selection(true),
        KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Up => app.move_selection(false),
        KeyCode::Char('r') | KeyCode::Char('R') => {
            app.rebuild()?;
            app.scroll = 0;
            app.notice = Some("refreshed".to_string());
        }
        KeyCode::Char('1') => app.set_view(TuiView::Dashboard),
        KeyCode::Char('2') => app.set_view(TuiView::Approvals),
        KeyCode::Char('3') => app.set_view(TuiView::Policies),
        KeyCode::Char('4') => app.set_view(TuiView::Audit),
        KeyCode::Char('5') => app.set_view(TuiView::Capabilities),
        KeyCode::Char('6') => app.set_view(TuiView::Recovery),
        KeyCode::Char('7') => app.set_view(TuiView::Onboarding),
        KeyCode::Char('8') => app.set_view(TuiView::Metrics),
        KeyCode::Char('?') => app.show_help = !app.show_help,
        KeyCode::PageDown => app.scroll = app.scroll.saturating_add(PAGE_STEP),
        KeyCode::PageUp => app.scroll = app.scroll.saturating_sub(PAGE_STEP),
        KeyCode::Char('t') if app.view == TuiView::Approvals => {
            app.approval_draft.cycle_ttl(false);
            app.notice = Some(format!(
                "approval ttl set to {}",
                app.approval_draft.ttl_label()
            ));
        }
        KeyCode::Char('T') if app.view == TuiView::Approvals => {
            app.approval_draft.cycle_ttl(true);
            app.notice = Some(format!(
                "approval ttl set to {}",
                app.approval_draft.ttl_label()
            ));
        }
        KeyCode::Char('u') if app.view == TuiView::Approvals => {
            app.approval_draft.cycle_uses(false);
            app.notice = Some(format!("approval uses set to {}", app.approval_draft.uses));
        }
        KeyCode::Char('U') if app.view == TuiView::Approvals => {
            app.approval_draft.cycle_uses(true);
            app.notice = Some(format!("approval uses set to {}", app.approval_draft.uses));
        }
        KeyCode::Char('A') if app.view == TuiView::Approvals => {
            if let Some(id) = selected_approval_id(&app.layout, app.selected_approval) {
                app.confirm = Some(PendingTuiAction::Approve(id, app.approval_draft.clone()));
                app.notice = None;
            } else {
                app.notice = Some("no pending approval selected".to_string());
            }
        }
        KeyCode::Char('D') if app.view == TuiView::Approvals => {
            if let Some(id) = selected_approval_id(&app.layout, app.selected_approval) {
                app.confirm = Some(PendingTuiAction::Deny(id));
                app.notice = None;
            } else {
                app.notice = Some("no pending approval selected".to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn ignored_confirm_message(code: KeyCode) -> String {
    match code {
        KeyCode::Char(ch) => format!("press y to confirm or n to cancel; ignored {ch:?}"),
        other => format!("press y to confirm or n to cancel; ignored {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Approval-selection helpers (moved out of tui.rs).
// ---------------------------------------------------------------------------

fn selected_approval_id(layout: &HomeLayout, selected: usize) -> Option<String> {
    pending_approval_ids(layout).into_iter().nth(selected)
}

fn pending_approval_max(layout: &HomeLayout) -> usize {
    pending_approval_ids(layout).len().saturating_sub(1)
}

fn clamp_approval_selection(layout: &HomeLayout, selected: usize) -> usize {
    selected.min(pending_approval_max(layout))
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(4), // header
        Constraint::Length(3), // tabs
        Constraint::Min(3),    // body
        Constraint::Length(4), // footer
    ])
    .split(area);

    render_header(frame, app, chunks[0]);
    render_tabs(frame, app, chunks[1]);
    render_body(frame, app, chunks[2]);
    render_footer(frame, app, chunks[3]);

    if app.show_help {
        render_help(frame, app, area);
    } else if let Some(action) = app.confirm.as_ref() {
        render_confirm(frame, app, area, action);
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let dashboard = &app.dashboard;
    let overall = dashboard.overall_status();
    let summary = dashboard.summary();
    let title = Line::from(vec![
        Span::styled(" GOMMAGE ", tone_bold(UiTone::Teal, app.colors)),
        Span::styled("operator dashboard ", tone_style(UiTone::Muted, app.colors)),
    ]);
    let line_one = Line::from(vec![
        Span::styled("version ", tone_style(UiTone::Muted, app.colors)),
        Span::styled(dashboard.version, tone_style(UiTone::Teal, app.colors)),
        Span::raw("   "),
        Span::styled("home ", tone_style(UiTone::Muted, app.colors)),
        Span::raw(dashboard.home.clone()),
    ]);
    let line_two = Line::from(vec![
        Span::styled("status ", tone_style(UiTone::Muted, app.colors)),
        Span::styled(overall.marker(), tone_bold(overall.tone(), app.colors)),
        Span::raw("   "),
        Span::styled("ready ", tone_style(UiTone::Muted, app.colors)),
        Span::styled(
            format!("{}%", summary.ready_percent()),
            tone_style(UiTone::Gold, app.colors),
        ),
        Span::raw("   "),
        Span::styled("updated ", tone_style(UiTone::Muted, app.colors)),
        Span::raw(dashboard.updated.clone()),
    ]);
    let paragraph = Paragraph::new(vec![line_one, line_two]).block(
        Block::bordered()
            .title(title)
            .border_style(tone_style(UiTone::Teal, app.colors)),
    );
    frame.render_widget(paragraph, area);
}

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = TAB_TITLES.iter().map(|title| Line::from(*title)).collect();
    let tabs = Tabs::new(titles)
        .select(tab_index(app.view))
        .block(Block::bordered().border_style(tone_style(UiTone::Teal, app.colors)))
        .style(tone_style(UiTone::Muted, app.colors))
        .highlight_style(tone_bold(UiTone::Gold, app.colors))
        .divider(" ");
    frame.render_widget(tabs, area);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mut legend: Vec<Span> = Vec::new();
    for (index, (key, desc)) in [
        ("q", "quit"),
        ("r", "refresh"),
        ("j/k", "move"),
        ("1-8", "views"),
        ("A/D", "approve/deny"),
        ("t/T u/U", "draft"),
        ("?", "help"),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            legend.push(Span::raw("   "));
        }
        legend.push(Span::styled(key, tone_bold(UiTone::Gold, app.colors)));
        legend.push(Span::raw(format!(" {desc}")));
    }

    let status = if let Some(action) = app.confirm.as_ref() {
        Line::from(vec![
            Span::styled("confirm ", tone_bold(UiTone::Gold, app.colors)),
            Span::raw(action.prompt()),
        ])
    } else if let Some(notice) = app.notice.as_ref() {
        Line::from(vec![
            Span::styled("notice ", tone_bold(UiTone::Gold, app.colors)),
            Span::raw(notice.clone()),
        ])
    } else {
        Line::raw("")
    };

    let paragraph = Paragraph::new(vec![Line::from(legend), status])
        .block(Block::bordered().border_style(tone_style(UiTone::Teal, app.colors)));
    frame.render_widget(paragraph, area);
}

fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.view {
        TuiView::Dashboard | TuiView::All => render_dashboard_view(frame, app, area),
        TuiView::Approvals => render_approvals_view(frame, app, area),
        other => render_report_view(frame, app, other, area),
    }
}

fn render_dashboard_view(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
    render_gauge(frame, app, rows[0]);

    let lower =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(rows[1]);
    render_rows_list(frame, app, lower[0]);

    let right =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(lower[1]);
    render_focus(frame, app, right[0]);
    render_next(frame, app, &app.dashboard.next_actions, right[1]);
}

fn render_gauge(frame: &mut Frame, app: &App, area: Rect) {
    let summary = app.dashboard.summary();
    let percent = summary.ready_percent().min(100) as u16;
    let overall = app.dashboard.overall_status();
    let gauge = Gauge::default()
        .block(
            Block::bordered()
                .title(" readiness ")
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .gauge_style(tone_style(overall.tone(), app.colors))
        .percent(percent)
        .label(format!("{percent}%  {}", summary.describe()));
    frame.render_widget(gauge, area);
}

fn render_rows_list(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .dashboard
        .rows
        .iter()
        .map(|row| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<4}", row.status.marker()),
                    tone_bold(row.status.tone(), app.colors),
                ),
                Span::styled(
                    format!(" {:<14}", row.label),
                    tone_style(UiTone::Gold, app.colors),
                ),
                Span::raw(row.summary.clone()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" checks ")
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    let mut state = ListState::default();
    if !app.dashboard.rows.is_empty() {
        state.select(Some(app.selected.min(app.dashboard.rows.len() - 1)));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_focus(frame: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(row) = app.dashboard.rows.get(app.selected) {
        Text::from(vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", row.label),
                    tone_bold(UiTone::Gold, app.colors),
                ),
                Span::styled(
                    format!("[{}]", row.status.label()),
                    tone_style(row.status.tone(), app.colors),
                ),
            ]),
            Line::raw(row.summary.clone()),
            Line::raw(""),
            Line::raw(row.detail.clone()),
        ])
    } else {
        Text::raw("no checks available")
    };
    let paragraph = Paragraph::new(text)
        .block(
            Block::bordered()
                .title(" focus ")
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_next(frame: &mut Frame, app: &App, actions: &[String], area: Rect) {
    let items: Vec<ListItem> = actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{}. ", index + 1),
                    tone_bold(UiTone::Gold, app.colors),
                ),
                Span::raw(action.clone()),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::bordered()
            .title(" next ")
            .border_style(tone_style(UiTone::Teal, app.colors)),
    );
    frame.render_widget(list, area);
}

fn render_approvals_view(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).split(area);

    let draft = Line::from(vec![
        Span::styled("ttl ", tone_style(UiTone::Muted, app.colors)),
        Span::styled(
            app.approval_draft.ttl_label(),
            tone_bold(UiTone::Gold, app.colors),
        ),
        Span::raw("    "),
        Span::styled("uses ", tone_style(UiTone::Muted, app.colors)),
        Span::styled(
            app.approval_draft.uses.to_string(),
            tone_bold(UiTone::Gold, app.colors),
        ),
        Span::raw("    "),
        Span::styled(
            "t/T ttl   u/U uses   A approve   D deny",
            tone_style(UiTone::Muted, app.colors),
        ),
    ]);
    let header = Paragraph::new(draft).block(
        Block::bordered()
            .title(" approval draft ")
            .border_style(tone_style(UiTone::Teal, app.colors)),
    );
    frame.render_widget(header, chunks[0]);

    let report = build_approvals_report(&app.layout, Some(app.selected_approval));
    render_report_inner(
        frame,
        app,
        &report.title,
        &report.lines,
        &report.next_actions,
        chunks[1],
    );
}

fn render_report_view(frame: &mut Frame, app: &mut App, view: TuiView, area: Rect) {
    match build_view_report(&app.layout, view) {
        Ok(report) => render_report_inner(
            frame,
            app,
            &report.title,
            &report.lines,
            &report.next_actions,
            area,
        ),
        Err(error) => {
            let paragraph = Paragraph::new(format!("could not render {}: {error}", view.label()))
                .block(
                    Block::bordered()
                        .title(format!(" {} ", view.label()))
                        .border_style(tone_style(UiTone::Red, app.colors)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(paragraph, area);
        }
    }
}

/// Shared scrollable body + numbered "next" panel. Writes the clamped scroll
/// offset back into `app` so PageUp/PageDown/wheel can never run away.
fn render_report_inner(
    frame: &mut Frame,
    app: &mut App,
    title: &str,
    lines: &[String],
    next: &[String],
    area: Rect,
) {
    let next_height = next_panel_height(next.len(), area.height);
    let chunks =
        Layout::vertical([Constraint::Min(3), Constraint::Length(next_height)]).split(area);
    let body_area = chunks[0];

    let total = lines.len();
    let inner_height = body_area.height.saturating_sub(2) as usize;
    let max_scroll = total.saturating_sub(inner_height) as u16;
    app.scroll = app.scroll.min(max_scroll);

    let body: Vec<Line> = lines.iter().map(|line| Line::raw(line.clone())).collect();
    let paragraph = Paragraph::new(body)
        .block(
            Block::bordered()
                .title(format!(" {title} "))
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .scroll((app.scroll, 0));
    frame.render_widget(paragraph, body_area);

    if total > inner_height {
        let mut scrollbar_state = ScrollbarState::new(total).position(app.scroll as usize);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("^"))
                .end_symbol(Some("v")),
            body_area,
            &mut scrollbar_state,
        );
    }

    render_next(frame, app, next, chunks[1]);
}

fn next_panel_height(count: usize, total_height: u16) -> u16 {
    let want = (count as u16).saturating_add(2).max(3);
    let cap = (total_height / 2).max(3);
    want.min(cap)
}

fn render_confirm(frame: &mut Frame, app: &App, area: Rect, action: &PendingTuiAction) {
    let popup = popup_area(area, 72, 7);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::styled("Confirm action", tone_bold(UiTone::Gold, app.colors)),
        Line::raw(""),
        Line::raw(action.prompt()),
        Line::raw(""),
        Line::styled(
            "press y to confirm, n to cancel",
            tone_style(UiTone::Muted, app.colors),
        ),
    ];
    let paragraph = Paragraph::new(lines)
        .block(
            Block::bordered()
                .title(" confirm ")
                .border_style(tone_style(UiTone::Gold, app.colors)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, popup);
}

fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let popup = popup_area(area, 56, 20);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::styled(
            "Gommage operator TUI — keys",
            tone_bold(UiTone::Gold, app.colors),
        ),
        Line::raw(""),
        Line::raw("q / Esc       quit"),
        Line::raw("j / k / Up/Dn move selection"),
        Line::raw("1 - 8         switch view"),
        Line::raw("r             refresh now"),
        Line::raw("PgUp / PgDn   scroll body"),
        Line::raw("wheel         scroll body"),
        Line::raw(""),
        Line::styled("Approvals view", tone_bold(UiTone::Gold, app.colors)),
        Line::raw("t / T         cycle ttl"),
        Line::raw("u / U         cycle uses"),
        Line::raw("A             approve selected"),
        Line::raw("D             deny selected"),
        Line::raw("y / n         confirm / cancel"),
        Line::raw(""),
        Line::raw("?             close this help"),
    ];
    let paragraph = Paragraph::new(lines)
        .block(
            Block::bordered()
                .title(" help ")
                .border_style(tone_style(UiTone::Gold, app.colors)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, popup);
}

fn tab_index(view: TuiView) -> usize {
    match view {
        TuiView::Dashboard | TuiView::All => 0,
        TuiView::Approvals => 1,
        TuiView::Policies => 2,
        TuiView::Audit => 3,
        TuiView::Capabilities => 4,
        TuiView::Recovery => 5,
        TuiView::Onboarding => 6,
        TuiView::Metrics => 7,
    }
}

/// Centered fixed-size rect, clamped so it always fits the frame.
fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

/// Foreground color for a `UiTone`, honoring `NO_COLOR`: returns
/// `Style::default()` when color is disabled (matching the old renderer). All
/// styling lives in ratatui here — we reuse only the tone/status enums.
fn tone_style(tone: UiTone, colors: bool) -> Style {
    if !colors {
        return Style::default();
    }
    let color = match tone {
        UiTone::Teal => Color::Rgb(0, 179, 164),
        UiTone::Gold => Color::Rgb(244, 185, 66),
        UiTone::Green => Color::Green,
        UiTone::Red => Color::Red,
        UiTone::Muted => Color::DarkGray,
    };
    Style::default().fg(color)
}

fn tone_bold(tone: UiTone, colors: bool) -> Style {
    if colors {
        tone_style(tone, colors).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        Terminal,
        backend::TestBackend,
        crossterm::event::{KeyEvent, KeyModifiers},
    };
    use tempfile::tempdir;

    fn test_app(view: TuiView) -> (tempfile::TempDir, App) {
        let temp = tempdir().unwrap();
        let layout = HomeLayout::at(&temp.path().join(".gommage"));
        let agents = [AgentKind::Claude, AgentKind::Codex];
        let app = App::new(&layout, &agents, view, Duration::from_millis(1500)).unwrap();
        (temp, app)
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn dashboard_renders_core_chrome() {
        let (_temp, mut app) = test_app(TuiView::Dashboard);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("GOMMAGE"), "header title missing: {text}");
        assert!(text.contains("version"), "version label missing");
        assert!(text.contains("doctor"), "doctor row missing");
        assert!(text.contains('%'), "readiness percent missing");
    }

    #[test]
    fn approvals_view_renders() {
        let (_temp, mut app) = test_app(TuiView::Approvals);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("approval"), "approvals body missing: {text}");
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let (_temp, mut app) = test_app(TuiView::Dashboard);
        let mut terminal = Terminal::new(TestBackend::new(20, 6)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }

    #[test]
    fn key_j_advances_selection() {
        let (_temp, mut app) = test_app(TuiView::Dashboard);
        let before = app.selected;
        let max = app.dashboard.rows.len().saturating_sub(1);
        handle_key(&mut app, press(KeyCode::Char('j'))).unwrap();
        assert_eq!(app.selected, (before + 1).min(max));
    }

    #[test]
    fn key_two_switches_to_approvals() {
        let (_temp, mut app) = test_app(TuiView::Dashboard);
        handle_key(&mut app, press(KeyCode::Char('2'))).unwrap();
        assert_eq!(app.view, TuiView::Approvals);
    }

    #[test]
    fn key_question_toggles_help() {
        let (_temp, mut app) = test_app(TuiView::Dashboard);
        assert!(!app.show_help);
        handle_key(&mut app, press(KeyCode::Char('?'))).unwrap();
        assert!(app.show_help);
        handle_key(&mut app, press(KeyCode::Char('?'))).unwrap();
        assert!(!app.show_help);
    }

    #[test]
    fn view_change_resets_scroll() {
        let (_temp, mut app) = test_app(TuiView::Policies);
        app.scroll = 7;
        handle_key(&mut app, press(KeyCode::Char('4'))).unwrap();
        assert_eq!(app.view, TuiView::Audit);
        assert_eq!(app.scroll, 0);
    }
}
