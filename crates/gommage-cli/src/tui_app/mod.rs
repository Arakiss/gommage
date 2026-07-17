//! Interactive Gommage operator console.
//!
//! The full-screen path renders a captured TuiSnapshot. It deliberately has no
//! filesystem or database reads in draw functions: refresh is the only point
//! where the visible state changes.

use anyhow::Result;
use gommage_core::{ApprovalState, runtime::HomeLayout};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use std::time::{Duration, Instant};

use crate::{
    agent::AgentKind,
    gestral::{UiTone, color_enabled},
    tui::{Dashboard, StatusRow},
    tui_actions::{ApprovalActionPreview, ApprovalDraft, PendingTuiAction, execute_tui_action},
    tui_data::TuiSnapshot,
    tui_views::TuiView,
};

mod approvals;

use approvals::{render_approvals, render_confirm, render_help, render_inspect};

const MIN_WIDTH: u16 = 80;
const MIN_HEIGHT: u16 = 24;
const PAGE_STEP: u16 = 10;
const WHEEL_STEP: u16 = 3;
const INSPECT_VIEWS: [TuiView; 6] = [
    TuiView::Policies,
    TuiView::Audit,
    TuiView::Capabilities,
    TuiView::Recovery,
    TuiView::Onboarding,
    TuiView::Metrics,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimaryView {
    Overview,
    Approvals,
    Inspect,
}

impl PrimaryView {
    fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Approvals => 1,
            Self::Inspect => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Approvals => "approvals",
            Self::Inspect => "inspect",
        }
    }
}

/// State that changes through operator input. The data itself stays inside a
/// TuiSnapshot and is only replaced in rebuild.
pub(crate) struct App {
    layout: HomeLayout,
    agents: Vec<AgentKind>,
    snapshot: TuiSnapshot,
    primary: PrimaryView,
    inspect_view: TuiView,
    selected_check: usize,
    selected_approval_id: Option<String>,
    approval_draft: ApprovalDraft,
    show_technical: bool,
    notice: Option<String>,
    confirm: Option<PendingTuiAction>,
    scroll: u16,
    show_help: bool,
    last_refresh: Instant,
    refresh: Duration,
    colors: bool,
    viewport: (u16, u16),
    quit: bool,
}

impl App {
    pub(crate) fn new(
        layout: &HomeLayout,
        agents: &[AgentKind],
        initial_view: TuiView,
        refresh: Duration,
    ) -> Result<Self> {
        let snapshot = TuiSnapshot::capture(layout, agents)?;
        let (primary, inspect_view) = initial_destination(initial_view);
        let selected_check = snapshot.dashboard.primary_row_index().unwrap_or(0);
        let selected_approval_id = snapshot
            .approvals
            .pending_ids()
            .first()
            .map(|id| (*id).to_string());
        Ok(Self {
            layout: HomeLayout::at(&layout.root),
            agents: agents.to_vec(),
            snapshot,
            primary,
            inspect_view,
            selected_check,
            selected_approval_id,
            approval_draft: ApprovalDraft::default(),
            show_technical: false,
            notice: None,
            confirm: None,
            scroll: 0,
            show_help: false,
            last_refresh: Instant::now(),
            refresh,
            colors: color_enabled(),
            viewport: (u16::MAX, u16::MAX),
            quit: false,
        })
    }

    fn rebuild(&mut self) -> Result<()> {
        let selected_approval_id = self.selected_approval_id.clone();
        self.snapshot = TuiSnapshot::capture(&self.layout, &self.agents)?;
        self.selected_check = self
            .selected_check
            .min(self.snapshot.dashboard.rows.len().saturating_sub(1));
        self.selected_approval_id = selected_approval_id
            .filter(|id| self.snapshot.approvals.selected(id).is_some())
            .or_else(|| {
                self.snapshot
                    .approvals
                    .pending_ids()
                    .first()
                    .map(|id| (*id).to_string())
            });
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn selected_approval(&self) -> Option<&ApprovalState> {
        self.selected_approval_id
            .as_deref()
            .and_then(|id| self.snapshot.approvals.selected(id))
    }

    fn pending_count(&self) -> usize {
        self.snapshot.approvals.pending().len()
    }

    fn move_selection(&mut self, down: bool) {
        match self.primary {
            PrimaryView::Overview => {
                let max = self.snapshot.dashboard.rows.len().saturating_sub(1);
                self.selected_check = step(self.selected_check, down, max);
            }
            PrimaryView::Approvals => self.move_approval_selection(down),
            PrimaryView::Inspect => {
                self.scroll = if down {
                    self.scroll.saturating_add(1)
                } else {
                    self.scroll.saturating_sub(1)
                };
            }
        }
        self.notice = None;
    }

    fn move_approval_selection(&mut self, down: bool) {
        let ids = self.snapshot.approvals.pending_ids();
        let Some(current) = self.selected_approval_id.as_deref() else {
            self.selected_approval_id = ids.first().map(|id| (*id).to_string());
            return;
        };
        let current_index = ids.iter().position(|id| *id == current).unwrap_or(0);
        let next = step(current_index, down, ids.len().saturating_sub(1));
        self.selected_approval_id = ids.get(next).map(|id| (*id).to_string());
    }

    fn set_primary(&mut self, primary: PrimaryView) {
        if self.primary != primary {
            self.primary = primary;
            self.scroll = 0;
            self.notice = None;
        }
    }

    fn set_inspect(&mut self, view: TuiView) {
        self.primary = PrimaryView::Inspect;
        self.inspect_view = view;
        self.scroll = 0;
        self.notice = None;
    }

    fn cycle_inspect(&mut self, reverse: bool) {
        let index = INSPECT_VIEWS
            .iter()
            .position(|view| *view == self.inspect_view)
            .unwrap_or(0);
        let next = if reverse {
            index.checked_sub(1).unwrap_or(INSPECT_VIEWS.len() - 1)
        } else {
            (index + 1) % INSPECT_VIEWS.len()
        };
        self.set_inspect(INSPECT_VIEWS[next]);
    }

    fn dashboard(&self) -> &Dashboard {
        &self.snapshot.dashboard
    }

    fn is_modal(&self) -> bool {
        self.confirm.is_some() || self.show_help
    }

    fn update_viewport(&mut self, width: u16, height: u16) {
        let was_compact = self.is_compact();
        self.viewport = (width, height);
        if !was_compact && self.is_compact() && self.confirm.take().is_some() {
            self.notice = Some(format!(
                "confirmation cancelled: terminal is smaller than {MIN_WIDTH}x{MIN_HEIGHT}"
            ));
        }
    }

    fn is_compact(&self) -> bool {
        self.viewport.0 < MIN_WIDTH || self.viewport.1 < MIN_HEIGHT
    }
}

fn initial_destination(view: TuiView) -> (PrimaryView, TuiView) {
    match view {
        TuiView::Dashboard | TuiView::All => (PrimaryView::Overview, TuiView::Policies),
        TuiView::Approvals => (PrimaryView::Approvals, TuiView::Policies),
        other => (PrimaryView::Inspect, other),
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
// Event loop and terminal lifecycle.
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
            match event::read().context("reading terminal events")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key)?,
                Event::Mouse(mouse) => handle_mouse(app, mouse),
                Event::Resize(width, height) => app.update_viewport(width, height),
                _ => {}
            }
        }
        if !app.is_modal() && app.last_refresh.elapsed() >= app.refresh {
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

    if app.is_modal() || app.primary != PrimaryView::Inspect {
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollDown => app.scroll = app.scroll.saturating_add(WHEEL_STEP),
        MouseEventKind::ScrollUp => app.scroll = app.scroll.saturating_sub(WHEEL_STEP),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Keyboard protocol.
// ---------------------------------------------------------------------------

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if app.is_compact() {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            _ => {
                app.notice = Some(format!(
                    "resize to at least {MIN_WIDTH}x{MIN_HEIGHT} before using the operator TUI"
                ));
            }
        }
        return Ok(());
    }

    if app.show_help {
        if matches!(
            key.code,
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q')
        ) {
            app.show_help = false;
        }
        return Ok(());
    }

    if let Some(action) = app.confirm.take() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.notice = Some(execute_tui_action(&app.layout, action));
                app.rebuild()?;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.notice = Some("cancelled approval action".to_string());
            }
            other => {
                app.notice = Some(ignored_confirm_message(other));
                app.confirm = Some(action);
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
        KeyCode::Char('1') => app.set_primary(PrimaryView::Overview),
        KeyCode::Char('2') => app.set_primary(PrimaryView::Approvals),
        KeyCode::Char('3') => app.set_inspect(TuiView::Policies),
        KeyCode::Char('4') => app.set_inspect(TuiView::Audit),
        KeyCode::Char('5') => app.set_inspect(TuiView::Capabilities),
        KeyCode::Char('6') => app.set_inspect(TuiView::Recovery),
        KeyCode::Char('7') => app.set_inspect(TuiView::Onboarding),
        KeyCode::Char('8') => app.set_inspect(TuiView::Metrics),
        KeyCode::Char('[') => app.cycle_inspect(true),
        KeyCode::Char(']') => app.cycle_inspect(false),
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::PageDown if app.primary == PrimaryView::Inspect => {
            app.scroll = app.scroll.saturating_add(PAGE_STEP);
        }
        KeyCode::PageUp if app.primary == PrimaryView::Inspect => {
            app.scroll = app.scroll.saturating_sub(PAGE_STEP);
        }
        KeyCode::Char('i') | KeyCode::Char('I') if app.primary == PrimaryView::Approvals => {
            app.show_technical = !app.show_technical;
            app.notice = Some(if app.show_technical {
                "technical approval context shown".to_string()
            } else {
                "technical approval context hidden".to_string()
            });
        }
        KeyCode::Char('t') if app.primary == PrimaryView::Approvals => {
            app.approval_draft.cycle_ttl(false);
            app.notice = Some(format!(
                "approval ttl set to {}",
                app.approval_draft.ttl_label()
            ));
        }
        KeyCode::Char('T') if app.primary == PrimaryView::Approvals => {
            app.approval_draft.cycle_ttl(true);
            app.notice = Some(format!(
                "approval ttl set to {}",
                app.approval_draft.ttl_label()
            ));
        }
        KeyCode::Char('u') if app.primary == PrimaryView::Approvals => {
            app.approval_draft.cycle_uses(false);
            app.notice = Some(format!("approval uses set to {}", app.approval_draft.uses));
        }
        KeyCode::Char('U') if app.primary == PrimaryView::Approvals => {
            app.approval_draft.cycle_uses(true);
            app.notice = Some(format!("approval uses set to {}", app.approval_draft.uses));
        }
        KeyCode::Char('A') if app.primary == PrimaryView::Approvals => {
            if let Some(state) = app.selected_approval() {
                app.confirm = Some(PendingTuiAction::Approve {
                    preview: ApprovalActionPreview::from_state(state),
                    draft: app.approval_draft.clone(),
                });
                app.notice = None;
            } else {
                app.notice = Some("no pending approval selected".to_string());
            }
        }
        KeyCode::Char('D') if app.primary == PrimaryView::Approvals => {
            if let Some(state) = app.selected_approval() {
                app.confirm = Some(PendingTuiAction::Deny {
                    preview: ApprovalActionPreview::from_state(state),
                });
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
// Rendering.
// ---------------------------------------------------------------------------

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    app.update_viewport(area.width, area.height);
    if app.is_compact() {
        render_compact_guard(frame, app, area);
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(3),
    ])
    .split(area);

    render_header(frame, app, chunks[0]);
    render_primary_nav(frame, app, chunks[1]);
    render_body(frame, app, chunks[2]);
    render_footer(frame, app, chunks[3]);

    if app.show_help {
        render_help(frame, app, area);
    } else if let Some(action) = app.confirm.as_ref() {
        render_confirm(frame, app, area, action);
    }
}

fn render_compact_guard(frame: &mut Frame, app: &App, area: Rect) {
    let mut text = vec![
        Line::styled(" GOMMAGE ", tone_bold(UiTone::Teal, app.colors)),
        Line::raw(""),
        Line::styled(
            "Terminal too small for the operator TUI.",
            tone_bold(UiTone::Gold, app.colors),
        ),
        Line::raw(format!(
            "Resize to at least {MIN_WIDTH}x{MIN_HEIGHT}; current size is {}x{}.",
            area.width, area.height
        )),
        Line::raw(""),
    ];
    if let Some(notice) = app.notice.as_deref() {
        text.push(Line::styled(
            shorten(notice, area.width.saturating_sub(4) as usize),
            tone_style(UiTone::Gold, app.colors),
        ));
        text.push(Line::raw(""));
    }
    text.extend([
        Line::styled("Alternative", tone_bold(UiTone::Teal, app.colors)),
        Line::raw("gommage tui --snapshot"),
        Line::raw(""),
        Line::raw("q / Esc  quit"),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(" compact mode "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let dashboard = app.dashboard();
    let summary = dashboard.summary();
    let overall = dashboard.overall_status();
    let pending = app.pending_count();
    let mut spans = vec![
        Span::styled(" GOMMAGE ", tone_bold(UiTone::Teal, app.colors)),
        Span::styled(app.primary.label(), tone_style(UiTone::Muted, app.colors)),
        Span::raw("   "),
        Span::styled(overall.marker(), tone_bold(overall.tone(), app.colors)),
        Span::raw(format!(" {}%", summary.ready_percent())),
        Span::raw("   "),
        Span::styled(
            format!(
                "{pending} pending approval{}",
                if pending == 1 { "" } else { "s" }
            ),
            tone_style(
                if pending > 0 {
                    UiTone::Gold
                } else {
                    UiTone::Muted
                },
                app.colors,
            ),
        ),
    ];
    if area.width >= 112 {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("home ", tone_style(UiTone::Muted, app.colors)));
        spans.push(Span::raw(shorten(&dashboard.home, 46)));
    }
    let detail = if app.primary == PrimaryView::Inspect {
        format!(
            "Inspecting {}  ·  [ / ] changes section  ·  r refresh",
            app.inspect_view.label()
        )
    } else {
        format!("updated {}", dashboard.updated)
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(spans),
            Line::styled(detail, tone_style(UiTone::Muted, app.colors)),
        ])
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(tone_style(UiTone::Teal, app.colors)),
        ),
        area,
    );
}

fn render_primary_nav(frame: &mut Frame, app: &App, area: Rect) {
    let titles = [
        nav_title("1 Overview", app.primary == PrimaryView::Overview),
        nav_title("2 Approvals", app.primary == PrimaryView::Approvals),
        nav_title("3 Inspect", app.primary == PrimaryView::Inspect),
    ];
    let tabs = Tabs::new(titles)
        .select(app.primary.index())
        .style(tone_style(UiTone::Muted, app.colors))
        .highlight_style(tone_bold(UiTone::Gold, app.colors))
        .divider("  ");
    frame.render_widget(tabs, area);
}

fn nav_title(label: &str, selected: bool) -> Line<'static> {
    if selected {
        Line::from(format!("[ {label} ]"))
    } else {
        Line::from(format!("  {label}  "))
    }
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let controls = match (app.primary, area.width < 100) {
        (PrimaryView::Overview, false) => {
            "q quit  ·  r refresh  ·  j/k focus  ·  1-3 navigate  ·  ? help"
        }
        (PrimaryView::Overview, true) => "q quit  ·  r refresh  ·  j/k focus  ·  1-3  ·  ? help",
        (PrimaryView::Approvals, false) => {
            "j/k select  ·  t/T TTL  ·  u/U uses  ·  i details  ·  A approve  ·  D deny  ·  ? help"
        }
        (PrimaryView::Approvals, true) => {
            "j/k select  ·  t/T ttl  ·  u/U uses  ·  i detail  ·  A/D decide  ·  ? help"
        }
        (PrimaryView::Inspect, false) => {
            "[ / ] section  ·  j/k or PgUp/PgDn scroll  ·  r refresh  ·  ? help"
        }
        (PrimaryView::Inspect, true) => "[ / ] inspect  ·  j/k scroll  ·  r refresh  ·  ? help",
    };
    let status = app
        .notice
        .as_deref()
        .unwrap_or("Actions are explicit; approval changes require confirmation.");
    let text = vec![
        Line::styled(controls, tone_style(UiTone::Muted, app.colors)),
        Line::styled(status, tone_style(UiTone::Gold, app.colors)),
    ];
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(tone_style(UiTone::Teal, app.colors)),
        ),
        area,
    );
}

fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.primary {
        PrimaryView::Overview => render_overview(frame, app, area),
        PrimaryView::Approvals => render_approvals(frame, app, area),
        PrimaryView::Inspect => render_inspect(frame, app, area),
    }
}

fn render_overview(frame: &mut Frame, app: &App, area: Rect) {
    if area.width >= 100 {
        let columns = Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        let left = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(columns[0]);
        render_readiness_gauge(frame, app, left[0]);
        render_check_list(frame, app, left[1]);
        render_primary_action(frame, app, columns[1]);
        return;
    }

    let rows = Layout::vertical([Constraint::Length(8), Constraint::Min(6)]).split(area);
    render_primary_action(frame, app, rows[0]);
    render_check_list(frame, app, rows[1]);
}

fn render_readiness_gauge(frame: &mut Frame, app: &App, area: Rect) {
    let summary = app.dashboard().summary();
    let percent = summary.ready_percent().min(100) as u16;
    let overall = app.dashboard().overall_status();
    frame.render_widget(
        Gauge::default()
            .block(
                Block::bordered()
                    .title(" health ")
                    .border_style(tone_style(UiTone::Teal, app.colors)),
            )
            .gauge_style(tone_style(overall.tone(), app.colors))
            .percent(percent)
            .label(format!("{percent}%  {}", summary.describe())),
        area,
    );
}

fn render_check_list(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .dashboard()
        .rows
        .iter()
        .map(|row| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", row.status.marker()),
                    tone_bold(row.status.tone(), app.colors),
                ),
                Span::styled(
                    format!("{:<13}", row.label),
                    tone_bold(UiTone::Gold, app.colors),
                ),
                Span::raw(row.summary.clone()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" health checks ")
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("› ");
    let mut state = ListState::default();
    if !app.dashboard().rows.is_empty() {
        state.select(Some(
            app.selected_check
                .min(app.dashboard().rows.len().saturating_sub(1)),
        ));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_primary_action(frame: &mut Frame, app: &App, area: Rect) {
    let lines = if let Some(request) = app.snapshot.approvals.pending().first() {
        let preview = ApprovalActionPreview::from_state(request);
        vec![
            Line::styled("NEXT SAFE ACTION", tone_bold(UiTone::Gold, app.colors)),
            Line::raw(""),
            Line::styled(
                "Review the pending approval",
                tone_bold(UiTone::Teal, app.colors),
            ),
            Line::raw(format!("{}  ·  {}", preview.tool, preview.scope)),
            Line::from(vec![
                Span::styled("binding ", tone_style(UiTone::Muted, app.colors)),
                Span::styled(preview.binding_label(), tone_bold(UiTone::Gold, app.colors)),
            ]),
            Line::styled(
                preview.binding_explanation(),
                tone_style(UiTone::Muted, app.colors),
            ),
            Line::raw(""),
            Line::styled(
                "Press 2 to open approvals.",
                tone_bold(UiTone::Teal, app.colors),
            ),
        ]
    } else {
        let row = app
            .dashboard()
            .rows
            .get(app.selected_check)
            .or_else(|| app.dashboard().rows.first());
        match row {
            Some(row) => focus_lines(row, app.colors),
            None => vec![Line::raw("No health checks are available.")],
        }
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title(" operator focus ")
                    .border_style(tone_style(UiTone::Teal, app.colors)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn focus_lines(row: &StatusRow, colors: bool) -> Vec<Line<'static>> {
    vec![
        Line::styled("NEXT SAFE ACTION", tone_bold(UiTone::Gold, colors)),
        Line::raw(""),
        Line::from(vec![
            Span::styled(row.label.clone(), tone_bold(UiTone::Teal, colors)),
            Span::raw("  "),
            Span::styled(
                format!("[{}]", row.status.label()),
                tone_style(row.status.tone(), colors),
            ),
        ]),
        Line::raw(row.summary.clone()),
        Line::raw(""),
        Line::styled(row.detail.clone(), tone_style(UiTone::Muted, colors)),
    ]
}

fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn shorten(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    truncated.push('…');
    truncated
}

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
        Style::default().add_modifier(Modifier::BOLD)
    }
}

#[cfg(test)]
mod tests;
