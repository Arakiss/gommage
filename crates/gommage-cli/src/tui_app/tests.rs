use super::*;
use gommage_core::{ApprovalRequest, ApprovalStatus, ApprovalStore};
use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{KeyEvent, KeyModifiers},
};
use tempfile::tempdir;
use time::OffsetDateTime;

fn test_app(view: TuiView) -> (tempfile::TempDir, App) {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    let agents = [AgentKind::Claude, AgentKind::Codex];
    let app = App::new(&layout, &agents, view, Duration::from_millis(1500)).unwrap();
    (temp, app)
}

fn approval_app(bind_input: bool) -> (tempfile::TempDir, App) {
    let temp = tempdir().unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    let request = ApprovalRequest {
        id: "apr_tui_decision".to_string(),
        created_at: OffsetDateTime::now_utc(),
        tool: "mcp__db__write_row".to_string(),
        input_hash: format!("sha256:{}", "a".repeat(64)),
        required_scope: "mcp.write".to_string(),
        bind_input,
        reason: "database write requires review".to_string(),
        capabilities: Vec::new(),
        matched_rule: None,
        policy_version: "sha256:test".to_string(),
    };
    ApprovalStore::open(&layout.approvals_log)
        .record_request(request)
        .unwrap();
    let agents = [AgentKind::Claude, AgentKind::Codex];
    let app = App::new(
        &layout,
        &agents,
        TuiView::Approvals,
        Duration::from_millis(1500),
    )
    .unwrap();
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

fn render(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, app)).unwrap();
    buffer_text(&terminal)
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn overview_renders_operator_focus_at_normal_width() {
    let (_temp, mut app) = test_app(TuiView::Dashboard);
    let text = render(&mut app, 100, 30);
    assert!(text.contains("GOMMAGE"), "header missing: {text}");
    assert!(text.contains("Overview"), "primary navigation missing");
    assert!(text.contains("NEXT SAFE ACTION"), "focus missing");
    assert!(text.contains("health checks"), "check list missing");
}

#[test]
fn approvals_show_exact_input_boundary_at_normal_and_narrow_width() {
    let (_temp, mut app) = approval_app(true);
    let wide = render(&mut app, 100, 30);
    assert!(wide.contains("mcp__db__write_row"), "tool missing: {wide}");
    assert!(wide.contains("queue"), "wide queue missing: {wide}");
    assert!(wide.contains("decision"), "wide detail missing: {wide}");
    assert!(wide.contains("EXACT INPUT"), "binding missing: {wide}");
    assert!(wide.contains("A approve"), "action missing: {wide}");

    let narrow = render(&mut app, 80, 24);
    assert!(
        narrow.contains("mcp__db__write_row"),
        "tool missing: {narrow}"
    );
    assert!(narrow.contains("mcp.write"), "scope missing: {narrow}");
    assert!(narrow.contains("EXACT INPUT"), "binding missing: {narrow}");
    assert!(narrow.contains("10m"), "draft missing: {narrow}");
    assert!(narrow.contains("? help"), "footer help missing: {narrow}");
    assert!(
        narrow.contains("updated"),
        "header detail missing: {narrow}"
    );
}

#[test]
fn chrome_keeps_header_detail_and_notice_visible() {
    let (_temp, mut app) = test_app(TuiView::Dashboard);
    handle_key(&mut app, press(KeyCode::Char('r'))).unwrap();
    let text = render(&mut app, 80, 24);
    assert!(text.contains("updated"), "header detail missing: {text}");
    assert!(text.contains("refreshed"), "notice missing: {text}");
}

#[test]
fn compact_terminal_explains_the_alternative() {
    let (_temp, mut app) = test_app(TuiView::Dashboard);
    let text = render(&mut app, 60, 18);
    assert!(text.contains("Terminal too small"), "guard missing: {text}");
    assert!(text.contains("80x24"), "minimum size missing: {text}");
    assert!(
        text.contains("gommage tui --snapshot"),
        "fallback missing: {text}"
    );
}

#[test]
fn compact_resize_cancels_an_unseen_confirmation() {
    let (temp, mut app) = approval_app(true);
    let _ = render(&mut app, 80, 24);
    handle_key(&mut app, press(KeyCode::Char('A'))).unwrap();
    assert!(app.confirm.is_some(), "approval should be staged");

    let compact = render(&mut app, 60, 18);
    assert!(
        app.confirm.is_none(),
        "hidden confirmation must be cancelled"
    );
    assert!(
        compact.contains("confirmation cancelled"),
        "cancellation notice missing: {compact}"
    );
    handle_key(&mut app, press(KeyCode::Char('y'))).unwrap();

    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    let states = ApprovalStore::open(&layout.approvals_log).list().unwrap();
    assert_eq!(states[0].status, ApprovalStatus::Pending);
}

#[test]
fn confirmation_describes_the_approval_boundary_and_cancel_is_safe() {
    let (temp, mut app) = approval_app(true);
    handle_key(&mut app, press(KeyCode::Char('A'))).unwrap();
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("Approve this approval?"),
        "verb missing: {text}"
    );
    assert!(text.contains("mcp__db__write_row"), "tool missing: {text}");
    assert!(text.contains("mcp.write"), "scope missing: {text}");
    assert!(text.contains("EXACT INPUT"), "binding missing: {text}");
    assert!(
        text.contains("Only this observed tool input"),
        "binding explanation missing: {text}"
    );
    assert!(text.contains("10m"), "ttl missing: {text}");
    assert!(text.contains("1 use"), "use count missing: {text}");

    handle_key(&mut app, press(KeyCode::Char('n'))).unwrap();
    let layout = HomeLayout::at(&temp.path().join(".gommage"));
    let states = ApprovalStore::open(&layout.approvals_log).list().unwrap();
    assert_eq!(states[0].status, ApprovalStatus::Pending);
}

#[test]
fn confirmation_keeps_controls_visible_for_long_fields() {
    let (_temp, mut app) = approval_app(true);
    handle_key(&mut app, press(KeyCode::Char('A'))).unwrap();
    let Some(PendingTuiAction::Approve { preview, .. }) = app.confirm.as_mut() else {
        panic!("approval should be staged");
    };
    preview.tool = "mcp__very_long_tool_name_".repeat(4);
    preview.scope = "scope.with.a.long.nested.segment.".repeat(4);
    preview.reason = "a long reason that should be shortened in the confirmation dialog ".repeat(3);

    let text = render(&mut app, 80, 24);
    assert!(
        text.contains("y confirm   n cancel"),
        "confirmation controls missing: {text}"
    );
    assert!(text.contains("…"), "long fields were not shortened: {text}");
}

#[test]
fn legacy_numeric_inspect_shortcuts_remain_available() {
    let (_temp, mut app) = test_app(TuiView::Dashboard);
    handle_key(&mut app, press(KeyCode::Char('4'))).unwrap();
    assert_eq!(app.primary, PrimaryView::Inspect);
    assert_eq!(app.inspect_view, TuiView::Audit);
    assert_eq!(app.scroll, 0);
}

#[test]
fn question_toggles_help() {
    let (_temp, mut app) = test_app(TuiView::Dashboard);
    handle_key(&mut app, press(KeyCode::Char('?'))).unwrap();
    assert!(app.show_help);
    handle_key(&mut app, press(KeyCode::Char('?'))).unwrap();
    assert!(!app.show_help);
}
