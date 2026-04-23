use gommage_core::runtime::HomeLayout;

use crate::{
    gestral::{UiTone, paint, strip_ansi, truncate_plain},
    tui::Dashboard,
    tui_views::{TuiView, ViewReport, build_approvals_report, build_view_report},
};

#[derive(Debug, Clone)]
pub(crate) struct RenderState<'a> {
    pub(crate) selected: usize,
    pub(crate) selected_approval: usize,
    pub(crate) view: TuiView,
    pub(crate) approval_uses: u32,
    pub(crate) approval_ttl: String,
    pub(crate) notice: Option<&'a str>,
    pub(crate) confirm: Option<&'a str>,
}

pub(crate) fn render_lines(
    layout: &HomeLayout,
    dashboard: &Dashboard,
    width: usize,
    colors: bool,
    state: RenderState<'_>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let overall = dashboard.overall_status();
    let summary = dashboard.summary();
    let title = format!(
        "{}  {}",
        paint("GOMMAGE", UiTone::Teal, true, colors),
        paint("operator dashboard", UiTone::Muted, false, colors)
    );
    lines.push(border(width, UiTone::Teal, colors));
    lines.push(boxed(
        format!(
            "{}  status {}",
            title,
            paint(overall.marker(), overall.tone(), true, colors)
        ),
        width,
    ));
    lines.push(boxed(
        format!("version {}  home {}", dashboard.version, dashboard.home),
        width,
    ));
    lines.push(boxed(format!("updated {}", dashboard.updated), width));
    lines.push(boxed(
        format!(
            "view {}  readiness {}  {}",
            state.view.label(),
            progress_bar(summary.ready_percent(), 18),
            summary.describe()
        ),
        width,
    ));
    lines.push(border(width, UiTone::Teal, colors));
    lines.push(String::new());
    lines.push(format!(
        "{}  {}",
        paint("Views", UiTone::Gold, true, colors),
        paint(
            "1 readiness  2 approvals  3 policies  4 audit  5 capabilities  6 recovery  7 onboarding",
            UiTone::Muted,
            false,
            colors
        )
    ));
    render_view_body(&mut lines, layout, dashboard, colors, &state);
    if let Some(confirm) = state.confirm {
        lines.push(String::new());
        lines.push(format!(
            "{} {}",
            paint("Confirm", UiTone::Gold, true, colors),
            paint(confirm, UiTone::Muted, false, colors)
        ));
        lines.push("press y to confirm, n to cancel".to_string());
    } else if let Some(notice) = state.notice {
        lines.push(String::new());
        lines.push(format!(
            "{} {}",
            paint("Notice", UiTone::Gold, true, colors),
            notice
        ));
    }
    lines.push(String::new());
    lines.push(format!(
        "{} quit   {} refresh   {} move   {} approve   {} deny   {} approval draft   {} for CI and issue reports",
        paint("q", UiTone::Gold, true, colors),
        paint("r", UiTone::Gold, true, colors),
        paint("j/k", UiTone::Gold, true, colors),
        paint("A", UiTone::Gold, true, colors),
        paint("D", UiTone::Gold, true, colors),
        paint("t/T u/U", UiTone::Gold, true, colors),
        paint("--snapshot", UiTone::Muted, false, colors)
    ));
    lines
}

fn render_view_body(
    lines: &mut Vec<String>,
    layout: &HomeLayout,
    dashboard: &Dashboard,
    colors: bool,
    state: &RenderState<'_>,
) {
    match state.view {
        TuiView::Dashboard | TuiView::All => {
            render_dashboard_body(lines, dashboard, colors, state.selected);
        }
        TuiView::Approvals => {
            lines.push(format!(
                "{} ttl {}  uses {}  {}",
                paint("Approval draft", UiTone::Gold, true, colors),
                state.approval_ttl,
                state.approval_uses,
                paint("t/T ttl  u/U uses", UiTone::Muted, false, colors)
            ));
            lines.push(String::new());
            render_report_body(
                lines,
                &build_approvals_report(layout, Some(state.selected_approval)),
                colors,
            );
        }
        other => match build_view_report(layout, other) {
            Ok(report) => render_report_body(lines, &report, colors),
            Err(error) => lines.push(format!("could not render {}: {error}", other.label())),
        },
    }
}

fn render_dashboard_body(
    lines: &mut Vec<String>,
    dashboard: &Dashboard,
    colors: bool,
    selected: usize,
) {
    lines.push(paint("Readiness", UiTone::Gold, true, colors));
    for (index, row) in dashboard.rows.iter().enumerate() {
        let cursor = if index == selected { ">" } else { " " };
        lines.push(format!(
            "{} {} {:<13} {}",
            paint(cursor, UiTone::Gold, true, colors),
            paint(row.status.marker(), row.status.tone(), true, colors),
            row.label,
            row.summary
        ));
    }
    lines.push(String::new());
    if let Some(row) = dashboard.rows.get(selected) {
        lines.push(paint("Focus", UiTone::Gold, true, colors));
        lines.push(format!(
            "{} [{}] {}",
            row.label,
            row.status.label(),
            row.summary
        ));
        lines.push(format!("  {}", row.detail));
        lines.push(String::new());
    }
    lines.push(paint("Next", UiTone::Gold, true, colors));
    for (index, action) in dashboard.next_actions.iter().enumerate() {
        lines.push(format!("{}. {action}", index + 1));
    }
}

fn render_report_body(lines: &mut Vec<String>, report: &ViewReport, colors: bool) {
    lines.push(paint(&report.title, UiTone::Gold, true, colors));
    lines.extend(report.lines.iter().map(|line| format!("- {line}")));
    lines.push(String::new());
    lines.push(paint("Next", UiTone::Gold, true, colors));
    for (index, action) in report.next_actions.iter().enumerate() {
        lines.push(format!("{}. {action}", index + 1));
    }
}

fn progress_bar(percent: usize, width: usize) -> String {
    let filled = width.saturating_mul(percent.min(100)) / 100;
    format!(
        "[{}{}] {:>3}%",
        "#".repeat(filled),
        "-".repeat(width.saturating_sub(filled)),
        percent.min(100)
    )
}

fn boxed(content: String, width: usize) -> String {
    let inner = width.saturating_sub(4);
    format!(
        "| {} |",
        pad_visible(&truncate_plain(&content, inner), inner)
    )
}

fn border(width: usize, tone: UiTone, colors: bool) -> String {
    paint(
        format!("+{}+", "-".repeat(width.saturating_sub(2))),
        tone,
        false,
        colors,
    )
}

fn pad_visible(input: &str, width: usize) -> String {
    let visible = strip_ansi(input).chars().count();
    if visible >= width {
        input.to_string()
    } else {
        format!("{input}{}", " ".repeat(width - visible))
    }
}
