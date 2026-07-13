//! Approval workbench, inspection, and modal rendering.

use gommage_core::ApprovalState;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Wrap,
    },
};

use super::{App, popup_area, shorten, tone_bold, tone_style};
use crate::{
    gestral::UiTone,
    tui_actions::{ApprovalActionPreview, PendingTuiAction},
};

pub(super) fn render_approvals(frame: &mut Frame, app: &mut App, area: Rect) {
    let pending = app.snapshot.approvals.pending();
    if pending.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "No approval is waiting.",
                    tone_bold(UiTone::Teal, app.colors),
                ),
                Line::raw(""),
                Line::raw("New ask_picto decisions will appear here on the next refresh."),
                Line::raw("Use Inspect for audit and policy context."),
            ])
            .block(
                Block::bordered()
                    .title(" approvals ")
                    .border_style(tone_style(UiTone::Teal, app.colors)),
            ),
            area,
        );
        return;
    }

    if area.width >= 100 {
        let columns = Layout::horizontal([Constraint::Percentage(34), Constraint::Percentage(66)])
            .split(area);
        render_approval_queue(frame, app, &pending, columns[0]);
        render_approval_detail(frame, app, app.selected_approval(), columns[1]);
        return;
    }

    let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(8)]).split(area);
    let selected_position = app
        .selected_approval_id
        .as_deref()
        .and_then(|id| pending.iter().position(|state| state.request.id == id))
        .map(|index| index + 1)
        .unwrap_or(1);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} pending", pending.len()),
                tone_bold(UiTone::Gold, app.colors),
            ),
            Span::raw(format!(
                "  ·  selected {selected_position}/{}",
                pending.len()
            )),
            Span::raw("  ·  j/k changes request"),
        ]))
        .block(
            Block::bordered()
                .title(" approval queue ")
                .border_style(tone_style(UiTone::Teal, app.colors)),
        ),
        rows[0],
    );
    render_approval_detail(frame, app, app.selected_approval(), rows[1]);
}

fn render_approval_queue(frame: &mut Frame, app: &App, pending: &[&ApprovalState], area: Rect) {
    let items = pending
        .iter()
        .map(|state| {
            let request = &state.request;
            let binding = if request.bind_input { "exact" } else { "scope" };
            ListItem::new(vec![
                Line::styled(
                    shorten(&request.tool, 27),
                    tone_bold(UiTone::Teal, app.colors),
                ),
                Line::from(vec![
                    Span::styled(binding, tone_style(UiTone::Gold, app.colors)),
                    Span::raw("  "),
                    Span::styled(
                        shorten(&request.required_scope, 25),
                        tone_style(UiTone::Muted, app.colors),
                    ),
                ]),
                Line::styled(
                    shorten(&request.id, 22),
                    tone_style(UiTone::Muted, app.colors),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let selected = app
        .selected_approval_id
        .as_deref()
        .and_then(|id| pending.iter().position(|state| state.request.id == id));
    let mut state = ListState::default();
    state.select(selected);
    frame.render_stateful_widget(
        List::new(items)
            .block(
                Block::bordered()
                    .title(format!(" queue · {} pending ", pending.len()))
                    .border_style(tone_style(UiTone::Teal, app.colors)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› "),
        area,
        &mut state,
    );
}

fn render_approval_detail(frame: &mut Frame, app: &App, state: Option<&ApprovalState>, area: Rect) {
    let Some(state) = state else {
        frame.render_widget(
            Paragraph::new("The selected approval is no longer pending. Refresh to continue.")
                .block(Block::bordered().title(" decision ")),
            area,
        );
        return;
    };
    let preview = ApprovalActionPreview::from_state(state);
    let mut lines = vec![
        Line::styled(preview.tool.clone(), tone_bold(UiTone::Teal, app.colors)),
        Line::from(vec![
            Span::styled("scope  ", tone_style(UiTone::Muted, app.colors)),
            Span::styled(preview.scope.clone(), tone_bold(UiTone::Gold, app.colors)),
        ]),
        Line::from(vec![
            Span::styled("binding  ", tone_style(UiTone::Muted, app.colors)),
            Span::styled(
                preview.binding_label(),
                tone_bold(
                    if preview.bind_input {
                        UiTone::Gold
                    } else {
                        UiTone::Teal
                    },
                    app.colors,
                ),
            ),
        ]),
        Line::styled(
            preview.binding_explanation(),
            tone_style(UiTone::Muted, app.colors),
        ),
        Line::raw(""),
        Line::from(vec![
            Span::styled("reason  ", tone_style(UiTone::Muted, app.colors)),
            Span::raw(preview.reason.clone()),
        ]),
        Line::from(vec![
            Span::styled("draft   ", tone_style(UiTone::Muted, app.colors)),
            Span::styled(
                format!(
                    "{} · {} use{}",
                    app.approval_draft.ttl_label(),
                    app.approval_draft.uses,
                    if app.approval_draft.uses == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                tone_bold(UiTone::Gold, app.colors),
            ),
        ]),
        Line::raw(""),
        Line::styled(
            "A approve   D deny   t/T TTL   u/U uses   i technical details",
            tone_bold(UiTone::Teal, app.colors),
        ),
    ];
    if app.show_technical {
        lines.extend([
            Line::raw(""),
            Line::styled("TECHNICAL CONTEXT", tone_bold(UiTone::Gold, app.colors)),
            Line::from(vec![
                Span::styled("request  ", tone_style(UiTone::Muted, app.colors)),
                Span::raw(preview.id.clone()),
            ]),
            Line::from(vec![
                Span::styled("input    ", tone_style(UiTone::Muted, app.colors)),
                Span::raw(preview.input_hash.clone()),
            ]),
            Line::from(vec![
                Span::styled("policy   ", tone_style(UiTone::Muted, app.colors)),
                Span::raw(state.request.policy_version.clone()),
            ]),
        ]);
        if let Some(rule) = &state.request.matched_rule {
            lines.push(Line::from(vec![
                Span::styled("rule     ", tone_style(UiTone::Muted, app.colors)),
                Span::raw(format!("{} ({}:{})", rule.name, rule.file, rule.index)),
            ]));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title(" decision ")
                    .border_style(tone_style(UiTone::Teal, app.colors)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub(super) fn render_inspect(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(report) = app.snapshot.report(app.inspect_view) else {
        frame.render_widget(
            Paragraph::new("No report is available for this inspection section.")
                .block(Block::bordered().title(" inspect ")),
            area,
        );
        return;
    };
    let next_height = if report.next_actions.is_empty() { 0 } else { 3 };
    let chunks = if next_height == 0 {
        vec![area]
    } else {
        Layout::vertical([Constraint::Min(5), Constraint::Length(next_height)])
            .split(area)
            .to_vec()
    };
    let body_area = chunks[0];
    let inner_height = body_area.height.saturating_sub(2) as usize;
    let max_scroll = report.lines.len().saturating_sub(inner_height) as u16;
    app.scroll = app.scroll.min(max_scroll);
    let title = format!(" inspect · {} ", report.title);
    frame.render_widget(
        Paragraph::new(
            report
                .lines
                .iter()
                .cloned()
                .map(Line::raw)
                .collect::<Vec<_>>(),
        )
        .block(
            Block::bordered()
                .title(title)
                .border_style(tone_style(UiTone::Teal, app.colors)),
        )
        .scroll((app.scroll, 0))
        .wrap(Wrap { trim: false }),
        body_area,
    );
    if report.lines.len() > inner_height {
        let mut state = ScrollbarState::new(report.lines.len()).position(app.scroll as usize);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("^"))
                .end_symbol(Some("v")),
            body_area,
            &mut state,
        );
    }
    if let Some(action) = report.next_actions.first()
        && next_height > 0
    {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled("NEXT COMMAND", tone_bold(UiTone::Gold, app.colors)),
                Line::raw(action.clone()),
            ])
            .block(Block::bordered().border_style(tone_style(UiTone::Teal, app.colors))),
            chunks[1],
        );
    }
}

pub(super) fn render_confirm(frame: &mut Frame, app: &App, area: Rect, action: &PendingTuiAction) {
    let popup = popup_area(area, 76, 15);
    let preview = action.preview();
    let field_width = usize::from(popup.width.saturating_sub(11)).max(1);
    let binding_tone = if preview.bind_input {
        UiTone::Gold
    } else {
        UiTone::Teal
    };
    let mut lines = vec![
        Line::styled(
            format!("{} this approval?", action.verb()),
            tone_bold(UiTone::Gold, app.colors),
        ),
        Line::raw(""),
        Line::from(vec![
            Span::styled("tool     ", tone_style(UiTone::Muted, app.colors)),
            Span::raw(shorten(&preview.tool, field_width)),
        ]),
        Line::from(vec![
            Span::styled("scope    ", tone_style(UiTone::Muted, app.colors)),
            Span::raw(shorten(&preview.scope, field_width)),
        ]),
        Line::from(vec![
            Span::styled("binding  ", tone_style(UiTone::Muted, app.colors)),
            Span::styled(preview.binding_label(), tone_bold(binding_tone, app.colors)),
        ]),
        Line::styled(
            preview.binding_explanation(),
            tone_style(UiTone::Muted, app.colors),
        ),
        Line::from(vec![
            Span::styled("reason   ", tone_style(UiTone::Muted, app.colors)),
            Span::raw(shorten(&preview.reason, field_width)),
        ]),
        Line::from(vec![
            Span::styled("input    ", tone_style(UiTone::Muted, app.colors)),
            Span::raw(preview.short_input_hash()),
        ]),
    ];
    if let Some(draft) = action.draft() {
        lines.push(Line::from(vec![
            Span::styled("grant    ", tone_style(UiTone::Muted, app.colors)),
            Span::styled(
                format!(
                    "{} · {} use{}",
                    draft.ttl_label(),
                    draft.uses,
                    if draft.uses == 1 { "" } else { "s" }
                ),
                tone_bold(UiTone::Gold, app.colors),
            ),
        ]));
    }
    let inner = Rect {
        x: popup.x.saturating_add(1),
        y: popup.y.saturating_add(1),
        width: popup.width.saturating_sub(2),
        height: popup.height.saturating_sub(2),
    };
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Block::bordered()
            .title(" confirmation ")
            .border_style(tone_style(UiTone::Gold, app.colors)),
        popup,
    );
    frame.render_widget(Paragraph::new(lines), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::styled(
            "y confirm   n cancel",
            tone_bold(UiTone::Teal, app.colors),
        )),
        chunks[1],
    );
}

pub(super) fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let popup = popup_area(area, 70, 20);
    let lines = vec![
        Line::styled(
            "Gommage operator console",
            tone_bold(UiTone::Gold, app.colors),
        ),
        Line::raw(""),
        Line::raw("q / Esc       quit"),
        Line::raw("r             refresh the captured state"),
        Line::raw("1 / 2 / 3     overview, approvals, inspect"),
        Line::raw("3 - 8         choose an inspect section directly"),
        Line::raw("[ / ]         cycle inspect sections"),
        Line::raw("j / k         move selection or inspect scroll"),
        Line::raw("PgUp / PgDn   inspect scroll"),
        Line::raw(""),
        Line::styled("Approvals", tone_bold(UiTone::Gold, app.colors)),
        Line::raw("t / T         cycle TTL"),
        Line::raw("u / U         cycle uses"),
        Line::raw("i             show or hide technical context"),
        Line::raw("A / D         stage approval or denial"),
        Line::raw("y / n         confirm or cancel the staged action"),
        Line::raw(""),
        Line::raw("?             close this help"),
    ];
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title(" help ")
                    .border_style(tone_style(UiTone::Gold, app.colors)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}
