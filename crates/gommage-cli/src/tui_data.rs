//! Read-only data capture for the interactive TUI.
//!
//! Rendering must never open the runtime, migrate SQLite, or re-read a moving
//! approval inbox. This module captures the immutable inputs for one visible
//! refresh; mutation remains in tui_actions.

use anyhow::Result;
use gommage_core::runtime::HomeLayout;

use crate::{
    agent::AgentKind,
    tui::{Dashboard, build_dashboard},
    tui_views::{ApprovalInbox, TuiView, ViewReport, build_view_report, load_approval_inbox},
};

pub(crate) struct TuiSnapshot {
    pub(crate) dashboard: Dashboard,
    pub(crate) approvals: ApprovalInbox,
    reports: Vec<(TuiView, ViewReport)>,
}

impl TuiSnapshot {
    pub(crate) fn capture(layout: &HomeLayout, agents: &[AgentKind]) -> Result<Self> {
        let dashboard = build_dashboard(layout, agents)?;
        let approvals = load_approval_inbox(layout);
        let mut reports = Vec::new();

        for view in [
            TuiView::Policies,
            TuiView::Audit,
            TuiView::Capabilities,
            TuiView::Recovery,
            TuiView::Onboarding,
            TuiView::Metrics,
        ] {
            let report = build_view_report(layout, view).unwrap_or_else(|error| ViewReport {
                title: view.label().to_string(),
                lines: vec![format!("could not load {}: {error:#}", view.label())],
                next_actions: Vec::new(),
            });
            reports.push((view, report));
        }

        Ok(Self {
            dashboard,
            approvals,
            reports,
        })
    }

    pub(crate) fn report(&self, view: TuiView) -> Option<&ViewReport> {
        self.reports
            .iter()
            .find_map(|(candidate, report)| (*candidate == view).then_some(report))
    }
}
