use gommage_core::runtime::HomeLayout;

use crate::approval_cmd::{approve_request, deny_request};

#[derive(Debug, Clone)]
pub(crate) enum PendingTuiAction {
    Approve(String, ApprovalDraft),
    Deny(String),
}

#[derive(Debug, Clone)]
pub(crate) struct ApprovalDraft {
    pub(crate) uses: u32,
    pub(crate) ttl_seconds: i64,
}

impl PendingTuiAction {
    pub(crate) fn prompt(&self) -> String {
        match self {
            PendingTuiAction::Approve(id, draft) => format!(
                "approve {id} with ttl={} uses={} from the TUI?",
                draft.ttl_label(),
                draft.uses
            ),
            PendingTuiAction::Deny(id) => format!("deny {id} from the TUI?"),
        }
    }
}

impl Default for ApprovalDraft {
    fn default() -> Self {
        Self {
            uses: 1,
            ttl_seconds: 600,
        }
    }
}

impl ApprovalDraft {
    pub(crate) fn ttl_label(&self) -> String {
        match self.ttl_seconds {
            seconds if seconds % 3600 == 0 => format!("{}h", seconds / 3600),
            seconds if seconds % 60 == 0 => format!("{}m", seconds / 60),
            seconds => format!("{seconds}s"),
        }
    }

    pub(crate) fn cycle_ttl(&mut self, reverse: bool) {
        const PRESETS: [i64; 6] = [60, 300, 600, 1800, 3600, 14_400];
        let index = PRESETS
            .iter()
            .position(|value| *value == self.ttl_seconds)
            .unwrap_or(2);
        let next = if reverse {
            index.checked_sub(1).unwrap_or(PRESETS.len() - 1)
        } else {
            (index + 1) % PRESETS.len()
        };
        self.ttl_seconds = PRESETS[next];
    }

    pub(crate) fn cycle_uses(&mut self, reverse: bool) {
        const PRESETS: [u32; 5] = [1, 2, 3, 5, 10];
        let index = PRESETS
            .iter()
            .position(|value| *value == self.uses)
            .unwrap_or(0);
        let next = if reverse {
            index.checked_sub(1).unwrap_or(PRESETS.len() - 1)
        } else {
            (index + 1) % PRESETS.len()
        };
        self.uses = PRESETS[next];
    }
}

pub(crate) fn execute_tui_action(layout: &HomeLayout, action: PendingTuiAction) -> String {
    match action {
        PendingTuiAction::Approve(id, draft) => match approve_request(
            layout,
            &id,
            draft.uses,
            draft.ttl_seconds,
            "approved from gommage tui",
        ) {
            Ok(report) => report.message,
            Err(error) => format!("approval failed: {error:#}"),
        },
        PendingTuiAction::Deny(id) => match deny_request(layout, &id, "denied from gommage tui") {
            Ok(report) => report.message,
            Err(error) => format!("deny failed: {error:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::ApprovalDraft;

    #[test]
    fn approval_draft_cycles_ttl_presets() {
        let mut draft = ApprovalDraft::default();
        assert_eq!(draft.ttl_label(), "10m");
        draft.cycle_ttl(false);
        assert_eq!(draft.ttl_label(), "30m");
        draft.cycle_ttl(true);
        assert_eq!(draft.ttl_label(), "10m");
    }

    #[test]
    fn approval_draft_cycles_use_presets() {
        let mut draft = ApprovalDraft::default();
        assert_eq!(draft.uses, 1);
        draft.cycle_uses(false);
        assert_eq!(draft.uses, 2);
        draft.cycle_uses(true);
        assert_eq!(draft.uses, 1);
    }
}
