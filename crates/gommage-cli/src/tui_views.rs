use anyhow::Result;
use clap::ValueEnum;
use gommage_audit::explain_log;
use gommage_core::{
    ApprovalStatus, ApprovalStore, CapabilityMapper, RuleDecision, ToolCall, runtime::HomeLayout,
};
use std::{fs, path::Path};

use crate::{doctor::build_doctor_report, util::path_display};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum TuiView {
    Dashboard,
    Policies,
    Audit,
    Capabilities,
    Recovery,
    All,
}

impl TuiView {
    pub(crate) fn label(self) -> &'static str {
        match self {
            TuiView::Dashboard => "dashboard",
            TuiView::Policies => "policies",
            TuiView::Audit => "audit",
            TuiView::Capabilities => "capabilities",
            TuiView::Recovery => "recovery",
            TuiView::All => "all",
        }
    }

    pub(crate) fn interactive_views() -> [TuiView; 5] {
        [
            TuiView::Dashboard,
            TuiView::Policies,
            TuiView::Audit,
            TuiView::Capabilities,
            TuiView::Recovery,
        ]
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ViewReport {
    pub(crate) title: String,
    pub(crate) lines: Vec<String>,
    pub(crate) next_actions: Vec<String>,
}

pub(crate) fn build_view_report(layout: &HomeLayout, view: TuiView) -> Result<ViewReport> {
    Ok(match view {
        TuiView::Dashboard | TuiView::All => ViewReport {
            title: "dashboard".to_string(),
            lines: vec!["readiness dashboard is shown in the primary panel".to_string()],
            next_actions: vec!["gommage verify --json".to_string()],
        },
        TuiView::Policies => policies_report(layout),
        TuiView::Audit => audit_report(layout),
        TuiView::Capabilities => capabilities_report(layout),
        TuiView::Recovery => recovery_report(layout),
    })
}

fn policies_report(layout: &HomeLayout) -> ViewReport {
    let files = yaml_files(&layout.policy_dir);
    match gommage_core::runtime::Runtime::open(HomeLayout::at(&layout.root)) {
        Ok(rt) => {
            let mut lines = vec![
                format!("policy files: {}", files.len()),
                format!("rules: {}", rt.policy.rules.len()),
                format!("version: {}", rt.policy.version_hash),
            ];
            lines.push("first rules:".to_string());
            for rule in rt.policy.rules.iter().take(8) {
                lines.push(format!(
                    "- {} [{}] {}:{}",
                    rule.name,
                    decision_label(rule.decision),
                    path_display(&rule.source.file),
                    rule.source.index
                ));
            }
            ViewReport {
                title: "policies".to_string(),
                lines,
                next_actions: vec![
                    "gommage policy check".to_string(),
                    "gommage policy schema".to_string(),
                ],
            }
        }
        Err(error) => ViewReport {
            title: "policies".to_string(),
            lines: vec![
                format!("policy files: {}", files.len()),
                format!("status: fail - {error}"),
            ],
            next_actions: vec!["gommage policy init --stdlib".to_string()],
        },
    }
}

fn audit_report(layout: &HomeLayout) -> ViewReport {
    let approvals = ApprovalStore::open(&layout.approvals_log)
        .list()
        .unwrap_or_default();
    let pending = approvals
        .iter()
        .filter(|state| state.status == ApprovalStatus::Pending)
        .count();
    let mut lines = vec![
        format!("audit log: {}", path_display(&layout.audit_log)),
        format!(
            "approval requests: {} pending, {} total",
            pending,
            approvals.len()
        ),
    ];
    match layout.load_verifying_key() {
        Ok(vk) if layout.audit_log.exists() => match explain_log(&layout.audit_log, &vk) {
            Ok(report) => {
                lines.push(format!(
                    "entries: {} total, {} verified",
                    report.entries_total, report.entries_verified
                ));
                lines.push(format!("key: {}", report.key_fingerprint));
                lines.push(format!(
                    "bypass: {} activation(s), {} hard-stop attempt(s)",
                    report.bypass_activations, report.hard_stop_bypass_attempts
                ));
                lines.push(format!("anomalies: {}", report.anomalies.len()));
                lines.extend(recent_audit_lines(&layout.audit_log, 4));
            }
            Err(error) => lines.push(format!("status: fail - {error}")),
        },
        Ok(_) => lines.push("entries: none yet".to_string()),
        Err(error) => lines.push(format!("status: fail - {error}")),
    }
    ViewReport {
        title: "audit".to_string(),
        lines,
        next_actions: vec![
            "gommage audit-verify --explain --format human".to_string(),
            "gommage approval list".to_string(),
        ],
    }
}

fn capabilities_report(layout: &HomeLayout) -> ViewReport {
    let files = yaml_files(&layout.capabilities_dir);
    match CapabilityMapper::load_from_dir(&layout.capabilities_dir) {
        Ok(mapper) => {
            let call = ToolCall {
                tool: "Bash".to_string(),
                input: serde_json::json!({"command": "git push origin main"}),
            };
            let sample = mapper
                .map(&call)
                .into_iter()
                .map(|cap| format!("- {cap}"))
                .collect::<Vec<_>>();
            let mut lines = vec![
                format!("capability files: {}", files.len()),
                format!("mapper rules: {}", mapper.rule_count()),
                "sample Bash mapping: git push origin main".to_string(),
            ];
            lines.extend(sample);
            ViewReport {
                title: "capabilities".to_string(),
                lines,
                next_actions: vec![
                    "gommage map --json --hook".to_string(),
                    "gommage smoke --json".to_string(),
                ],
            }
        }
        Err(error) => ViewReport {
            title: "capabilities".to_string(),
            lines: vec![
                format!("capability files: {}", files.len()),
                format!("status: fail - {error}"),
            ],
            next_actions: vec!["gommage policy init --stdlib".to_string()],
        },
    }
}

fn recovery_report(layout: &HomeLayout) -> ViewReport {
    let doctor = build_doctor_report(layout);
    let approvals = ApprovalStore::open(&layout.approvals_log)
        .pending()
        .unwrap_or_default();
    let backups = backup_count(&layout.root);
    let lines = vec![
        format!("home: {}", path_display(&layout.root)),
        format!("doctor: {:?}", doctor.status),
        format!(
            "doctor summary: {} failure(s), {} warning(s)",
            doctor.summary.failures, doctor.summary.warnings
        ),
        format!("socket: {}", path_display(&layout.socket)),
        format!("socket exists: {}", layout.socket.exists()),
        format!("pending approvals: {}", approvals.len()),
        format!("local backups under home: {}", backups),
    ];
    ViewReport {
        title: "recovery".to_string(),
        lines,
        next_actions: vec![
            "gommage verify --json".to_string(),
            "gommage agent status claude --json".to_string(),
            "gommage uninstall --all --dry-run".to_string(),
            "GOMMAGE_BYPASS=1 gommage-mcp < hook.json".to_string(),
        ],
    }
}

fn yaml_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| matches!(ext, "yaml" | "yml"))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn recent_audit_lines(path: &Path, limit: usize) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines = text
        .lines()
        .rev()
        .take(limit)
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|value| {
            let id = value
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("-");
            let kind = value
                .get("kind")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    value
                        .get("decision")
                        .and_then(|decision| decision.get("kind"))
                        .and_then(|kind| kind.as_str())
                })
                .unwrap_or("decision");
            format!("- {} {}", short_hash(id), kind)
        })
        .collect::<Vec<_>>();
    lines.reverse();
    if !lines.is_empty() {
        lines.insert(0, "recent audit:".to_string());
    }
    lines
}

fn backup_count(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains(".gommage-bak-")
        })
        .count()
}

fn decision_label(decision: RuleDecision) -> &'static str {
    match decision {
        RuleDecision::Allow => "allow",
        RuleDecision::Gommage => "gommage",
        RuleDecision::AskPicto => "ask_picto",
    }
}

fn short_hash(value: &str) -> String {
    value.chars().take(12).collect()
}
