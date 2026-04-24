use gommage_audit::explain_log;
use gommage_core::{
    ApprovalStatus, ApprovalStore, ApprovalWebhookDeadLetterStore, Picto, PictoStatus, PictoStore,
    runtime::HomeLayout,
};
use time::OffsetDateTime;

use crate::gestral::UiStatus;

#[derive(Debug, Clone)]
pub(crate) struct OperatorTelemetry {
    pub(crate) daemon: DaemonHealth,
    pub(crate) pictos: PictoInventory,
    pub(crate) metrics: LocalMetrics,
}

#[derive(Debug, Clone)]
pub(crate) struct DaemonHealth {
    pub(crate) status: UiStatus,
    pub(crate) summary: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PictoInventory {
    pub(crate) total: usize,
    pub(crate) active: usize,
    pub(crate) pending_confirmation: usize,
    pub(crate) spent: usize,
    pub(crate) revoked: usize,
    pub(crate) expired: usize,
    pub(crate) expiring_soon: usize,
    pub(crate) next_active: Option<PictoSummary>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PictoSummary {
    pub(crate) id: String,
    pub(crate) scope: String,
    pub(crate) remaining_uses: u32,
    pub(crate) expires_at: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LocalMetrics {
    pub(crate) audit_entries: usize,
    pub(crate) decisions: usize,
    pub(crate) allows: usize,
    pub(crate) asks: usize,
    pub(crate) denies: usize,
    pub(crate) hard_stops: usize,
    pub(crate) approval_requests: usize,
    pub(crate) approval_resolutions: usize,
    pub(crate) pending_approvals: usize,
    pub(crate) total_approvals: usize,
    pub(crate) picto_creations: usize,
    pub(crate) picto_consumptions: usize,
    pub(crate) picto_rejections: usize,
    pub(crate) dead_letter_entries: usize,
    pub(crate) webhook_dead_letters: usize,
    pub(crate) malformed_audit_lines: usize,
    pub(crate) audit_anomalies: Option<usize>,
    pub(crate) error: Option<String>,
}

pub(crate) fn build_operator_telemetry(layout: &HomeLayout) -> OperatorTelemetry {
    let daemon = daemon_health(layout);
    let pictos = picto_inventory(layout);
    let metrics = local_metrics(layout);
    OperatorTelemetry {
        daemon,
        pictos,
        metrics,
    }
}

impl OperatorTelemetry {
    pub(crate) fn snapshot_lines(&self) -> Vec<String> {
        let mut lines = vec![
            self.daemon.line(),
            self.pictos.summary_line(),
            self.metrics.summary_line(),
        ];
        if let Some(line) = self.pictos.next_active_line() {
            lines.push(line);
        }
        if let Some(line) = self.metrics.audit_health_line() {
            lines.push(line);
        }
        lines.push(self.daemon.detail_line());
        lines
    }
}

impl DaemonHealth {
    pub(crate) fn line(&self) -> String {
        format!("daemon: {} - {}", self.status.label(), self.summary)
    }

    pub(crate) fn detail_line(&self) -> String {
        format!("daemon detail: {}", self.detail)
    }
}

impl PictoInventory {
    pub(crate) fn summary_line(&self) -> String {
        let mut line = format!(
            "pictos: {} active, {} pending, {} spent, {} revoked, {} expired, {} total",
            self.active,
            self.pending_confirmation,
            self.spent,
            self.revoked,
            self.expired,
            self.total
        );
        if self.expiring_soon > 0 {
            line.push_str(&format!(", {} expiring soon", self.expiring_soon));
        }
        if let Some(error) = &self.error {
            line.push_str(&format!(" - {error}"));
        }
        line
    }

    pub(crate) fn next_active_line(&self) -> Option<String> {
        self.next_active.as_ref().map(|picto| {
            format!(
                "next active picto: {} scope={} remaining={} expires={}",
                picto.id, picto.scope, picto.remaining_uses, picto.expires_at
            )
        })
    }
}

impl LocalMetrics {
    pub(crate) fn summary_line(&self) -> String {
        let anomaly = self
            .audit_anomalies
            .map_or_else(|| "unknown".to_string(), |count| count.to_string());
        let mut line = format!(
            "metrics: {} decisions, {} allow, {} ask, {} deny, {} hard-stop, {} approvals pending, {} webhook DLQ, {} audit anomalies",
            self.decisions,
            self.allows,
            self.asks,
            self.denies,
            self.hard_stops,
            self.pending_approvals,
            self.dead_letter_entries,
            anomaly
        );
        if let Some(error) = &self.error {
            line.push_str(&format!(" - {error}"));
        }
        line
    }

    pub(crate) fn audit_health_line(&self) -> Option<String> {
        if self.audit_entries == 0 && self.malformed_audit_lines == 0 {
            return None;
        }
        Some(format!(
            "audit counters: {} entries, {} malformed, {} approval request(s), {} approval resolution(s), {} picto creation(s), {} picto consumption(s), {} webhook dead-letter event(s)",
            self.audit_entries,
            self.malformed_audit_lines,
            self.approval_requests,
            self.approval_resolutions,
            self.picto_creations,
            self.picto_consumptions,
            self.webhook_dead_letters
        ))
    }
}

fn local_metrics(layout: &HomeLayout) -> LocalMetrics {
    let mut metrics = LocalMetrics::default();
    match ApprovalStore::open(&layout.approvals_log).list() {
        Ok(states) => {
            metrics.total_approvals = states.len();
            metrics.pending_approvals = states
                .iter()
                .filter(|state| state.status == ApprovalStatus::Pending)
                .count();
        }
        Err(error) => metrics.error = Some(format!("approval metrics unavailable: {error}")),
    }
    metrics.dead_letter_entries =
        ApprovalWebhookDeadLetterStore::open(&layout.approval_webhook_dlq)
            .count()
            .unwrap_or(0);
    add_audit_metrics(layout, &mut metrics);
    if layout.audit_log.exists()
        && let Ok(verifying_key) = layout.load_verifying_key()
        && let Ok(report) = explain_log(&layout.audit_log, &verifying_key)
    {
        metrics.audit_anomalies = Some(report.anomalies.len());
    }
    metrics
}

fn add_audit_metrics(layout: &HomeLayout, metrics: &mut LocalMetrics) {
    let Ok(text) = std::fs::read_to_string(&layout.audit_log) else {
        return;
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            metrics.malformed_audit_lines += 1;
            continue;
        };
        metrics.audit_entries += 1;
        if value.get("kind").and_then(|kind| kind.as_str()) == Some("event") {
            count_event(&value, metrics);
        } else {
            count_decision(&value, metrics);
        }
    }
}

fn count_decision(value: &serde_json::Value, metrics: &mut LocalMetrics) {
    metrics.decisions += 1;
    match value
        .pointer("/decision/kind")
        .and_then(|kind| kind.as_str())
    {
        Some("allow") => metrics.allows += 1,
        Some("ask_picto") => metrics.asks += 1,
        Some("gommage") => metrics.denies += 1,
        _ => {}
    }
    if value
        .pointer("/decision/hard_stop")
        .and_then(|hard_stop| hard_stop.as_bool())
        .unwrap_or(false)
    {
        metrics.hard_stops += 1;
    }
}

fn count_event(value: &serde_json::Value, metrics: &mut LocalMetrics) {
    match value
        .pointer("/event/type")
        .and_then(|event_type| event_type.as_str())
    {
        Some("approval_requested") => metrics.approval_requests += 1,
        Some("approval_resolved") => metrics.approval_resolutions += 1,
        Some("picto_created") => metrics.picto_creations += 1,
        Some("picto_consumed") => metrics.picto_consumptions += 1,
        Some("picto_rejected") => metrics.picto_rejections += 1,
        Some("approval_webhook_dead_lettered") => metrics.webhook_dead_letters += 1,
        _ => {}
    }
}

fn picto_inventory(layout: &HomeLayout) -> PictoInventory {
    if !layout.pictos_db.exists() {
        return PictoInventory::default();
    }
    let now = OffsetDateTime::now_utc();
    let soon = now + time::Duration::minutes(15);
    let mut inventory = PictoInventory::default();
    let pictos = match PictoStore::open(&layout.pictos_db).and_then(|store| store.list()) {
        Ok(pictos) => pictos,
        Err(error) => {
            inventory.error = Some(format!("picto metrics unavailable: {error}"));
            return inventory;
        }
    };
    inventory.total = pictos.len();
    let mut next_active_expires: Option<OffsetDateTime> = None;
    for picto in pictos {
        let current_status = current_picto_status(&picto, now);
        match current_status {
            PictoStatus::Active => {
                inventory.active += 1;
                if picto.ttl_expires_at <= soon {
                    inventory.expiring_soon += 1;
                }
                if next_active_expires.is_none_or(|current| picto.ttl_expires_at < current) {
                    next_active_expires = Some(picto.ttl_expires_at);
                    inventory.next_active = Some(picto_summary(&picto));
                }
            }
            PictoStatus::PendingConfirmation => inventory.pending_confirmation += 1,
            PictoStatus::Spent => inventory.spent += 1,
            PictoStatus::Revoked => inventory.revoked += 1,
            PictoStatus::Expired => inventory.expired += 1,
        }
    }
    inventory
}

fn current_picto_status(picto: &Picto, now: OffsetDateTime) -> PictoStatus {
    if matches!(
        picto.status,
        PictoStatus::Active | PictoStatus::PendingConfirmation
    ) && picto.ttl_expires_at <= now
    {
        return PictoStatus::Expired;
    }
    if picto.status == PictoStatus::Active && picto.uses >= picto.max_uses {
        return PictoStatus::Spent;
    }
    picto.status
}

fn picto_summary(picto: &Picto) -> PictoSummary {
    PictoSummary {
        id: short_id(&picto.id),
        scope: picto.scope.clone(),
        remaining_uses: picto.max_uses.saturating_sub(picto.uses),
        expires_at: picto.ttl_expires_at.to_string(),
    }
}

fn short_id(value: &str) -> String {
    value.chars().take(18).collect()
}

#[cfg(unix)]
fn daemon_health(layout: &HomeLayout) -> DaemonHealth {
    use crate::util::path_display;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    if !layout.socket.exists() {
        return DaemonHealth {
            status: UiStatus::Warn,
            summary: "not reachable".to_string(),
            detail: format!(
                "socket {} is missing; stream mode will read {} directly",
                path_display(&layout.socket),
                path_display(&layout.audit_log)
            ),
        };
    }
    match UnixStream::connect(&layout.socket) {
        Ok(mut stream) => {
            let timeout = Some(Duration::from_millis(500));
            let _ = stream.set_read_timeout(timeout);
            let _ = stream.set_write_timeout(timeout);
            let request = serde_json::json!({"op": "ping"});
            let request = match serde_json::to_string(&request) {
                Ok(request) => request,
                Err(error) => {
                    return DaemonHealth {
                        status: UiStatus::Fail,
                        summary: "ping request failed".to_string(),
                        detail: error.to_string(),
                    };
                }
            };
            if let Err(error) = writeln!(stream, "{request}") {
                return DaemonHealth {
                    status: UiStatus::Warn,
                    summary: "socket write failed".to_string(),
                    detail: error.to_string(),
                };
            }
            let mut line = String::new();
            if let Err(error) = BufReader::new(stream).read_line(&mut line) {
                return DaemonHealth {
                    status: UiStatus::Warn,
                    summary: "socket read failed".to_string(),
                    detail: error.to_string(),
                };
            }
            match serde_json::from_str::<DaemonPingResponse>(&line) {
                Ok(response) if response.ok && response.result.as_deref() == Some("pong") => {
                    DaemonHealth {
                        status: UiStatus::Ok,
                        summary: "ipc ping ok".to_string(),
                        detail: format!("socket {} answered ping", path_display(&layout.socket)),
                    }
                }
                Ok(response) => DaemonHealth {
                    status: UiStatus::Warn,
                    summary: "unexpected ping response".to_string(),
                    detail: response
                        .error
                        .unwrap_or_else(|| "daemon did not return pong".to_string()),
                },
                Err(error) => DaemonHealth {
                    status: UiStatus::Warn,
                    summary: "unparseable ping response".to_string(),
                    detail: error.to_string(),
                },
            }
        }
        Err(error) => DaemonHealth {
            status: UiStatus::Warn,
            summary: "socket present but unreachable".to_string(),
            detail: format!("{}: {error}", path_display(&layout.socket)),
        },
    }
}

#[cfg(not(unix))]
fn daemon_health(_layout: &HomeLayout) -> DaemonHealth {
    DaemonHealth {
        status: UiStatus::Skip,
        summary: "unix daemon socket unavailable on this platform".to_string(),
        detail: "daemon health uses Unix socket ping on supported hosts".to_string(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct DaemonPingResponse {
    ok: bool,
    result: Option<String>,
    error: Option<String>,
}
