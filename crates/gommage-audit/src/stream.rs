use crate::{AuditError, AuditEvent};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufRead, BufReader, ErrorKind},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStreamItem {
    pub line: usize,
    pub id: String,
    pub ts: String,
    pub kind: String,
    pub summary: String,
    pub detail: String,
}

pub fn recent_stream_items(path: &Path, limit: usize) -> Result<Vec<AuditStreamItem>, AuditError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut items = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(item) = stream_item_from_line(index + 1, &line) {
            items.push(item);
        }
    }
    let keep = limit.max(1);
    if items.len() > keep {
        items.drain(0..items.len() - keep);
    }
    Ok(items)
}

fn stream_item_from_line(line: usize, raw: &str) -> Result<AuditStreamItem, AuditError> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    if value.get("kind").and_then(|kind| kind.as_str()) == Some("event") {
        return event_item(line, value);
    }
    decision_item(line, value)
}

fn decision_item(line: usize, value: serde_json::Value) -> Result<AuditStreamItem, AuditError> {
    let decision = &value["decision"];
    let decision_kind = decision
        .get("kind")
        .and_then(|kind| kind.as_str())
        .unwrap_or("unknown");
    let tool = value
        .get("tool")
        .and_then(|tool| tool.as_str())
        .unwrap_or("<unknown>");
    let hard_stop = decision
        .get("hard_stop")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let summary = if hard_stop {
        format!("deny hard-stop {tool}")
    } else {
        format!("decision {decision_kind} {tool}")
    };
    let capability_count = value
        .get("capabilities")
        .and_then(|items| items.as_array())
        .map_or(0, Vec::len);
    Ok(AuditStreamItem {
        line,
        id: string_field(&value, "id"),
        ts: string_field(&value, "ts"),
        kind: "decision".to_string(),
        summary,
        detail: format!(
            "input={} policy={} capabilities={}",
            string_field(&value, "input_hash"),
            string_field(&value, "policy_version"),
            capability_count
        ),
    })
}

fn event_item(line: usize, value: serde_json::Value) -> Result<AuditStreamItem, AuditError> {
    let event: AuditEvent = serde_json::from_value(value["event"].clone())?;
    let (summary, detail) = match event {
        AuditEvent::ApprovalRequested {
            id,
            tool,
            input_hash,
            required_scope,
            ..
        } => (
            format!("approval requested {id}"),
            format!("tool={tool} scope={required_scope} input={input_hash}"),
        ),
        AuditEvent::ApprovalResolved {
            id,
            status,
            picto_id,
            ..
        } => (
            format!("approval {status} {id}"),
            format!("picto={}", picto_id.unwrap_or_else(|| "none".to_string())),
        ),
        AuditEvent::ApprovalWebhookDelivered {
            id,
            status,
            signature,
            ..
        } => (
            format!("webhook delivered {id}"),
            format!(
                "http={} signed={}",
                status.map_or_else(|| "unknown".to_string(), |status| status.to_string()),
                signature.is_some()
            ),
        ),
        AuditEvent::ApprovalWebhookFailed {
            id,
            error,
            signature,
            ..
        } => (
            format!("webhook failed {id}"),
            format!("signed={} error={error}", signature.is_some()),
        ),
        AuditEvent::PictoCreated { id, scope, .. } => {
            (format!("picto created {id}"), format!("scope={scope}"))
        }
        AuditEvent::PictoConsumed {
            id, scope, status, ..
        } => (
            format!("picto consumed {id}"),
            format!("scope={scope} status={status}"),
        ),
        AuditEvent::PictoRejected { id, scope, reason } => (
            format!("picto rejected {id}"),
            format!("scope={scope} reason={reason}"),
        ),
        AuditEvent::PictoConfirmed { id } => (format!("picto confirmed {id}"), String::new()),
        AuditEvent::PictoRevoked { id } => (format!("picto revoked {id}"), String::new()),
        AuditEvent::PictosExpired { count } => {
            ("pictos expired".to_string(), format!("count={count}"))
        }
        AuditEvent::PolicyReloaded {
            source,
            rules,
            mapper_rules,
            policy_version,
        } => (
            "policy reloaded".to_string(),
            format!(
                "source={source} rules={rules} mapper_rules={mapper_rules} policy={policy_version}"
            ),
        ),
        AuditEvent::BypassActivated {
            tool,
            hard_stop,
            bypass_decision,
            ..
        } => (
            format!("bypass {bypass_decision} {tool}"),
            format!("hard_stop={hard_stop}"),
        ),
    };
    Ok(AuditStreamItem {
        line,
        id: string_field(&value, "id"),
        ts: string_field(&value, "ts"),
        kind: "event".to_string(),
        summary,
        detail,
    })
}

fn string_field(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .unwrap_or("<unknown>")
        .to_string()
}
