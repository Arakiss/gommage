use crate::{
    ApprovalRequest,
    runtime::HomeLayout,
    webhook_signature::{WebhookSignatureReport, sign_webhook_body},
};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DEFAULT_ATTEMPTS: u32 = 3;
const DEFAULT_BACKOFF_MS: u64 = 250;
const MAX_ATTEMPTS: u32 = 10;
const MAX_BACKOFF_MS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWebhookSource {
    Cli,
    Daemon,
    McpFallback,
}

impl ApprovalWebhookSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Daemon => "daemon",
            Self::McpFallback => "mcp_fallback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWebhookDeadLetter {
    pub id: String,
    pub dead_lettered_at: String,
    pub request_id: String,
    pub source: String,
    pub provider: String,
    pub url: String,
    pub attempts: u32,
    pub error: String,
    pub request: ApprovalRequest,
    pub payload: serde_json::Value,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<WebhookSignatureReport>,
}

pub struct ApprovalWebhookDeadLetterStore {
    path: PathBuf,
}

impl ApprovalWebhookDeadLetterStore {
    pub fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(
        &self,
        entry: &ApprovalWebhookDeadLetter,
    ) -> Result<(), ApprovalWebhookDeliveryError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ApprovalWebhookDeadLetter>, ApprovalWebhookDeliveryError> {
        let mut entries = Vec::new();
        if !self.path.exists() {
            return Ok(entries);
        }
        let text = fs::read_to_string(&self.path)?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(line)?);
        }
        Ok(entries)
    }

    pub fn count(&self) -> Result<usize, ApprovalWebhookDeliveryError> {
        Ok(self.list()?.len())
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalWebhookDeliverySettings {
    pub attempts: u32,
    pub backoff: Duration,
}

impl ApprovalWebhookDeliverySettings {
    pub fn new(attempts: u32, backoff_ms: u64) -> Self {
        Self {
            attempts: attempts.clamp(1, MAX_ATTEMPTS),
            backoff: Duration::from_millis(backoff_ms.min(MAX_BACKOFF_MS)),
        }
    }

    pub fn from_env() -> Self {
        let attempts = env::var("GOMMAGE_APPROVAL_WEBHOOK_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_ATTEMPTS);
        let backoff_ms = env::var("GOMMAGE_APPROVAL_WEBHOOK_BACKOFF_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_BACKOFF_MS);
        Self::new(attempts, backoff_ms)
    }
}

impl Default for ApprovalWebhookDeliverySettings {
    fn default() -> Self {
        Self::new(DEFAULT_ATTEMPTS, DEFAULT_BACKOFF_MS)
    }
}

#[derive(Debug, Clone)]
pub struct PreparedApprovalWebhook {
    pub payload: serde_json::Value,
    pub body: Vec<u8>,
    pub signature: Option<WebhookSignatureReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalWebhookDeliveryKind {
    Delivered,
    DeadLettered,
}

#[derive(Debug, Clone)]
pub struct ApprovalWebhookDeliveryOutcome {
    pub kind: ApprovalWebhookDeliveryKind,
    pub attempts: u32,
    pub http_status: Option<i32>,
    pub error: Option<String>,
    pub dead_letter_id: Option<String>,
    pub signature: Option<WebhookSignatureReport>,
}

#[derive(Debug, Error)]
pub enum ApprovalWebhookDeliveryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("delivery: {0}")]
    Delivery(String),
}

pub fn approval_webhook_generic_payload(request: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({
        "kind": "gommage_approval_request",
        "id": request.id,
        "created_at": format_timestamp(request.created_at),
        "tool": request.tool,
        "input_hash": request.input_hash,
        "required_scope": request.required_scope,
        "reason": request.reason,
        "capabilities": request.capabilities,
        "matched_rule": request.matched_rule,
        "policy_version": request.policy_version,
        "commands": {
            "show": format!("gommage approval show {} --json", request.id),
            "approve": format!("gommage approval approve {}", request.id),
            "deny": format!("gommage approval deny {}", request.id),
            "replay": format!("gommage approval replay {} --json", request.id),
            "evidence": format!("gommage approval evidence {} --redact", request.id),
            "audit_verify": "gommage audit-verify --explain --format human",
            "tui": "gommage tui --snapshot --view approvals"
        }
    })
}

fn format_timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

pub fn prepare_approval_webhook(
    payload: serde_json::Value,
    signing_secret: Option<&str>,
    signing_key_id: Option<&str>,
) -> Result<PreparedApprovalWebhook, ApprovalWebhookDeliveryError> {
    let body = serde_json::to_vec(&payload)?;
    let signature = signing_secret
        .filter(|secret| !secret.trim().is_empty())
        .map(|secret| sign_webhook_body(&body, secret, signing_key_id));
    Ok(PreparedApprovalWebhook {
        payload,
        body,
        signature,
    })
}

pub fn deliver_prepared_approval_webhook(
    layout: &HomeLayout,
    request: &ApprovalRequest,
    source: ApprovalWebhookSource,
    provider: &str,
    url: &str,
    prepared: &PreparedApprovalWebhook,
    settings: &ApprovalWebhookDeliverySettings,
) -> Result<ApprovalWebhookDeliveryOutcome, ApprovalWebhookDeliveryError> {
    let mut last_error = None;
    for attempt in 1..=settings.attempts {
        match post_json_with_curl(url, &prepared.body, prepared.signature.as_ref()) {
            Ok(status) => {
                return Ok(ApprovalWebhookDeliveryOutcome {
                    kind: ApprovalWebhookDeliveryKind::Delivered,
                    attempts: attempt,
                    http_status: Some(status),
                    error: None,
                    dead_letter_id: None,
                    signature: prepared.signature.clone(),
                });
            }
            Err(error) => {
                last_error = Some(error);
                if attempt < settings.attempts && settings.backoff > Duration::ZERO {
                    thread::sleep(settings.backoff);
                }
            }
        }
    }

    let error = last_error.unwrap_or_else(|| "webhook delivery failed".to_string());
    let dead_letter = ApprovalWebhookDeadLetter {
        id: format!("dlq_{}", &uuid::Uuid::now_v7().simple().to_string()[..20]),
        dead_lettered_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().to_string()),
        request_id: request.id.clone(),
        source: source.as_str().to_string(),
        provider: provider.to_string(),
        url: url.to_string(),
        attempts: settings.attempts,
        error: error.clone(),
        request: request.clone(),
        payload: prepared.payload.clone(),
        body: String::from_utf8_lossy(&prepared.body).into_owned(),
        signature: prepared.signature.clone(),
    };
    let store = ApprovalWebhookDeadLetterStore::open(&layout.approval_webhook_dlq);
    store.append(&dead_letter)?;
    Ok(ApprovalWebhookDeliveryOutcome {
        kind: ApprovalWebhookDeliveryKind::DeadLettered,
        attempts: settings.attempts,
        http_status: None,
        error: Some(error),
        dead_letter_id: Some(dead_letter.id),
        signature: prepared.signature.clone(),
    })
}

fn post_json_with_curl(
    url: &str,
    body: &[u8],
    signature: Option<&WebhookSignatureReport>,
) -> Result<i32, String> {
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "5",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--header",
        "content-type: application/json",
    ]);
    if let Some(signature) = signature {
        for header in signature.curl_headers() {
            command.args(["--header", &header]);
        }
    }
    let mut child = command
        .args(["--request", "POST", "--data-binary", "@-", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting curl for approval webhook delivery: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "opening curl stdin".to_string())?
        .write_all(body)
        .map_err(|error| error.to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(0))
}
