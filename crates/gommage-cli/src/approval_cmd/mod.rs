use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalState, ApprovalStatus, ApprovalStore, ApprovalWebhookDeadLetter,
    ApprovalWebhookDeadLetterStore, ApprovalWebhookDeliveryKind, ApprovalWebhookDeliverySettings,
    ApprovalWebhookSource, Decision, PictoStore, approval_callback_nonce,
    deliver_prepared_approval_webhook, evaluate, prepare_approval_webhook,
    runtime::{HomeLayout, PolicyReadModel},
    webhook_signature::{
        WebhookSignatureReport, WebhookSignatureVerification, verify_webhook_body,
    },
};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::PathBuf, process::ExitCode};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::approval_workflow::{
    WebhookProvider, WebhookTemplateProvider, approval_evidence, approval_replay,
    approval_template, webhook_payload,
};
use crate::gestral::{UiTone, color_enabled, paint};

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ApprovalCmd {
    /// List approval requests.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Filter by request status. Defaults to pending; use all for history.
        #[arg(long, value_enum, default_value = "pending")]
        status: ApprovalStatusArg,
    },
    /// Show one approval request.
    Show {
        id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Approve a request by minting a signed scope- or input-bound picto.
    Approve {
        id: String,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// TTL as seconds or duration suffix (s, m, h, d). Max 24h.
        #[arg(long, default_value = "600", value_parser = parse_ttl_seconds)]
        ttl: i64,
        #[arg(long, default_value = "")]
        reason: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deny a request without minting a picto.
    Deny {
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Deny pending approval requests older than a duration.
    DenyStale {
        /// Only include requests older than this duration (s, m, h, d).
        #[arg(long, default_value = "24h", value_parser = parse_positive_duration_seconds)]
        older_than: i64,
        /// Apply the deny resolutions. Without this flag the command is a dry-run.
        #[arg(long)]
        apply: bool,
        /// Maximum stale requests to process.
        #[arg(long)]
        limit: Option<usize>,
        #[arg(
            long,
            default_value = "stale approval request closed by operator sweep"
        )]
        reason: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Print every matched request in human output. JSON output is always complete.
        #[arg(long, visible_alias = "verbose")]
        show_all: bool,
    },
    /// POST pending approval request payloads to a webhook URL.
    Webhook {
        #[arg(long, env = "GOMMAGE_APPROVAL_WEBHOOK_URL")]
        url: String,
        /// Shape payloads for a known incoming webhook provider.
        #[arg(long, value_enum, default_value = "generic")]
        provider: WebhookProvider,
        /// Print payloads without sending them.
        #[arg(long)]
        dry_run: bool,
        /// Maximum requests to send.
        #[arg(long)]
        limit: Option<usize>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// HMAC secret used to sign the exact webhook HTTP body.
        #[arg(long, env = "GOMMAGE_APPROVAL_WEBHOOK_SECRET")]
        signing_secret: Option<String>,
        /// Optional non-secret key identifier emitted with webhook signatures.
        #[arg(long, env = "GOMMAGE_APPROVAL_WEBHOOK_SECRET_ID")]
        signing_key_id: Option<String>,
        /// Total delivery attempts before the request is dead-lettered.
        #[arg(long, env = "GOMMAGE_APPROVAL_WEBHOOK_ATTEMPTS", default_value_t = 3)]
        attempts: u32,
        /// Delay between retry attempts in milliseconds.
        #[arg(
            long,
            env = "GOMMAGE_APPROVAL_WEBHOOK_BACKOFF_MS",
            default_value_t = 250
        )]
        backoff_ms: u64,
    },
    /// Apply a signed remote approval callback payload.
    Callback {
        /// JSON callback body. Defaults to stdin.
        #[arg(long, value_name = "FILE")]
        body: Option<PathBuf>,
        /// HMAC signature over `<timestamp>.<body>`.
        #[arg(long, env = "GOMMAGE_APPROVAL_CALLBACK_SIGNATURE")]
        signature: String,
        /// RFC3339 timestamp used in the HMAC signed message.
        #[arg(long, env = "GOMMAGE_APPROVAL_CALLBACK_TIMESTAMP")]
        timestamp: String,
        /// HMAC secret shared with the callback provider.
        #[arg(long, env = "GOMMAGE_APPROVAL_CALLBACK_SECRET")]
        signing_secret: String,
        /// Maximum accepted timestamp age in seconds.
        #[arg(long, default_value_t = 300)]
        max_age_seconds: i64,
        /// Verify and report the intended action without mutating approval state.
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect locally dead-lettered approval webhook deliveries.
    Dlq {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Maximum entries to print.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Replay one approval request against the current policy.
    Replay {
        id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export a JSON evidence bundle for one approval request.
    Evidence {
        id: String,
        /// Redact the selected Gommage home path.
        #[arg(long)]
        redact: bool,
        /// Output JSON file. Defaults to stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Print provider setup and payload templates.
    Template {
        /// Provider template to render.
        #[arg(long, value_enum)]
        provider: WebhookTemplateProvider,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ApprovalStatusArg {
    All,
    Pending,
    Approved,
    Denied,
    Satisfied,
    Superseded,
}

impl ApprovalStatusArg {
    fn status(self) -> Option<ApprovalStatus> {
        match self {
            ApprovalStatusArg::All => None,
            ApprovalStatusArg::Pending => Some(ApprovalStatus::Pending),
            ApprovalStatusArg::Approved => Some(ApprovalStatus::Approved),
            ApprovalStatusArg::Denied => Some(ApprovalStatus::Denied),
            ApprovalStatusArg::Satisfied => Some(ApprovalStatus::Satisfied),
            ApprovalStatusArg::Superseded => Some(ApprovalStatus::Superseded),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ApprovalStatusArg::All => "all",
            ApprovalStatusArg::Pending => "pending",
            ApprovalStatusArg::Approved => "approved",
            ApprovalStatusArg::Denied => "denied",
            ApprovalStatusArg::Satisfied => "satisfied",
            ApprovalStatusArg::Superseded => "superseded",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ApprovalActionReport {
    pub(crate) schema_version: u8,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) request_id: String,
    pub(crate) tool: String,
    pub(crate) scope: String,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) picto_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) picto: Option<ApprovalPictoReport>,
    pub(crate) next_action: String,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApprovalPictoReport {
    pub(crate) kind: String,
    pub(crate) id: String,
    pub(crate) scope: String,
    pub(crate) input_bound: bool,
    pub(crate) authorizes: String,
    pub(crate) consumption: String,
    pub(crate) matching_call_consumes_use: bool,
    pub(crate) non_matching_call_consumes_use: bool,
    pub(crate) max_uses: u32,
    pub(crate) uses_remaining: u32,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
struct WebhookReport {
    url: String,
    provider: String,
    dry_run: bool,
    sent: usize,
    failed: usize,
    requests: Vec<WebhookRequestReport>,
}

#[derive(Debug, Serialize)]
struct WebhookRequestReport {
    id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<WebhookSignatureReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dead_letter_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebhookDlqReport<'a> {
    path: String,
    count: usize,
    entries: Vec<WebhookDlqItem<'a>>,
}

#[derive(Debug, Serialize)]
struct WebhookDlqItem<'a> {
    id: &'a str,
    request_id: &'a str,
    dead_lettered_at: &'a str,
    source: &'a str,
    provider: &'a str,
    url: &'a str,
    attempts: u32,
    error: &'a str,
    body: &'a str,
    request: &'a gommage_core::ApprovalRequest,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApprovalCallbackPayload {
    #[serde(default)]
    kind: Option<String>,
    request_id: String,
    action: ApprovalCallbackAction,
    nonce: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    ttl: Option<i64>,
    #[serde(default)]
    uses: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalCallbackAction {
    Approve,
    Deny,
}

impl ApprovalCallbackAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Serialize)]
struct ApprovalCallbackReport {
    schema_version: u8,
    kind: &'static str,
    status: ApprovalCallbackStatus,
    dry_run: bool,
    request_id: Option<String>,
    action: Option<ApprovalCallbackAction>,
    signature: WebhookSignatureVerification,
    nonce_match: bool,
    pending: bool,
    errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<ApprovalActionReport>,
}

#[derive(Debug, Serialize)]
struct ApprovalDenyStaleReport {
    schema_version: u8,
    kind: &'static str,
    apply: bool,
    older_than_seconds: i64,
    matched: usize,
    denied: usize,
    requests: Vec<ApprovalDenyStaleItem>,
}

#[derive(Debug, Serialize)]
struct ApprovalDenyStaleItem {
    id: String,
    status: &'static str,
    created_at: String,
    age_seconds: u64,
    tool: String,
    scope: String,
}

const DENY_STALE_HUMAN_DEFAULT_LIMIT: usize = 20;

impl ApprovalCallbackReport {
    fn exit_code(&self) -> ExitCode {
        if matches!(
            self.status,
            ApprovalCallbackStatus::Valid | ApprovalCallbackStatus::Applied
        ) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalCallbackStatus {
    Valid,
    Applied,
    Rejected,
}

impl<'a> From<&'a ApprovalWebhookDeadLetter> for WebhookDlqItem<'a> {
    fn from(entry: &'a ApprovalWebhookDeadLetter) -> Self {
        Self {
            id: &entry.id,
            request_id: &entry.request_id,
            dead_lettered_at: &entry.dead_lettered_at,
            source: &entry.source,
            provider: &entry.provider,
            url: &entry.url,
            attempts: entry.attempts,
            error: &entry.error,
            body: &entry.body,
            request: &entry.request,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApprovalListItem<'a> {
    id: &'a str,
    status: ApprovalStatus,
    created_at: String,
    tool: &'a str,
    required_scope: &'a str,
    request: &'a gommage_core::ApprovalRequest,
    resolution: &'a Option<gommage_core::ApprovalResolution>,
}

impl<'a> From<&'a ApprovalState> for ApprovalListItem<'a> {
    fn from(state: &'a ApprovalState) -> Self {
        Self {
            id: &state.request.id,
            status: state.status,
            created_at: format_timestamp(state.request.created_at),
            tool: &state.request.tool,
            required_scope: &state.request.required_scope,
            request: &state.request,
            resolution: &state.resolution,
        }
    }
}

pub(crate) fn cmd_approval(cmd: ApprovalCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        ApprovalCmd::List { json, status } => approval_list(layout, json, status),
        ApprovalCmd::Show { id, json } => approval_show(layout, &id, json),
        ApprovalCmd::Approve {
            id,
            uses,
            ttl,
            reason,
            json,
        } => approval_approve(layout, &id, uses, ttl, &reason, json),
        ApprovalCmd::Deny { id, reason, json } => approval_deny(layout, &id, &reason, json),
        ApprovalCmd::DenyStale {
            older_than,
            apply,
            limit,
            reason,
            json,
            show_all,
        } => approval_deny_stale(layout, older_than, apply, limit, &reason, json, show_all),
        ApprovalCmd::Webhook {
            url,
            provider,
            dry_run,
            limit,
            json,
            signing_secret,
            signing_key_id,
            attempts,
            backoff_ms,
        } => approval_webhook(ApprovalWebhookOptions {
            layout,
            url,
            provider,
            dry_run,
            limit,
            json,
            signing_secret,
            signing_key_id,
            attempts,
            backoff_ms,
        }),
        ApprovalCmd::Callback {
            body,
            signature,
            timestamp,
            signing_secret,
            max_age_seconds,
            dry_run,
            json,
        } => approval_callback(ApprovalCallbackOptions {
            layout,
            body,
            signature,
            timestamp,
            signing_secret,
            max_age_seconds,
            dry_run,
            json,
        }),
        ApprovalCmd::Dlq { json, limit } => approval_dlq(layout, json, limit),
        ApprovalCmd::Replay { id, json } => approval_replay(layout, &id, json),
        ApprovalCmd::Evidence {
            id,
            redact,
            output,
            force,
        } => approval_evidence(layout, &id, redact, output, force),
        ApprovalCmd::Template { provider, json } => approval_template(provider, json),
    }
}

struct ApprovalCallbackOptions {
    layout: HomeLayout,
    body: Option<PathBuf>,
    signature: String,
    timestamp: String,
    signing_secret: String,
    max_age_seconds: i64,
    dry_run: bool,
    json: bool,
}

fn approval_callback(options: ApprovalCallbackOptions) -> Result<ExitCode> {
    let ApprovalCallbackOptions {
        layout,
        body,
        signature,
        timestamp,
        signing_secret,
        max_age_seconds,
        dry_run,
        json,
    } = options;
    let body = read_callback_body(body)?;
    let verification = verify_webhook_body(
        &body,
        &signing_secret,
        &timestamp,
        &signature,
        max_age_seconds,
    );
    let payload = serde_json::from_slice::<ApprovalCallbackPayload>(&body);
    let mut errors = Vec::new();
    if let Some(error) = &verification.error {
        errors.push(error.clone());
    }
    let (request_id, action, nonce, reason, ttl, uses) = match payload {
        Ok(payload) => {
            if payload.kind.as_deref() != Some("gommage_approval_callback") {
                errors.push("callback kind must be gommage_approval_callback".to_string());
            }
            (
                Some(payload.request_id),
                Some(payload.action),
                Some(payload.nonce),
                payload.reason,
                payload.ttl,
                payload.uses,
            )
        }
        Err(error) => {
            errors.push(format!("callback body is not valid JSON: {error}"));
            (None, None, None, None, None, None)
        }
    };

    let mut nonce_match = false;
    let mut pending = false;
    if let Some(request_id) = &request_id {
        let store = ApprovalStore::open(&layout.approvals_log);
        match store.get(request_id)? {
            Some(state) => {
                pending = state.status == ApprovalStatus::Pending;
                if !pending {
                    errors.push(format!(
                        "approval request {request_id} is {}",
                        state.status.as_str()
                    ));
                }
                let expected_nonce = approval_callback_nonce(&state.request);
                nonce_match = nonce.as_deref() == Some(expected_nonce.as_str());
                if !nonce_match {
                    errors.push("callback nonce does not match pending request".to_string());
                }
            }
            None => errors.push(format!("approval request {request_id} not found")),
        }
    }

    if !errors.is_empty() {
        let report = ApprovalCallbackReport {
            schema_version: 1,
            kind: "approval_callback",
            status: ApprovalCallbackStatus::Rejected,
            dry_run,
            request_id,
            action,
            signature: verification,
            nonce_match,
            pending,
            errors,
            outcome: None,
        };
        return print_callback_report(json, report);
    }

    if dry_run {
        let report = ApprovalCallbackReport {
            schema_version: 1,
            kind: "approval_callback",
            status: ApprovalCallbackStatus::Valid,
            dry_run,
            request_id,
            action,
            signature: verification,
            nonce_match,
            pending,
            errors,
            outcome: None,
        };
        return print_callback_report(json, report);
    }

    let request_id = request_id.expect("validated request id");
    let action = action.expect("validated callback action");
    let reason = reason.unwrap_or_else(|| format!("signed callback {}", action.as_str()));
    let outcome = match action {
        ApprovalCallbackAction::Approve => approve_request(
            &layout,
            &request_id,
            uses.unwrap_or(1),
            ttl.unwrap_or(600),
            &reason,
        )?,
        ApprovalCallbackAction::Deny => deny_request(&layout, &request_id, &reason)?,
    };
    let report = ApprovalCallbackReport {
        schema_version: 1,
        kind: "approval_callback",
        status: ApprovalCallbackStatus::Applied,
        dry_run,
        request_id: Some(request_id),
        action: Some(action),
        signature: verification,
        nonce_match,
        pending,
        errors,
        outcome: Some(outcome),
    };
    print_callback_report(json, report)
}

mod actions;
mod delivery;

use actions::*;
pub(crate) use actions::{approve_request, deny_request};
use delivery::*;
