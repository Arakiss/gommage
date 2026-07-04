use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalState, ApprovalStatus, ApprovalStore, ApprovalWebhookDeadLetter,
    ApprovalWebhookDeadLetterStore, ApprovalWebhookDeliveryKind, ApprovalWebhookDeliverySettings,
    ApprovalWebhookSource, PictoStore, approval_callback_nonce, deliver_prepared_approval_webhook,
    prepare_approval_webhook,
    runtime::HomeLayout,
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
    /// Approve a request by minting an exact-scope signed picto.
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
}

impl ApprovalStatusArg {
    fn status(self) -> Option<ApprovalStatus> {
        match self {
            ApprovalStatusArg::All => None,
            ApprovalStatusArg::Pending => Some(ApprovalStatus::Pending),
            ApprovalStatusArg::Approved => Some(ApprovalStatus::Approved),
            ApprovalStatusArg::Denied => Some(ApprovalStatus::Denied),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ApprovalStatusArg::All => "all",
            ApprovalStatusArg::Pending => "pending",
            ApprovalStatusArg::Approved => "approved",
            ApprovalStatusArg::Denied => "denied",
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

fn read_callback_body(path: Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(path) = path {
        return Ok(std::fs::read(path)?);
    }
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body)?;
    Ok(body)
}

fn approval_list(layout: HomeLayout, json: bool, status: ApprovalStatusArg) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut states = store.list()?;
    if let Some(status) = status.status() {
        states.retain(|state| state.status == status);
    }
    if json {
        let items = states
            .iter()
            .map(ApprovalListItem::from)
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(ExitCode::SUCCESS);
    }
    if states.is_empty() {
        print_empty_inbox(status);
        return Ok(ExitCode::SUCCESS);
    }
    print_inbox(&states, status);
    Ok(ExitCode::SUCCESS)
}

fn approval_show(layout: HomeLayout, id: &str, json: bool) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let Some(state) = store.get(id)? else {
        println!("approval request {id} not found");
        return Ok(ExitCode::from(1));
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
    } else {
        print_state_detail(&state);
    }
    Ok(ExitCode::SUCCESS)
}

fn approval_approve(
    layout: HomeLayout,
    id: &str,
    uses: u32,
    ttl: i64,
    reason: &str,
    json: bool,
) -> Result<ExitCode> {
    let report = approve_request(&layout, id, uses, ttl, reason)?;
    print_action(json, report)
}

pub(crate) fn approve_request(
    layout: &HomeLayout,
    id: &str,
    uses: u32,
    ttl: i64,
    reason: &str,
) -> Result<ApprovalActionReport> {
    layout.ensure()?;
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    if state.status != ApprovalStatus::Pending {
        anyhow::bail!("approval request {id:?} is {}", state.status.as_str());
    }

    let sk = layout.load_key()?;
    let pictos = PictoStore::open(&layout.pictos_db)?;
    let picto_id = format!("picto_{}", uuid::Uuid::now_v7());
    let approval_reason = if reason.trim().is_empty() {
        format!("approved request {id}")
    } else {
        reason.to_string()
    };
    let picto = pictos.create(
        &picto_id,
        &state.request.required_scope,
        uses,
        ttl,
        &approval_reason,
        &sk,
        false,
    )?;
    let resolution = store.resolve(
        id,
        ApprovalStatus::Approved,
        &approval_reason,
        Some(picto.id.clone()),
    )?;

    let mut writer = AuditWriter::open(&layout.audit_log, sk)?;
    writer.append_event(AuditEvent::PictoCreated {
        id: picto.id.clone(),
        scope: picto.scope.clone(),
        max_uses: picto.max_uses,
        ttl_expires_at: picto.ttl_expires_at.to_string(),
        require_confirmation: false,
    })?;
    writer.append_event(AuditEvent::ApprovalResolved {
        id: resolution.request_id.clone(),
        status: resolution.status.as_str().to_string(),
        reason: resolution.reason.clone(),
        picto_id: resolution.picto_id.clone(),
    })?;

    let picto_id = picto.id.clone();
    let picto_scope = picto.scope.clone();
    let picto_expires_at = format_timestamp(picto.ttl_expires_at);
    let picto_max_uses = picto.max_uses;
    let uses_remaining = picto.max_uses.saturating_sub(picto.uses);
    Ok(ApprovalActionReport {
        schema_version: 1,
        kind: "approval_action".to_string(),
        status: "approved".to_string(),
        request_id: id.to_string(),
        tool: state.request.tool,
        scope: picto_scope.clone(),
        reason: approval_reason,
        picto_id: Some(picto_id.clone()),
        picto: Some(ApprovalPictoReport {
            kind: "exact_scope".to_string(),
            id: picto_id,
            scope: picto_scope.clone(),
            max_uses: picto_max_uses,
            uses_remaining,
            expires_at: picto_expires_at,
        }),
        next_action: "retry_blocked_call".to_string(),
        message: format!(
            "approved {id}; minted exact-scope picto for {}",
            picto_scope
        ),
    })
}

fn approval_deny(layout: HomeLayout, id: &str, reason: &str, json: bool) -> Result<ExitCode> {
    let report = deny_request(&layout, id, reason)?;
    print_action(json, report)
}

pub(crate) fn deny_request(
    layout: &HomeLayout,
    id: &str,
    reason: &str,
) -> Result<ApprovalActionReport> {
    layout.ensure()?;
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    let deny_reason = if reason.trim().is_empty() {
        format!("denied request {id}")
    } else {
        reason.to_string()
    };
    let sk = layout.load_key()?;
    let resolution = store.resolve(id, ApprovalStatus::Denied, &deny_reason, None)?;
    let mut writer = AuditWriter::open(&layout.audit_log, sk)?;
    writer.append_event(AuditEvent::ApprovalResolved {
        id: resolution.request_id.clone(),
        status: resolution.status.as_str().to_string(),
        reason: resolution.reason.clone(),
        picto_id: None,
    })?;
    Ok(ApprovalActionReport {
        schema_version: 1,
        kind: "approval_action".to_string(),
        status: "denied".to_string(),
        request_id: id.to_string(),
        tool: state.request.tool,
        scope: state.request.required_scope,
        reason: deny_reason,
        picto_id: None,
        picto: None,
        next_action: "none".to_string(),
        message: format!("denied {id}"),
    })
}

struct ApprovalWebhookOptions {
    layout: HomeLayout,
    url: String,
    provider: WebhookProvider,
    dry_run: bool,
    limit: Option<usize>,
    json: bool,
    signing_secret: Option<String>,
    signing_key_id: Option<String>,
    attempts: u32,
    backoff_ms: u64,
}

fn approval_webhook(options: ApprovalWebhookOptions) -> Result<ExitCode> {
    let ApprovalWebhookOptions {
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
    } = options;
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut pending = store.pending()?;
    if let Some(limit) = limit {
        pending.truncate(limit);
    }
    let mut report = WebhookReport {
        url: url.clone(),
        provider: provider.as_str().to_string(),
        dry_run,
        sent: 0,
        failed: 0,
        requests: Vec::new(),
    };
    let settings = ApprovalWebhookDeliverySettings::new(attempts, backoff_ms);
    let audit = layout
        .load_key()
        .ok()
        .and_then(|sk| AuditWriter::open(&layout.audit_log, sk).ok());
    let mut audit = audit;

    for state in pending {
        let payload = webhook_payload(&state.request, provider);
        let prepared = prepare_approval_webhook(
            payload.clone(),
            signing_secret.as_deref(),
            signing_key_id.as_deref(),
        )?;
        if dry_run {
            if !json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
                if let Some(signature) = &prepared.signature {
                    println!("signature: {} {}", signature.algorithm, signature.signature);
                }
            }
            report.requests.push(WebhookRequestReport {
                id: state.request.id,
                status: "dry_run".to_string(),
                attempts: None,
                payload: Some(payload),
                body: Some(String::from_utf8(prepared.body.clone())?),
                signature: prepared.signature,
                http_status: None,
                dead_letter_id: None,
                error: None,
            });
            continue;
        }
        let outcome = deliver_prepared_approval_webhook(
            &layout,
            &state.request,
            ApprovalWebhookSource::Cli,
            provider.as_str(),
            &url,
            &prepared,
            &settings,
        )?;
        match outcome.kind {
            ApprovalWebhookDeliveryKind::Delivered => {
                report.sent += 1;
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookDelivered {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        status: outcome.http_status,
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "sent".to_string(),
                    attempts: Some(outcome.attempts),
                    payload: None,
                    body: None,
                    signature: outcome.signature,
                    http_status: outcome.http_status,
                    dead_letter_id: None,
                    error: None,
                });
            }
            ApprovalWebhookDeliveryKind::DeadLettered => {
                report.failed += 1;
                let message = outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "webhook delivery failed".to_string());
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookFailed {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        error: message.clone(),
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                    writer.append_event(AuditEvent::ApprovalWebhookDeadLettered {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        dead_letter_id: outcome
                            .dead_letter_id
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        provider: provider.as_str().to_string(),
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        error: message.clone(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "dead_lettered".to_string(),
                    attempts: Some(outcome.attempts),
                    payload: None,
                    body: None,
                    signature: outcome.signature,
                    http_status: None,
                    dead_letter_id: outcome.dead_letter_id,
                    error: Some(message),
                });
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if dry_run {
        eprintln!("gommage approval webhook: dry-run rendered pending payloads");
    } else {
        println!(
            "webhook delivery complete: {} sent, {} failed",
            report.sent, report.failed
        );
    }
    if report.failed > 0 {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn approval_dlq(layout: HomeLayout, json: bool, limit: Option<usize>) -> Result<ExitCode> {
    let store = ApprovalWebhookDeadLetterStore::open(&layout.approval_webhook_dlq);
    let mut entries = store.list()?;
    entries.reverse();
    if let Some(limit) = limit {
        entries.truncate(limit);
    }
    if json {
        let report = WebhookDlqReport {
            path: layout.approval_webhook_dlq.display().to_string(),
            count: entries.len(),
            entries: entries.iter().map(WebhookDlqItem::from).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "approval webhook dlq: {}",
        layout.approval_webhook_dlq.display()
    );
    if entries.is_empty() {
        println!("entries: none");
        return Ok(ExitCode::SUCCESS);
    }
    println!("entries: {}", entries.len());
    for entry in entries {
        println!(
            "- {} request={} source={} provider={} attempts={} url={}",
            entry.id, entry.request_id, entry.source, entry.provider, entry.attempts, entry.url
        );
        println!("  error: {}", entry.error);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_action(json: bool, report: ApprovalActionReport) -> Result<ExitCode> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_action_human(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_callback_report(json: bool, report: ApprovalCallbackReport) -> Result<ExitCode> {
    let exit_code = report.exit_code();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("approval callback: {:?}", report.status);
        if let Some(request_id) = &report.request_id {
            println!("request: {request_id}");
        }
        if let Some(action) = report.action {
            println!("action: {}", action.as_str());
        }
        println!(
            "signature: {}",
            if report.signature.ok { "ok" } else { "invalid" }
        );
        println!(
            "nonce: {}",
            if report.nonce_match { "ok" } else { "mismatch" }
        );
        if report.dry_run {
            println!("dry-run: state not changed");
        }
        for error in &report.errors {
            println!("error: {error}");
        }
        if let Some(outcome) = &report.outcome {
            println!("outcome: {}", outcome.message);
        }
    }
    Ok(exit_code)
}

fn print_action_human(report: &ApprovalActionReport) {
    let colors = color_enabled();
    let title = match report.status.as_str() {
        "approved" => "Approval granted",
        "denied" => "Approval denied",
        _ => "Approval resolved",
    };
    println!(
        "{}",
        paint(title, action_tone(&report.status), true, colors)
    );
    println!("request: {}", report.request_id);
    println!(
        "status:  {}",
        paint(&report.status, action_tone(&report.status), true, colors)
    );
    println!("tool:    {}", report.tool);
    println!("scope:   {}", report.scope);
    println!("reason:  {}", report.reason);

    if let Some(picto) = &report.picto {
        println!();
        println!("{}", paint("Picto minted", UiTone::Gold, true, colors));
        println!("id:      {}", picto.id);
        println!("kind:    {}", picto.kind.replace('_', "-"));
        println!(
            "uses:    {}/{} remaining",
            picto.uses_remaining, picto.max_uses
        );
        println!("expires: {}", picto.expires_at);
    }

    println!();
    match report.next_action.as_str() {
        "retry_blocked_call" => {
            println!("next:    retry the blocked tool call; the picto matches this exact scope")
        }
        "none" => println!("next:    no picto minted"),
        other => println!("next:    {other}"),
    }
}

fn print_empty_inbox(status: ApprovalStatusArg) {
    let colors = color_enabled();
    println!("{}", paint("Approval inbox", UiTone::Teal, true, colors));
    println!("filter:   {}", status.as_str());
    println!("requests: 0");
    if matches!(status, ApprovalStatusArg::Pending) {
        println!("next:     use --status all to inspect approval history");
    }
}

fn print_inbox(states: &[ApprovalState], status: ApprovalStatusArg) {
    let colors = color_enabled();
    println!("{}", paint("Approval inbox", UiTone::Teal, true, colors));
    println!("filter:   {}", status.as_str());
    println!("requests: {}", states.len());
    for state in states {
        println!();
        print_state_summary(state, colors);
    }
}

fn print_state_summary(state: &ApprovalState, colors: bool) {
    println!("{}", paint(&state.request.id, UiTone::Teal, true, colors));
    println!(
        "  status: {}",
        paint(
            state.status.as_str(),
            approval_status_tone(state.status),
            true,
            colors
        )
    );
    println!("  tool:   {}", state.request.tool);
    println!("  scope:  {}", state.request.required_scope);
    println!("  input:  {}", state.request.input_hash);
    println!("  reason: {}", state.request.reason);
    if state.status == ApprovalStatus::Pending {
        println!("  next:   gommage approval show {}", state.request.id);
    }
}

fn print_state_detail(state: &ApprovalState) {
    let colors = color_enabled();
    println!("{}", paint("Approval request", UiTone::Teal, true, colors));
    println!("id:      {}", state.request.id);
    println!(
        "status:  {}",
        paint(
            state.status.as_str(),
            approval_status_tone(state.status),
            true,
            colors
        )
    );
    println!("created: {}", format_timestamp(state.request.created_at));
    println!("tool:    {}", state.request.tool);
    println!("scope:   {}", state.request.required_scope);
    println!("input:   {}", state.request.input_hash);
    println!("reason:  {}", state.request.reason);
    println!("policy:  {}", state.request.policy_version);
    if let Some(rule) = &state.request.matched_rule {
        println!("rule:    {} ({}:{})", rule.name, rule.file, rule.index);
    }
    if !state.request.capabilities.is_empty() {
        println!();
        println!("{}", paint("Capabilities", UiTone::Gold, true, colors));
        for capability in &state.request.capabilities {
            println!("- {}", capability.as_str());
        }
    }
    if state.status == ApprovalStatus::Pending {
        println!();
        println!("{}", paint("Next", UiTone::Gold, true, colors));
        println!(
            "approve: gommage approval approve {} --ttl 10m --uses 1",
            state.request.id
        );
        println!(
            "deny:    gommage approval deny {} --reason <reason>",
            state.request.id
        );
    }
}

fn action_tone(status: &str) -> UiTone {
    match status {
        "approved" => UiTone::Green,
        "denied" => UiTone::Red,
        _ => UiTone::Muted,
    }
}

fn approval_status_tone(status: ApprovalStatus) -> UiTone {
    match status {
        ApprovalStatus::Pending => UiTone::Gold,
        ApprovalStatus::Approved => UiTone::Green,
        ApprovalStatus::Denied => UiTone::Red,
    }
}

fn format_timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

fn signature_audit_summary(
    signature: &WebhookSignatureReport,
) -> gommage_audit::WebhookSignatureAudit {
    gommage_audit::WebhookSignatureAudit {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        timestamp: signature.timestamp.clone(),
        body_sha256: signature.body_sha256.clone(),
        signature_prefix: signature.signature.chars().take(18).collect(),
    }
}

fn parse_ttl_seconds(raw: &str) -> std::result::Result<i64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("ttl cannot be empty".to_string());
    }
    let (number, multiplier) = match raw.chars().last().unwrap() {
        's' | 'S' => (&raw[..raw.len() - 1], 1),
        'm' | 'M' => (&raw[..raw.len() - 1], 60),
        'h' | 'H' => (&raw[..raw.len() - 1], 3_600),
        'd' | 'D' => (&raw[..raw.len() - 1], 86_400),
        c if c.is_ascii_digit() => (raw, 1),
        other => {
            return Err(format!(
                "unsupported ttl suffix {other:?}; use s, m, h, or d"
            ));
        }
    };
    let value: i64 = number
        .parse()
        .map_err(|_| "ttl must start with a positive integer".to_string())?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| "ttl is too large".to_string())?;
    if !(1..=86_400).contains(&seconds) {
        return Err("ttl must be between 1 second and 24 hours".to_string());
    }
    Ok(seconds)
}
