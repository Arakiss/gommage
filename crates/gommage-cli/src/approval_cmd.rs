use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalState, ApprovalStatus, ApprovalStore, PictoStore,
    runtime::HomeLayout,
    webhook_signature::{WebhookSignatureReport, sign_webhook_body},
};
use serde::Serialize;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::approval_workflow::{
    WebhookProvider, WebhookTemplateProvider, approval_evidence, approval_replay,
    approval_template, webhook_payload,
};

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
}

#[derive(Debug, Serialize)]
pub(crate) struct ApprovalActionReport {
    pub(crate) status: String,
    pub(crate) request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) picto_id: Option<String>,
    pub(crate) message: String,
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
    payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<WebhookSignatureReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
        } => approval_webhook(
            layout,
            &url,
            provider,
            dry_run,
            limit,
            json,
            signing_secret.as_deref(),
            signing_key_id.as_deref(),
        ),
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
        println!("no approval requests");
        return Ok(ExitCode::SUCCESS);
    }
    for state in states {
        print_state_line(&state);
    }
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

    Ok(ApprovalActionReport {
        status: "approved".to_string(),
        request_id: id.to_string(),
        picto_id: Some(picto.id),
        message: format!(
            "approved {id}; minted exact-scope picto for {}",
            picto.scope
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
        status: "denied".to_string(),
        request_id: id.to_string(),
        picto_id: None,
        message: format!("denied {id}"),
    })
}

fn approval_webhook(
    layout: HomeLayout,
    url: &str,
    provider: WebhookProvider,
    dry_run: bool,
    limit: Option<usize>,
    json: bool,
    signing_secret: Option<&str>,
    signing_key_id: Option<&str>,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut pending = store.pending()?;
    if let Some(limit) = limit {
        pending.truncate(limit);
    }
    let mut report = WebhookReport {
        url: url.to_string(),
        provider: provider.as_str().to_string(),
        dry_run,
        sent: 0,
        failed: 0,
        requests: Vec::new(),
    };
    let audit = layout
        .load_key()
        .ok()
        .and_then(|sk| AuditWriter::open(&layout.audit_log, sk).ok());
    let mut audit = audit;

    for state in pending {
        let payload = webhook_payload(&state.request, provider);
        let body = serde_json::to_vec(&payload)?;
        let signature = signing_secret
            .filter(|secret| !secret.trim().is_empty())
            .map(|secret| sign_webhook_body(&body, secret, signing_key_id));
        if dry_run {
            if !json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
                if let Some(signature) = &signature {
                    println!("signature: {} {}", signature.algorithm, signature.signature);
                }
            }
            report.requests.push(WebhookRequestReport {
                id: state.request.id,
                status: "dry_run".to_string(),
                payload: Some(payload),
                body: Some(String::from_utf8(body)?),
                signature,
                http_status: None,
                error: None,
            });
            continue;
        }
        match post_json_with_curl(url, &body, signature.as_ref()) {
            Ok(status) => {
                report.sent += 1;
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookDelivered {
                        id: state.request.id.clone(),
                        url: url.to_string(),
                        status: Some(status),
                        signature: signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "sent".to_string(),
                    payload: None,
                    body: None,
                    signature,
                    http_status: Some(status),
                    error: None,
                });
            }
            Err(error) => {
                report.failed += 1;
                let message = error.to_string();
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookFailed {
                        id: state.request.id.clone(),
                        url: url.to_string(),
                        error: message.clone(),
                        signature: signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "failed".to_string(),
                    payload: None,
                    body: None,
                    signature,
                    http_status: None,
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

fn print_action(json: bool, report: ApprovalActionReport) -> Result<ExitCode> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.message);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_state_line(state: &ApprovalState) {
    println!(
        "{} [{}] tool={} scope={} input={} reason={}",
        state.request.id,
        state.status.as_str(),
        state.request.tool,
        state.request.required_scope,
        state.request.input_hash,
        state.request.reason
    );
}

fn print_state_detail(state: &ApprovalState) {
    println!("approval {}", state.request.id);
    println!("  status:  {}", state.status.as_str());
    println!("  tool:    {}", state.request.tool);
    println!("  input:   {}", state.request.input_hash);
    println!("  scope:   {}", state.request.required_scope);
    println!("  reason:  {}", state.request.reason);
    println!("  policy:  {}", state.request.policy_version);
    if let Some(rule) = &state.request.matched_rule {
        println!("  rule:    {} ({}:{})", rule.name, rule.file, rule.index);
    }
    if state.status == ApprovalStatus::Pending {
        println!(
            "  approve: gommage approval approve {} --ttl 10m --uses 1",
            state.request.id
        );
        println!(
            "  deny:    gommage approval deny {} --reason <reason>",
            state.request.id
        );
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

fn post_json_with_curl(
    url: &str,
    body: &[u8],
    signature: Option<&WebhookSignatureReport>,
) -> Result<i32> {
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
        .context("starting curl for approval webhook delivery")?;
    child
        .stdin
        .take()
        .context("opening curl stdin")?
        .write_all(body)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(0);
    Ok(status)
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
