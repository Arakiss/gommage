use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalRequest, ApprovalState, ApprovalStatus, ApprovalStore, PictoStore, runtime::HomeLayout,
};
use serde::Serialize;
use std::{
    io::Write,
    process::{Command, ExitCode, Stdio},
};

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ApprovalCmd {
    /// List approval requests.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Filter by request status.
        #[arg(long, value_enum)]
        status: Option<ApprovalStatusArg>,
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
        /// Print payloads without sending them.
        #[arg(long)]
        dry_run: bool,
        /// Maximum requests to send.
        #[arg(long)]
        limit: Option<usize>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ApprovalStatusArg {
    Pending,
    Approved,
    Denied,
}

impl From<ApprovalStatusArg> for ApprovalStatus {
    fn from(value: ApprovalStatusArg) -> Self {
        match value {
            ApprovalStatusArg::Pending => ApprovalStatus::Pending,
            ApprovalStatusArg::Approved => ApprovalStatus::Approved,
            ApprovalStatusArg::Denied => ApprovalStatus::Denied,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApprovalActionReport {
    status: String,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    picto_id: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct WebhookReport {
    url: String,
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
    http_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
            dry_run,
            limit,
            json,
        } => approval_webhook(layout, &url, dry_run, limit, json),
    }
}

fn approval_list(
    layout: HomeLayout,
    json: bool,
    status: Option<ApprovalStatusArg>,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut states = store.list()?;
    if let Some(status) = status {
        let status = ApprovalStatus::from(status);
        states.retain(|state| state.status == status);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&states)?);
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

    print_action(
        json,
        ApprovalActionReport {
            status: "approved".to_string(),
            request_id: id.to_string(),
            picto_id: Some(picto.id),
            message: format!(
                "approved {id}; minted exact-scope picto for {}",
                picto.scope
            ),
        },
    )
}

fn approval_deny(layout: HomeLayout, id: &str, reason: &str, json: bool) -> Result<ExitCode> {
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
    print_action(
        json,
        ApprovalActionReport {
            status: "denied".to_string(),
            request_id: id.to_string(),
            picto_id: None,
            message: format!("denied {id}"),
        },
    )
}

fn approval_webhook(
    layout: HomeLayout,
    url: &str,
    dry_run: bool,
    limit: Option<usize>,
    json: bool,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut pending = store.pending()?;
    if let Some(limit) = limit {
        pending.truncate(limit);
    }
    let mut report = WebhookReport {
        url: url.to_string(),
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
        let payload = webhook_payload(&state.request);
        if dry_run {
            if !json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            report.requests.push(WebhookRequestReport {
                id: state.request.id,
                status: "dry_run".to_string(),
                http_status: None,
                error: None,
            });
            continue;
        }
        match post_json_with_curl(url, &payload) {
            Ok(status) => {
                report.sent += 1;
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookDelivered {
                        id: state.request.id.clone(),
                        url: url.to_string(),
                        status: Some(status),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "sent".to_string(),
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
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "failed".to_string(),
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

fn webhook_payload(request: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({
        "kind": "gommage_approval_request",
        "id": request.id,
        "created_at": request.created_at,
        "tool": request.tool,
        "input_hash": request.input_hash,
        "required_scope": request.required_scope,
        "reason": request.reason,
        "capabilities": request.capabilities,
        "matched_rule": request.matched_rule,
        "policy_version": request.policy_version,
        "commands": {
            "approve": format!("gommage approval approve {}", request.id),
            "deny": format!("gommage approval deny {}", request.id)
        }
    })
}

fn post_json_with_curl(url: &str, payload: &serde_json::Value) -> Result<i32> {
    let mut child = Command::new("curl")
        .args([
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
            "--request",
            "POST",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting curl for approval webhook delivery")?;
    child
        .stdin
        .take()
        .context("opening curl stdin")?
        .write_all(serde_json::to_string(payload)?.as_bytes())?;
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
