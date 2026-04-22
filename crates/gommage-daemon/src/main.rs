//! gommage-daemon — Unix socket listener that proxies tool calls through the
//! policy engine and into the audit log.
//!
//! Wire protocol: line-delimited JSON. One request per line; one response per
//! line. Requests and responses both fit well under a single TCP segment, so
//! there is no framing beyond `\n`.
//!
//! Example request:  `{"op":"decide","call":{"tool":"Bash","input":{"command":"ls"}}}`
//! Example response: `{"ok":true,"result":{...EvalResult...}}`

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    ApprovalRequest, Decision, PictoConsume, PictoLookup, ToolCall, evaluate,
    runtime::{HomeLayout, Runtime},
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    sync::Mutex,
};

#[derive(Parser)]
#[command(name = "gommage-daemon", version)]
struct Args {
    #[arg(long, env = "GOMMAGE_HOME")]
    home: Option<PathBuf>,
    /// Run in foreground (log to stderr, no detach). For v0.1 this is the only mode.
    #[arg(long, default_value_t = true)]
    foreground: bool,
    /// Override the socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// Evaluate a tool call.
    Decide { call: ToolCall },
    /// Force-reload policy + capability mappers from disk.
    Reload,
    /// Ping.
    Ping,
}

#[derive(Debug, Serialize)]
struct Response<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let layout = match &args.home {
        Some(p) => HomeLayout::at(p),
        None => HomeLayout::default(),
    };
    layout.ensure().context("initializing gommage home")?;
    let sk = layout.load_key().context("loading signing key")?;
    let verifying_key = sk.verifying_key();

    let rt = Runtime::open(HomeLayout::at(&layout.root)).context("opening runtime")?;
    let audit_path = layout.audit_log.clone();
    let writer = AuditWriter::open(&audit_path, sk)?;

    let socket_path = args.socket.unwrap_or_else(|| layout.socket.clone());
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }
    let listener = UnixListener::bind(&socket_path).context("binding socket")?;
    tracing::info!(
        ?socket_path,
        rules = rt.policy.rules.len(),
        "gommage daemon listening"
    );

    let shared = Arc::new(Mutex::new(State {
        rt,
        writer,
        verifying_key,
        home_root: layout.root.clone(),
    }));

    // SIGHUP → reload policy + capability mappers. Standard Unix convention
    // for long-running daemons; no restart required after editing
    // `~/.gommage/policy.d/*.yaml`.
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    // SIGTERM / SIGINT → graceful shutdown. We don't hold any state that
    // needs flushing beyond the audit log (which flushes on every append),
    // so returning from main is enough.
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _addr) = accept?;
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, shared).await {
                        tracing::warn!(?e, "connection error");
                    }
                });
            }
            _ = sighup.recv() => {
                let mut s = shared.lock().await;
                match s.rt.reload_policy() {
                    Ok(()) => {
                        let rules = s.rt.policy.rules.len();
                        let mapper_rules = s.rt.mapper.rule_count();
                        let policy_version = s.rt.policy.version_hash.clone();
                        if let Err(e) = s.writer.append_event(AuditEvent::PolicyReloaded {
                            source: "sighup".to_string(),
                            rules,
                            mapper_rules,
                            policy_version: policy_version.clone(),
                        }) {
                            tracing::error!(?e, "failed to audit SIGHUP reload");
                        }
                        tracing::info!(
                            rules,
                            version = %policy_version,
                            "policy reloaded via SIGHUP"
                        )
                    },
                    Err(e) => tracing::error!(?e, "SIGHUP reload failed; keeping previous policy"),
                }
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
        }
    }
    Ok(())
}

struct State {
    rt: Runtime,
    writer: AuditWriter,
    verifying_key: VerifyingKey,
    home_root: PathBuf,
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    shared: Arc<Mutex<State>>,
) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(req, &shared).await,
            Err(e) => serde_json::to_string(&Response::<()> {
                ok: false,
                result: None,
                error: Some(format!("bad request: {e}")),
            })?,
        };
        w.write_all(response.as_bytes()).await?;
        w.write_all(b"\n").await?;
    }
    Ok(())
}

async fn handle_request(req: Request, shared: &Arc<Mutex<State>>) -> String {
    match req {
        Request::Ping => ok(&"pong"),
        Request::Reload => {
            let mut s = shared.lock().await;
            match s.rt.reload_policy() {
                Ok(()) => {
                    let rules = s.rt.policy.rules.len();
                    let mapper_rules = s.rt.mapper.rule_count();
                    let policy_version = s.rt.policy.version_hash.clone();
                    match s.writer.append_event(AuditEvent::PolicyReloaded {
                        source: "ipc".to_string(),
                        rules,
                        mapper_rules,
                        policy_version,
                    }) {
                        Ok(_) => ok(&format!("reloaded {rules} rules")),
                        Err(e) => err(format!("reload audited failed: {e}")),
                    }
                }
                Err(e) => err(format!("reload failed: {e}")),
            }
        }
        Request::Decide { call } => {
            let mut s = shared.lock().await;
            match decide_and_audit(&mut s, &call) {
                Ok(eval) => ok(&eval),
                Err(e) => err(format!("decide failed: {e}")),
            }
        }
    }
}

fn decide_and_audit(s: &mut State, call: &ToolCall) -> Result<gommage_core::EvalResult> {
    let caps = s.rt.mapper.map(call);
    let mut eval = evaluate(&caps, &s.rt.policy);

    if let Decision::AskPicto {
        required_scope,
        reason,
    } = eval.decision.clone()
    {
        let now = OffsetDateTime::now_utc();
        match s
            .rt
            .pictos
            .find_verified_match(&required_scope, now, &s.verifying_key)?
        {
            PictoLookup::None => {
                let request =
                    s.rt.approvals
                        .request_for_ask(call, &eval, &required_scope, &reason)?;
                s.writer.append_event(AuditEvent::ApprovalRequested {
                    id: request.id.clone(),
                    tool: request.tool.clone(),
                    input_hash: request.input_hash.clone(),
                    required_scope: request.required_scope.clone(),
                    reason: request.reason.clone(),
                    policy_version: request.policy_version.clone(),
                })?;
                notify_approval_webhook_best_effort(&mut s.writer, &request);
                eval.decision = Decision::AskPicto {
                    required_scope,
                    reason: approval_reason(&reason, &request.id),
                };
            }
            PictoLookup::BadSignature { id, scope } => {
                s.writer.append_event(AuditEvent::PictoRejected {
                    id,
                    scope,
                    reason: "bad signature".to_string(),
                })?;
            }
            PictoLookup::Verified { picto } => {
                match s
                    .rt
                    .pictos
                    .consume_verified(&picto.id, now, &s.verifying_key)?
                {
                    PictoConsume::Consumed { picto } => {
                        s.writer.append_event(AuditEvent::PictoConsumed {
                            id: picto.id,
                            scope: picto.scope,
                            uses: picto.uses,
                            max_uses: picto.max_uses,
                            status: picto.status.as_str().to_string(),
                        })?;
                        eval.decision = Decision::Allow;
                    }
                    PictoConsume::NotUsable => {}
                    PictoConsume::BadSignature { id, scope } => {
                        s.writer.append_event(AuditEvent::PictoRejected {
                            id,
                            scope,
                            reason: "bad signature".to_string(),
                        })?;
                    }
                }
            }
        }
    }

    let expedition_name = s.rt.expedition.as_ref().map(|e| e.name.clone());
    s.writer.append(call, &eval, expedition_name.as_deref())?;
    // touch home_root to silence dead-code lint and document the field's purpose.
    let _ = &s.home_root;
    Ok(eval)
}

fn approval_reason(reason: &str, request_id: &str) -> String {
    format!(
        "{reason}; approval request {request_id} pending; run `gommage approval approve {request_id}`"
    )
}

fn notify_approval_webhook_best_effort(writer: &mut AuditWriter, request: &ApprovalRequest) {
    let Ok(url) = env::var("GOMMAGE_APPROVAL_WEBHOOK_URL") else {
        return;
    };
    if url.trim().is_empty() {
        return;
    }
    match post_approval_json(&url, request) {
        Ok(status) => {
            if let Err(error) = writer.append_event(AuditEvent::ApprovalWebhookDelivered {
                id: request.id.clone(),
                url,
                status: Some(status),
            }) {
                tracing::warn!(?error, "failed to audit approval webhook delivery");
            }
        }
        Err(error) => {
            if let Err(audit_error) = writer.append_event(AuditEvent::ApprovalWebhookFailed {
                id: request.id.clone(),
                url,
                error: error.to_string(),
            }) {
                tracing::warn!(?audit_error, "failed to audit approval webhook failure");
            }
        }
    }
}

fn post_approval_json(url: &str, request: &ApprovalRequest) -> Result<i32> {
    let payload = serde_json::json!({
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
    });
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
        .write_all(serde_json::to_string(&payload)?.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .unwrap_or(0))
}

fn ok<T: Serialize>(v: &T) -> String {
    serde_json::to_string(&Response {
        ok: true,
        result: Some(v),
        error: None,
    })
    .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialize\"}".into())
}

fn err(msg: String) -> String {
    serde_json::to_string(&Response::<()> {
        ok: false,
        result: None,
        error: Some(msg),
    })
    .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialize\"}".into())
}
