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
use gommage_audit::AuditWriter;
use gommage_core::{
    Decision, ToolCall, evaluate,
    runtime::{HomeLayout, Runtime},
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
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
        home_root: layout.root.clone(),
    }));

    loop {
        let (stream, _addr) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, shared).await {
                tracing::warn!(?e, "connection error");
            }
        });
    }
}

struct State {
    rt: Runtime,
    writer: AuditWriter,
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
                Ok(()) => ok(&format!("reloaded {} rules", s.rt.policy.rules.len())),
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

    if let Decision::AskPicto { required_scope, .. } = eval.decision.clone()
        && let Some(p) = s.rt.pictos.find_match(&required_scope, OffsetDateTime::now_utc())?
        && s.rt.pictos.consume(&p.id)?
    {
        eval.decision = Decision::Allow;
    }

    let expedition_name = s.rt.expedition.as_ref().map(|e| e.name.clone());
    s.writer.append(call, &eval, expedition_name.as_deref())?;
    // touch home_root to silence dead-code lint and document the field's purpose.
    let _ = &s.home_root;
    Ok(eval)
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
