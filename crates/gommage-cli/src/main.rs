use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use gommage_audit::{AuditWriter, verify_log};
use gommage_core::{
    Decision, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, Runtime},
};
use std::{
    io::{self, Read},
    path::PathBuf,
    process::ExitCode,
};
use time::OffsetDateTime;

#[derive(Parser)]
#[command(
    name = "gommage",
    about = "Policy-as-code for AI coding agents. Zero heuristics. You own the rules.",
    version
)]
struct Cli {
    /// Override the Gommage home directory (default: ~/.gommage or $GOMMAGE_HOME).
    #[arg(long, global = true, env = "GOMMAGE_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize ~/.gommage (create layout, generate keypair).
    Init,

    /// Start a new expedition (task context).
    #[command(subcommand)]
    Expedition(ExpeditionCmd),

    /// Manage pictos (signed grants).
    #[command(alias = "g")]
    Grant {
        #[arg(long)]
        scope: String,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// TTL in seconds. Max 86400 (24h).
        #[arg(long, default_value_t = 600)]
        ttl: i64,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long)]
        require_confirmation: bool,
    },

    /// List pictos.
    List {
        #[arg(long)]
        json: bool,
    },

    /// Revoke a picto by id.
    Revoke { id: String },

    /// Confirm a pending picto.
    Confirm { id: String },

    /// Check a policy file or directory.
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Tail the audit log.
    Tail {
        /// Follow mode — keep reading new entries.
        #[arg(short, long)]
        follow: bool,
    },

    /// Explain a past audit entry by id.
    Explain { id: String },

    /// Verify the full audit log signature chain.
    #[command(name = "audit-verify")]
    AuditVerify,

    /// Evaluate a tool call JSON from stdin. Useful for tests and MCP adapters.
    Decide {
        #[arg(long)]
        pretty: bool,
    },

    /// Run the MCP / PreToolUse hook adapter (stdin → decision JSON on stdout).
    Mcp,

    /// Run the daemon in the foreground (delegates to gommage-daemon binary).
    Daemon {
        #[arg(long)]
        foreground: bool,
    },
}

#[derive(Subcommand)]
enum ExpeditionCmd {
    /// Start an expedition with a name. Current working directory is the root.
    Start {
        name: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// End the current expedition.
    End,
    /// Show the current expedition.
    Status,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Parse and compile every policy file under policy.d/.
    Check,
    /// Parse a single file.
    Lint { file: PathBuf },
    /// Print the policy version hash.
    Hash,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let layout = match &cli.home {
        Some(p) => HomeLayout::at(p),
        None => HomeLayout::default(),
    };

    match run(cli.command, layout) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gommage: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cmd: Cmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        Cmd::Init => {
            layout.ensure().context("initializing home")?;
            println!("ok ~/.gommage initialized at {}", layout.root.display());
        }
        Cmd::Expedition(sub) => return cmd_expedition(sub, layout),
        Cmd::Grant {
            scope,
            uses,
            ttl,
            reason,
            require_confirmation,
        } => {
            layout.ensure()?;
            let sk = layout.load_key()?;
            let rt = Runtime::open(layout).context("opening runtime")?;
            let id = format!("picto_{}", uuid::Uuid::now_v7());
            let picto = rt
                .pictos
                .create(&id, &scope, uses, ttl, &reason, &sk, require_confirmation)
                .context("creating picto")?;
            println!("granted {}", picto.id);
            println!("  scope:   {}", picto.scope);
            println!("  uses:    {}/{}", picto.uses, picto.max_uses);
            println!("  expires: {}", picto.ttl_expires_at);
            if require_confirmation {
                println!(
                    "  status:  pending confirmation — run `gommage confirm {}` to activate",
                    picto.id
                );
            }
        }
        Cmd::List { json } => {
            let rt = Runtime::open(layout)?;
            let pictos = rt.pictos.list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&pictos)?);
            } else if pictos.is_empty() {
                println!("no pictos");
            } else {
                for p in pictos {
                    println!(
                        "{} [{:?}] scope={} uses={}/{} ttl={} reason={:?}",
                        p.id, p.status, p.scope, p.uses, p.max_uses, p.ttl_expires_at, p.reason
                    );
                }
            }
        }
        Cmd::Revoke { id } => {
            let rt = Runtime::open(layout)?;
            let ok = rt.pictos.revoke(&id)?;
            if ok {
                println!("revoked {id}");
            } else {
                println!("no active picto with id {id}");
                return Ok(ExitCode::from(1));
            }
        }
        Cmd::Confirm { id } => {
            let rt = Runtime::open(layout)?;
            let ok = rt.pictos.confirm(&id)?;
            if ok {
                println!("activated {id}");
            } else {
                println!("no pending-confirmation picto with id {id}");
                return Ok(ExitCode::from(1));
            }
        }
        Cmd::Policy(sub) => return cmd_policy(sub, layout),
        Cmd::Tail { follow } => {
            use std::io::{BufRead, BufReader};
            let path = layout.audit_log.clone();
            let (start, _) = if follow {
                // naive follow: print existing then poll the file size.
                print_log(&path)?;
                println!("-- tailing {} --", path.display());
                (std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0), ())
            } else {
                return print_log(&path).map(|_| ExitCode::SUCCESS);
            };
            let mut offset = start;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let Ok(md) = std::fs::metadata(&path) else {
                    continue;
                };
                if md.len() > offset {
                    let mut f = std::fs::File::open(&path)?;
                    use std::io::Seek as _;
                    f.seek(std::io::SeekFrom::Start(offset))?;
                    let rdr = BufReader::new(f);
                    for line in rdr.lines() {
                        println!("{}", line?);
                    }
                    offset = md.len();
                }
            }
        }
        Cmd::Explain { id } => {
            use std::io::{BufRead, BufReader};
            let file = std::fs::File::open(&layout.audit_log).context("opening audit log")?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.contains(&id) {
                    println!("{}", line);
                    return Ok(ExitCode::SUCCESS);
                }
            }
            eprintln!("no audit entry with id {id}");
            return Ok(ExitCode::from(1));
        }
        Cmd::AuditVerify => {
            let vk = layout.load_verifying_key()?;
            let n = verify_log(&layout.audit_log, &vk).context("verifying audit log")?;
            println!("ok {n} entries verified");
        }
        Cmd::Decide { pretty } => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            let call: ToolCall = serde_json::from_str(&buf).context("parsing stdin as ToolCall")?;
            let rt = Runtime::open(layout)?;
            let eval = decide(&rt, &call)?;
            let out = if pretty {
                serde_json::to_string_pretty(&eval)?
            } else {
                serde_json::to_string(&eval)?
            };
            println!("{out}");
        }
        Cmd::Mcp => return run_mcp(layout),
        Cmd::Daemon { foreground } => {
            if foreground {
                eprintln!(
                    "gommage: daemon is implemented in gommage-daemon; run `gommage-daemon --foreground`"
                );
                return Ok(ExitCode::from(1));
            }
            eprintln!("gommage: use the `gommage-daemon` binary for now");
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn decide(rt: &Runtime, call: &ToolCall) -> Result<gommage_core::EvalResult> {
    let caps = rt.mapper.map(call);
    let mut eval = evaluate(&caps, &rt.policy);
    // If the decision is AskPicto, check the store for a matching picto.
    if let Decision::AskPicto { required_scope, .. } = eval.decision.clone()
        && let Some(p) = rt
            .pictos
            .find_match(&required_scope, OffsetDateTime::now_utc())?
        && rt.pictos.consume(&p.id)?
    {
        eval.decision = Decision::Allow;
    }
    Ok(eval)
}

fn cmd_expedition(sub: ExpeditionCmd, layout: HomeLayout) -> Result<ExitCode> {
    layout.ensure()?;
    match sub {
        ExpeditionCmd::Start { name, root } => {
            let root = root
                .map(Ok::<_, anyhow::Error>)
                .unwrap_or_else(|| Ok(std::env::current_dir()?))?;
            let exp = Expedition {
                name: name.clone(),
                root,
                started_at: OffsetDateTime::now_utc(),
            };
            exp.save(&layout.expedition_file)?;
            println!("started expedition {} at {}", exp.name, exp.root.display());
        }
        ExpeditionCmd::End => {
            if Expedition::load(&layout.expedition_file)?.is_some() {
                Expedition::clear(&layout.expedition_file)?;
                println!("expedition ended");
            } else {
                println!("no active expedition");
            }
        }
        ExpeditionCmd::Status => match Expedition::load(&layout.expedition_file)? {
            None => println!("no active expedition"),
            Some(exp) => {
                println!("active: {}", exp.name);
                println!("  root:    {}", exp.root.display());
                println!("  started: {}", exp.started_at);
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_policy(sub: PolicyCmd, layout: HomeLayout) -> Result<ExitCode> {
    layout.ensure()?;
    let env = Expedition::load(&layout.expedition_file)?
        .map(|e| e.policy_env())
        .unwrap_or_default();
    match sub {
        PolicyCmd::Check => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("ok {} rules loaded", pol.rules.len());
            println!("version: {}", pol.version_hash);
        }
        PolicyCmd::Lint { file } => {
            let raw = std::fs::read_to_string(&file)?;
            let _ = Policy::from_yaml_string(&raw, &env, &file.to_string_lossy())?;
            println!("ok {}", file.display());
        }
        PolicyCmd::Hash => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("{}", pol.version_hash);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_log(path: &std::path::Path) -> Result<()> {
    use std::io::{BufRead, BufReader};
    if !path.exists() {
        println!("(no audit log yet at {})", path.display());
        return Ok(());
    }
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        println!("{}", line?);
    }
    Ok(())
}

/// MCP / PreToolUse hook adapter. Reads one Claude Code hook JSON object from
/// stdin and writes one hook response JSON object to stdout.
///
/// Input shape (Claude Code):
/// ```json
/// { "session_id": "...", "hook_event_name": "PreToolUse",
///   "tool_name": "Bash", "tool_input": { "command": "git push origin main" } }
/// ```
/// Output shape:
/// ```json
/// { "hookSpecificOutput": { "hookEventName": "PreToolUse",
///   "permissionDecision": "allow" | "deny" | "ask",
///   "permissionDecisionReason": "..." } }
/// ```
fn run_mcp(layout: HomeLayout) -> Result<ExitCode> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    let input: serde_json::Value = serde_json::from_str(&buf).context("parsing hook input")?;
    let tool_name = input
        .get("tool_name")
        .and_then(|v| v.as_str())
        .context("missing tool_name")?;
    let tool_input = input
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let call = ToolCall {
        tool: tool_name.to_string(),
        input: tool_input,
    };

    let sk: SigningKey = layout.load_key()?;
    let mut rt = Runtime::open(layout.clone_layout())?;
    let eval = decide(&rt, &call)?;

    // Append to audit log (signed).
    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
    let _entry = writer.append(&call, &eval, expedition_name.as_deref())?;

    // Drop writer so file flushes.
    drop(writer);
    let _ = &mut rt; // silence unused warning

    let (decision_str, reason) = match &eval.decision {
        Decision::Allow => ("allow", "gommage allowed".to_string()),
        Decision::Gommage { reason, hard_stop } => (
            "deny",
            if *hard_stop {
                format!("gommaged (hard-stop): {reason}")
            } else {
                format!("gommaged: {reason}")
            },
        ),
        Decision::AskPicto {
            reason,
            required_scope,
        } => (
            "ask",
            format!("gommage: requires picto scope {required_scope:?} — {reason}"),
        ),
    };
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision_str,
            "permissionDecisionReason": reason,
        }
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(ExitCode::SUCCESS)
}

// Tiny shim to avoid moving `layout` twice in `run_mcp`.
trait CloneLayout {
    fn clone_layout(&self) -> HomeLayout;
}
impl CloneLayout for HomeLayout {
    fn clone_layout(&self) -> HomeLayout {
        HomeLayout::at(&self.root)
    }
}
