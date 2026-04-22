use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gommage_audit::{AuditEvent, AuditWriter};
use gommage_core::{
    Decision, PictoConsume, PictoLookup, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, Runtime},
};
use std::{path::PathBuf, process::ExitCode};
use time::OffsetDateTime;

mod agent;
mod agent_status;
mod agent_uninstall;
mod audit_cmd;
mod daemon;
mod doctor;
mod input;
mod map;
mod mascot;
mod mcp;
mod policy_cmd;
mod quickstart;
mod quickstart_plan;
mod report;
mod smoke;
mod uninstall;
mod util;
mod verify;

use agent::{AgentCmd, AgentKind, cmd_agent};
use agent_uninstall::AgentUninstallTarget;
use audit_cmd::{AuditExplainFormat, cmd_audit_verify, cmd_explain, print_log};
use daemon::{DaemonCmd, ServiceManager, cmd_daemon};
use doctor::cmd_doctor;
use input::{evaluate_only, read_tool_call_from_stdin};
use map::cmd_map;
use mascot::{MascotOptions, print_mascot};
use mcp::run_mcp;
use policy_cmd::{PolicyCmd, cmd_policy};
use quickstart::{QuickstartOptions, cmd_quickstart};
use report::{ReportCmd, cmd_report};
use smoke::cmd_smoke;
use uninstall::{UninstallOptions, cmd_uninstall};
use verify::cmd_verify;

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

    /// One-command local setup: home, stdlib, native permission import, hooks.
    Quickstart {
        /// Agent integration to install. Defaults to claude.
        #[arg(long = "agent", value_enum)]
        agents: Vec<AgentKind>,
        /// Replace existing PreToolUse hook groups instead of preserving them.
        #[arg(long)]
        replace_hooks: bool,
        /// Skip importing native agent permission rules into Gommage policy.
        #[arg(long)]
        no_import_native_permissions: bool,
        /// Install and start the user-level daemon service as part of quickstart.
        #[arg(long)]
        daemon: bool,
        /// Service manager to use with --daemon. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        daemon_manager: Option<ServiceManager>,
        /// Replace an existing daemon service file when using --daemon.
        #[arg(long)]
        daemon_force: bool,
        /// Write the daemon service file without starting it. Implies --daemon.
        #[arg(long)]
        daemon_no_start: bool,
        /// Run the readiness gate after setup completes. Default; kept for scripts.
        #[arg(long)]
        self_test: bool,
        /// Skip the post-install readiness gate. Use only when recovering manually.
        #[arg(long, conflicts_with = "self_test")]
        no_self_test: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
        /// Emit a machine-readable dry-run plan. Requires --dry-run.
        #[arg(long, requires = "dry_run")]
        json: bool,
    },

    /// Install or inspect host-agent integrations.
    #[command(subcommand)]
    Agent(AgentCmd),

    /// Remove Gommage integrations and installed state.
    Uninstall {
        /// Agent integration to remove.
        #[arg(long, value_enum)]
        agent: Option<AgentUninstallTarget>,
        /// Stop/disable and remove the daemon user service.
        #[arg(long)]
        daemon: bool,
        /// Service manager to use with --daemon. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        daemon_manager: Option<ServiceManager>,
        /// Remove installed binaries from $GOMMAGE_BIN_DIR or ~/.local/bin.
        #[arg(long)]
        binaries: bool,
        /// Remove installed Codex and Claude Code skills.
        #[arg(long)]
        skills: bool,
        /// Remove the Gommage home directory selected by --home / $GOMMAGE_HOME.
        #[arg(long = "purge-home", visible_alias = "home-data")]
        purge_home: bool,
        /// Select agent=all, daemon, binaries, skills, and purge-home.
        #[arg(long)]
        all: bool,
        /// Restore the newest validated .gommage-bak-* agent config backup when available.
        #[arg(long)]
        restore_backup: bool,
        /// Show planned removals without mutating.
        #[arg(long)]
        dry_run: bool,
        /// Confirm destructive home removal.
        #[arg(long)]
        yes: bool,
    },

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
        /// TTL as seconds or duration suffix (s, m, h, d). Max 24h.
        #[arg(long, default_value = "600", value_parser = parse_ttl_seconds)]
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
    Explain {
        id: String,
        #[arg(long)]
        json: bool,
    },

    /// Verify the full audit log signature chain.
    #[command(name = "audit-verify")]
    AuditVerify {
        /// Produce a detailed forensic report instead of a simple count.
        /// Includes per-line signature verification, key fingerprint, policy
        /// version history, expeditions seen, and any anomalies (tamper, bad
        /// signature, timestamp out of order, mid-log policy change).
        #[arg(long)]
        explain: bool,
        /// Report format for --explain. Defaults to JSON for automation compatibility.
        #[arg(long, value_enum, requires = "explain")]
        format: Option<AuditExplainFormat>,
    },

    /// Evaluate a tool call JSON from stdin. Useful for tests and MCP adapters.
    Decide {
        #[arg(long)]
        pretty: bool,
        /// Read a PreToolUse hook payload (`tool_name` / `tool_input`) instead of a ToolCall.
        #[arg(long)]
        hook: bool,
    },

    /// Map a tool call JSON from stdin into capabilities without evaluating policy.
    Map {
        /// Emit a stable machine-readable mapper report.
        #[arg(long)]
        json: bool,
        /// Read a PreToolUse hook payload (`tool_name` / `tool_input`) instead of a ToolCall.
        #[arg(long)]
        hook: bool,
    },

    /// Diagnose the local Gommage installation and runtime state.
    Doctor {
        /// Emit a stable machine-readable diagnostic report.
        #[arg(long)]
        json: bool,
    },

    /// Run the full readiness gate: doctor, smoke, and optional policy fixtures.
    Verify {
        /// Emit a stable machine-readable verification report.
        #[arg(long)]
        json: bool,
        /// Include a repository-owned policy fixture file. Can be repeated.
        #[arg(long = "policy-test", value_name = "FILE")]
        policy_tests: Vec<PathBuf>,
    },

    /// Create diagnostic reports for support and issue triage.
    #[command(subcommand)]
    Report(ReportCmd),

    /// Run semantic policy smoke tests against the active home.
    Smoke {
        /// Emit a stable machine-readable smoke-test report.
        #[arg(long)]
        json: bool,
    },

    /// Print the Gommage terminal logo and Gestral signature.
    #[command(visible_alias = "logo")]
    Mascot {
        /// Disable ANSI color even when stdout is a terminal.
        #[arg(long)]
        plain: bool,
        /// Print a one-line signature.
        #[arg(long)]
        compact: bool,
    },

    /// Run the MCP / PreToolUse hook adapter (stdin → decision JSON on stdout).
    Mcp,

    /// Install, uninstall, or inspect the user-level daemon service.
    #[command(subcommand)]
    Daemon(DaemonCmd),
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
        Cmd::Quickstart {
            agents,
            replace_hooks,
            no_import_native_permissions,
            daemon,
            daemon_manager,
            daemon_force,
            daemon_no_start,
            self_test,
            no_self_test,
            dry_run,
            json,
        } => {
            return cmd_quickstart(
                layout,
                QuickstartOptions {
                    agents,
                    replace_hooks,
                    import_native_permissions: !no_import_native_permissions,
                    install_daemon: daemon || daemon_no_start,
                    daemon_manager,
                    daemon_force,
                    daemon_no_start,
                    self_test: self_test || !no_self_test,
                    dry_run,
                    json,
                },
            );
        }
        Cmd::Agent(sub) => return cmd_agent(sub, layout),
        Cmd::Uninstall {
            agent,
            daemon,
            daemon_manager,
            binaries,
            skills,
            purge_home,
            all,
            restore_backup,
            dry_run,
            yes,
        } => {
            return cmd_uninstall(
                layout,
                UninstallOptions {
                    agent,
                    daemon,
                    daemon_manager,
                    binaries,
                    skills,
                    purge_home,
                    all,
                    restore_backup,
                    dry_run,
                    yes,
                },
            );
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
            let rt = Runtime::open(HomeLayout::at(&layout.root)).context("opening runtime")?;
            let id = format!("picto_{}", uuid::Uuid::now_v7());
            let picto = rt
                .pictos
                .create(&id, &scope, uses, ttl, &reason, &sk, require_confirmation)
                .context("creating picto")?;
            let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
            writer.append_event(AuditEvent::PictoCreated {
                id: picto.id.clone(),
                scope: picto.scope.clone(),
                max_uses: picto.max_uses,
                ttl_expires_at: picto.ttl_expires_at.to_string(),
                require_confirmation,
            })?;
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
            let sk = layout.load_key()?;
            let rt = Runtime::open(HomeLayout::at(&layout.root))?;
            let ok = rt.pictos.revoke(&id)?;
            if ok {
                let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
                writer.append_event(AuditEvent::PictoRevoked { id: id.clone() })?;
                println!("revoked {id}");
            } else {
                println!("no active picto with id {id}");
                return Ok(ExitCode::from(1));
            }
        }
        Cmd::Confirm { id } => {
            let sk = layout.load_key()?;
            let rt = Runtime::open(HomeLayout::at(&layout.root))?;
            let ok = rt.pictos.confirm(&id)?;
            if ok {
                let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
                writer.append_event(AuditEvent::PictoConfirmed { id: id.clone() })?;
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
        Cmd::Explain { id, json } => return cmd_explain(layout, &id, json),
        Cmd::AuditVerify { explain, format } => return cmd_audit_verify(layout, explain, format),
        Cmd::Decide { pretty, hook } => {
            let call = read_tool_call_from_stdin(hook)?;
            let rt = Runtime::open(layout)?;
            let eval = evaluate_only(&rt, &call);
            let out = if pretty {
                serde_json::to_string_pretty(&eval)?
            } else {
                serde_json::to_string(&eval)?
            };
            println!("{out}");
        }
        Cmd::Map { json, hook } => return cmd_map(layout, json, hook),
        Cmd::Doctor { json } => return cmd_doctor(layout, json),
        Cmd::Verify { json, policy_tests } => return cmd_verify(layout, json, policy_tests),
        Cmd::Report(sub) => return cmd_report(sub, layout),
        Cmd::Smoke { json } => return cmd_smoke(layout, json),
        Cmd::Mascot { plain, compact } => {
            print_mascot(MascotOptions { plain, compact });
        }
        Cmd::Mcp => return run_mcp(layout),
        Cmd::Daemon(sub) => return cmd_daemon(sub, layout),
    }
    Ok(ExitCode::SUCCESS)
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

pub(crate) fn decide_with_pictos(
    rt: &Runtime,
    call: &ToolCall,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(gommage_core::EvalResult, Vec<AuditEvent>)> {
    let caps = rt.mapper.map(call);
    let mut eval = evaluate(&caps, &rt.policy);
    let mut events = Vec::new();
    if let Decision::AskPicto { required_scope, .. } = eval.decision.clone() {
        let now = OffsetDateTime::now_utc();
        match rt
            .pictos
            .find_verified_match(&required_scope, now, verifying_key)?
        {
            PictoLookup::None => {}
            PictoLookup::BadSignature { id, scope } => {
                events.push(AuditEvent::PictoRejected {
                    id,
                    scope,
                    reason: "bad signature".to_string(),
                });
            }
            PictoLookup::Verified { picto } => {
                match rt.pictos.consume_verified(&picto.id, now, verifying_key)? {
                    PictoConsume::Consumed { picto } => {
                        events.push(AuditEvent::PictoConsumed {
                            id: picto.id,
                            scope: picto.scope,
                            uses: picto.uses,
                            max_uses: picto.max_uses,
                            status: picto.status.as_str().to_string(),
                        });
                        eval.decision = Decision::Allow;
                    }
                    PictoConsume::NotUsable => {}
                    PictoConsume::BadSignature { id, scope } => {
                        events.push(AuditEvent::PictoRejected {
                            id,
                            scope,
                            reason: "bad signature".to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok((eval, events))
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
