use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use gommage_audit::{
    Anomaly, AuditEntry, AuditEvent, AuditEventEntry, AuditWriter,
    VerifyReport as AuditVerifyReport, verify_log,
};
use gommage_core::{
    Capability, Decision, MatchedRule, PictoConsume, PictoLookup, Policy, ToolCall, evaluate,
    runtime::{Expedition, HomeLayout, Runtime, default_policy_env},
};
use gommage_stdlib::{
    CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES, StdlibFile,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
use time::OffsetDateTime;

mod agent;
mod util;

use agent::{AgentCmd, AgentKind, cmd_agent, install_agent};
use util::{env_path_or_home, path_details, path_display, write_text};

const POLICY_FIXTURE_SCHEMA: &str = include_str!("../schemas/policy-fixture.schema.json");

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
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },

    /// Install or inspect host-agent integrations.
    #[command(subcommand)]
    Agent(AgentCmd),

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

#[derive(Subcommand)]
enum PolicyCmd {
    /// Initialize policy.d/ and capabilities.d/ from the embedded stdlib.
    Init {
        #[arg(long)]
        stdlib: bool,
        #[arg(long)]
        force: bool,
    },
    /// Parse and compile every policy file under policy.d/.
    Check,
    /// Parse a single file.
    Lint { file: PathBuf },
    /// Print the JSON Schema for policy test fixture files.
    Schema,
    /// Run YAML policy regression fixtures against the active home.
    Test {
        file: PathBuf,
        /// Emit a stable machine-readable fixture report.
        #[arg(long)]
        json: bool,
    },
    /// Capture a tool call from stdin as a YAML policy fixture.
    #[command(alias = "capture")]
    Snapshot {
        /// Stable fixture case name to write into the YAML output.
        #[arg(long)]
        name: String,
        /// Optional human-readable fixture description.
        #[arg(long)]
        description: Option<String>,
        /// Emit only the YAML case list, useful when appending to an existing file.
        #[arg(long)]
        case_only: bool,
        /// Read a PreToolUse hook payload (`tool_name` / `tool_input`) instead of a ToolCall.
        #[arg(long)]
        hook: bool,
    },
    /// Print the policy version hash.
    Hash,
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Install the daemon as a user service.
    Install {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
        /// Replace an existing service file.
        #[arg(long)]
        force: bool,
        /// Write the service file but do not start/enable it.
        #[arg(long)]
        no_start: bool,
        /// Show planned file edits and commands without writing or starting.
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall the user service and remove its service file.
    Uninstall {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
        /// Show planned file edits and commands without removing or stopping.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show daemon service status.
    Status {
        /// Service manager to target. Defaults to launchd on macOS and systemd on Linux.
        #[arg(long, value_enum)]
        manager: Option<ServiceManager>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ServiceManager {
    Launchd,
    Systemd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AuditExplainFormat {
    Json,
    Human,
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
            dry_run,
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
                    dry_run,
                },
            );
        }
        Cmd::Agent(sub) => return cmd_agent(sub, layout),
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
            let rt = Runtime::open(layout.clone_layout()).context("opening runtime")?;
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
            let rt = Runtime::open(layout.clone_layout())?;
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
            let rt = Runtime::open(layout.clone_layout())?;
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
        Cmd::AuditVerify { explain, format } => {
            let vk = layout.load_verifying_key()?;
            if explain {
                let report = gommage_audit::explain_log(&layout.audit_log, &vk)
                    .context("explaining audit log")?;
                match format.unwrap_or(AuditExplainFormat::Json) {
                    AuditExplainFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                    AuditExplainFormat::Human => print_audit_verify_report(&report),
                }
                if !report.anomalies.is_empty() {
                    return Ok(ExitCode::from(1));
                }
            } else {
                let n = verify_log(&layout.audit_log, &vk).context("verifying audit log")?;
                println!("ok {n} entries verified");
            }
        }
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
        Cmd::Smoke { json } => return cmd_smoke(layout, json),
        Cmd::Mascot { plain, compact } => {
            print_mascot(MascotOptions { plain, compact });
        }
        Cmd::Mcp => return run_mcp(layout),
        Cmd::Daemon(sub) => return cmd_daemon(sub, layout),
    }
    Ok(ExitCode::SUCCESS)
}

struct QuickstartOptions {
    agents: Vec<AgentKind>,
    replace_hooks: bool,
    import_native_permissions: bool,
    install_daemon: bool,
    daemon_manager: Option<ServiceManager>,
    daemon_force: bool,
    daemon_no_start: bool,
    dry_run: bool,
}

struct MascotOptions {
    plain: bool,
    compact: bool,
}

const GOMMAGE_TEAL: &str = "\x1b[38;2;0;179;164m";
const GOMMAGE_GOLD: &str = "\x1b[38;2;242;201;76m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RESET: &str = "\x1b[0m";
const GOMMAGE_LOGO_LINES: &[&str] = &[
    "  ██████╗  ██████╗ ███╗   ███╗███╗   ███╗ █████╗  ██████╗ ███████╗",
    " ██╔════╝ ██╔═══██╗████╗ ████║████╗ ████║██╔══██╗██╔════╝ ██╔════╝",
    " ██║  ███╗██║   ██║██╔████╔██║██╔████╔██║███████║██║  ███╗█████╗",
    " ██║   ██║██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝",
    " ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗",
    "  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
];

fn print_mascot(options: MascotOptions) {
    let color = mascot_color_enabled(options.plain);
    if options.compact {
        println!("{}", mascot_compact(color));
        return;
    }

    for line in mascot_full(color) {
        println!("{line}");
    }
}

fn mascot_color_enabled(plain: bool) -> bool {
    !plain && env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal()
}

fn paint(text: &str, style: &str, color: bool) -> String {
    if color {
        format!("{style}{text}{ANSI_RESET}")
    } else {
        text.to_owned()
    }
}

fn mascot_compact(color: bool) -> String {
    format!(
        "{} {} {}",
        paint("[Gestral]", GOMMAGE_TEAL, color),
        paint("GOMMAGE policy sentinel", ANSI_BOLD, color),
        paint("tool call -> capabilities -> signed audit", ANSI_DIM, color)
    )
}

fn mascot_full(color: bool) -> Vec<String> {
    let gold = |text: &str| paint(text, GOMMAGE_GOLD, color);
    let bold = |text: &str| paint(text, ANSI_BOLD, color);
    let dim = |text: &str| paint(text, ANSI_DIM, color);

    let mut lines = Vec::new();
    lines.push(format!(
        "{} {} {}",
        bold("Gommage"),
        dim(format!("v{}", env!("CARGO_PKG_VERSION")).as_str()),
        gold("Gestral signature")
    ));
    lines.push(dim("policy decisions with a signed trail"));
    lines.push(String::new());
    for logo_line in GOMMAGE_LOGO_LINES {
        lines.push(gradient_line(logo_line, color));
    }
    lines.extend([
        String::new(),
        format!(
            "        {} {}",
            gold("Gommage Gestral"),
            dim("| policy sentinel")
        ),
        format!(
            "        {} {}",
            bold("Loop:"),
            "tool call -> typed capabilities -> signed audit"
        ),
        format!(
            "        {} {} {} {}",
            bold("Colors:"),
            "Gommage Teal #00B3A4",
            dim("+"),
            gold("Picto Gold #F2C94C")
        ),
        format!("        {} {}", bold("Next:"), "gommage doctor --json"),
    ]);
    lines
}

fn gradient_line(line: &str, color: bool) -> String {
    if !color {
        return line.to_owned();
    }

    let chars: Vec<char> = line.chars().collect();
    let width = chars.len().saturating_sub(1).max(1);
    let mut out = String::new();
    for (index, ch) in chars.iter().enumerate() {
        if ch.is_whitespace() {
            out.push(*ch);
            continue;
        }
        let (r, g, b) = logo_gradient(index, width);
        out.push_str(&format!("\x1b[38;2;{r};{g};{b}m{ch}{ANSI_RESET}"));
    }
    out
}

fn logo_gradient(index: usize, width: usize) -> (u8, u8, u8) {
    const TEAL: (u8, u8, u8) = (0, 179, 164);
    const GOLD: (u8, u8, u8) = (242, 201, 76);
    let numerator = index as u32;
    let denominator = width as u32;
    (
        interpolate_channel(TEAL.0, GOLD.0, numerator, denominator),
        interpolate_channel(TEAL.1, GOLD.1, numerator, denominator),
        interpolate_channel(TEAL.2, GOLD.2, numerator, denominator),
    )
}

fn interpolate_channel(start: u8, end: u8, numerator: u32, denominator: u32) -> u8 {
    let start = start as i32;
    let end = end as i32;
    let delta = end - start;
    (start + (delta * numerator as i32 / denominator as i32)) as u8
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

fn evaluate_only(rt: &Runtime, call: &ToolCall) -> gommage_core::EvalResult {
    let caps = rt.mapper.map(call);
    evaluate(&caps, &rt.policy)
}

fn read_tool_call_from_stdin(hook: bool) -> Result<ToolCall> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    if hook {
        let input: serde_json::Value =
            serde_json::from_str(&buf).context("parsing stdin as hook payload")?;
        tool_call_from_hook_payload(input)
    } else {
        serde_json::from_str(&buf).context("parsing stdin as ToolCall")
    }
}

fn tool_call_from_hook_payload(input: serde_json::Value) -> Result<ToolCall> {
    let tool_name = input
        .get("tool_name")
        .and_then(|v| v.as_str())
        .context("missing tool_name")?;
    let tool_input = input
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cwd = input.get("cwd").and_then(|v| v.as_str());
    Ok(ToolCall {
        tool: tool_name.to_string(),
        input: enrich_hook_tool_input(tool_name, tool_input, cwd),
    })
}

#[derive(Debug, Serialize)]
struct MapReport {
    input_hash: String,
    tool: String,
    capabilities_dir: String,
    mapper_rules: usize,
    capabilities: Vec<Capability>,
}

fn build_map_report(layout: &HomeLayout, call: ToolCall) -> Result<MapReport> {
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers")?;
    let capabilities = mapper.map(&call);
    Ok(MapReport {
        input_hash: call.input_hash(),
        tool: call.tool,
        capabilities_dir: path_display(&layout.capabilities_dir),
        mapper_rules: mapper.rule_count(),
        capabilities,
    })
}

fn cmd_map(layout: HomeLayout, json: bool, hook: bool) -> Result<ExitCode> {
    let call = read_tool_call_from_stdin(hook)?;
    let report = build_map_report(&layout, call)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_map_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_map_report(report: &MapReport) {
    println!("input_hash: {}", report.input_hash);
    println!("tool: {}", report.tool);
    println!("capabilities_dir: {}", report.capabilities_dir);
    println!("mapper_rules: {}", report.mapper_rules);
    if report.capabilities.is_empty() {
        println!("capabilities: none");
    } else {
        println!("capabilities:");
        for capability in &report.capabilities {
            println!("- {capability}");
        }
    }
}

fn decide_with_pictos(
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

fn cmd_smoke(layout: HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_smoke_report(&layout)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_smoke_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SmokeStatus {
    Pass,
    Fail,
}

impl SmokeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
struct SmokeReport {
    status: SmokeStatus,
    home: String,
    policy_version: String,
    mapper_rules: usize,
    summary: SmokeSummary,
    checks: Vec<SmokeCheck>,
}

impl SmokeReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.failed == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct SmokeSummary {
    passed: usize,
    failed: usize,
}

#[derive(Debug, Serialize)]
struct SmokeCheck {
    name: &'static str,
    description: &'static str,
    status: SmokeStatus,
    expected: String,
    actual: Decision,
    tool: String,
    input: serde_json::Value,
    input_hash: String,
    capabilities: Vec<Capability>,
    matched_rule: Option<MatchedRule>,
}

struct SmokeFixture {
    name: &'static str,
    description: &'static str,
    call: ToolCall,
    expectation: SmokeExpectation,
}

enum SmokeExpectation {
    Allow,
    Gommage { hard_stop: Option<bool> },
    AskPicto { scope: &'static str },
}

impl SmokeExpectation {
    fn label(&self) -> String {
        match self {
            Self::Allow => "allow".to_string(),
            Self::Gommage {
                hard_stop: Some(value),
            } => format!("gommage hard_stop={value}"),
            Self::Gommage { hard_stop: None } => "gommage".to_string(),
            Self::AskPicto { scope } => format!("ask_picto scope={scope}"),
        }
    }

    fn matches(&self, decision: &Decision) -> bool {
        match (self, decision) {
            (Self::Allow, Decision::Allow) => true,
            (
                Self::Gommage {
                    hard_stop: expected,
                },
                Decision::Gommage { hard_stop, .. },
            ) => expected.is_none_or(|expected| expected == *hard_stop),
            (Self::AskPicto { scope }, Decision::AskPicto { required_scope, .. }) => {
                required_scope == scope
            }
            _ => false,
        }
    }
}

fn build_smoke_report(layout: &HomeLayout) -> Result<SmokeReport> {
    let env = Expedition::load(&layout.expedition_file)?
        .map(|expedition| expedition.policy_env())
        .unwrap_or_else(default_policy_env);
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for smoke tests")?;
    let policy = Policy::load_from_dir(&layout.policy_dir, &env)
        .context("loading policy for smoke tests")?;

    let mut checks = Vec::new();
    let mut summary = SmokeSummary::default();
    for fixture in smoke_fixtures() {
        let capabilities = mapper.map(&fixture.call);
        let eval = evaluate(&capabilities, &policy);
        let status = if fixture.expectation.matches(&eval.decision) {
            summary.passed += 1;
            SmokeStatus::Pass
        } else {
            summary.failed += 1;
            SmokeStatus::Fail
        };

        checks.push(SmokeCheck {
            name: fixture.name,
            description: fixture.description,
            status,
            expected: fixture.expectation.label(),
            actual: eval.decision,
            tool: fixture.call.tool.clone(),
            input: fixture.call.input.clone(),
            input_hash: fixture.call.input_hash(),
            capabilities: eval.capabilities,
            matched_rule: eval.matched_rule,
        });
    }

    Ok(SmokeReport {
        status: if summary.failed == 0 {
            SmokeStatus::Pass
        } else {
            SmokeStatus::Fail
        },
        home: path_display(&layout.root),
        policy_version: policy.version_hash,
        mapper_rules: mapper.rule_count(),
        summary,
        checks,
    })
}

fn smoke_fixtures() -> Vec<SmokeFixture> {
    vec![
        SmokeFixture {
            name: "hardstop_rm_root",
            description: "compiled hard-stop blocks destructive root deletion",
            call: bash_call("rm -rf /"),
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(true),
            },
        },
        SmokeFixture {
            name: "fail_closed_unmapped_shell",
            description: "ordinary shell command denies when no policy rule matches",
            call: bash_call("ls -la"),
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(false),
            },
        },
        SmokeFixture {
            name: "allow_feature_push",
            description: "feature-style branch pushes are allowed by stdlib policy",
            call: bash_call("git push origin chore/test-branch"),
            expectation: SmokeExpectation::Allow,
        },
        SmokeFixture {
            name: "ask_main_push",
            description: "main branch pushes require a git.push:main picto",
            call: bash_call("git push origin main"),
            expectation: SmokeExpectation::AskPicto {
                scope: "git.push:main",
            },
        },
        SmokeFixture {
            name: "deny_force_push",
            description: "force pushes deny before the main-push gate can grant",
            call: bash_call("git push --force origin main"),
            expectation: SmokeExpectation::Gommage {
                hard_stop: Some(false),
            },
        },
        SmokeFixture {
            name: "ask_web_fetch",
            description: "agent-native WebFetch crosses the local trust boundary",
            call: ToolCall {
                tool: "WebFetch".to_string(),
                input: serde_json::json!({ "url": "https://example.com/docs" }),
            },
            expectation: SmokeExpectation::AskPicto { scope: "net.fetch" },
        },
        SmokeFixture {
            name: "ask_mcp_write",
            description: "write-like MCP tools require explicit approval",
            call: ToolCall {
                tool: "mcp__github__create_issue".to_string(),
                input: serde_json::json!({ "title": "smoke" }),
            },
            expectation: SmokeExpectation::AskPicto { scope: "mcp.write" },
        },
    ]
}

fn bash_call(command: &str) -> ToolCall {
    ToolCall {
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": command }),
    }
}

fn print_smoke_report(report: &SmokeReport) {
    for check in &report.checks {
        println!(
            "{} {}: expected {}, got {}",
            check.status.as_str(),
            check.name,
            check.expected,
            decision_summary(&check.actual)
        );
    }
    println!(
        "summary: {} passed, {} failed ({}; {} mapper rules)",
        report.summary.passed, report.summary.failed, report.policy_version, report.mapper_rules
    );
}

fn decision_summary(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::Gommage { hard_stop, reason } => {
            format!("gommage hard_stop={hard_stop} reason={reason:?}")
        }
        Decision::AskPicto {
            required_scope,
            reason,
        } => {
            format!("ask_picto scope={required_scope} reason={reason:?}")
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PolicyTestDocument {
    Wrapped(PolicyTestFile),
    Cases(Vec<PolicyTestCase>),
}

impl PolicyTestDocument {
    fn into_parts(self) -> (Option<u32>, Vec<PolicyTestCase>) {
        match self {
            Self::Wrapped(file) => (file.version, file.cases),
            Self::Cases(cases) => (None, cases),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestFile {
    #[serde(default)]
    version: Option<u32>,
    cases: Vec<PolicyTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCase {
    name: String,
    #[serde(default)]
    description: Option<String>,
    tool: String,
    #[serde(default = "empty_json_object")]
    input: serde_json::Value,
    expect: PolicyTestExpectation,
}

fn empty_json_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestExpectation {
    decision: PolicyTestDecision,
    #[serde(default)]
    hard_stop: Option<bool>,
    #[serde(default)]
    required_scope: Option<String>,
    #[serde(default)]
    matched_rule: Option<String>,
}

impl PolicyTestExpectation {
    fn label(&self) -> String {
        let mut parts = vec![self.decision.as_str().to_string()];
        if let Some(hard_stop) = self.hard_stop {
            parts.push(format!("hard_stop={hard_stop}"));
        }
        if let Some(scope) = &self.required_scope {
            parts.push(format!("scope={scope}"));
        }
        if let Some(rule) = &self.matched_rule {
            parts.push(format!("matched_rule={rule}"));
        }
        parts.join(" ")
    }

    fn mismatch_errors(&self, eval: &gommage_core::EvalResult) -> Vec<String> {
        let mut errors = Vec::new();
        let actual = PolicyTestDecision::from_decision(&eval.decision);
        if self.decision != actual {
            errors.push(format!(
                "expected decision {}, got {}",
                self.decision.as_str(),
                actual.as_str()
            ));
        }

        if let Some(expected) = self.hard_stop {
            match &eval.decision {
                Decision::Gommage { hard_stop, .. } if *hard_stop == expected => {}
                Decision::Gommage { hard_stop, .. } => errors.push(format!(
                    "expected hard_stop={expected}, got hard_stop={hard_stop}"
                )),
                _ => errors.push(format!(
                    "expected hard_stop={expected}, but actual decision is {}",
                    actual.as_str()
                )),
            }
        }

        if let Some(expected) = &self.required_scope {
            match &eval.decision {
                Decision::AskPicto { required_scope, .. } if required_scope == expected => {}
                Decision::AskPicto { required_scope, .. } => errors.push(format!(
                    "expected required_scope={expected}, got required_scope={required_scope}"
                )),
                _ => errors.push(format!(
                    "expected required_scope={expected}, but actual decision is {}",
                    actual.as_str()
                )),
            }
        }

        if let Some(expected) = &self.matched_rule {
            match &eval.matched_rule {
                Some(rule) if &rule.name == expected => {}
                Some(rule) => errors.push(format!(
                    "expected matched_rule={expected}, got matched_rule={}",
                    rule.name
                )),
                None => errors.push(format!(
                    "expected matched_rule={expected}, but no rule matched"
                )),
            }
        }

        errors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyTestDecision {
    Allow,
    Gommage,
    AskPicto,
}

impl PolicyTestDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Gommage => "gommage",
            Self::AskPicto => "ask_picto",
        }
    }

    fn from_decision(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Gommage { .. } => Self::Gommage,
            Decision::AskPicto { .. } => Self::AskPicto,
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicyTestReport {
    status: SmokeStatus,
    fixture_file: String,
    home: String,
    policy_version: String,
    mapper_rules: usize,
    summary: SmokeSummary,
    cases: Vec<PolicyTestCaseResult>,
}

impl PolicyTestReport {
    fn exit_code(&self) -> ExitCode {
        if self.summary.failed == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicyTestCaseResult {
    name: String,
    description: Option<String>,
    status: SmokeStatus,
    expected: PolicyTestExpectation,
    actual: Decision,
    errors: Vec<String>,
    tool: String,
    input: serde_json::Value,
    input_hash: String,
    capabilities: Vec<Capability>,
    matched_rule: Option<MatchedRule>,
}

#[derive(Debug, Serialize)]
struct PolicySnapshotDocument {
    version: u32,
    cases: Vec<PolicySnapshotCase>,
}

#[derive(Debug, Serialize)]
struct PolicySnapshotCase {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    tool: String,
    input: serde_json::Value,
    expect: PolicySnapshotExpectation,
}

#[derive(Debug, Serialize)]
struct PolicySnapshotExpectation {
    decision: PolicyTestDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    hard_stop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<String>,
}

impl PolicySnapshotExpectation {
    fn from_eval(eval: &gommage_core::EvalResult) -> Self {
        let (hard_stop, required_scope) = match &eval.decision {
            Decision::Allow => (None, None),
            Decision::Gommage { hard_stop, .. } => (Some(*hard_stop), None),
            Decision::AskPicto { required_scope, .. } => (None, Some(required_scope.clone())),
        };

        Self {
            decision: PolicyTestDecision::from_decision(&eval.decision),
            hard_stop,
            required_scope,
            matched_rule: eval.matched_rule.as_ref().map(|rule| rule.name.clone()),
        }
    }
}

fn build_policy_snapshot_case(
    layout: &HomeLayout,
    env: &std::collections::HashMap<String, String>,
    name: String,
    description: Option<String>,
    call: ToolCall,
) -> Result<PolicySnapshotCase> {
    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for policy snapshot")?;
    let policy = Policy::load_from_dir(&layout.policy_dir, env)
        .context("loading policy for policy snapshot")?;
    let capabilities = mapper.map(&call);
    let eval = evaluate(&capabilities, &policy);

    Ok(PolicySnapshotCase {
        name,
        description,
        tool: call.tool,
        input: call.input,
        expect: PolicySnapshotExpectation::from_eval(&eval),
    })
}

fn build_policy_test_report(
    layout: &HomeLayout,
    env: &std::collections::HashMap<String, String>,
    file: &Path,
) -> Result<PolicyTestReport> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("reading policy test fixture {}", file.display()))?;
    let document: PolicyTestDocument = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing policy test fixture {}", file.display()))?;
    let (version, cases) = document.into_parts();
    if let Some(version) = version
        && version != 1
    {
        anyhow::bail!("unsupported policy test fixture version {version}; expected 1");
    }
    if cases.is_empty() {
        anyhow::bail!("policy test fixture {} has no cases", file.display());
    }

    let mapper = gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading capability mappers for policy test")?;
    let policy =
        Policy::load_from_dir(&layout.policy_dir, env).context("loading policy for policy test")?;

    let mut results = Vec::new();
    let mut summary = SmokeSummary::default();
    for case in cases {
        let call = ToolCall {
            tool: case.tool,
            input: case.input,
        };
        let capabilities = mapper.map(&call);
        let eval = evaluate(&capabilities, &policy);
        let input_hash = call.input_hash();
        let errors = case.expect.mismatch_errors(&eval);
        let status = if errors.is_empty() {
            summary.passed += 1;
            SmokeStatus::Pass
        } else {
            summary.failed += 1;
            SmokeStatus::Fail
        };

        results.push(PolicyTestCaseResult {
            name: case.name,
            description: case.description,
            status,
            expected: case.expect,
            actual: eval.decision,
            errors,
            tool: call.tool,
            input: call.input,
            input_hash,
            capabilities: eval.capabilities,
            matched_rule: eval.matched_rule,
        });
    }

    Ok(PolicyTestReport {
        status: if summary.failed == 0 {
            SmokeStatus::Pass
        } else {
            SmokeStatus::Fail
        },
        fixture_file: path_display(file),
        home: path_display(&layout.root),
        policy_version: policy.version_hash,
        mapper_rules: mapper.rule_count(),
        summary,
        cases: results,
    })
}

fn print_policy_test_report(report: &PolicyTestReport) {
    for case in &report.cases {
        println!(
            "{} {}: expected {}, got {}",
            case.status.as_str(),
            case.name,
            case.expected.label(),
            decision_summary(&case.actual)
        );
        for error in &case.errors {
            println!("  - {error}");
        }
    }
    println!(
        "summary: {} passed, {} failed ({}; {} mapper rules)",
        report.summary.passed, report.summary.failed, report.policy_version, report.mapper_rules
    );
}

fn cmd_verify(layout: HomeLayout, json: bool, policy_tests: Vec<PathBuf>) -> Result<ExitCode> {
    let report = build_verify_report(&layout, &policy_tests);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_verify_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerifyStatus {
    Pass,
    Warn,
    Fail,
}

impl VerifyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    fn from_doctor(status: DoctorStatus) -> Self {
        match status {
            DoctorStatus::Ok => Self::Pass,
            DoctorStatus::Warn => Self::Warn,
            DoctorStatus::Fail => Self::Fail,
        }
    }

    fn from_smoke(status: SmokeStatus) -> Self {
        match status {
            SmokeStatus::Pass => Self::Pass,
            SmokeStatus::Fail => Self::Fail,
        }
    }
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    status: VerifyStatus,
    home: String,
    summary: VerifySummary,
    doctor: VerifySection<DoctorReport>,
    smoke: VerifySection<SmokeReport>,
    policy_tests: Vec<VerifyPolicyTestSection>,
}

impl VerifyReport {
    fn exit_code(&self) -> ExitCode {
        if self.status == VerifyStatus::Fail {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct VerifySummary {
    failures: usize,
    warnings: usize,
    policy_tests: usize,
}

#[derive(Debug, Serialize)]
struct VerifySection<T: Serialize> {
    status: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyPolicyTestSection {
    file: String,
    status: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<PolicyTestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn build_verify_report(layout: &HomeLayout, policy_test_files: &[PathBuf]) -> VerifyReport {
    let mut summary = VerifySummary {
        policy_tests: policy_test_files.len(),
        ..VerifySummary::default()
    };

    let doctor_report = build_doctor_report(layout);
    let doctor_status = VerifyStatus::from_doctor(doctor_report.status);
    push_verify_status(&mut summary, doctor_status);
    let doctor = VerifySection {
        status: doctor_status,
        report: Some(doctor_report),
        error: None,
    };

    let smoke = match build_smoke_report(layout) {
        Ok(report) => {
            let status = VerifyStatus::from_smoke(report.status);
            push_verify_status(&mut summary, status);
            VerifySection {
                status,
                report: Some(report),
                error: None,
            }
        }
        Err(error) => {
            push_verify_status(&mut summary, VerifyStatus::Fail);
            VerifySection {
                status: VerifyStatus::Fail,
                report: None,
                error: Some(error.to_string()),
            }
        }
    };

    let policy_env = Expedition::load(&layout.expedition_file)
        .map(|expedition| {
            expedition
                .map(|expedition| expedition.policy_env())
                .unwrap_or_else(default_policy_env)
        })
        .map_err(|error| format!("loading expedition policy environment: {error}"));

    let mut policy_tests = Vec::new();
    for file in policy_test_files {
        let section = match &policy_env {
            Ok(env) => match build_policy_test_report(layout, env, file) {
                Ok(report) => {
                    let status = VerifyStatus::from_smoke(report.status);
                    VerifyPolicyTestSection {
                        file: path_display(file),
                        status,
                        report: Some(report),
                        error: None,
                    }
                }
                Err(error) => VerifyPolicyTestSection {
                    file: path_display(file),
                    status: VerifyStatus::Fail,
                    report: None,
                    error: Some(error.to_string()),
                },
            },
            Err(error) => VerifyPolicyTestSection {
                file: path_display(file),
                status: VerifyStatus::Fail,
                report: None,
                error: Some(error.clone()),
            },
        };
        push_verify_status(&mut summary, section.status);
        policy_tests.push(section);
    }

    VerifyReport {
        status: if summary.failures > 0 {
            VerifyStatus::Fail
        } else if summary.warnings > 0 {
            VerifyStatus::Warn
        } else {
            VerifyStatus::Pass
        },
        home: path_display(&layout.root),
        summary,
        doctor,
        smoke,
        policy_tests,
    }
}

fn push_verify_status(summary: &mut VerifySummary, status: VerifyStatus) {
    match status {
        VerifyStatus::Pass => {}
        VerifyStatus::Warn => summary.warnings += 1,
        VerifyStatus::Fail => summary.failures += 1,
    }
}

fn print_verify_report(report: &VerifyReport) {
    println!(
        "{} doctor: {} failure(s), {} warning(s)",
        report.doctor.status.as_str(),
        report
            .doctor
            .report
            .as_ref()
            .map(|doctor| doctor.summary.failures)
            .unwrap_or(1),
        report
            .doctor
            .report
            .as_ref()
            .map(|doctor| doctor.summary.warnings)
            .unwrap_or(0)
    );

    match (&report.smoke.report, &report.smoke.error) {
        (Some(smoke), _) => println!(
            "{} smoke: {} passed, {} failed",
            report.smoke.status.as_str(),
            smoke.summary.passed,
            smoke.summary.failed
        ),
        (None, Some(error)) => println!("fail smoke: {error}"),
        (None, None) => println!("fail smoke: missing report"),
    }

    for section in &report.policy_tests {
        match (&section.report, &section.error) {
            (Some(policy), _) => println!(
                "{} policy test {}: {} passed, {} failed",
                section.status.as_str(),
                section.file,
                policy.summary.passed,
                policy.summary.failed
            ),
            (None, Some(error)) => println!("fail policy test {}: {error}", section.file),
            (None, None) => println!("fail policy test {}: missing report", section.file),
        }
    }

    println!(
        "summary: {} failure(s), {} warning(s), {} policy test file(s)",
        report.summary.failures, report.summary.warnings, report.summary.policy_tests
    );
}

fn cmd_daemon(sub: DaemonCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        DaemonCmd::Install {
            manager,
            force,
            no_start,
            dry_run,
        } => daemon_install(
            layout,
            resolve_service_manager(manager)?,
            force,
            no_start,
            dry_run,
        ),
        DaemonCmd::Uninstall { manager, dry_run } => {
            daemon_uninstall(layout, resolve_service_manager(manager)?, dry_run)
        }
        DaemonCmd::Status { manager } => daemon_status(resolve_service_manager(manager)?),
    }
}

fn daemon_install(
    layout: HomeLayout,
    manager: ServiceManager,
    force: bool,
    no_start: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    if !dry_run {
        layout.ensure()?;
    }
    let daemon_bin = find_daemon_binary()?;
    let spec = daemon_service_spec(manager, &layout, &daemon_bin)?;
    write_service_file(&spec.path, &spec.contents, force, dry_run)?;
    println!("ok daemon: service file {}", spec.path.display());
    if no_start {
        println!("ok daemon: service installed but not started (--no-start)");
        return Ok(ExitCode::SUCCESS);
    }
    if dry_run {
        if manager == ServiceManager::Launchd {
            for command in service_stop_commands(manager, &spec.path) {
                println!("plan run best-effort: {}", command.join(" "));
            }
        }
        for command in service_start_commands(manager, &spec.path) {
            println!("plan run: {}", command.join(" "));
        }
        return Ok(ExitCode::SUCCESS);
    }
    if manager == ServiceManager::Launchd {
        let _ = run_service_commands_allow_failure(service_stop_commands(manager, &spec.path));
    }
    run_service_commands(service_start_commands(manager, &spec.path))?;
    println!("ok daemon: service enabled and started");
    Ok(ExitCode::SUCCESS)
}

fn daemon_uninstall(
    _layout: HomeLayout,
    manager: ServiceManager,
    dry_run: bool,
) -> Result<ExitCode> {
    let path = service_file_path(manager)?;
    if dry_run {
        for command in service_stop_commands(manager, &path) {
            println!("plan run: {}", command.join(" "));
        }
        println!("plan remove: {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    let _ = run_service_commands_allow_failure(service_stop_commands(manager, &path));
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("ok daemon: removed {}", path.display());
    } else {
        println!("ok daemon: service file not found at {}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn daemon_status(manager: ServiceManager) -> Result<ExitCode> {
    let commands = service_status_commands(manager)?;
    let status = run_service_commands_allow_failure(commands)?;
    Ok(if status {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

struct ServiceSpec {
    path: PathBuf,
    contents: String,
}

fn daemon_service_spec(
    manager: ServiceManager,
    layout: &HomeLayout,
    daemon_bin: &Path,
) -> Result<ServiceSpec> {
    let path = service_file_path(manager)?;
    let contents = match manager {
        ServiceManager::Launchd => launchd_plist(layout, daemon_bin),
        ServiceManager::Systemd => systemd_service(layout, daemon_bin),
    };
    Ok(ServiceSpec { path, contents })
}

fn resolve_service_manager(manager: Option<ServiceManager>) -> Result<ServiceManager> {
    if let Some(manager) = manager {
        return Ok(manager);
    }
    if cfg!(target_os = "macos") {
        Ok(ServiceManager::Launchd)
    } else if cfg!(target_os = "linux") {
        Ok(ServiceManager::Systemd)
    } else {
        anyhow::bail!("daemon install supports launchd on macOS and systemd user services on Linux")
    }
}

fn service_file_path(manager: ServiceManager) -> Result<PathBuf> {
    match manager {
        ServiceManager::Launchd => Ok(env_path_or_home(
            "GOMMAGE_LAUNCHD_DIR",
            &["Library", "LaunchAgents"],
        )
        .join("dev.gommage.daemon.plist")),
        ServiceManager::Systemd => Ok(env_path_or_home(
            "GOMMAGE_SYSTEMD_USER_DIR",
            &[".config", "systemd", "user"],
        )
        .join("gommage-daemon.service")),
    }
}

fn launchd_plist(layout: &HomeLayout, daemon_bin: &Path) -> String {
    let stdout = layout.root.join("daemon.log");
    let stderr = layout.root.join("daemon.err.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.gommage.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--foreground</string>
    <string>--home</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&daemon_bin.to_string_lossy()),
        xml_escape(&layout.root.to_string_lossy()),
        xml_escape(&stdout.to_string_lossy()),
        xml_escape(&stderr.to_string_lossy())
    )
}

fn systemd_service(layout: &HomeLayout, daemon_bin: &Path) -> String {
    format!(
        r#"[Unit]
Description=Gommage policy daemon
Documentation=https://github.com/Arakiss/gommage

[Service]
Type=simple
ExecStart={} --foreground --home {}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#,
        systemd_quote(&daemon_bin.to_string_lossy()),
        systemd_quote(&layout.root.to_string_lossy())
    )
}

fn write_service_file(path: &Path, contents: &str, force: bool, dry_run: bool) -> Result<()> {
    if path.exists() {
        let current = std::fs::read_to_string(path)?;
        if current == contents {
            println!("ok unchanged: {}", path.display());
            return Ok(());
        }
        if !force {
            anyhow::bail!(
                "{} exists; rerun with --force to replace it",
                path.display()
            );
        }
    }
    write_text(path, contents, dry_run)
}

fn find_daemon_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("GOMMAGE_DAEMON_BIN") {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_exe()?;
    if let Some(dir) = current.parent() {
        let sibling = dir.join("gommage-daemon");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("gommage-daemon");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!("could not find gommage-daemon; install it or set GOMMAGE_DAEMON_BIN")
}

fn service_start_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
    match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "bootstrap".to_string(),
            launchd_domain(),
            path.to_string_lossy().to_string(),
        ]],
        ServiceManager::Systemd => vec![
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "daemon-reload".to_string(),
            ],
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "enable".to_string(),
                "--now".to_string(),
                "gommage-daemon.service".to_string(),
            ],
        ],
    }
}

fn service_stop_commands(manager: ServiceManager, path: &Path) -> Vec<Vec<String>> {
    match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "bootout".to_string(),
            launchd_domain(),
            path.to_string_lossy().to_string(),
        ]],
        ServiceManager::Systemd => vec![
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "disable".to_string(),
                "--now".to_string(),
                "gommage-daemon.service".to_string(),
            ],
            vec![
                "systemctl".to_string(),
                "--user".to_string(),
                "daemon-reload".to_string(),
            ],
        ],
    }
}

fn service_status_commands(manager: ServiceManager) -> Result<Vec<Vec<String>>> {
    Ok(match manager {
        ServiceManager::Launchd => vec![vec![
            "launchctl".to_string(),
            "print".to_string(),
            format!("{}/dev.gommage.daemon", launchd_domain()),
        ]],
        ServiceManager::Systemd => vec![vec![
            "systemctl".to_string(),
            "--user".to_string(),
            "status".to_string(),
            "--no-pager".to_string(),
            "gommage-daemon.service".to_string(),
        ]],
    })
}

fn run_service_commands(commands: Vec<Vec<String>>) -> Result<()> {
    for command in commands {
        let status = command_status(&command)?;
        if !status {
            anyhow::bail!("service command failed: {}", command.join(" "));
        }
    }
    Ok(())
}

fn run_service_commands_allow_failure(commands: Vec<Vec<String>>) -> Result<bool> {
    let mut ok = true;
    for command in commands {
        ok &= command_status(&command)?;
    }
    Ok(ok)
}

fn command_status(command: &[String]) -> Result<bool> {
    let Some(program) = command.first() else {
        anyhow::bail!("empty service command");
    };
    let status = Command::new(program).args(&command[1..]).status()?;
    Ok(status.success())
}

fn launchd_domain() -> String {
    format!("gui/{}", unsafe { libc_getuid() })
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

#[cfg(not(unix))]
unsafe fn libc_getuid() -> u32 {
    0
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(raw: &str) -> String {
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}

fn cmd_quickstart(layout: HomeLayout, options: QuickstartOptions) -> Result<ExitCode> {
    let QuickstartOptions {
        agents,
        replace_hooks,
        import_native_permissions,
        install_daemon,
        daemon_manager,
        daemon_force,
        daemon_no_start,
        dry_run,
    } = options;

    if dry_run {
        println!("dry-run: no files will be written");
    }
    if !dry_run {
        layout.ensure().context("initializing home")?;
    } else {
        println!("plan home: ensure {}", layout.root.display());
    }

    let installed = if dry_run {
        (0, 0)
    } else {
        install_stdlib(&layout, false)?
    };
    if dry_run {
        println!("plan stdlib: install bundled policy and capability defaults if missing");
    } else {
        println!(
            "ok stdlib: {} policy files, {} capability files installed",
            installed.0, installed.1
        );
        let env = Expedition::load(&layout.expedition_file)?
            .map(|e| e.policy_env())
            .unwrap_or_else(default_policy_env);
        let policy = Policy::load_from_dir(&layout.policy_dir, &env)?;
        println!(
            "ok policy: {} rules ({})",
            policy.rules.len(),
            policy.version_hash
        );
    }

    let agents = if agents.is_empty() {
        vec![AgentKind::Claude]
    } else {
        agents
    };
    for agent in agents {
        install_agent(
            agent,
            &layout,
            replace_hooks,
            import_native_permissions,
            dry_run,
        )?;
    }

    if install_daemon {
        daemon_install(
            HomeLayout::at(&layout.root),
            resolve_service_manager(daemon_manager)?,
            daemon_force,
            daemon_no_start,
            dry_run,
        )?;
    }

    if !dry_run {
        let env = Expedition::load(&layout.expedition_file)?
            .map(|e| e.policy_env())
            .unwrap_or_else(default_policy_env);
        let policy = Policy::load_from_dir(&layout.policy_dir, &env)?;
        println!(
            "ok final policy: {} rules ({})",
            policy.rules.len(),
            policy.version_hash
        );
    }

    println!("ok quickstart complete");
    println!("next: start an expedition with `gommage expedition start <name>`");
    if install_daemon {
        println!("next: inspect runtime health with `gommage doctor`");
    } else {
        println!("optional: run `gommage daemon install` for long sessions");
    }
    Ok(ExitCode::SUCCESS)
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
    if matches!(sub, PolicyCmd::Schema) {
        println!("{}", POLICY_FIXTURE_SCHEMA.trim_end());
        return Ok(ExitCode::SUCCESS);
    }

    layout.ensure()?;
    let env = Expedition::load(&layout.expedition_file)?
        .map(|e| e.policy_env())
        .unwrap_or_else(default_policy_env);
    match sub {
        PolicyCmd::Init { stdlib, force } => {
            if !stdlib {
                anyhow::bail!("policy init currently requires --stdlib");
            }
            let installed = install_stdlib(&layout, force)?;
            println!(
                "ok stdlib installed: {} policy files, {} capability files",
                installed.0, installed.1
            );
        }
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
        PolicyCmd::Schema => unreachable!("policy schema returns before home validation"),
        PolicyCmd::Test { file, json } => {
            let report = build_policy_test_report(&layout, &env, &file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_policy_test_report(&report);
            }
            return Ok(report.exit_code());
        }
        PolicyCmd::Snapshot {
            name,
            description,
            case_only,
            hook,
        } => {
            let call = read_tool_call_from_stdin(hook)?;
            let case = build_policy_snapshot_case(&layout, &env, name, description, call)?;
            if case_only {
                println!("{}", serde_yaml::to_string(&[case])?.trim_end());
            } else {
                let document = PolicySnapshotDocument {
                    version: 1,
                    cases: vec![case],
                };
                println!("{}", serde_yaml::to_string(&document)?.trim_end());
            }
        }
        PolicyCmd::Hash => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("{}", pol.version_hash);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn install_stdlib(layout: &HomeLayout, force: bool) -> Result<(usize, usize)> {
    let policies = install_embedded_files(&layout.policy_dir, STDLIB_POLICIES, force)?;
    let capabilities =
        install_embedded_files(&layout.capabilities_dir, STDLIB_CAPABILITIES, force)?;
    Ok((policies, capabilities))
}

fn install_embedded_files(
    dir: &std::path::Path,
    files: &[StdlibFile],
    force: bool,
) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut installed = 0usize;
    for file in files {
        let path = dir.join(file.name);
        if path.exists() && !force {
            continue;
        }
        std::fs::write(path, file.contents)?;
        installed += 1;
    }
    Ok(installed)
}

fn cmd_explain(layout: HomeLayout, id: &str, json: bool) -> Result<ExitCode> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(&layout.audit_log).context("opening audit log")?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let value: serde_json::Value = serde_json::from_str(&line)?;
        if value.get("id").and_then(|v| v.as_str()) != Some(id) {
            continue;
        }
        if json {
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else if value.get("kind").and_then(|v| v.as_str()) == Some("event") {
            let entry: AuditEventEntry = serde_json::from_value(value)?;
            print_event_explain(&entry)?;
        } else {
            let entry: AuditEntry = serde_json::from_value(value)?;
            print_decision_explain(&entry)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("no audit entry with id {id}");
    Ok(ExitCode::from(1))
}

fn print_decision_explain(entry: &AuditEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: decision");
    println!("tool: {}", entry.tool);
    println!("input_hash: {}", entry.input_hash);
    println!("decision: {}", serde_json::to_string(&entry.decision)?);
    if let Some(rule) = &entry.matched_rule {
        println!("matched_rule: {} ({}:{})", rule.name, rule.file, rule.index);
    } else {
        println!("matched_rule: <none>");
    }
    println!("policy_version: {}", entry.policy_version);
    if let Some(expedition) = &entry.expedition {
        println!("expedition: {expedition}");
    }
    println!("capabilities:");
    for cap in &entry.capabilities {
        println!("  - {}", cap.as_str());
    }
    Ok(())
}

fn print_event_explain(entry: &AuditEventEntry) -> Result<()> {
    println!("audit_id: {}", entry.id);
    println!("timestamp: {}", entry.ts);
    println!("kind: event");
    println!("event: {}", serde_json::to_string(&entry.event)?);
    Ok(())
}

fn print_audit_verify_report(report: &AuditVerifyReport) {
    let status = if report.anomalies.is_empty() {
        "ok"
    } else {
        "anomaly"
    };

    println!("audit verification report");
    println!("status: {status}");
    println!(
        "entries: {} total, {} verified",
        report.entries_total, report.entries_verified
    );
    println!("key_fingerprint: {}", report.key_fingerprint);
    print_string_list("policy_versions", &report.policy_versions_seen);
    print_string_list("expeditions", &report.expeditions_seen);

    if report.anomalies.is_empty() {
        println!("anomalies: none");
    } else {
        println!("anomalies:");
        for anomaly in &report.anomalies {
            println!("  - {}", format_anomaly(anomaly));
        }
    }
}

fn print_string_list(label: &str, values: &[String]) {
    if values.is_empty() {
        println!("{label}: none");
        return;
    }

    println!("{label}:");
    for value in values {
        println!("  - {value}");
    }
}

fn format_anomaly(anomaly: &Anomaly) -> String {
    match anomaly {
        Anomaly::MalformedEntry { line, error } => {
            format!("line {line}: malformed_entry error={error}")
        }
        Anomaly::BadSignature { line, entry_id } => {
            format!("line {line}: bad_signature entry_id={entry_id}")
        }
        Anomaly::TimestampOutOfOrder {
            line,
            previous_ts,
            current_ts,
        } => format!(
            "line {line}: timestamp_out_of_order previous_ts={previous_ts} current_ts={current_ts}"
        ),
        Anomaly::PolicyVersionChanged { line, from, to } => {
            format!("line {line}: policy_version_changed from={from} to={to}")
        }
    }
}

fn cmd_doctor(layout: HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_doctor_report(&layout);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_doctor_report(&report);
    }
    Ok(report.exit_code())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    status: DoctorStatus,
    home: String,
    summary: DoctorSummary,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new(layout: &HomeLayout) -> Self {
        Self {
            status: DoctorStatus::Ok,
            home: path_display(&layout.root),
            summary: DoctorSummary::default(),
            checks: Vec::new(),
        }
    }

    fn push(
        &mut self,
        name: impl Into<String>,
        status: DoctorStatus,
        message: impl Into<String>,
        details: Option<serde_json::Value>,
    ) {
        match status {
            DoctorStatus::Ok => {}
            DoctorStatus::Warn => self.summary.warnings += 1,
            DoctorStatus::Fail => self.summary.failures += 1,
        }
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            message: message.into(),
            details,
        });
        self.status = if self.summary.failures > 0 {
            DoctorStatus::Fail
        } else if self.summary.warnings > 0 {
            DoctorStatus::Warn
        } else {
            DoctorStatus::Ok
        };
    }

    fn exit_code(&self) -> ExitCode {
        if self.summary.failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct DoctorSummary {
    failures: usize,
    warnings: usize,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

fn build_doctor_report(layout: &HomeLayout) -> DoctorReport {
    let mut report = DoctorReport::new(layout);

    push_path_check(&mut report, "home", &layout.root);
    push_path_check(&mut report, "policy_dir", &layout.policy_dir);
    push_path_check(&mut report, "capabilities_dir", &layout.capabilities_dir);

    match layout.load_key() {
        Ok(_) => report.push(
            "key",
            DoctorStatus::Ok,
            format!("{} is loadable", layout.key_file.display()),
            Some(path_details(&layout.key_file)),
        ),
        Err(e) => report.push(
            "key",
            DoctorStatus::Fail,
            format!("could not load key: {e}"),
            Some(path_details(&layout.key_file)),
        ),
    }

    let env = match Expedition::load(&layout.expedition_file) {
        Ok(Some(expedition)) => {
            let details = serde_json::json!({
                "path": path_display(&layout.expedition_file),
                "name": expedition.name,
                "root": path_display(&expedition.root),
                "started_at": expedition.started_at.to_string(),
            });
            let env = expedition.policy_env();
            report.push(
                "expedition",
                DoctorStatus::Ok,
                "active expedition loaded",
                Some(details),
            );
            env
        }
        Ok(None) => {
            report.push(
                "expedition",
                DoctorStatus::Ok,
                "no active expedition",
                Some(path_details(&layout.expedition_file)),
            );
            default_policy_env()
        }
        Err(e) => {
            report.push(
                "expedition",
                DoctorStatus::Fail,
                format!("could not load expedition state: {e}"),
                Some(path_details(&layout.expedition_file)),
            );
            default_policy_env()
        }
    };

    match Policy::load_from_dir(&layout.policy_dir, &env) {
        Ok(policy) => report.push(
            "policy",
            DoctorStatus::Ok,
            format!("{} rules ({})", policy.rules.len(), policy.version_hash),
            Some(serde_json::json!({
                "path": path_display(&layout.policy_dir),
                "rules": policy.rules.len(),
                "version": policy.version_hash,
            })),
        ),
        Err(e) => report.push(
            "policy",
            DoctorStatus::Fail,
            format!("could not load policy: {e}"),
            Some(path_details(&layout.policy_dir)),
        ),
    }

    match gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir) {
        Ok(mapper) => report.push(
            "capabilities",
            DoctorStatus::Ok,
            format!("{} rules", mapper.rule_count()),
            Some(serde_json::json!({
                "path": path_display(&layout.capabilities_dir),
                "rules": mapper.rule_count(),
            })),
        ),
        Err(e) => report.push(
            "capabilities",
            DoctorStatus::Fail,
            format!("could not load capabilities: {e}"),
            Some(path_details(&layout.capabilities_dir)),
        ),
    }

    if layout.audit_log.exists() {
        match layout
            .load_verifying_key()
            .ok()
            .and_then(|vk| verify_log(&layout.audit_log, &vk).ok())
        {
            Some(count) => report.push(
                "audit",
                DoctorStatus::Ok,
                format!("{count} entries verified"),
                Some(serde_json::json!({
                    "path": path_display(&layout.audit_log),
                    "entries": count,
                })),
            ),
            None => report.push(
                "audit",
                DoctorStatus::Fail,
                format!("could not verify {}", layout.audit_log.display()),
                Some(path_details(&layout.audit_log)),
            ),
        }
    } else {
        report.push(
            "audit",
            DoctorStatus::Warn,
            "no audit log yet",
            Some(path_details(&layout.audit_log)),
        );
    }

    if layout.socket.exists() {
        report.push(
            "daemon",
            DoctorStatus::Ok,
            format!("socket exists at {}", layout.socket.display()),
            Some(serde_json::json!({
                "socket": path_display(&layout.socket),
            })),
        );
    } else {
        report.push(
            "daemon",
            DoctorStatus::Warn,
            "socket not found; hook adapter will use audited fallback",
            Some(serde_json::json!({
                "socket": path_display(&layout.socket),
            })),
        );
    }

    report
}

fn push_path_check(report: &mut DoctorReport, name: &str, path: &Path) {
    if path.exists() {
        report.push(
            name,
            DoctorStatus::Ok,
            format!("{} exists", path.display()),
            Some(path_details(path)),
        );
    } else {
        report.push(
            name,
            DoctorStatus::Fail,
            "missing",
            Some(path_details(path)),
        );
    }
}

fn print_doctor_report(report: &DoctorReport) {
    for check in &report.checks {
        println!(
            "{} {}: {}",
            check.status.as_str(),
            check.name,
            check.message
        );
    }
    println!(
        "summary: {} failure(s), {} warning(s)",
        report.summary.failures, report.summary.warnings
    );
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
    let call = tool_call_from_hook_payload(input)?;

    let sk: SigningKey = layout.load_key()?;
    let vk = sk.verifying_key();
    let mut rt = Runtime::open(layout.clone_layout())?;
    let (eval, events) = decide_with_pictos(&rt, &call, &vk)?;

    // Append to audit log (signed).
    let expedition_name = rt.expedition.as_ref().map(|e| e.name.clone());
    let mut writer = AuditWriter::open(&rt.layout.audit_log, sk)?;
    for event in events {
        writer.append_event(event)?;
    }
    writer.append(&call, &eval, expedition_name.as_deref())?;

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

fn enrich_hook_tool_input(
    tool: &str,
    mut input: serde_json::Value,
    cwd: Option<&str>,
) -> serde_json::Value {
    let Some(cwd) = cwd else {
        return input;
    };
    let serde_json::Value::Object(map) = &mut input else {
        return input;
    };

    match tool {
        "Grep" => {
            let base = map
                .get("path")
                .and_then(|v| v.as_str())
                .map(|path| resolve_hook_path(cwd, path))
                .unwrap_or_else(|| cwd.to_string());
            map.entry("__gommage_path".to_string())
                .or_insert_with(|| serde_json::Value::String(base.clone()));
            if let Some(glob) = map.get("glob").and_then(|v| v.as_str()) {
                let glob_path = resolve_hook_path(&base, glob);
                map.entry("__gommage_glob_path".to_string())
                    .or_insert_with(|| serde_json::Value::String(glob_path));
            }
        }
        "Glob" => {
            if let Some(pattern) = map.get("pattern").and_then(|v| v.as_str()) {
                let pattern_path = resolve_hook_path(cwd, pattern);
                map.entry("__gommage_pattern".to_string())
                    .or_insert_with(|| serde_json::Value::String(pattern_path));
            }
        }
        _ => {}
    }

    input
}

fn resolve_hook_path(base: &str, path: &str) -> String {
    if path.starts_with('/') || path.starts_with('~') {
        return path.to_string();
    }
    if path == "." || path.is_empty() {
        return base.to_string();
    }
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches("./")
    )
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
