use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use gommage_audit::{AuditEntry, AuditEvent, AuditEventEntry, AuditWriter, verify_log};
use gommage_core::{
    Decision, PictoConsume, PictoLookup, Policy, ToolCall, evaluate,
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
        /// Produce a detailed forensic report (JSON) instead of a simple count.
        /// Includes per-line signature verification, key fingerprint, policy
        /// version history, expeditions seen, and any anomalies (tamper, bad
        /// signature, timestamp out of order, mid-log policy change).
        #[arg(long)]
        explain: bool,
    },

    /// Evaluate a tool call JSON from stdin. Useful for tests and MCP adapters.
    Decide {
        #[arg(long)]
        pretty: bool,
    },

    /// Diagnose the local Gommage installation and runtime state.
    Doctor,

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
        Cmd::AuditVerify { explain } => {
            let vk = layout.load_verifying_key()?;
            if explain {
                let report = gommage_audit::explain_log(&layout.audit_log, &vk)
                    .context("explaining audit log")?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.anomalies.is_empty() {
                    return Ok(ExitCode::from(1));
                }
            } else {
                let n = verify_log(&layout.audit_log, &vk).context("verifying audit log")?;
                println!("ok {n} entries verified");
            }
        }
        Cmd::Decide { pretty } => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            let call: ToolCall = serde_json::from_str(&buf).context("parsing stdin as ToolCall")?;
            let rt = Runtime::open(layout)?;
            let eval = evaluate_only(&rt, &call);
            let out = if pretty {
                serde_json::to_string_pretty(&eval)?
            } else {
                serde_json::to_string(&eval)?
            };
            println!("{out}");
        }
        Cmd::Doctor => return cmd_doctor(layout),
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
        PolicyCmd::Hash => {
            let pol = Policy::load_from_dir(&layout.policy_dir, &env)?;
            println!("{}", pol.version_hash);
        }
    }
    Ok(ExitCode::SUCCESS)
}

const STDLIB_POLICIES: &[(&str, &str)] = &[
    (
        "00-hard-stops.yaml",
        include_str!("../../../policies/00-hard-stops.yaml"),
    ),
    (
        "10-filesystem.yaml",
        include_str!("../../../policies/10-filesystem.yaml"),
    ),
    ("20-git.yaml", include_str!("../../../policies/20-git.yaml")),
    (
        "30-package-managers.yaml",
        include_str!("../../../policies/30-package-managers.yaml"),
    ),
    (
        "40-cloud.yaml",
        include_str!("../../../policies/40-cloud.yaml"),
    ),
    (
        "50-cloud-tools.yaml",
        include_str!("../../../policies/50-cloud-tools.yaml"),
    ),
];

const STDLIB_CAPABILITIES: &[(&str, &str)] = &[
    ("bash.yaml", include_str!("../../../capabilities/bash.yaml")),
    (
        "cloud-tools.yaml",
        include_str!("../../../capabilities/cloud-tools.yaml"),
    ),
    (
        "filesystem.yaml",
        include_str!("../../../capabilities/filesystem.yaml"),
    ),
];

fn install_stdlib(layout: &HomeLayout, force: bool) -> Result<(usize, usize)> {
    let policies = install_embedded_files(&layout.policy_dir, STDLIB_POLICIES, force)?;
    let capabilities =
        install_embedded_files(&layout.capabilities_dir, STDLIB_CAPABILITIES, force)?;
    Ok((policies, capabilities))
}

fn install_embedded_files(
    dir: &std::path::Path,
    files: &[(&str, &str)],
    force: bool,
) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut installed = 0usize;
    for (name, contents) in files {
        let path = dir.join(name);
        if path.exists() && !force {
            continue;
        }
        std::fs::write(path, contents)?;
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

fn cmd_doctor(layout: HomeLayout) -> Result<ExitCode> {
    let mut failures = 0usize;
    let mut warnings = 0usize;

    doctor_check(layout.root.exists(), &mut failures, "home", || {
        format!("{} exists", layout.root.display())
    });
    doctor_check(
        layout.policy_dir.exists(),
        &mut failures,
        "policy_dir",
        || format!("{} exists", layout.policy_dir.display()),
    );
    doctor_check(
        layout.capabilities_dir.exists(),
        &mut failures,
        "capabilities_dir",
        || format!("{} exists", layout.capabilities_dir.display()),
    );
    match layout.load_key() {
        Ok(_) => println!("ok key: {}", layout.key_file.display()),
        Err(e) => {
            failures += 1;
            println!("fail key: {e}");
        }
    }

    let env = Expedition::load(&layout.expedition_file)?
        .map(|e| e.policy_env())
        .unwrap_or_default();
    match Policy::load_from_dir(&layout.policy_dir, &env) {
        Ok(policy) => println!(
            "ok policy: {} rules ({})",
            policy.rules.len(),
            policy.version_hash
        ),
        Err(e) => {
            failures += 1;
            println!("fail policy: {e}");
        }
    }
    match gommage_core::CapabilityMapper::load_from_dir(&layout.capabilities_dir) {
        Ok(mapper) => println!("ok capabilities: {} rules", mapper.rule_count()),
        Err(e) => {
            failures += 1;
            println!("fail capabilities: {e}");
        }
    }
    if layout.audit_log.exists() {
        match layout
            .load_verifying_key()
            .ok()
            .and_then(|vk| verify_log(&layout.audit_log, &vk).ok())
        {
            Some(count) => println!("ok audit: {count} entries verified"),
            None => {
                failures += 1;
                println!(
                    "fail audit: could not verify {}",
                    layout.audit_log.display()
                );
            }
        }
    } else {
        warnings += 1;
        println!("warn audit: no audit log yet");
    }
    if layout.socket.exists() {
        println!("ok daemon: socket exists at {}", layout.socket.display());
    } else {
        warnings += 1;
        println!("warn daemon: socket not found; hook adapter will use audited fallback");
    }

    println!("summary: {failures} failure(s), {warnings} warning(s)");
    if failures == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn doctor_check(ok: bool, failures: &mut usize, name: &str, message: impl FnOnce() -> String) {
    if ok {
        println!("ok {name}: {}", message());
    } else {
        *failures += 1;
        println!("fail {name}: missing");
    }
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

// Tiny shim to avoid moving `layout` twice in `run_mcp`.
trait CloneLayout {
    fn clone_layout(&self) -> HomeLayout;
}
impl CloneLayout for HomeLayout {
    fn clone_layout(&self) -> HomeLayout {
        HomeLayout::at(&self.root)
    }
}
