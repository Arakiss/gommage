use anyhow::{Context, Result};
use clap::Subcommand;
use gommage_core::runtime::{
    Expedition, HomeLayout, active_policy_layers, default_policy_env, load_active_policy,
};
use serde::Serialize;
use std::process::ExitCode;

use crate::util::path_display;

#[derive(Subcommand)]
pub(crate) enum SandboxCmd {
    /// Print advisory native sandbox suggestions for the active project.
    Advise {
        /// Emit a stable machine-readable advice report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct SandboxAdviceReport {
    status: &'static str,
    advisory_only: bool,
    home: String,
    expedition: Option<SandboxExpedition>,
    policy_version: String,
    policy_layers: Vec<SandboxPolicyLayer>,
    warning: String,
    suggestions: Vec<SandboxSuggestion>,
}

#[derive(Debug, Serialize)]
struct SandboxExpedition {
    name: String,
    root: String,
}

#[derive(Debug, Serialize)]
struct SandboxPolicyLayer {
    name: String,
    dir: String,
}

#[derive(Debug, Serialize)]
struct SandboxSuggestion {
    target: &'static str,
    command: String,
    notes: Vec<String>,
}

pub(crate) fn cmd_sandbox(sub: SandboxCmd, layout: HomeLayout) -> Result<ExitCode> {
    layout.ensure()?;
    match sub {
        SandboxCmd::Advise { json } => {
            let report = build_sandbox_advice(&layout)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_sandbox_advice(&report);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn build_sandbox_advice(layout: &HomeLayout) -> Result<SandboxAdviceReport> {
    let expedition = Expedition::load(&layout.expedition_file)?;
    let env = expedition
        .as_ref()
        .map(Expedition::policy_env)
        .unwrap_or_else(default_policy_env);
    let policy = load_active_policy(layout, expedition.as_ref(), &env)
        .context("loading active policy for sandbox advice")?;
    let layers = active_policy_layers(layout, expedition.as_ref())?;
    let project_root = expedition
        .as_ref()
        .map(|expedition| expedition.root.clone())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| layout.root.clone()));
    let root = path_display(&project_root);
    let suggestions = vec![
        SandboxSuggestion {
            target: "codex",
            command: "codex exec --sandbox workspace-write <task>".to_string(),
            notes: vec![
                "Codex sandboxing remains the OS-level authority for file and MCP tools."
                    .to_string(),
                "Use read-only for audit tasks and workspace-write only when the project tree should be writable."
                    .to_string(),
            ],
        },
        SandboxSuggestion {
            target: "bwrap",
            command: format!(
                "bwrap --ro-bind / / --bind {root} {root} --dev /dev --proc /proc --tmpfs /tmp <agent-command>"
            ),
            notes: vec![
                "Review device, network, and home-directory bindings before use.".to_string(),
                "This is a starting point, not a generated security profile.".to_string(),
            ],
        },
        SandboxSuggestion {
            target: "macos-seatbelt",
            command: format!(
                "sandbox-exec -p '(version 1)(allow default)(deny file-write*)(allow file-write* (subpath \"{root}\"))' <agent-command>"
            ),
            notes: vec![
                "Seatbelt profiles are host-specific and should be tested with the exact agent binary."
                    .to_string(),
                "Keep native agent approvals enabled even when using this wrapper.".to_string(),
            ],
        },
        SandboxSuggestion {
            target: "apparmor",
            command: format!("aa-genprof <agent-command> # then constrain writes to {root}"),
            notes: vec![
                "Use AppArmor tooling to review learned accesses before enforcing.".to_string(),
                "Do not treat this note as a complete profile.".to_string(),
            ],
        },
    ];

    Ok(SandboxAdviceReport {
        status: "pass",
        advisory_only: true,
        home: path_display(&layout.root),
        expedition: expedition.map(|expedition| SandboxExpedition {
            name: expedition.name,
            root: path_display(&expedition.root),
        }),
        policy_version: policy.version_hash,
        policy_layers: layers
            .into_iter()
            .map(|layer| SandboxPolicyLayer {
                name: layer.name,
                dir: path_display(&layer.dir),
            })
            .collect(),
        warning: "Gommage does not enforce OS confinement; these commands are advisory helpers for native sandbox layers.".to_string(),
        suggestions,
    })
}

fn print_sandbox_advice(report: &SandboxAdviceReport) {
    println!("sandbox advice: advisory only");
    println!("{}", report.warning);
    println!("policy version: {}", report.policy_version);
    for suggestion in &report.suggestions {
        println!();
        println!("{}:", suggestion.target);
        println!("  {}", suggestion.command);
        for note in &suggestion.notes {
            println!("  - {note}");
        }
    }
}
