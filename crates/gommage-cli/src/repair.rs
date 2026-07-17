use anyhow::Result;
use clap::Subcommand;
use gommage_core::runtime::HomeLayout;
use std::process::ExitCode;

use crate::{
    agent::{AgentKind, AgentPolicyMode, install_agents_transactional},
    agent_uninstall::{AgentUninstallTarget, uninstall_agent_target},
};

#[derive(Subcommand)]
pub(crate) enum RepairCmd {
    /// Repair host-agent hook wiring for old or broken Gommage alpha installs.
    Agent {
        #[arg(value_enum)]
        agent: AgentUninstallTarget,
        /// Restore newest .gommage-bak-* config backup instead of rewriting hooks.
        #[arg(long)]
        restore_backup: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },
}

pub(crate) fn cmd_repair(cmd: RepairCmd, layout: HomeLayout) -> Result<ExitCode> {
    match cmd {
        RepairCmd::Agent {
            agent,
            restore_backup,
            dry_run,
        } => repair_agent(agent, layout, restore_backup, dry_run),
    }
}

fn repair_agent(
    target: AgentUninstallTarget,
    layout: HomeLayout,
    restore_backup: bool,
    dry_run: bool,
) -> Result<ExitCode> {
    if restore_backup {
        uninstall_agent_target(target, &layout, true, dry_run)?;
        print_restore_next(target);
        return Ok(ExitCode::SUCCESS);
    }

    let agents = target_agents(target);
    install_agents_transactional(
        &agents,
        &layout,
        false,
        true,
        AgentPolicyMode::Strict,
        dry_run,
    )?;
    for agent in agents {
        println!(
            "next {}: gommage agent status {} --json",
            agent.as_str(),
            agent.as_str()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn target_agents(target: AgentUninstallTarget) -> Vec<AgentKind> {
    match target {
        AgentUninstallTarget::Claude => vec![AgentKind::Claude],
        AgentUninstallTarget::Codex => vec![AgentKind::Codex],
        AgentUninstallTarget::All => vec![AgentKind::Claude, AgentKind::Codex],
    }
}

fn print_restore_next(target: AgentUninstallTarget) {
    for agent in target_agents(target) {
        println!(
            "next {}: gommage agent status {} --json",
            agent.as_str(),
            agent.as_str()
        );
    }
}
