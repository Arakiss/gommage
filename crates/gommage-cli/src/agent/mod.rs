use crate::{
    agent_status::cmd_agent_status,
    agent_uninstall::{AgentUninstallTarget, cmd_agent_uninstall},
    codex_config::enable_codex_hooks_feature,
    daemon::{recover_recorded_daemon_runtime, reload_policy_runtime},
    util::{
        InstallTransaction, TransactionFile, backup_and_remove_file, ensure_home, env_path_or_home,
        read_json_object, read_toml_document, write_json, write_text,
    },
};
use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use gommage_core::runtime::HomeLayout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, process::ExitCode};

pub(crate) const CODEX_GOMMAGE_MATCHER: &str = "*";
const LEGACY_CLAUDE_GOMMAGE_HOOK_COMMAND: &str = "gommage hook --agent claude";
const LEGACY_CODEX_GOMMAGE_HOOK_COMMAND: &str = "gommage hook --agent codex";

pub(crate) fn render_agent_hook_command(agent: AgentKind, layout: &HomeLayout) -> Result<String> {
    let canonical_home = canonical_install_home(layout)?;
    Ok(format!(
        "gommage --home {} hook --agent {}",
        shell_quote(&canonical_home.to_string_lossy()),
        agent.as_str()
    ))
}

pub(crate) fn legacy_agent_hook_command(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Claude => LEGACY_CLAUDE_GOMMAGE_HOOK_COMMAND,
        AgentKind::Codex => LEGACY_CODEX_GOMMAGE_HOOK_COMMAND,
    }
}

fn canonical_install_home(layout: &HomeLayout) -> Result<std::path::PathBuf> {
    match std::fs::symlink_metadata(&layout.root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Gommage home {} is a symbolic link", layout.root.display())
        }
        Ok(metadata) if metadata.is_dir() => std::fs::canonicalize(&layout.root)
            .with_context(|| format!("canonicalizing Gommage home {}", layout.root.display())),
        Ok(_) => anyhow::bail!("Gommage home {} is not a directory", layout.root.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = layout.root.parent().ok_or_else(|| {
                anyhow::anyhow!("Gommage home {} has no parent", layout.root.display())
            })?;
            let name = layout.root.file_name().ok_or_else(|| {
                anyhow::anyhow!("Gommage home {} has no file name", layout.root.display())
            })?;
            Ok(std::fs::canonicalize(parent)
                .with_context(|| {
                    format!("canonicalizing Gommage home parent {}", parent.display())
                })?
                .join(name))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspecting Gommage home {}", layout.root.display()))
        }
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub(crate) fn codex_pre_tool_use_path(root: &serde_json::Value) -> &'static [&'static str] {
    if root.pointer("/hooks/PreToolUse").is_some() {
        &["hooks", "PreToolUse"]
    } else {
        &["PreToolUse"]
    }
}

pub(crate) fn codex_pre_tool_use_pointer(root: &serde_json::Value) -> &'static str {
    if root.pointer("/hooks/PreToolUse").is_some() {
        "/hooks/PreToolUse"
    } else {
        "/PreToolUse"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Claude,
    Codex,
}

impl AgentKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentPolicyMode {
    Strict,
    Relaxed,
}

impl AgentPolicyMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
        }
    }
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Install a PreToolUse hook for a supported agent.
    Install {
        #[arg(value_enum)]
        agent: AgentKind,
        /// Replace existing PreToolUse hook groups instead of preserving them.
        #[arg(long)]
        replace_hooks: bool,
        /// Skip importing native agent permission rules into Gommage policy.
        #[arg(long)]
        no_import_native_permissions: bool,
        /// Install legacy broad allow rules. This weakens shell and file mediation.
        #[arg(long)]
        relaxed: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove only Gommage-owned hooks; shared agent feature flags are preserved.
    Uninstall {
        #[arg(value_enum)]
        agent: AgentUninstallTarget,
        /// Restore the newest validated .gommage-bak-* backup instead of only removing the hook.
        #[arg(long)]
        restore_backup: bool,
        /// Show planned file edits without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect whether a supported agent integration is wired correctly.
    Status {
        #[arg(value_enum)]
        agent: AgentKind,
        /// Emit a stable machine-readable status report.
        #[arg(long)]
        json: bool,
    },
}

pub fn cmd_agent(sub: AgentCmd, layout: HomeLayout) -> Result<ExitCode> {
    match sub {
        AgentCmd::Install {
            agent,
            replace_hooks,
            no_import_native_permissions,
            relaxed,
            dry_run,
        } => {
            let policy_mode = if relaxed {
                AgentPolicyMode::Relaxed
            } else {
                AgentPolicyMode::Strict
            };
            install_agents_transactional(
                &[agent],
                &layout,
                replace_hooks,
                !no_import_native_permissions,
                policy_mode,
                dry_run,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        AgentCmd::Uninstall {
            agent,
            restore_backup,
            dry_run,
        } => cmd_agent_uninstall(agent, &layout, restore_backup, dry_run),
        AgentCmd::Status { agent, json } => cmd_agent_status(agent, &layout, json),
    }
}

pub(crate) fn install_agents_transactional(
    agents: &[AgentKind],
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    policy_mode: AgentPolicyMode,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        return install_agents(
            agents,
            layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
            true,
        );
    }

    let mut transaction = InstallTransaction::begin(
        layout,
        agent_transaction_files(agents, layout),
        vec![
            layout.root.clone(),
            layout.policy_dir.clone(),
            layout.capabilities_dir.clone(),
        ],
    )?;
    if transaction.recovered_previous() {
        recover_recorded_daemon_runtime(&transaction, layout)?;
        reload_policy_runtime(layout)
            .context("restoring the runtime after an interrupted agent installation")?;
        transaction.acknowledge_recovery()?;
    }

    let result = install_agents(
        agents,
        layout,
        replace_hooks,
        import_native_permissions,
        policy_mode,
        false,
    )
    .and_then(|()| reload_policy_runtime(layout));
    match result {
        Ok(()) => match transaction.commit() {
            Ok(()) => Ok(()),
            Err(primary) => Err(rollback_agent_install(transaction, layout, primary)),
        },
        Err(primary) if !transaction.has_mutations() => {
            transaction.commit()?;
            Err(primary)
        }
        Err(primary) => Err(rollback_agent_install(transaction, layout, primary)),
    }
}

fn rollback_agent_install(
    mut transaction: InstallTransaction,
    layout: &HomeLayout,
    primary: anyhow::Error,
) -> anyhow::Error {
    let rollback = transaction.rollback();
    let reload = reload_policy_runtime(layout);
    let mut secondary = Vec::new();
    if let Err(error) = &rollback {
        secondary.push(format!("filesystem rollback failed: {error:#}"));
    }
    if let Err(error) = &reload {
        secondary.push(format!(
            "restoring the prior daemon policy failed: {error:#}"
        ));
    }
    if rollback.is_ok()
        && reload.is_ok()
        && let Err(error) = transaction.commit()
    {
        secondary.push(format!(
            "discarding the completed rollback journal failed: {error:#}"
        ));
    }
    if secondary.is_empty() {
        anyhow::anyhow!("{primary:#}; agent installation was rolled back")
    } else {
        anyhow::anyhow!(
            "{primary:#}; agent installation rollback was incomplete: {}",
            secondary.join("; ")
        )
    }
}

pub(crate) fn agent_transaction_files(
    agents: &[AgentKind],
    layout: &HomeLayout,
) -> Vec<TransactionFile> {
    let mut paths = vec![
        layout.key_file.clone(),
        layout.policy_dir.join("05-claude-import.yaml"),
        layout.policy_dir.join("06-agent-config-writable.yaml"),
        layout.policy_dir.join("90-claude-allow-import.yaml"),
        layout.policy_dir.join("95-agent-catch-all.yaml"),
    ];
    for agent in agents {
        match agent {
            AgentKind::Claude => paths.push(env_path_or_home(
                "GOMMAGE_CLAUDE_SETTINGS",
                &[".claude", "settings.json"],
            )),
            AgentKind::Codex => {
                paths.push(env_path_or_home(
                    "GOMMAGE_CODEX_HOOKS",
                    &[".codex", "hooks.json"],
                ));
                paths.push(env_path_or_home(
                    "GOMMAGE_CODEX_CONFIG",
                    &[".codex", "config.toml"],
                ));
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.into_iter().map(TransactionFile::new).collect()
}

/// Install one or more agent integrations as one recoverable local mutation.
///
/// Every config and reserved policy path is parsed and ownership-checked before
/// the first write. If a later filesystem operation fails, active files are
/// restored byte-for-byte and any backups created by the failed attempt are
/// removed. The daemon reload guard owned by the caller then reloads that
/// restored on-disk state.
pub(crate) fn install_agents(
    agents: &[AgentKind],
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    policy_mode: AgentPolicyMode,
    dry_run: bool,
) -> Result<()> {
    preflight_agent_installs(
        agents,
        layout,
        replace_hooks,
        import_native_permissions,
        policy_mode,
    )?;

    if dry_run {
        for agent in agents {
            apply_agent_install(
                *agent,
                layout,
                replace_hooks,
                import_native_permissions,
                policy_mode,
                true,
            )?;
        }
        return Ok(());
    }

    ensure_home(layout).context("initializing home")?;
    for agent in agents {
        apply_agent_install(
            *agent,
            layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
            false,
        )?;
    }
    Ok(())
}

pub(crate) fn preflight_agent_installs(
    agents: &[AgentKind],
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    policy_mode: AgentPolicyMode,
) -> Result<()> {
    for agent in agents {
        preflight_agent_install(
            *agent,
            layout,
            replace_hooks,
            import_native_permissions,
            policy_mode,
        )?;
    }
    Ok(())
}

fn apply_agent_install(
    agent: AgentKind,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    policy_mode: AgentPolicyMode,
    dry_run: bool,
) -> Result<()> {
    match agent {
        AgentKind::Claude => {
            let path = env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
            install_claude(
                &path,
                layout,
                replace_hooks,
                import_native_permissions,
                policy_mode == AgentPolicyMode::Relaxed,
                dry_run,
            )
        }
        AgentKind::Codex => {
            let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
            let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
            install_codex(&hooks_path, &config_path, layout, replace_hooks, dry_run)
        }
    }?;
    write_agent_posture_policy(layout, policy_mode, dry_run)
}

fn preflight_agent_install(
    agent: AgentKind,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    policy_mode: AgentPolicyMode,
) -> Result<()> {
    match agent {
        AgentKind::Claude => {
            let settings_path =
                env_path_or_home("GOMMAGE_CLAUDE_SETTINGS", &[".claude", "settings.json"]);
            let mut settings = read_json_object(&settings_path)?;
            if import_native_permissions {
                preflight_claude_permission_imports(&settings, layout, policy_mode)?;
            }
            let matcher = claude_gommage_matcher(&settings);
            let hook_command = render_agent_hook_command(AgentKind::Claude, layout)?;
            if !matcher.is_empty() {
                let group = serde_json::json!({
                    "matcher": matcher,
                    "hooks": [{
                        "type": "command",
                        "command": hook_command,
                        "timeout": 10
                    }]
                });
                install_json_hook_group(
                    &mut settings,
                    &["hooks", "PreToolUse"],
                    group,
                    replace_hooks,
                    AgentKind::Claude,
                )?;
            }
        }
        AgentKind::Codex => {
            let hooks_path = env_path_or_home("GOMMAGE_CODEX_HOOKS", &[".codex", "hooks.json"]);
            let config_path = env_path_or_home("GOMMAGE_CODEX_CONFIG", &[".codex", "config.toml"]);
            let mut hooks = read_json_object(&hooks_path)?;
            let hook_command = render_agent_hook_command(AgentKind::Codex, layout)?;
            let group = serde_json::json!({
                "matcher": CODEX_GOMMAGE_MATCHER,
                "hooks": [{
                    "type": "command",
                    "command": hook_command
                }]
            });
            let hook_path = codex_pre_tool_use_path(&hooks);
            install_json_hook_group(
                &mut hooks,
                hook_path,
                group,
                replace_hooks,
                AgentKind::Codex,
            )?;
            let mut config = read_toml_document(&config_path)?;
            enable_codex_hooks_feature(&mut config);
        }
    }
    preflight_agent_posture(layout, policy_mode)
}

/// `06-agent-config-writable.yaml` — loads before `10-filesystem` so the
/// blanket `fs.write:${HOME}/.*` deny (its glob `*` crosses `/`) cannot lock the
/// agent out of editing its OWN config dirs. Credential dirs stay denied by 10.
const AGENT_CARVE_OUT_YAML: &str = r#"# Agent-managed config dirs — writable carve-out.
#
# Generated by `gommage agent install`. Loads BEFORE 10-filesystem so the first
# match for each capability within the user layer makes these allows beat 10's
# `no-writes-to-home-dotfiles` blanket deny
# (`fs.write:${HOME}/.*`, whose glob `*` crosses `/` and would otherwise stop the
# agent from editing its own configuration under these dot-dirs).
#
# Scope is limited to the trees an agent legitimately owns. Credential dirs
# (.ssh/.aws/.gnupg) are NOT carved out here — 10-filesystem still denies them —
# and secret READS stay denied by the 05 import layer regardless of this file.

- name: agent-config-writable-claude
  decision: allow
  match:
    any_capability:
      - "fs.write:${HOME}/.claude/**"
  reason: "agent maintains its own Claude Code config under ~/.claude"

- name: agent-config-writable-codex
  decision: allow
  match:
    any_capability:
      - "fs.write:${HOME}/.codex/**"
  reason: "agent maintains its own Codex config under ~/.codex"

- name: agent-config-writable-gommage
  decision: allow
  match:
    any_capability:
      - "fs.write:${HOME}/.gommage/**"
  reason: "agent maintains its own Gommage policy home under ~/.gommage"
"#;

/// `95-agent-catch-all.yaml` — loads after every gate so they win first, then
/// flips the evaluator's fail-closed default: anything not stopped is allowed.
const AGENT_CATCH_ALL_YAML: &str = r#"# Catch-all allow — fail-open EXCEPT gates.
#
# Generated by `gommage agent install`. Loads AFTER every hard-stop, deny, and
# gate (00 hard-stops, 05 import denies, 10 filesystem, 15 agent-tools, 20 git,
# 30 pkg, 40 cloud, 50 cloud-tools), all of which win first. This flips the
# evaluator's built-in "no rule matched -> fail-closed deny": anything the layers
# above did not stop falls through to ALLOW here.
#
# Every Bash call always emits `proc.exec:<command>`, so `proc.exec:**` catches
# any shell the gates did not stop; Read/Glob -> fs.read, Write/Edit -> fs.write.
# Delete this file to return the agent to a strict fail-closed posture.

- name: agent-catch-all-proc-exec
  decision: allow
  match:
    any_capability:
      - "proc.exec:**"
  reason: "catch-all: shell not stopped by an earlier gate/deny is allowed"

- name: agent-catch-all-fs-read
  decision: allow
  match:
    any_capability:
      - "fs.read:**"
      - "fs.search:**"
  reason: "catch-all: reads/searches not denied by an earlier secret rule are allowed"

- name: agent-catch-all-fs-write
  decision: allow
  match:
    any_capability:
      - "fs.write:**"
  reason: "catch-all: writes not denied by an earlier dotfile/build rule are allowed"

- name: agent-catch-all-net-out
  decision: allow
  match:
    any_capability:
      - "net.out:**"
  reason: "catch-all: outbound network emitted alongside allowed ops is allowed"
"#;

/// Apply the selected agent policy posture.
///
/// Strict mode is the default and removes only recognized Gommage-generated
/// relaxation layers. Relaxed mode recreates the legacy broad allows, but only
/// after the operator selected it explicitly.
pub(crate) fn write_agent_posture_policy(
    layout: &HomeLayout,
    policy_mode: AgentPolicyMode,
    dry_run: bool,
) -> Result<()> {
    preflight_agent_posture(layout, policy_mode)?;
    if policy_mode == AgentPolicyMode::Strict {
        let removed = remove_generated_relaxation_layers(layout, dry_run)?;
        println!(
            "{} agent posture: strict ({} generated relaxation file(s) {})",
            if dry_run { "plan" } else { "ok" },
            removed,
            if dry_run {
                "would be removed"
            } else {
                "removed"
            }
        );
        return Ok(());
    }

    let files: &[(&str, &str)] = &[
        ("06-agent-config-writable.yaml", AGENT_CARVE_OUT_YAML),
        ("95-agent-catch-all.yaml", AGENT_CATCH_ALL_YAML),
    ];
    for (name, contents) in files {
        let path = layout.policy_dir.join(name);
        write_text(&path, contents, dry_run)?;
    }
    println!(
        "{} agent posture: relaxed with {} broad allow policy file(s) under {}",
        if dry_run { "plan" } else { "ok" },
        files.len(),
        layout.policy_dir.display()
    );
    println!(
        "warn relaxed posture permits shell, file, and outbound capabilities that strict mode denies; rerun without --relaxed to remove generated relaxations"
    );
    Ok(())
}

const GENERATED_RELAXATION_LAYERS: &[&str] = &[
    "06-agent-config-writable.yaml",
    "90-claude-allow-import.yaml",
    "95-agent-catch-all.yaml",
];

fn preflight_agent_posture(layout: &HomeLayout, policy_mode: AgentPolicyMode) -> Result<()> {
    let names: &[&str] = match policy_mode {
        AgentPolicyMode::Strict => GENERATED_RELAXATION_LAYERS,
        AgentPolicyMode::Relaxed => &["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"],
    };
    for name in names {
        let path = layout.policy_dir.join(name);
        if path.exists() && !is_generated_relaxation_layer(&path, name)? {
            anyhow::bail!(
                "{} is a custom or modified file at a Gommage-reserved policy path; move or review it before changing agent posture",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn is_generated_relaxation_layer(path: &Path, name: &str) -> Result<bool> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading reserved policy layer {}", path.display()))?;
    match name {
        "06-agent-config-writable.yaml" => Ok(raw == AGENT_CARVE_OUT_YAML),
        "90-claude-allow-import.yaml" => {
            is_generated_claude_permission_import_contents(&raw, ClaudeImportKind::Allow)
        }
        "95-agent-catch-all.yaml" => Ok(raw == AGENT_CATCH_ALL_YAML),
        _ => anyhow::bail!("unknown generated relaxation layer: {name}"),
    }
}

pub(crate) fn remove_generated_relaxation_layers(
    layout: &HomeLayout,
    dry_run: bool,
) -> Result<usize> {
    preflight_generated_relaxation_removal(layout)?;
    let mut removable = Vec::new();
    for name in GENERATED_RELAXATION_LAYERS {
        let path = layout.policy_dir.join(name);
        if !path.exists() {
            continue;
        }
        removable.push(path);
    }

    for path in &removable {
        if dry_run {
            println!(
                "plan backup and remove generated relaxation: {}",
                path.display()
            );
            continue;
        }
        backup_and_remove_file(path, false).with_context(|| {
            format!(
                "backing up and removing generated relaxation {}",
                path.display()
            )
        })?;
        println!("ok removed generated relaxation: {}", path.display());
    }
    Ok(removable.len())
}

pub(crate) fn preflight_generated_relaxation_removal(layout: &HomeLayout) -> Result<()> {
    for name in GENERATED_RELAXATION_LAYERS {
        let path = layout.policy_dir.join(name);
        if path.exists() && !is_generated_relaxation_layer(&path, name)? {
            anyhow::bail!(
                "{} is a custom file at a Gommage-reserved relaxation path; move or review it before installing strict posture",
                path.display()
            );
        }
    }
    Ok(())
}

mod integration;
mod native_permissions;

use integration::*;
pub(crate) use integration::{
    ClaudeImportKind, NativePermissionImport, is_generated_claude_permission_import,
    native_permission_rules, render_claude_permission_import, translate_claude_native_rules,
};
use native_permissions::*;
pub(crate) use native_permissions::{
    claude_gommage_matcher, hook_command_is_owned_by_gommage, translate_claude_permission_allow,
    translate_claude_permission_deny,
};

#[cfg(test)]
mod tests;
