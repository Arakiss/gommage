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

fn install_claude(
    settings_path: &Path,
    layout: &HomeLayout,
    replace_hooks: bool,
    import_native_permissions: bool,
    import_native_allows: bool,
    dry_run: bool,
) -> Result<()> {
    let mut settings = read_json_object(settings_path)?;
    if import_native_permissions {
        import_claude_permissions(&settings, layout, import_native_allows, dry_run)?;
    }

    let matcher = claude_gommage_matcher(&settings);
    if matcher.is_empty() {
        println!("warn claude: no currently allowed Claude tools have Gommage capability mappers");
        return Ok(());
    }

    let hook_command = render_agent_hook_command(AgentKind::Claude, layout)?;
    let group = serde_json::json!({
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": 10
            }
        ]
    });
    install_json_hook_group(
        &mut settings,
        &["hooks", "PreToolUse"],
        group,
        replace_hooks,
        AgentKind::Claude,
    )?;

    write_json(settings_path, &settings, dry_run)?;
    println!(
        "ok claude: PreToolUse hook installed at {}",
        settings_path.display()
    );
    Ok(())
}

fn install_codex(
    hooks_path: &Path,
    config_path: &Path,
    layout: &HomeLayout,
    replace_hooks: bool,
    dry_run: bool,
) -> Result<()> {
    let mut hooks = read_json_object(hooks_path)?;
    let hook_command = render_agent_hook_command(AgentKind::Codex, layout)?;
    let group = serde_json::json!({
        "matcher": CODEX_GOMMAGE_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": hook_command
            }
        ]
    });
    let hook_path = codex_pre_tool_use_path(&hooks);
    install_json_hook_group(
        &mut hooks,
        hook_path,
        group,
        replace_hooks,
        AgentKind::Codex,
    )?;
    write_json(hooks_path, &hooks, dry_run)?;
    println!(
        "ok codex: PreToolUse hook installed at {}",
        hooks_path.display()
    );

    let mut config = read_toml_document(config_path)?;
    let sandbox_mode = config
        .get("sandbox_mode")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    enable_codex_hooks_feature(&mut config);
    write_text(config_path, &config.to_string(), dry_run)?;
    println!(
        "ok codex: features.hooks enabled at {}",
        config_path.display()
    );
    if sandbox_mode.as_deref() == Some("danger-full-access") {
        println!(
            "warn codex: sandbox_mode is danger-full-access; Gommage's default Codex integration governs supported hook events only, so keep Codex sandboxing enabled for other tool boundaries"
        );
    }
    println!(
        "warn codex: native sandbox/approval config remains authoritative and is not converted to Gommage YAML"
    );
    Ok(())
}

fn import_claude_permissions(
    settings: &serde_json::Value,
    layout: &HomeLayout,
    import_allows: bool,
    dry_run: bool,
) -> Result<()> {
    let deny_path = layout.policy_dir.join("05-claude-import.yaml");
    let deny_rules = native_permission_rules(settings, "/permissions/deny");
    let (translated_denies, skipped_denies) =
        translate_claude_native_rules(&deny_rules, translate_claude_permission_deny);
    sync_claude_permission_import(
        &deny_path,
        ClaudeImportKind::Deny,
        &translated_denies,
        dry_run,
    )?;
    if translated_denies.is_empty() {
        println!("warn claude: no importable native deny rules found");
    }
    if !skipped_denies.is_empty() {
        println!(
            "warn claude: skipped {} native deny rule(s) that need manual policy review",
            skipped_denies.len()
        );
    }

    if !import_allows {
        println!("ok claude: native allow permissions remain outside strict Gommage policy");
        return Ok(());
    }

    let allow_rules = native_permission_rules(settings, "/permissions/allow");
    let (translated_allows, skipped_allows) =
        translate_claude_native_rules(&allow_rules, translate_claude_permission_allow);
    let allow_path = layout.policy_dir.join("90-claude-allow-import.yaml");
    sync_claude_permission_import(
        &allow_path,
        ClaudeImportKind::Allow,
        &translated_allows,
        dry_run,
    )?;
    if translated_allows.is_empty() {
        println!("warn claude: no narrow native allow rules were imported");
    }
    if !skipped_allows.is_empty() {
        println!(
            "warn claude: skipped {} native allow rule(s) that need manual policy review",
            skipped_allows.len()
        );
    }
    Ok(())
}

fn preflight_claude_permission_imports(
    settings: &serde_json::Value,
    layout: &HomeLayout,
    policy_mode: AgentPolicyMode,
) -> Result<()> {
    let deny_rules = native_permission_rules(settings, "/permissions/deny");
    let (translated_denies, _) =
        translate_claude_native_rules(&deny_rules, translate_claude_permission_deny);
    render_claude_permission_import(ClaudeImportKind::Deny, &translated_denies)?;
    preflight_claude_permission_import_path(
        &layout.policy_dir.join("05-claude-import.yaml"),
        ClaudeImportKind::Deny,
    )?;

    if policy_mode == AgentPolicyMode::Relaxed {
        let allow_rules = native_permission_rules(settings, "/permissions/allow");
        let (translated_allows, _) =
            translate_claude_native_rules(&allow_rules, translate_claude_permission_allow);
        render_claude_permission_import(ClaudeImportKind::Allow, &translated_allows)?;
        preflight_claude_permission_import_path(
            &layout.policy_dir.join("90-claude-allow-import.yaml"),
            ClaudeImportKind::Allow,
        )?;
    }
    Ok(())
}

pub(crate) struct NativePermissionImport {
    raw: String,
    capability: String,
}

pub(crate) fn native_permission_rules(settings: &serde_json::Value, pointer: &str) -> Vec<String> {
    settings
        .pointer(pointer)
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

pub(crate) fn translate_claude_native_rules(
    rules: &[String],
    translate: fn(&str) -> Option<String>,
) -> (Vec<NativePermissionImport>, Vec<String>) {
    let mut translated = Vec::new();
    let mut skipped = Vec::new();
    for raw in rules {
        match translate(raw) {
            Some(capability) => translated.push(NativePermissionImport {
                raw: raw.clone(),
                capability,
            }),
            None => skipped.push(raw.clone()),
        }
    }
    (translated, skipped)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeImportKind {
    Deny,
    Allow,
}

impl ClaudeImportKind {
    fn source_label(self) -> &'static str {
        match self {
            Self::Deny => "Claude Code permissions.deny",
            Self::Allow => "Claude Code permissions.allow",
        }
    }

    fn ordering_note(self) -> &'static str {
        match self {
            Self::Deny => {
                "Deny imports live before stdlib allow rules so native blocks remain fail-closed."
            }
            Self::Allow => {
                "Allow imports load late so Gommage hard-stop, deny, and ask rules win first."
            }
        }
    }

    fn name_prefix(self) -> &'static str {
        match self {
            Self::Deny => "claude-import-deny",
            Self::Allow => "claude-import-allow",
        }
    }

    fn decision(self) -> &'static str {
        match self {
            Self::Deny => "gommage",
            Self::Allow => "allow",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedImportRule {
    name: String,
    decision: String,
    #[serde(rename = "match")]
    matcher: GeneratedImportMatch,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedImportMatch {
    any_capability: Vec<String>,
}

pub(crate) fn render_claude_permission_import(
    kind: ClaudeImportKind,
    translated: &[NativePermissionImport],
) -> Result<Option<String>> {
    if translated.is_empty() {
        return Ok(None);
    }

    let grouped = group_native_permission_imports(translated);
    let mut body = String::new();
    for (index, imported) in grouped.iter().enumerate() {
        body.push_str(&format!(
            "- name: {}-{:02}\n",
            kind.name_prefix(),
            index + 1
        ));
        body.push_str(&format!("  decision: {}\n", kind.decision()));
        body.push_str("  match:\n");
        body.push_str("    any_capability:\n");
        body.push_str(&format!(
            "      - {}\n",
            serde_json::to_string(&imported.capability)?
        ));
        body.push_str(&format!(
            "  reason: {}\n\n",
            serde_json::to_string(&format!(
                "imported from {}: {}",
                kind.source_label(),
                imported.raws.join(", ")
            ))?
        ));
    }

    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    Ok(Some(format!(
        "# Generated by `gommage quickstart` from {}.\n# Review before sharing; native permission syntax is broader than Gommage capabilities.\n# {}\n# Generated content SHA-256: {digest}\n\n{body}",
        kind.source_label(),
        kind.ordering_note(),
    )))
}

fn sync_claude_permission_import(
    import_path: &Path,
    kind: ClaudeImportKind,
    translated: &[NativePermissionImport],
    dry_run: bool,
) -> Result<()> {
    preflight_claude_permission_import_path(import_path, kind)?;
    let desired = render_claude_permission_import(kind, translated)?;
    if let Some(yaml) = desired {
        let changed = !import_path.exists() || std::fs::read_to_string(import_path)? != yaml;
        write_text(import_path, &yaml, dry_run)?;
        println!(
            "ok claude: {} {} native rule(s) as {} capability rule(s) in {}",
            if changed { "synchronized" } else { "verified" },
            translated.len(),
            group_native_permission_imports(translated).len(),
            import_path.display()
        );
        return Ok(());
    }

    if import_path.exists() {
        backup_and_remove_generated_policy(import_path, dry_run)?;
        println!(
            "{} claude: removed stale generated permission import {}",
            if dry_run { "plan" } else { "ok" },
            import_path.display()
        );
    }
    Ok(())
}

fn preflight_claude_permission_import_path(path: &Path, kind: ClaudeImportKind) -> Result<()> {
    if path.exists() && !is_generated_claude_permission_import(path, kind)? {
        anyhow::bail!(
            "{} is custom or modified at a Gommage-reserved import path; move or review it before synchronizing native permissions",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn is_generated_claude_permission_import(
    path: &Path,
    kind: ClaudeImportKind,
) -> Result<bool> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading generated import candidate {}", path.display()))?;
    is_generated_claude_permission_import_contents(&raw, kind)
}

fn is_generated_claude_permission_import_contents(
    raw: &str,
    kind: ClaudeImportKind,
) -> Result<bool> {
    let legacy_header = format!(
        "# Generated by `gommage quickstart` from {}.\n# Review before sharing; native permission syntax is broader than Gommage capabilities.\n# {}\n",
        kind.source_label(),
        kind.ordering_note(),
    );
    let Some(mut remainder) = raw.strip_prefix(&legacy_header) else {
        return Ok(false);
    };

    if let Some(after_label) = remainder.strip_prefix("# Generated content SHA-256: ") {
        let Some((digest, body)) = after_label.split_once("\n\n") else {
            return Ok(false);
        };
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !digest.eq_ignore_ascii_case(&hex::encode(Sha256::digest(body.as_bytes())))
        {
            return Ok(false);
        }
        remainder = body;
    } else {
        // Digest-less legacy imports cannot prove which exact bytes Gommage
        // last generated. Treat them as operator-owned and require review.
        return Ok(false);
    }

    let rules: Vec<GeneratedImportRule> = match serde_yaml::from_str(remainder) {
        Ok(rules) => rules,
        Err(_) => return Ok(false),
    };
    if rules.is_empty() {
        return Ok(false);
    }
    for (index, rule) in rules.iter().enumerate() {
        if rule.name != format!("{}-{:02}", kind.name_prefix(), index + 1)
            || rule.decision != kind.decision()
            || rule.matcher.any_capability.len() != 1
            || rule.matcher.any_capability[0].is_empty()
            || !rule
                .reason
                .starts_with(&format!("imported from {}: ", kind.source_label()))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn backup_and_remove_generated_policy(path: &Path, dry_run: bool) -> Result<()> {
    if dry_run {
        println!(
            "plan backup and remove generated policy: {}",
            path.display()
        );
        return Ok(());
    }
    backup_and_remove_file(path, false).with_context(|| {
        format!(
            "backing up and removing generated policy {}",
            path.display()
        )
    })?;
    Ok(())
}

struct NativePermissionImportGroup {
    capability: String,
    raws: Vec<String>,
}

fn group_native_permission_imports(
    translated: &[NativePermissionImport],
) -> Vec<NativePermissionImportGroup> {
    let mut groups: Vec<NativePermissionImportGroup> = Vec::new();
    for imported in translated {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.capability == imported.capability)
        {
            group.raws.push(imported.raw.clone());
        } else {
            groups.push(NativePermissionImportGroup {
                capability: imported.capability.clone(),
                raws: vec![imported.raw.clone()],
            });
        }
    }
    groups
}

pub(crate) fn translate_claude_permission_deny(raw: &str) -> Option<String> {
    translate_claude_permission_specifier(raw)
}

pub(crate) fn translate_claude_permission_allow(raw: &str) -> Option<String> {
    translate_claude_permission_specifier(raw)
}

fn translate_claude_permission_specifier(raw: &str) -> Option<String> {
    if let Some((tool, value)) = raw.split_once('(') {
        let value = value.strip_suffix(')')?;
        let capability = match tool {
            "Read" | "Glob" => format!("fs.read:{}", normalize_native_path_pattern(value)),
            "Grep" => format!("fs.search:{}", normalize_native_path_pattern(value)),
            "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
                format!("fs.write:{}", normalize_native_path_pattern(value))
            }
            "Bash" => format!("proc.exec:{}", normalize_bash_permission_pattern(value)),
            "WebFetch" => format!(
                "net.fetch:{}",
                value.strip_prefix("domain:").unwrap_or(value)
            ),
            tool if tool.starts_with("mcp__") => format!("mcp.call:{tool}"),
            _ => return None,
        };
        return Some(capability);
    }

    let capability = match raw {
        "*" => "**".to_string(),
        "Read" | "Glob" => "fs.read:**".to_string(),
        "Grep" => "fs.search:**".to_string(),
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "fs.write:**".to_string(),
        "Bash" => "proc.exec:*".to_string(),
        "WebFetch" => "net.fetch:*".to_string(),
        "WebSearch" => "net.search:web".to_string(),
        tool if tool.starts_with("mcp__") && tool.matches("__").count() >= 2 => {
            format!("mcp.call:{tool}")
        }
        _ => return None,
    };
    Some(capability)
}

fn normalize_native_path_pattern(raw: &str) -> String {
    if raw == "*" || raw == "**" {
        "**".to_string()
    } else if raw == "~" {
        "${HOME}".to_string()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        format!("${{HOME}}/{rest}")
    } else if raw == "." || raw == "./" {
        "${EXPEDITION_ROOT}/**".to_string()
    } else if let Some(rest) = raw.strip_prefix("./") {
        format!("${{EXPEDITION_ROOT}}/{rest}")
    } else {
        raw.to_string()
    }
}

fn normalize_bash_permission_pattern(raw: &str) -> String {
    raw.replace(":*", "*")
}

pub(crate) fn claude_gommage_matcher(_settings: &serde_json::Value) -> String {
    "*".to_string()
}

fn install_json_hook_group(
    root: &mut serde_json::Value,
    path: &[&str],
    group: serde_json::Value,
    replace_hooks: bool,
    agent: AgentKind,
) -> Result<()> {
    let canonical_command = group
        .pointer("/hooks/0/command")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let pre_tool_use = ensure_array_path(root, path)?;
    if replace_hooks {
        pre_tool_use.clear();
    } else {
        remove_owned_hook_commands(pre_tool_use, agent, canonical_command.as_deref());
        if !pre_tool_use.is_empty() {
            println!(
                "warn {}: preserving existing PreToolUse hook group(s); use --replace-hooks to let Gommage own the hook surface",
                agent.as_str()
            );
        }
    }
    pre_tool_use.push(group);
    Ok(())
}

fn ensure_array_path<'a>(
    root: &'a mut serde_json::Value,
    path: &[&str],
) -> Result<&'a mut Vec<serde_json::Value>> {
    let mut current = root;
    for key in &path[..path.len() - 1] {
        if !current.is_object() {
            anyhow::bail!("expected JSON object while creating {key}");
        }
        let object = current.as_object_mut().expect("checked object");
        current = object
            .entry((*key).to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let key = path[path.len() - 1];
    if !current.is_object() {
        anyhow::bail!("expected JSON object while creating {key}");
    }
    let value = current
        .as_object_mut()
        .expect("checked object")
        .entry(key.to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !value.is_array() {
        anyhow::bail!("{key} exists but is not an array");
    }
    Ok(value.as_array_mut().expect("checked array"))
}

fn remove_owned_hook_commands(
    groups: &mut Vec<serde_json::Value>,
    agent: AgentKind,
    canonical_command: Option<&str>,
) {
    groups.retain_mut(|entry| {
        let Some(hooks) = entry
            .get_mut("hooks")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return true;
        };
        hooks.retain(|hook| {
            !hook
                .get("command")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|command| {
                    hook_command_is_owned_by_gommage(command, agent, canonical_command)
                })
        });
        !hooks.is_empty()
    });
}

pub(crate) fn hook_command_is_owned_by_gommage(
    command: &str,
    agent: AgentKind,
    canonical_command: Option<&str>,
) -> bool {
    let command = command.trim();
    if canonical_command.is_some_and(|expected| command == expected.trim())
        || command == legacy_agent_hook_command(agent)
    {
        return true;
    }

    let Some(words) = simple_shell_command_words(command) else {
        return false;
    };
    let mut command_index = 0;
    while words
        .get(command_index)
        .is_some_and(|word| is_shell_assignment(word))
    {
        command_index += 1;
    }
    let Some(executable) = words.get(command_index) else {
        return false;
    };
    let executable_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    if executable_name == "gommage-mcp" {
        return true;
    }
    if agent == AgentKind::Codex && executable_name == "gommage-codex-pretooluse.sh" {
        return true;
    }
    if executable_name != "gommage" {
        return false;
    }

    let mut args = &words[command_index + 1..];
    if matches!(args, [home, ..] if home.starts_with("--home=")) {
        args = &args[1..];
    } else if args.len() >= 2 && args.first().is_some_and(|arg| arg == "--home") {
        args = &args[2..];
    }
    match args.first().map(String::as_str) {
        Some("mcp") => true,
        Some("hook") => {
            args.windows(2).any(|pair| {
                pair.first().map(String::as_str) == Some("--agent")
                    && pair.get(1).map(String::as_str) == Some(agent.as_str())
            }) || args
                .iter()
                .any(|arg| arg == &format!("--agent={}", agent.as_str()))
        }
        _ => false,
    }
}

fn is_shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn simple_shell_command_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                _ => current.push(ch),
            },
            Some(_) => unreachable!(),
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => escaped = true,
                // A compound shell expression is not wholly owned by Gommage,
                // even when its first command is. Preserve the hook rather
                // than deleting operator-provided work after a separator.
                ';' | '|' | '&' | '\n' | '\r' => return None,
                _ if ch.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_hook_parser_handles_escaped_arguments_conservatively() {
        assert!(hook_command_is_owned_by_gommage(
            r"gommage --home /tmp/gommage\ home hook --agent claude",
            AgentKind::Claude,
            None,
        ));
        assert!(!hook_command_is_owned_by_gommage(
            r"echo\ gommage hook --agent claude",
            AgentKind::Claude,
            None,
        ));
        assert!(!hook_command_is_owned_by_gommage(
            "gommage hook --agent claude && operator-command",
            AgentKind::Claude,
            None,
        ));
    }

    #[test]
    fn broad_write_native_permissions_collapse_to_one_capability() {
        let rules = vec![
            "Write".to_string(),
            "Edit".to_string(),
            "NotebookEdit(*)".to_string(),
            "MultiEdit(**)".to_string(),
        ];

        let (translated, skipped) =
            translate_claude_native_rules(&rules, translate_claude_permission_allow);
        let grouped = group_native_permission_imports(&translated);

        assert!(skipped.is_empty());
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].capability, "fs.write:**");
        assert_eq!(
            grouped[0].raws,
            vec!["Write", "Edit", "NotebookEdit(*)", "MultiEdit(**)"]
        );
    }

    #[test]
    fn native_star_path_is_normalized_to_recursive_glob() {
        assert_eq!(
            translate_claude_permission_allow("Read(*)").as_deref(),
            Some("fs.read:**")
        );
        assert_eq!(
            translate_claude_permission_allow("Write(*)").as_deref(),
            Some("fs.write:**")
        );
    }

    #[test]
    fn agent_install_generates_posture_policy_that_parses() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(tmp.path());
        layout.ensure().unwrap();

        write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();

        for name in ["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"] {
            assert!(
                layout.policy_dir.join(name).exists(),
                "expected generated posture file {name}"
            );
        }

        let mut env = std::collections::HashMap::new();
        env.insert("HOME".to_string(), "/home/test".to_string());
        env.insert("EXPEDITION_ROOT".to_string(), "/home/test/proj".to_string());
        let policy = gommage_core::Policy::load_from_dir(&layout.policy_dir, &env).unwrap();

        for rule in [
            "agent-config-writable-claude",
            "agent-config-writable-gommage",
            "agent-catch-all-proc-exec",
            "agent-catch-all-fs-write",
        ] {
            assert!(
                policy.rules.iter().any(|r| r.name == rule),
                "expected posture rule {rule}"
            );
        }
    }

    #[test]
    fn agent_posture_dry_run_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(tmp.path());
        layout.ensure().unwrap();

        write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, true).unwrap();

        assert!(
            !layout.policy_dir.join("95-agent-catch-all.yaml").exists(),
            "dry-run must not write posture files"
        );
    }

    #[test]
    fn strict_posture_backs_up_and_removes_generated_relaxations() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(tmp.path());
        layout.ensure().unwrap();
        write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();

        write_agent_posture_policy(&layout, AgentPolicyMode::Strict, false).unwrap();

        for name in ["06-agent-config-writable.yaml", "95-agent-catch-all.yaml"] {
            assert!(!layout.policy_dir.join(name).exists(), "active {name}");
            let prefix = format!("{name}.gommage-bak-");
            assert!(
                std::fs::read_dir(&layout.policy_dir)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .any(|candidate| candidate.starts_with(&prefix)),
                "missing backup for {name}"
            );
        }
    }

    #[test]
    fn strict_posture_preserves_all_files_when_a_reserved_layer_is_custom() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = HomeLayout::at(tmp.path());
        layout.ensure().unwrap();
        write_agent_posture_policy(&layout, AgentPolicyMode::Relaxed, false).unwrap();
        let custom = layout.policy_dir.join("90-claude-allow-import.yaml");
        std::fs::write(&custom, "# operator-owned\n[]\n").unwrap();

        let error = write_agent_posture_policy(&layout, AgentPolicyMode::Strict, false)
            .expect_err("custom reserved layer must block strict migration");

        assert!(error.to_string().contains("custom or modified file"));
        assert_eq!(
            std::fs::read_to_string(&custom).unwrap(),
            "# operator-owned\n[]\n"
        );
        assert!(
            layout
                .policy_dir
                .join("06-agent-config-writable.yaml")
                .exists()
        );
        assert!(layout.policy_dir.join("95-agent-catch-all.yaml").exists());
    }
}
