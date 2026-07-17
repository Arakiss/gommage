use super::*;

pub(super) fn install_claude(
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

pub(super) fn install_codex(
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

pub(super) fn import_claude_permissions(
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

pub(super) fn preflight_claude_permission_imports(
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
    pub(super) raw: String,
    pub(super) capability: String,
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
pub(super) struct GeneratedImportRule {
    name: String,
    decision: String,
    #[serde(rename = "match")]
    matcher: GeneratedImportMatch,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GeneratedImportMatch {
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

pub(super) fn sync_claude_permission_import(
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

pub(super) fn preflight_claude_permission_import_path(
    path: &Path,
    kind: ClaudeImportKind,
) -> Result<()> {
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

pub(super) fn is_generated_claude_permission_import_contents(
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

pub(super) fn backup_and_remove_generated_policy(path: &Path, dry_run: bool) -> Result<()> {
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
