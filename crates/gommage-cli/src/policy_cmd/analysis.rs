use super::*;

pub(crate) fn build_policy_test_report(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
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
        load_active_policy(layout, expedition, env).context("loading policy for policy test")?;

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

pub(super) fn build_policy_lint_report(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
    env: &HashMap<String, String>,
    file: Option<&Path>,
    strict: bool,
) -> Result<PolicyLintReport> {
    let target = file.map(Path::to_path_buf);
    let (target_display, compiled_policy, files) = if let Some(target) = target {
        let compiled_policy = if target.is_file() {
            let raw = std::fs::read_to_string(&target)
                .with_context(|| format!("reading policy file {}", target.display()))?;
            Policy::from_yaml_string(&raw, env, &target.to_string_lossy())
                .with_context(|| format!("linting policy file {}", target.display()))?
        } else {
            Policy::load_from_dir(&target, env)
                .with_context(|| format!("linting policy directory {}", target.display()))?
        };
        let files = collect_policy_files(&target)?;
        (path_display(&target), compiled_policy, files)
    } else {
        let layers = active_policy_layers(layout, expedition)?;
        let compiled_policy =
            Policy::load_from_layers(&layers, env).context("linting active policy layers")?;
        let mut files = Vec::new();
        for layer in &layers {
            files.extend(collect_policy_files(&layer.dir)?);
        }
        ("active policy layers".to_string(), compiled_policy, files)
    };
    let records = parse_raw_policy_rules(&files, env)?;
    let mut issues = Vec::new();
    if strict {
        collect_strict_policy_issues(&records, &mut issues);
    }
    let summary = summarize_policy_lint_issues(&issues);

    Ok(PolicyLintReport {
        status: if summary.errors == 0 {
            SmokeStatus::Pass
        } else {
            SmokeStatus::Fail
        },
        target: target_display,
        strict,
        files: files.len(),
        rules: compiled_policy.rules.len(),
        summary,
        issues,
    })
}

pub(super) fn collect_policy_files(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    let mut files = Vec::new();
    if target.exists() {
        for entry in std::fs::read_dir(target)
            .with_context(|| format!("reading policy directory {}", target.display()))?
        {
            let path = entry?.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "yaml" || extension == "yml")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn parse_raw_policy_rules(
    files: &[PathBuf],
    env: &HashMap<String, String>,
) -> Result<Vec<RawPolicyRuleRecord>> {
    let mut records = Vec::new();
    for file in files {
        let raw = std::fs::read_to_string(file)
            .with_context(|| format!("reading policy file {}", file.display()))?;
        let substituted = substitute_env(&raw, env)
            .with_context(|| format!("substituting policy variables in {}", file.display()))?;
        let rules: Vec<RawRule> = serde_yaml::from_str(&substituted)
            .with_context(|| format!("parsing policy file {}", file.display()))?;
        for (index, rule) in rules.into_iter().enumerate() {
            records.push(RawPolicyRuleRecord {
                file: file.clone(),
                file_display: path_display(file),
                index,
                rule,
            });
        }
    }
    Ok(records)
}

pub(super) fn collect_strict_policy_issues(
    records: &[RawPolicyRuleRecord],
    issues: &mut Vec<PolicyLintIssue>,
) {
    if records.is_empty() {
        issues.push(PolicyLintIssue {
            severity: PolicyLintSeverity::Error,
            code: "no_policy_rules",
            message: "strict lint requires at least one policy rule".to_string(),
            file: "<policy>".to_string(),
            rule_name: None,
            rule_index: None,
        });
        return;
    }

    let mut names: HashMap<String, (String, usize)> = HashMap::new();
    let mut match_keys: HashMap<String, (String, String, usize)> = HashMap::new();
    for record in records {
        if record.rule.name.trim().is_empty() {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Error,
                "empty_rule_name",
                "rule name must not be empty".to_string(),
                record,
            );
        }
        if let Some((file, index)) = names.insert(
            record.rule.name.clone(),
            (record.file_display.clone(), record.index),
        ) {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Error,
                "duplicate_rule_name",
                format!("rule name duplicates an earlier rule at {file}:{index}"),
                record,
            );
        }
        if record.rule.reason.trim().is_empty() {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Warning,
                "missing_reason",
                "strict lint expects a human review reason".to_string(),
                record,
            );
        }
        if match_is_empty(&record.rule.r#match) {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Error,
                "empty_match",
                "rule has no match clauses and would match every capability set".to_string(),
                record,
            );
        }
        for pattern in all_match_patterns(&record.rule.r#match) {
            if pattern.trim().is_empty() {
                push_lint_issue(
                    issues,
                    PolicyLintSeverity::Error,
                    "empty_capability_pattern",
                    "capability patterns must not be empty".to_string(),
                    record,
                );
            }
        }
        if record
            .rule
            .required_scope
            .as_ref()
            .is_some_and(|scope| scope.trim().is_empty())
        {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Error,
                "empty_required_scope",
                "ask_picto required_scope must not be empty".to_string(),
                record,
            );
        }

        let match_key = serde_json::to_string(&record.rule.r#match)
            .expect("RawMatch serialization is infallible");
        if let Some((name, file, index)) = match_keys.insert(
            match_key,
            (
                record.rule.name.clone(),
                record.file_display.clone(),
                record.index,
            ),
        ) {
            push_lint_issue(
                issues,
                PolicyLintSeverity::Error,
                "duplicate_match_shadowed",
                format!(
                    "same match clauses already appear on rule {name} at {file}:{index}; first match wins"
                ),
                record,
            );
        }
    }
}

pub(super) fn push_lint_issue(
    issues: &mut Vec<PolicyLintIssue>,
    severity: PolicyLintSeverity,
    code: &'static str,
    message: String,
    record: &RawPolicyRuleRecord,
) {
    issues.push(PolicyLintIssue {
        severity,
        code,
        message,
        file: record.file.to_string_lossy().to_string(),
        rule_name: Some(record.rule.name.clone()),
        rule_index: Some(record.index),
    });
}

pub(super) fn match_is_empty(raw_match: &RawMatch) -> bool {
    raw_match.any_capability.is_empty()
        && raw_match.all_capability.is_empty()
        && raw_match.none_capability.is_empty()
}

pub(super) fn all_match_patterns(raw_match: &RawMatch) -> impl Iterator<Item = &String> {
    raw_match
        .any_capability
        .iter()
        .chain(raw_match.all_capability.iter())
        .chain(raw_match.none_capability.iter())
}

pub(super) fn summarize_policy_lint_issues(issues: &[PolicyLintIssue]) -> PolicyLintSummary {
    let mut summary = PolicyLintSummary::default();
    for issue in issues {
        match issue.severity {
            PolicyLintSeverity::Error => summary.errors += 1,
            PolicyLintSeverity::Warning => summary.warnings += 1,
        }
    }
    summary
}

pub(super) fn print_policy_lint_report(report: &PolicyLintReport) {
    println!("Gommage policy lint");
    println!("status: {}", report.status.as_str());
    println!("target: {}", report.target);
    println!("strict: {}", report.strict);
    println!("files: {}", report.files);
    println!("rules: {}", report.rules);
    if report.issues.is_empty() {
        println!("issues: none");
    } else {
        println!("issues:");
        for issue in &report.issues {
            println!(
                "  - {} {} {}:{} {}",
                issue.severity.as_str(),
                issue.code,
                issue.file,
                issue.rule_index.unwrap_or(0),
                issue.message
            );
        }
    }
    println!(
        "summary: {} error(s), {} warning(s)",
        report.summary.errors, report.summary.warnings
    );
}

pub(super) fn print_policy_suggest_report(report: &PolicySuggestReport) {
    println!("Gommage policy suggest");
    println!("status: {}", report.status.as_str());
    println!("audit: {}", report.audit);
    println!("home: {}", report.home);
    println!("active_policy_version: {}", report.active_policy_version);
    println!("mutated: {}", report.mutated);
    println!(
        "summary: {} decision(s), {} suggestion(s), {} evidence item(s), {} covered by active policy, {} empty-capability decision(s), {} event(s) skipped",
        report.summary.decisions,
        report.summary.suggestions,
        report.summary.evidence,
        report.summary.covered_by_active_policy,
        report.summary.skipped_empty_capabilities,
        report.summary.skipped_events
    );
    if report.suggestions.is_empty() {
        println!("suggestions: none");
        return;
    }

    println!("suggestions:");
    for suggestion in &report.suggestions {
        println!(
            "  - {} [{}; review_required={}] {} evidence item(s)",
            suggestion.id,
            decision_summary(&suggestion.evidence[0].audited_decision),
            suggestion.review_required,
            suggestion.evidence.len()
        );
        println!("    rule_yaml: included");
        println!(
            "    fixture: draft included; usable={}; input_available={}",
            suggestion.fixture_case.usable, suggestion.fixture_case.input_available
        );
        for warning in &suggestion.warnings {
            println!("    warning: {warning}");
        }
    }
}

pub(crate) fn print_policy_test_report(report: &PolicyTestReport) {
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

pub(super) fn build_policy_layer_report(
    layout: &HomeLayout,
    expedition: Option<&Expedition>,
    env: &HashMap<String, String>,
) -> Result<PolicyLayerReport> {
    let layers = active_policy_layers(layout, expedition)?;
    let policy = Policy::load_from_layers(&layers, env).context("loading active policy layers")?;
    let mut entries = Vec::new();
    for layer in layers {
        let files = collect_policy_files(&layer.dir)?;
        let records = parse_raw_policy_rules(&files, env)?;
        entries.push(PolicyLayerEntry {
            name: layer.name().to_string(),
            dir: path_display(&layer.dir),
            files: files.len(),
            rules: records.len(),
        });
    }

    Ok(PolicyLayerReport {
        status: SmokeStatus::Pass,
        policy_version: policy.version_hash,
        layers: entries,
    })
}

pub(super) fn print_policy_layer_report(report: &PolicyLayerReport) {
    println!("policy version: {}", report.policy_version);
    for (index, layer) in report.layers.iter().enumerate() {
        println!(
            "{}. {}: {} ({} files, {} rules)",
            index + 1,
            layer.name,
            layer.dir,
            layer.files,
            layer.rules
        );
    }
}
