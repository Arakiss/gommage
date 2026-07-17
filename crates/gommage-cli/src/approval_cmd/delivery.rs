use super::*;

pub(super) struct ApprovalWebhookOptions {
    pub(super) layout: HomeLayout,
    pub(super) url: String,
    pub(super) provider: WebhookProvider,
    pub(super) dry_run: bool,
    pub(super) limit: Option<usize>,
    pub(super) json: bool,
    pub(super) signing_secret: Option<String>,
    pub(super) signing_key_id: Option<String>,
    pub(super) attempts: u32,
    pub(super) backoff_ms: u64,
}

pub(super) fn approval_webhook(options: ApprovalWebhookOptions) -> Result<ExitCode> {
    let ApprovalWebhookOptions {
        layout,
        url,
        provider,
        dry_run,
        limit,
        json,
        signing_secret,
        signing_key_id,
        attempts,
        backoff_ms,
    } = options;
    let store = ApprovalStore::open(&layout.approvals_log);
    let mut pending = store.pending()?;
    if let Some(limit) = limit {
        pending.truncate(limit);
    }
    let mut report = WebhookReport {
        url: url.clone(),
        provider: provider.as_str().to_string(),
        dry_run,
        sent: 0,
        failed: 0,
        requests: Vec::new(),
    };
    let settings = ApprovalWebhookDeliverySettings::new(attempts, backoff_ms);
    let audit = layout
        .load_key()
        .ok()
        .and_then(|sk| AuditWriter::open(&layout.audit_log, sk).ok());
    let mut audit = audit;

    for state in pending {
        let payload = webhook_payload(&state.request, provider);
        let prepared = prepare_approval_webhook(
            payload.clone(),
            signing_secret.as_deref(),
            signing_key_id.as_deref(),
        )?;
        if dry_run {
            if !json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
                if let Some(signature) = &prepared.signature {
                    println!("signature: {} {}", signature.algorithm, signature.signature);
                }
            }
            report.requests.push(WebhookRequestReport {
                id: state.request.id,
                status: "dry_run".to_string(),
                attempts: None,
                payload: Some(payload),
                body: Some(String::from_utf8(prepared.body.clone())?),
                signature: prepared.signature,
                http_status: None,
                dead_letter_id: None,
                error: None,
            });
            continue;
        }
        let outcome = deliver_prepared_approval_webhook(
            &layout,
            &state.request,
            ApprovalWebhookSource::Cli,
            provider.as_str(),
            &url,
            &prepared,
            &settings,
        )?;
        match outcome.kind {
            ApprovalWebhookDeliveryKind::Delivered => {
                report.sent += 1;
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookDelivered {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        status: outcome.http_status,
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "sent".to_string(),
                    attempts: Some(outcome.attempts),
                    payload: None,
                    body: None,
                    signature: outcome.signature,
                    http_status: outcome.http_status,
                    dead_letter_id: None,
                    error: None,
                });
            }
            ApprovalWebhookDeliveryKind::DeadLettered => {
                report.failed += 1;
                let message = outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "webhook delivery failed".to_string());
                if let Some(writer) = audit.as_mut() {
                    writer.append_event(AuditEvent::ApprovalWebhookFailed {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        error: message.clone(),
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                    writer.append_event(AuditEvent::ApprovalWebhookDeadLettered {
                        id: state.request.id.clone(),
                        url: url.clone(),
                        dead_letter_id: outcome
                            .dead_letter_id
                            .clone()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        provider: provider.as_str().to_string(),
                        attempts: outcome.attempts,
                        source: ApprovalWebhookSource::Cli.as_str().to_string(),
                        error: message.clone(),
                        signature: outcome.signature.as_ref().map(signature_audit_summary),
                    })?;
                }
                report.requests.push(WebhookRequestReport {
                    id: state.request.id,
                    status: "dead_lettered".to_string(),
                    attempts: Some(outcome.attempts),
                    payload: None,
                    body: None,
                    signature: outcome.signature,
                    http_status: None,
                    dead_letter_id: outcome.dead_letter_id,
                    error: Some(message),
                });
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if dry_run {
        eprintln!("gommage approval webhook: dry-run rendered pending payloads");
    } else {
        println!(
            "webhook delivery complete: {} sent, {} failed",
            report.sent, report.failed
        );
    }
    if report.failed > 0 {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

pub(super) fn approval_dlq(
    layout: HomeLayout,
    json: bool,
    limit: Option<usize>,
) -> Result<ExitCode> {
    let store = ApprovalWebhookDeadLetterStore::open(&layout.approval_webhook_dlq);
    let mut entries = store.list()?;
    entries.reverse();
    if let Some(limit) = limit {
        entries.truncate(limit);
    }
    if json {
        let report = WebhookDlqReport {
            path: layout.approval_webhook_dlq.display().to_string(),
            count: entries.len(),
            entries: entries.iter().map(WebhookDlqItem::from).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "approval webhook dlq: {}",
        layout.approval_webhook_dlq.display()
    );
    if entries.is_empty() {
        println!("entries: none");
        return Ok(ExitCode::SUCCESS);
    }
    println!("entries: {}", entries.len());
    for entry in entries {
        println!(
            "- {} request={} source={} provider={} attempts={} url={}",
            entry.id, entry.request_id, entry.source, entry.provider, entry.attempts, entry.url
        );
        println!("  error: {}", entry.error);
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn print_action(json: bool, report: ApprovalActionReport) -> Result<ExitCode> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_action_human(&report);
    }
    Ok(ExitCode::SUCCESS)
}

pub(super) fn print_callback_report(
    json: bool,
    report: ApprovalCallbackReport,
) -> Result<ExitCode> {
    let exit_code = report.exit_code();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("approval callback: {:?}", report.status);
        if let Some(request_id) = &report.request_id {
            println!("request: {request_id}");
        }
        if let Some(action) = report.action {
            println!("action: {}", action.as_str());
        }
        println!(
            "signature: {}",
            if report.signature.ok { "ok" } else { "invalid" }
        );
        println!(
            "nonce: {}",
            if report.nonce_match { "ok" } else { "mismatch" }
        );
        if report.dry_run {
            println!("dry-run: state not changed");
        }
        for error in &report.errors {
            println!("error: {error}");
        }
        if let Some(outcome) = &report.outcome {
            println!("outcome: {}", outcome.message);
        }
    }
    Ok(exit_code)
}

pub(super) fn print_deny_stale_report(
    json: bool,
    report: &ApprovalDenyStaleReport,
    show_all: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let colors = color_enabled();
    println!(
        "{}",
        paint("Stale approval sweep", UiTone::Teal, true, colors)
    );
    println!(
        "mode:    {}",
        if report.apply { "apply" } else { "dry-run" }
    );
    println!("older:  {} seconds", report.older_than_seconds);
    println!("matched: {}", report.matched);
    println!("denied:  {}", report.denied);
    let shown = if show_all {
        report.requests.len()
    } else {
        report.requests.len().min(DENY_STALE_HUMAN_DEFAULT_LIMIT)
    };
    for request in report.requests.iter().take(shown) {
        println!();
        println!("{}", paint(&request.id, UiTone::Gold, true, colors));
        println!("  status: {}", request.status);
        println!("  age:    {} seconds", request.age_seconds);
        println!("  tool:   {}", request.tool);
        println!("  scope:  {}", request.scope);
    }
    let hidden = report.requests.len().saturating_sub(shown);
    if hidden > 0 {
        println!();
        println!("omitted: {hidden} request(s)");
        println!("detail:  rerun with --show-all for every request, or --json for full data");
    }
    if !report.apply && report.matched > 0 {
        println!();
        println!("next:    rerun with --apply to append denied resolutions");
    }
    Ok(())
}

pub(super) fn print_action_human(report: &ApprovalActionReport) {
    let colors = color_enabled();
    let title = match report.status.as_str() {
        "approved" => "Approval granted",
        "denied" => "Approval denied",
        _ => "Approval resolved",
    };
    println!(
        "{}",
        paint(title, action_tone(&report.status), true, colors)
    );
    println!("request: {}", report.request_id);
    println!(
        "status:  {}",
        paint(&report.status, action_tone(&report.status), true, colors)
    );
    println!("tool:    {}", report.tool);
    println!("scope:   {}", report.scope);
    println!("reason:  {}", report.reason);

    if let Some(picto) = &report.picto {
        println!();
        println!("{}", paint("Picto minted", UiTone::Gold, true, colors));
        println!("id:      {}", picto.id);
        println!("kind:    {}", picto.kind.replace('_', "-"));
        if picto.input_bound {
            println!("binding: exact tool input only");
            println!("allows:  only the exact observed tool input");
        } else {
            println!("binding: scope only — not tied to the request input hash");
            println!("allows:  any matching call in scope {}", picto.scope);
        }
        println!("spends:  one use per matching call; non-matches do not consume");
        println!(
            "uses:    {}/{} remaining",
            picto.uses_remaining, picto.max_uses
        );
        println!("expires: {}", picto.expires_at);
    }

    println!();
    match report.next_action.as_str() {
        "retry_blocked_call" => {
            if report.picto.as_ref().is_some_and(|picto| picto.input_bound) {
                println!(
                    "next:    retry the intended blocked call; only the exact-input match spends a use"
                )
            } else {
                println!(
                    "next:    retry the intended blocked call directly; any in-scope probe would spend one use"
                )
            }
        }
        "none" => println!("next:    no picto minted"),
        other => println!("next:    {other}"),
    }
}

pub(super) fn print_empty_inbox(status: ApprovalStatusArg) {
    let colors = color_enabled();
    println!("{}", paint("Approval inbox", UiTone::Teal, true, colors));
    println!("filter:   {}", status.as_str());
    println!("requests: 0");
    if matches!(status, ApprovalStatusArg::Pending) {
        println!("next:     use --status all to inspect approval history");
    }
}

pub(super) fn print_inbox(states: &[ApprovalState], status: ApprovalStatusArg) {
    let colors = color_enabled();
    println!("{}", paint("Approval inbox", UiTone::Teal, true, colors));
    println!("filter:   {}", status.as_str());
    println!("requests: {}", states.len());
    for state in states {
        println!();
        print_state_summary(state, colors);
    }
}

pub(super) fn print_state_summary(state: &ApprovalState, colors: bool) {
    println!("{}", paint(&state.request.id, UiTone::Teal, true, colors));
    println!(
        "  status: {}",
        paint(
            state.status.as_str(),
            approval_status_tone(state.status),
            true,
            colors
        )
    );
    println!("  tool:   {}", state.request.tool);
    println!("  scope:  {}", state.request.required_scope);
    println!(
        "  binding: {}",
        request_binding_label(state.request.bind_input)
    );
    println!("  input:  {}", state.request.input_hash);
    println!("  reason: {}", state.request.reason);
    if state.status == ApprovalStatus::Pending {
        println!("  next:   gommage approval show {}", state.request.id);
    }
}

pub(super) fn print_state_detail(state: &ApprovalState) {
    let colors = color_enabled();
    println!("{}", paint("Approval request", UiTone::Teal, true, colors));
    println!("id:      {}", state.request.id);
    println!(
        "status:  {}",
        paint(
            state.status.as_str(),
            approval_status_tone(state.status),
            true,
            colors
        )
    );
    println!("created: {}", format_timestamp(state.request.created_at));
    println!("tool:    {}", state.request.tool);
    println!("scope:   {}", state.request.required_scope);
    println!(
        "binding: {}",
        request_binding_label(state.request.bind_input)
    );
    println!(
        "meaning: {}",
        request_binding_explanation(state.request.bind_input)
    );
    println!("input:   {}", state.request.input_hash);
    println!("reason:  {}", state.request.reason);
    println!("policy:  {}", state.request.policy_version);
    if let Some(rule) = &state.request.matched_rule {
        println!("rule:    {} ({}:{})", rule.name, rule.file, rule.index);
    }
    if !state.request.capabilities.is_empty() {
        println!();
        println!("{}", paint("Capabilities", UiTone::Gold, true, colors));
        for capability in &state.request.capabilities {
            println!("- {}", capability.as_str());
        }
    }
    if state.status == ApprovalStatus::Pending {
        println!();
        println!("{}", paint("Next", UiTone::Gold, true, colors));
        println!(
            "approve: gommage approval approve {} --ttl 10m --uses 1",
            state.request.id
        );
        println!(
            "deny:    gommage approval deny {} --reason <reason>",
            state.request.id
        );
    }
}

pub(super) fn request_binding_label(bind_input: bool) -> &'static str {
    if bind_input {
        "exact tool input"
    } else {
        "scope only"
    }
}

pub(super) fn request_binding_explanation(bind_input: bool) -> &'static str {
    if bind_input {
        "approval authorizes only this exact observed tool input; each matching call consumes one use"
    } else {
        "approval authorizes any matching call in this scope, not this input hash; each matching call consumes one use"
    }
}

pub(super) fn action_tone(status: &str) -> UiTone {
    match status {
        "approved" => UiTone::Green,
        "denied" => UiTone::Red,
        _ => UiTone::Muted,
    }
}

pub(super) fn approval_status_tone(status: ApprovalStatus) -> UiTone {
    match status {
        ApprovalStatus::Pending => UiTone::Gold,
        ApprovalStatus::Approved => UiTone::Green,
        ApprovalStatus::Denied => UiTone::Red,
        ApprovalStatus::Satisfied => UiTone::Green,
        ApprovalStatus::Superseded => UiTone::Muted,
    }
}

pub(super) fn format_timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

pub(super) fn signature_audit_summary(
    signature: &WebhookSignatureReport,
) -> gommage_audit::WebhookSignatureAudit {
    gommage_audit::WebhookSignatureAudit {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        timestamp: signature.timestamp.clone(),
        body_sha256: signature.body_sha256.clone(),
        signature_prefix: signature.signature.chars().take(18).collect(),
    }
}

pub(super) fn parse_ttl_seconds(raw: &str) -> std::result::Result<i64, String> {
    let seconds = parse_positive_duration_seconds(raw)?;
    if !(1..=86_400).contains(&seconds) {
        return Err("ttl must be between 1 second and 24 hours".to_string());
    }
    Ok(seconds)
}

pub(super) fn parse_positive_duration_seconds(raw: &str) -> std::result::Result<i64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    let (number, multiplier) = match raw.chars().last().unwrap() {
        's' | 'S' => (&raw[..raw.len() - 1], 1),
        'm' | 'M' => (&raw[..raw.len() - 1], 60),
        'h' | 'H' => (&raw[..raw.len() - 1], 3_600),
        'd' | 'D' => (&raw[..raw.len() - 1], 86_400),
        c if c.is_ascii_digit() => (raw, 1),
        other => {
            return Err(format!(
                "unsupported duration suffix {other:?}; use s, m, h, or d"
            ));
        }
    };
    let value: i64 = number
        .parse()
        .map_err(|_| "duration must start with a positive integer".to_string())?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_string())?;
    if seconds < 1 {
        return Err("duration must be at least 1 second".to_string());
    }
    Ok(seconds)
}
