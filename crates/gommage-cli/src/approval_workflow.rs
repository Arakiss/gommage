use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use gommage_audit::explain_log;
use gommage_core::{
    ApprovalRequest, ApprovalState, ApprovalStore, Decision, evaluate, runtime::HomeLayout,
    runtime::Runtime,
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};
use time::OffsetDateTime;

use crate::util::path_display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WebhookProvider {
    Generic,
    Slack,
    Discord,
}

impl WebhookProvider {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            WebhookProvider::Generic => "generic",
            WebhookProvider::Slack => "slack",
            WebhookProvider::Discord => "discord",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WebhookTemplateProvider {
    Generic,
    Slack,
    Discord,
    Ntfy,
}

impl WebhookTemplateProvider {
    fn as_str(self) -> &'static str {
        match self {
            WebhookTemplateProvider::Generic => "generic",
            WebhookTemplateProvider::Slack => "slack",
            WebhookTemplateProvider::Discord => "discord",
            WebhookTemplateProvider::Ntfy => "ntfy",
        }
    }
}

pub(crate) fn approval_replay(layout: HomeLayout, id: &str, json: bool) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    let rt = Runtime::open(HomeLayout::at(&layout.root)).context("opening current runtime")?;
    let eval = evaluate(&state.request.capabilities, &rt.policy);
    let conclusion = replay_conclusion(&state.request.required_scope, &eval.decision);
    let report = ReplayReport {
        schema_version: 1,
        request_id: id.to_string(),
        status: state.status.as_str().to_string(),
        stored_policy_version: state.request.policy_version.clone(),
        current_policy_version: eval.policy_version.clone(),
        policy_changed: state.request.policy_version != eval.policy_version,
        required_scope: state.request.required_scope.clone(),
        capabilities: state
            .request
            .capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        stored_matched_rule: state.request.matched_rule.clone(),
        current_decision: eval.decision,
        current_matched_rule: eval.matched_rule,
        conclusion,
        commands: approval_commands(id),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_replay_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn approval_evidence(
    layout: HomeLayout,
    id: &str,
    redact: bool,
    output: Option<PathBuf>,
    force: bool,
) -> Result<ExitCode> {
    let store = ApprovalStore::open(&layout.approvals_log);
    let state = store
        .get(id)?
        .with_context(|| format!("approval request {id:?} not found"))?;
    if let Some(output) = &output
        && output.exists()
        && !force
    {
        bail!(
            "{} already exists; pass --force to replace it",
            output.display()
        );
    }

    let verification = layout
        .load_verifying_key()
        .ok()
        .and_then(|vk| explain_log(&layout.audit_log, &vk).ok())
        .and_then(|report| serde_json::to_value(report).ok());
    let picto_id = state
        .resolution
        .as_ref()
        .and_then(|resolution| resolution.picto_id.as_deref());
    let entries = relevant_audit_entries(
        &layout.audit_log,
        &state.request.id,
        &state.request.input_hash,
        picto_id,
    );
    let bundle = EvidenceBundle {
        schema_version: 1,
        generated_at: OffsetDateTime::now_utc().to_string(),
        redacted: redact,
        home: path_display(&layout.root),
        audit_log: path_display(&layout.audit_log),
        approval_log: path_display(&layout.approvals_log),
        state,
        verification,
        relevant_audit_entries: entries,
        commands: approval_commands(id),
    };
    let mut value = serde_json::to_value(bundle)?;
    if redact {
        redact_paths(&mut value, &layout.root);
    }
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&output, text).with_context(|| format!("writing {}", output.display()))?;
        println!("ok approval evidence: {}", output.display());
    } else {
        print!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn approval_template(provider: WebhookTemplateProvider, json: bool) -> Result<ExitCode> {
    let value = serde_json::json!({
        "provider": provider.as_str(),
        "stable_contract": provider == WebhookTemplateProvider::Generic,
        "docs": provider_docs(provider),
        "command": provider_command(provider),
        "payload": provider_example_payload(provider),
        "notes": provider_notes(provider),
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("approval webhook template: {}", provider.as_str());
        println!("  docs: {}", provider_docs(provider));
        println!("  command: {}", provider_command(provider));
        for note in provider_notes(provider) {
            println!("  note: {note}");
        }
        println!("  payload:");
        println!("{}", serde_json::to_string_pretty(&value["payload"])?);
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn webhook_payload(
    request: &ApprovalRequest,
    provider: WebhookProvider,
) -> serde_json::Value {
    match provider {
        WebhookProvider::Generic => generic_payload(request),
        WebhookProvider::Slack => slack_payload(request),
        WebhookProvider::Discord => discord_payload(request),
    }
}

fn generic_payload(request: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({
        "kind": "gommage_approval_request",
        "id": request.id,
        "created_at": request.created_at,
        "tool": request.tool,
        "input_hash": request.input_hash,
        "required_scope": request.required_scope,
        "reason": request.reason,
        "capabilities": request.capabilities,
        "matched_rule": request.matched_rule,
        "policy_version": request.policy_version,
        "commands": approval_commands(&request.id)
    })
}

fn slack_payload(request: &ApprovalRequest) -> serde_json::Value {
    let text = approval_message(request);
    serde_json::json!({
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": format!("*Gommage approval request*\\n{}", text)}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": format!("*ID*\\n`{}`", request.id)},
                {"type": "mrkdwn", "text": format!("*Scope*\\n`{}`", request.required_scope)},
                {"type": "mrkdwn", "text": format!("*Tool*\\n`{}`", request.tool)},
                {"type": "mrkdwn", "text": format!("*Input*\\n`{}`", request.input_hash)}
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": format!("Approve: `gommage approval approve {} --ttl 10m --uses 1`\\nDeny: `gommage approval deny {} --reason <reason>`", request.id, request.id)}}
        ]
    })
}

fn discord_payload(request: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({
        "content": approval_message(request),
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": "Gommage approval request",
            "description": request.reason,
            "fields": [
                {"name": "ID", "value": format!("`{}`", request.id), "inline": false},
                {"name": "Scope", "value": format!("`{}`", request.required_scope), "inline": true},
                {"name": "Tool", "value": format!("`{}`", request.tool), "inline": true},
                {"name": "Input", "value": format!("`{}`", request.input_hash), "inline": false},
                {"name": "Approve", "value": format!("`gommage approval approve {} --ttl 10m --uses 1`", request.id), "inline": false},
                {"name": "Deny", "value": format!("`gommage approval deny {} --reason <reason>`", request.id), "inline": false}
            ]
        }]
    })
}

fn approval_message(request: &ApprovalRequest) -> String {
    format!(
        "Gommage approval required: {} for {} ({})",
        request.required_scope, request.tool, request.id
    )
}

fn replay_conclusion(required_scope: &str, decision: &Decision) -> String {
    match decision {
        Decision::AskPicto {
            required_scope: current,
            ..
        } if current == required_scope => "still_requires_same_scope".to_string(),
        Decision::AskPicto { .. } => "ask_scope_changed".to_string(),
        Decision::Allow => "current_policy_allows_without_picto".to_string(),
        Decision::Gommage {
            hard_stop: true, ..
        } => "current_policy_hard_stops".to_string(),
        Decision::Gommage { .. } => "current_policy_denies".to_string(),
    }
}

fn print_replay_report(report: &ReplayReport) {
    println!("approval replay {}", report.request_id);
    println!("  status:        {}", report.status);
    println!("  stored policy: {}", report.stored_policy_version);
    println!("  current policy: {}", report.current_policy_version);
    println!("  policy changed: {}", report.policy_changed);
    println!("  scope:         {}", report.required_scope);
    println!("  conclusion:    {}", report.conclusion);
    println!("  commands:");
    println!("    approve: {}", report.commands.approve);
    println!("    deny:    {}", report.commands.deny);
    println!("    evidence: {}", report.commands.evidence);
}

fn relevant_audit_entries(
    path: &Path,
    id: &str,
    input_hash: &str,
    picto_id: Option<&str>,
) -> Vec<serde_json::Value> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| {
            line.contains(id)
                || line.contains(input_hash)
                || picto_id.is_some_and(|picto_id| line.contains(picto_id))
        })
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect()
}

fn redact_paths(value: &mut serde_json::Value, home: &Path) {
    match value {
        serde_json::Value::String(text) => {
            let home = home.to_string_lossy();
            if text.contains(home.as_ref()) {
                *text = text.replace(home.as_ref(), "<gommage-home>");
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_paths(item, home);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                redact_paths(item, home);
            }
        }
        _ => {}
    }
}

fn approval_commands(id: &str) -> ApprovalCommands {
    ApprovalCommands {
        show: format!("gommage approval show {id} --json"),
        approve: format!("gommage approval approve {id} --ttl 10m --uses 1"),
        deny: format!("gommage approval deny {id} --reason <reason>"),
        replay: format!("gommage approval replay {id} --json"),
        evidence: format!("gommage approval evidence {id} --redact"),
        audit_verify: "gommage audit-verify --explain".to_string(),
        tui: "gommage tui --view approvals".to_string(),
    }
}

fn provider_docs(provider: WebhookTemplateProvider) -> &'static str {
    match provider {
        WebhookTemplateProvider::Generic => "https://github.com/Arakiss/gommage",
        WebhookTemplateProvider::Slack => {
            "https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/"
        }
        WebhookTemplateProvider::Discord => "https://docs.discord.com/developers/resources/webhook",
        WebhookTemplateProvider::Ntfy => "https://docs.ntfy.sh/publish/",
    }
}

fn provider_command(provider: WebhookTemplateProvider) -> &'static str {
    match provider {
        WebhookTemplateProvider::Generic => {
            "gommage approval webhook --url \"$GOMMAGE_APPROVAL_WEBHOOK_URL\""
        }
        WebhookTemplateProvider::Slack => {
            "gommage approval webhook --provider slack --url \"$SLACK_WEBHOOK_URL\""
        }
        WebhookTemplateProvider::Discord => {
            "gommage approval webhook --provider discord --url \"$DISCORD_WEBHOOK_URL\""
        }
        WebhookTemplateProvider::Ntfy => "gommage approval template --provider ntfy --json",
    }
}

fn provider_example_payload(provider: WebhookTemplateProvider) -> serde_json::Value {
    let request = ApprovalRequest {
        id: "apr_example".to_string(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        tool: "Bash".to_string(),
        input_hash: "sha256:example".to_string(),
        required_scope: "git.push:main".to_string(),
        reason: "main branch push requires a picto".to_string(),
        capabilities: Vec::new(),
        matched_rule: None,
        policy_version: "sha256:policy".to_string(),
    };
    match provider {
        WebhookTemplateProvider::Generic => generic_payload(&request),
        WebhookTemplateProvider::Slack => slack_payload(&request),
        WebhookTemplateProvider::Discord => discord_payload(&request),
        WebhookTemplateProvider::Ntfy => serde_json::json!({
            "topic": "gommage-approvals",
            "title": "Gommage approval request",
            "message": approval_message(&request),
            "tags": ["warning", "gommage"],
            "actions": [{
                "action": "view",
                "label": "Open terminal",
                "url": "file:///dev/null"
            }]
        }),
    }
}

fn provider_notes(provider: WebhookTemplateProvider) -> Vec<&'static str> {
    match provider {
        WebhookTemplateProvider::Generic => vec![
            "Generic JSON is the stable automation contract.",
            "The receiving service decides how humans approve or deny locally.",
        ],
        WebhookTemplateProvider::Slack => vec![
            "Slack incoming webhooks accept JSON with text and optional blocks.",
            "Approval still happens locally with gommage approval approve/deny.",
        ],
        WebhookTemplateProvider::Discord => vec![
            "Discord incoming webhooks accept JSON content and optional embeds.",
            "allowed_mentions is disabled to avoid accidental pings.",
        ],
        WebhookTemplateProvider::Ntfy => vec![
            "ntfy JSON publishing posts to the server root URL with a topic field.",
            "This loop documents the shape but does not send ntfy directly yet.",
        ],
    }
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    schema_version: u32,
    request_id: String,
    status: String,
    stored_policy_version: String,
    current_policy_version: String,
    policy_changed: bool,
    required_scope: String,
    capabilities: Vec<String>,
    stored_matched_rule: Option<gommage_core::MatchedRule>,
    current_decision: Decision,
    current_matched_rule: Option<gommage_core::MatchedRule>,
    conclusion: String,
    commands: ApprovalCommands,
}

#[derive(Debug, Serialize)]
struct EvidenceBundle {
    schema_version: u32,
    generated_at: String,
    redacted: bool,
    home: String,
    audit_log: String,
    approval_log: String,
    state: ApprovalState,
    verification: Option<serde_json::Value>,
    relevant_audit_entries: Vec<serde_json::Value>,
    commands: ApprovalCommands,
}

#[derive(Debug, Serialize)]
struct ApprovalCommands {
    show: String,
    approve: String,
    deny: String,
    replay: String,
    evidence: String,
    audit_verify: String,
    tui: String,
}
