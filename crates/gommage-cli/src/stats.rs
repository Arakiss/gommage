use anyhow::Result;
use gommage_core::{
    ApprovalState, ApprovalStatus, ApprovalStore, MatchedRule, runtime::HomeLayout,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::ExitCode,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Copy)]
pub(crate) struct StatsOptions {
    pub(crate) json: bool,
    pub(crate) window_days: u32,
}

#[derive(Debug, Serialize)]
struct StatsReport {
    schema_version: u8,
    kind: &'static str,
    generated_at: String,
    window_days: u32,
    audit_log: String,
    approvals_log: String,
    totals: AuditTotals,
    approvals: ApprovalTotals,
    asks_by_rule: Vec<RuleStats>,
    deny_loops: Vec<DenyLoop>,
    reclassification_candidates: Vec<ReclassificationCandidate>,
    hygiene: HygieneReport,
}

#[derive(Debug, Default, Serialize)]
struct AuditTotals {
    audit_records: usize,
    decisions: usize,
    events: usize,
    allows: usize,
    asks: usize,
    denies: usize,
    hard_stops: usize,
    malformed_records: usize,
    null_tool_records: usize,
    null_decision_records: usize,
    unknown_decision_records: usize,
}

#[derive(Debug, Default, Serialize)]
struct ApprovalTotals {
    total: usize,
    pending: usize,
    approved: usize,
    denied: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_time_to_resolution_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuleStats {
    rule: String,
    file: String,
    total_asks: usize,
    window_asks: usize,
    required_scope: Option<String>,
    last_seen: Option<String>,
    approval_requests: usize,
    approvals_pending: usize,
    approvals_approved: usize,
    approvals_denied: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_time_to_resolution_seconds: Option<f64>,
}

#[derive(Debug, Serialize)]
struct DenyLoop {
    tool: String,
    input_hash: String,
    rule: String,
    file: String,
    occurrences: usize,
    window_occurrences: usize,
    hard_stop: bool,
    last_seen: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReclassificationCandidate {
    rule: String,
    file: String,
    kind: &'static str,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HygieneReport {
    schema_versions: BTreeMap<String, usize>,
    malformed_records: usize,
    null_tool_records: usize,
    null_decision_records: usize,
}

#[derive(Debug, Default)]
struct RuleStatsBuilder {
    rule: String,
    file: String,
    total_asks: usize,
    window_asks: usize,
    required_scope: Option<String>,
    last_seen: Option<OffsetDateTime>,
    approval_requests: usize,
    approvals_pending: usize,
    approvals_approved: usize,
    approvals_denied: usize,
    resolution_seconds_total: i128,
    resolution_count: usize,
}

#[derive(Debug, Default)]
struct DenyLoopBuilder {
    tool: String,
    input_hash: String,
    rule: String,
    file: String,
    occurrences: usize,
    window_occurrences: usize,
    hard_stop: bool,
    last_seen: Option<OffsetDateTime>,
}

pub(crate) fn cmd_stats(layout: HomeLayout, options: StatsOptions) -> Result<ExitCode> {
    let report = build_stats_report(&layout, options.window_days.max(1));
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn build_stats_report(layout: &HomeLayout, window_days: u32) -> StatsReport {
    let generated_at = OffsetDateTime::now_utc();
    let window_start = generated_at - Duration::days(i64::from(window_days));
    let mut totals = AuditTotals::default();
    let mut schema_versions = BTreeMap::new();
    let mut rules = BTreeMap::<String, RuleStatsBuilder>::new();
    let mut deny_loops = BTreeMap::<String, DenyLoopBuilder>::new();

    add_audit_stats(
        &layout.audit_log,
        window_start,
        &mut totals,
        &mut schema_versions,
        &mut rules,
        &mut deny_loops,
    );

    let approvals = add_approval_stats(&layout.approvals_log, &mut rules);

    let mut asks_by_rule = rules
        .into_values()
        .map(RuleStatsBuilder::finish)
        .collect::<Vec<_>>();
    asks_by_rule.sort_by(|a, b| {
        b.window_asks
            .cmp(&a.window_asks)
            .then_with(|| b.total_asks.cmp(&a.total_asks))
            .then_with(|| a.rule.cmp(&b.rule))
    });

    let mut deny_loops = deny_loops
        .into_values()
        .filter(|loop_stats| loop_stats.occurrences > 1)
        .map(DenyLoopBuilder::finish)
        .collect::<Vec<_>>();
    deny_loops.sort_by(|a, b| {
        b.window_occurrences
            .cmp(&a.window_occurrences)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.rule.cmp(&b.rule))
    });

    let reclassification_candidates = candidate_rules(&asks_by_rule);
    let hygiene = HygieneReport {
        schema_versions,
        malformed_records: totals.malformed_records,
        null_tool_records: totals.null_tool_records,
        null_decision_records: totals.null_decision_records,
    };

    StatsReport {
        schema_version: 1,
        kind: "gommage_stats",
        generated_at: format_time(generated_at),
        window_days,
        audit_log: layout.audit_log.display().to_string(),
        approvals_log: layout.approvals_log.display().to_string(),
        totals,
        approvals,
        asks_by_rule,
        deny_loops,
        reclassification_candidates,
        hygiene,
    }
}

fn add_audit_stats(
    audit_log: &Path,
    window_start: OffsetDateTime,
    totals: &mut AuditTotals,
    schema_versions: &mut BTreeMap<String, usize>,
    rules: &mut BTreeMap<String, RuleStatsBuilder>,
    deny_loops: &mut BTreeMap<String, DenyLoopBuilder>,
) {
    let Ok(file) = File::open(audit_log) else {
        return;
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            totals.malformed_records += 1;
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            totals.malformed_records += 1;
            continue;
        };
        totals.audit_records += 1;
        count_schema_version(&value, schema_versions);

        if value.get("kind").and_then(Value::as_str) == Some("event") {
            totals.events += 1;
            continue;
        }

        if value.get("tool").is_none_or(Value::is_null) {
            totals.null_tool_records += 1;
        }
        if value.get("decision").is_none_or(Value::is_null) {
            totals.null_decision_records += 1;
            continue;
        }

        let ts = value.get("ts").and_then(Value::as_str).and_then(parse_time);
        let in_window = ts.is_some_and(|ts| ts >= window_start);
        let identity = rule_identity_from_value(&value);
        let decision_kind = value.pointer("/decision/kind").and_then(Value::as_str);
        match decision_kind {
            Some("allow") => {
                totals.decisions += 1;
                totals.allows += 1;
            }
            Some("ask_picto") => {
                totals.decisions += 1;
                totals.asks += 1;
                let required_scope = value
                    .pointer("/decision/required_scope")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let builder = rules
                    .entry(identity.key())
                    .or_insert_with(|| RuleStatsBuilder::new(&identity));
                builder.total_asks += 1;
                if in_window {
                    builder.window_asks += 1;
                }
                if builder.required_scope.is_none() {
                    builder.required_scope = required_scope;
                }
                builder.last_seen = max_time(builder.last_seen, ts);
            }
            Some("gommage") => {
                totals.decisions += 1;
                totals.denies += 1;
                let hard_stop = value
                    .pointer("/decision/hard_stop")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if hard_stop {
                    totals.hard_stops += 1;
                }
                count_deny_loop(&value, &identity, ts, in_window, hard_stop, deny_loops);
            }
            Some(_) | None => {
                totals.unknown_decision_records += 1;
            }
        }
    }
}

fn add_approval_stats(
    approvals_log: &Path,
    rules: &mut BTreeMap<String, RuleStatsBuilder>,
) -> ApprovalTotals {
    let mut totals = ApprovalTotals::default();
    let store = ApprovalStore::open(approvals_log);
    let states = match store.list() {
        Ok(states) => states,
        Err(error) => {
            totals.error = Some(error.to_string());
            return totals;
        }
    };
    let mut resolution_seconds_total = 0i128;
    let mut resolution_count = 0usize;
    for state in states {
        totals.total += 1;
        match state.status {
            ApprovalStatus::Pending => totals.pending += 1,
            ApprovalStatus::Approved => totals.approved += 1,
            ApprovalStatus::Denied => totals.denied += 1,
        }
        let identity = rule_identity_from_approval(&state);
        let builder = rules
            .entry(identity.key())
            .or_insert_with(|| RuleStatsBuilder::new(&identity));
        builder.approval_requests += 1;
        match state.status {
            ApprovalStatus::Pending => builder.approvals_pending += 1,
            ApprovalStatus::Approved => builder.approvals_approved += 1,
            ApprovalStatus::Denied => builder.approvals_denied += 1,
        }
        if let Some(seconds) = resolution_seconds(&state) {
            resolution_seconds_total += i128::from(seconds);
            resolution_count += 1;
            builder.resolution_seconds_total += i128::from(seconds);
            builder.resolution_count += 1;
        }
    }
    let resolved = totals.approved + totals.denied;
    totals.approval_rate = rate(totals.approved, resolved);
    totals.avg_time_to_resolution_seconds = average(resolution_seconds_total, resolution_count);
    totals
}

fn count_deny_loop(
    value: &Value,
    identity: &RuleIdentity,
    ts: Option<OffsetDateTime>,
    in_window: bool,
    hard_stop: bool,
    deny_loops: &mut BTreeMap<String, DenyLoopBuilder>,
) {
    let tool = value
        .get("tool")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>")
        .to_string();
    let input_hash = value
        .get("input_hash")
        .and_then(Value::as_str)
        .unwrap_or("<missing>")
        .to_string();
    let key = format!("{}\0{}\0{}", tool, input_hash, identity.key());
    let builder = deny_loops.entry(key).or_insert_with(|| DenyLoopBuilder {
        tool,
        input_hash,
        rule: identity.name.clone(),
        file: identity.file.clone(),
        occurrences: 0,
        window_occurrences: 0,
        hard_stop,
        last_seen: None,
    });
    builder.occurrences += 1;
    if in_window {
        builder.window_occurrences += 1;
    }
    builder.hard_stop |= hard_stop;
    builder.last_seen = max_time(builder.last_seen, ts);
}

fn candidate_rules(rules: &[RuleStats]) -> Vec<ReclassificationCandidate> {
    let mut candidates = Vec::new();
    for rule in rules {
        let resolved = rule.approvals_approved + rule.approvals_denied;
        if rule.approvals_approved >= 3 && rule.approvals_denied == 0 {
            candidates.push(ReclassificationCandidate {
                rule: rule.rule.clone(),
                file: rule.file.clone(),
                kind: "candidate_allow",
                reason: format!(
                    "{} approval(s), 0 denials; review whether this gate should become allow or narrower",
                    rule.approvals_approved
                ),
            });
        } else if rule.window_asks >= 10 {
            candidates.push(ReclassificationCandidate {
                rule: rule.rule.clone(),
                file: rule.file.clone(),
                kind: "high_friction_review",
                reason: format!(
                    "{} ask(s) in the last reporting window; review policy/docs posture",
                    rule.window_asks
                ),
            });
        } else if resolved >= 3 && rule.approvals_denied > 0 {
            candidates.push(ReclassificationCandidate {
                rule: rule.rule.clone(),
                file: rule.file.clone(),
                kind: "keep_or_tighten",
                reason: format!(
                    "{} approval(s), {} denial(s); this gate is making real distinctions",
                    rule.approvals_approved, rule.approvals_denied
                ),
            });
        }
    }
    candidates
}

fn print_human_report(report: &StatsReport) {
    println!("gommage stats ({})", report.generated_at);
    println!(
        "audit: {} records, {} decisions, {} malformed, {} null tool, {} null decision",
        report.totals.audit_records,
        report.totals.decisions,
        report.totals.malformed_records,
        report.totals.null_tool_records,
        report.totals.null_decision_records
    );
    println!(
        "decisions: {} allow, {} ask, {} deny, {} hard-stop",
        report.totals.allows, report.totals.asks, report.totals.denies, report.totals.hard_stops
    );
    println!(
        "approvals: {} total, {} pending, {} approved, {} denied",
        report.approvals.total,
        report.approvals.pending,
        report.approvals.approved,
        report.approvals.denied
    );
    if report.asks_by_rule.is_empty() {
        println!("asks by rule: none");
    } else {
        println!("asks by rule:");
        for rule in &report.asks_by_rule {
            println!(
                "  {} total={} window={} approvals={}/{} pending={}",
                rule.rule,
                rule.total_asks,
                rule.window_asks,
                rule.approvals_approved,
                rule.approval_requests,
                rule.approvals_pending
            );
        }
    }
    if !report.deny_loops.is_empty() {
        println!("deny loops:");
        for loop_stats in &report.deny_loops {
            println!(
                "  {} {} occurrences={} window={}",
                loop_stats.tool,
                loop_stats.rule,
                loop_stats.occurrences,
                loop_stats.window_occurrences
            );
        }
    }
    if !report.reclassification_candidates.is_empty() {
        println!("reclassification candidates:");
        for candidate in &report.reclassification_candidates {
            println!(
                "  {} [{}] {}",
                candidate.rule, candidate.kind, candidate.reason
            );
        }
    }
}

impl RuleStatsBuilder {
    fn new(identity: &RuleIdentity) -> Self {
        Self {
            rule: identity.name.clone(),
            file: identity.file.clone(),
            ..Self::default()
        }
    }

    fn finish(self) -> RuleStats {
        let resolved = self.approvals_approved + self.approvals_denied;
        RuleStats {
            rule: self.rule,
            file: self.file,
            total_asks: self.total_asks,
            window_asks: self.window_asks,
            required_scope: self.required_scope,
            last_seen: self.last_seen.map(format_time),
            approval_requests: self.approval_requests,
            approvals_pending: self.approvals_pending,
            approvals_approved: self.approvals_approved,
            approvals_denied: self.approvals_denied,
            approval_rate: rate(self.approvals_approved, resolved),
            avg_time_to_resolution_seconds: average(
                self.resolution_seconds_total,
                self.resolution_count,
            ),
        }
    }
}

impl DenyLoopBuilder {
    fn finish(self) -> DenyLoop {
        DenyLoop {
            tool: self.tool,
            input_hash: self.input_hash,
            rule: self.rule,
            file: self.file,
            occurrences: self.occurrences,
            window_occurrences: self.window_occurrences,
            hard_stop: self.hard_stop,
            last_seen: self.last_seen.map(format_time),
        }
    }
}

#[derive(Debug)]
struct RuleIdentity {
    name: String,
    file: String,
}

impl RuleIdentity {
    fn key(&self) -> String {
        format!("{}\0{}", self.file, self.name)
    }
}

fn rule_identity_from_value(value: &Value) -> RuleIdentity {
    let matched_rule = value.get("matched_rule");
    let name = matched_rule
        .and_then(|rule| rule.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("<none>")
        .to_string();
    let file = matched_rule
        .and_then(|rule| rule.get("file"))
        .and_then(Value::as_str)
        .unwrap_or("<none>")
        .to_string();
    RuleIdentity { name, file }
}

fn rule_identity_from_approval(state: &ApprovalState) -> RuleIdentity {
    match &state.request.matched_rule {
        Some(MatchedRule { name, file, .. }) => RuleIdentity {
            name: name.clone(),
            file: file.clone(),
        },
        None => RuleIdentity {
            name: "<none>".to_string(),
            file: "<none>".to_string(),
        },
    }
}

fn resolution_seconds(state: &ApprovalState) -> Option<u64> {
    let resolution = state.resolution.as_ref()?;
    let duration = resolution.resolved_at - state.request.created_at;
    if duration.is_negative() {
        return None;
    }
    Some(duration.whole_seconds() as u64)
}

fn count_schema_version(value: &Value, schema_versions: &mut BTreeMap<String, usize>) {
    let key = match value.get("v") {
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) => "null".to_string(),
        Some(_) => "other".to_string(),
        None => "missing".to_string(),
    };
    *schema_versions.entry(key).or_default() += 1;
}

fn max_time(
    current: Option<OffsetDateTime>,
    candidate: Option<OffsetDateTime>,
) -> Option<OffsetDateTime> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (None, Some(candidate)) => Some(candidate),
        (current, None) => current,
    }
}

fn parse_time(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn format_time(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

fn rate(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn average(total: i128, count: usize) -> Option<f64> {
    if count == 0 {
        None
    } else {
        Some(total as f64 / count as f64)
    }
}
