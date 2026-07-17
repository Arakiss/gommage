use anyhow::{Context, Result};
use gommage_core::{
    Capability, CapabilityMapper, Decision, MatchedRule, Policy,
    runtime::{
        Expedition, HomeLayout, active_policy_layers, default_policy_env, load_active_policy,
    },
};
use gommage_stdlib::{CAPABILITIES as STDLIB_CAPABILITIES, POLICIES as STDLIB_POLICIES};
use serde::Serialize;
use std::process::ExitCode;

use crate::{
    smoke::{SmokeStatus, smoke_fixtures},
    util::path_display,
};

#[derive(Debug, Serialize)]
pub(crate) struct PostureReport {
    status: SmokeStatus,
    posture: PostureKind,
    home: String,
    active_policy_version: String,
    strict_policy_version: String,
    active_mapper_rules: usize,
    strict_mapper_rules: usize,
    layers: Vec<PostureLayer>,
    summary: PostureSummary,
    checks: Vec<PostureCheck>,
}

impl PostureReport {
    fn exit_code(&self) -> ExitCode {
        if self.status == SmokeStatus::Fail {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PostureKind {
    Strict,
    Relaxed,
    Custom,
    Failing,
}

impl PostureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
            Self::Custom => "custom",
            Self::Failing => "failing",
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct PostureSummary {
    same: usize,
    relaxed: usize,
    tightened: usize,
    changed: usize,
    failed: usize,
}

#[derive(Debug, Serialize)]
struct PostureLayer {
    name: String,
    dir: String,
}

#[derive(Debug, Serialize)]
struct PostureCheck {
    name: &'static str,
    description: &'static str,
    status: SmokeStatus,
    classification: PostureClassification,
    strict_decision: Decision,
    active_decision: Decision,
    strict_capabilities: Vec<Capability>,
    active_capabilities: Vec<Capability>,
    strict_matched_rule: Option<MatchedRule>,
    active_matched_rule: Option<MatchedRule>,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PostureClassification {
    Same,
    Relaxed,
    Tightened,
    Changed,
    Failed,
}

impl PostureClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Relaxed => "relaxed",
            Self::Tightened => "tightened",
            Self::Changed => "changed",
            Self::Failed => "failed",
        }
    }
}

pub(crate) fn cmd_posture(layout: HomeLayout, json: bool) -> Result<ExitCode> {
    let report = build_posture_report(&layout)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_posture_report(&report);
    }
    Ok(report.exit_code())
}

fn build_posture_report(layout: &HomeLayout) -> Result<PostureReport> {
    let expedition = Expedition::load(&layout.expedition_file)?;
    let env = expedition
        .as_ref()
        .map(Expedition::policy_env)
        .unwrap_or_else(default_policy_env);
    let active_mapper = CapabilityMapper::load_from_dir(&layout.capabilities_dir)
        .context("loading active capability mappers for posture")?;
    let active_policy = load_active_policy(layout, expedition.as_ref(), &env)
        .context("loading active policy for posture")?;
    let strict_mapper = CapabilityMapper::from_yaml_string(
        &concat_stdlib(STDLIB_CAPABILITIES),
        "<gommage-stdlib-capabilities>",
    )
    .context("loading bundled capability mappers for posture")?;
    let strict_policy = Policy::from_yaml_string(
        &concat_stdlib(STDLIB_POLICIES),
        &env,
        "<gommage-stdlib-policy>",
    )
    .context("loading bundled policy for posture")?;
    let layers = active_policy_layers(layout, expedition.as_ref())?
        .into_iter()
        .map(|layer| PostureLayer {
            name: layer.name().to_string(),
            dir: path_display(&layer.dir),
        })
        .collect::<Vec<_>>();

    let mut checks = Vec::new();
    let mut summary = PostureSummary::default();
    for fixture in smoke_fixtures() {
        let strict_capabilities = strict_mapper.map(&fixture.call);
        let strict_eval = gommage_core::evaluate(&strict_capabilities, &strict_policy);
        let active_capabilities = active_mapper.map(&fixture.call);
        let active_eval = gommage_core::evaluate(&active_capabilities, &active_policy);
        let classification = classify(&strict_eval.decision, &active_eval.decision);
        let status = match classification {
            PostureClassification::Same => {
                summary.same += 1;
                SmokeStatus::Pass
            }
            PostureClassification::Relaxed => {
                summary.relaxed += 1;
                SmokeStatus::Warn
            }
            PostureClassification::Tightened => {
                summary.tightened += 1;
                SmokeStatus::Warn
            }
            PostureClassification::Changed => {
                summary.changed += 1;
                SmokeStatus::Warn
            }
            PostureClassification::Failed => {
                summary.failed += 1;
                SmokeStatus::Fail
            }
        };
        let message = posture_message(
            classification,
            &strict_eval.decision,
            &active_eval.decision,
            active_eval.matched_rule.as_ref(),
        );
        checks.push(PostureCheck {
            name: fixture.name,
            description: fixture.description,
            status,
            classification,
            strict_decision: strict_eval.decision,
            active_decision: active_eval.decision,
            strict_capabilities,
            active_capabilities,
            strict_matched_rule: strict_eval.matched_rule,
            active_matched_rule: active_eval.matched_rule,
            message,
        });
    }

    let posture = if summary.failed > 0 {
        PostureKind::Failing
    } else if summary.relaxed > 0 {
        PostureKind::Relaxed
    } else if summary.tightened > 0 || summary.changed > 0 {
        PostureKind::Custom
    } else {
        PostureKind::Strict
    };
    let status = if summary.failed > 0 {
        SmokeStatus::Fail
    } else if posture == PostureKind::Strict {
        SmokeStatus::Pass
    } else {
        SmokeStatus::Warn
    };

    Ok(PostureReport {
        status,
        posture,
        home: path_display(&layout.root),
        active_policy_version: active_policy.version_hash,
        strict_policy_version: strict_policy.version_hash,
        active_mapper_rules: active_mapper.rule_count(),
        strict_mapper_rules: strict_mapper.rule_count(),
        layers,
        summary,
        checks,
    })
}

fn concat_stdlib(files: &[gommage_stdlib::StdlibFile]) -> String {
    let mut out = String::new();
    for file in files {
        out.push_str(file.contents.trim_end());
        out.push('\n');
    }
    out
}

fn classify(strict: &Decision, active: &Decision) -> PostureClassification {
    if decisions_equivalent(strict, active) {
        return PostureClassification::Same;
    }
    match (decision_rank(strict), decision_rank(active)) {
        (Some(strict), Some(active)) if active < strict => PostureClassification::Relaxed,
        (Some(strict), Some(active)) if active > strict => PostureClassification::Tightened,
        (Some(_), Some(_)) => PostureClassification::Changed,
        _ => PostureClassification::Failed,
    }
}

fn decision_rank(decision: &Decision) -> Option<u8> {
    match decision {
        Decision::Allow => Some(0),
        Decision::AskPicto { .. } => Some(1),
        Decision::Gommage {
            hard_stop: false, ..
        } => Some(2),
        Decision::Gommage {
            hard_stop: true, ..
        } => Some(3),
    }
}

fn decisions_equivalent(a: &Decision, b: &Decision) -> bool {
    match (a, b) {
        (Decision::Allow, Decision::Allow) => true,
        (
            Decision::AskPicto {
                required_scope: left,
                ..
            },
            Decision::AskPicto {
                required_scope: right,
                ..
            },
        ) => left == right,
        (
            Decision::Gommage {
                hard_stop: left, ..
            },
            Decision::Gommage {
                hard_stop: right, ..
            },
        ) => left == right,
        _ => false,
    }
}

fn posture_message(
    classification: PostureClassification,
    strict: &Decision,
    active: &Decision,
    active_rule: Option<&MatchedRule>,
) -> String {
    match classification {
        PostureClassification::Same => {
            format!(
                "active policy matches bundled stdlib: {}",
                decision_label(active)
            )
        }
        PostureClassification::Relaxed => format!(
            "active policy is less strict than bundled stdlib: {} -> {}{}",
            decision_label(strict),
            decision_label(active),
            rule_suffix(active_rule)
        ),
        PostureClassification::Tightened => format!(
            "active policy is stricter than bundled stdlib: {} -> {}{}",
            decision_label(strict),
            decision_label(active),
            rule_suffix(active_rule)
        ),
        PostureClassification::Changed => format!(
            "active policy differs from bundled stdlib: {} -> {}{}",
            decision_label(strict),
            decision_label(active),
            rule_suffix(active_rule)
        ),
        PostureClassification::Failed => {
            "could not compare this decision against bundled stdlib".to_string()
        }
    }
}

fn rule_suffix(rule: Option<&MatchedRule>) -> String {
    rule.map(|rule| format!(" via {} ({}:{})", rule.name, rule.file, rule.index))
        .unwrap_or_default()
}

fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::AskPicto { required_scope, .. } => format!("ask_picto:{required_scope}"),
        Decision::Gommage { hard_stop, .. } => format!("gommage:hard_stop={hard_stop}"),
    }
}

fn print_posture_report(report: &PostureReport) {
    println!(
        "posture: {} [{}]",
        report.posture.as_str(),
        report.status.as_str()
    );
    println!("active policy: {}", report.active_policy_version);
    println!("strict stdlib: {}", report.strict_policy_version);
    println!(
        "mappers: active={} strict={}",
        report.active_mapper_rules, report.strict_mapper_rules
    );
    println!("layers:");
    for layer in &report.layers {
        println!("  - {}: {}", layer.name, layer.dir);
    }
    println!();
    for check in &report.checks {
        println!(
            "{} {}: {}",
            check.status.as_str(),
            check.name,
            check.classification.as_str()
        );
        println!("  {}", check.message);
    }
    println!(
        "summary: same={} relaxed={} tightened={} changed={} failed={}",
        report.summary.same,
        report.summary.relaxed,
        report.summary.tightened,
        report.summary.changed,
        report.summary.failed
    );
}
