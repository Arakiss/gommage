use crate::{Capability, Policy, Rule, RuleDecision, hardstop};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeMap};

/// The final decision the daemon will return to the agent.
///
/// `Allow` and `Gommage` are self-explanatory. `AskPicto` is returned to the
/// daemon, not to the agent directly — the daemon consults the picto store and
/// (if no matching picto) escalates out-of-band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Decision {
    Allow,
    /// Denied by policy. `hard_stop` is true when the rule said so OR when the
    /// hit came from the hardcoded hardstop set.
    Gommage {
        reason: String,
        hard_stop: bool,
    },
    /// Rule matched with `decision=ask_picto`. Daemon must consult the picto store.
    /// A matching, valid picto causes this to become `Allow`; otherwise the daemon
    /// escalates out-of-band.
    AskPicto {
        required_scope: String,
        reason: String,
        /// When true, only a Picto bound to this exact canonical tool-call
        /// input hash may turn this decision into an allow.
        #[serde(default, skip_serializing_if = "is_false")]
        bind_input: bool,
    },
}

fn is_false(value: &bool) -> bool {
    !value
}

/// A summary of which rule produced the decision. Written to the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedRule {
    pub name: String,
    pub file: String,
    pub index: usize,
}

/// How one normalized capability participated in policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityProvenanceStatus {
    /// At least one policy layer contributed a decision for the capability.
    Resolved,
    /// No policy layer contributed, so the call fails closed.
    Unresolved,
    /// This capability triggered a compiled-in hard-stop.
    HardStop,
    /// Evaluation stopped after a sibling capability triggered a hard-stop.
    SkippedDueToHardStop,
    /// Policy evaluation was explicitly bypassed for this capability.
    PolicyBypassed,
}

/// One layer's first matching rule for a normalized capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleContribution {
    /// Stable layer name retained from policy loading.
    pub layer: String,
    /// Layer precedence in the ordered load request.
    pub layer_index: usize,
    /// Source file order inside the layer.
    pub file_index: usize,
    /// Compatibility rule provenance.
    pub rule: MatchedRule,
    /// Decision contributed by this layer for the capability.
    pub decision: Decision,
}

/// Complete deterministic provenance for one normalized capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProvenance {
    /// Normalized capability this provenance describes.
    pub capability: Capability,
    /// Whether the capability resolved, failed closed, or was skipped.
    pub status: CapabilityProvenanceStatus,
    /// Conservative resolution of this capability's layer contributions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_decision: Option<Decision>,
    /// At most one first-match contribution per policy layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<RuleContribution>,
}

/// The full result of evaluation: decision + provenance + the capabilities that
/// were in play at the time. Stored in audit so `gommage explain` can be exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalResult {
    pub decision: Decision,
    pub matched_rule: Option<MatchedRule>,
    pub capabilities: Vec<Capability>,
    pub policy_version: String,
    /// Per-capability provenance. The default preserves deserialization of
    /// evaluation results recorded before compositional policy evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_provenance: Vec<CapabilityProvenance>,
}

/// Pure evaluation. Given the set of capabilities produced by the mapper and a
/// compiled policy, produce a decision.
///
/// Ordering rules (**do not change without updating the determinism suite**):
///   1. Normalize, byte-sort, and deduplicate capabilities.
///   2. Check hardcoded hard-stops (always first, cannot be bypassed by policy).
///   3. Resolve each capability independently, preserving first-match only
///      inside one layer and one capability.
///   4. Aggregate all layer contributions conservatively: deny beats ask,
///      ask beats allow, and an unresolved capability fails closed.
pub fn evaluate(caps: &[Capability], policy: &Policy) -> EvalResult {
    let caps = policy.normalize_capabilities(caps);
    if let Some(hit) = hardstop::check(&caps) {
        let decision = hard_stop_decision(&hit);
        let matched_rule = hard_stop_matched_rule(&hit);
        return EvalResult {
            decision: decision.clone(),
            matched_rule: Some(matched_rule.clone()),
            capability_provenance: hard_stop_provenance(
                &caps,
                &hit.capability,
                &decision,
                &matched_rule,
            ),
            capabilities: caps,
            policy_version: policy.version_hash.clone(),
        };
    }

    let mut capability_provenance = Vec::with_capacity(caps.len());
    for capability in &caps {
        let contributions = resolve_capability(capability, &caps, policy);
        if contributions.is_empty() {
            capability_provenance.push(CapabilityProvenance {
                capability: capability.clone(),
                status: CapabilityProvenanceStatus::Unresolved,
                effective_decision: None,
                contributions,
            });
        } else {
            let (effective_decision, _) = aggregate_contributions(&contributions);
            capability_provenance.push(CapabilityProvenance {
                capability: capability.clone(),
                status: CapabilityProvenanceStatus::Resolved,
                effective_decision: Some(effective_decision),
                contributions,
            });
        }
    }

    let unresolved = capability_provenance
        .iter()
        .find(|entry| entry.status == CapabilityProvenanceStatus::Unresolved);
    let mut contributions: Vec<&RuleContribution> = capability_provenance
        .iter()
        .flat_map(|entry| entry.contributions.iter())
        .collect();
    contributions.sort_by(|left, right| compare_contributions(left, right));

    let policy_denies: Vec<&RuleContribution> = contributions
        .iter()
        .copied()
        .filter(|entry| matches!(entry.decision, Decision::Gommage { .. }))
        .collect();
    let (decision, matched_rule) = if !policy_denies.is_empty() {
        aggregate_contributions(&policy_denies)
    } else if let Some(unresolved) = unresolved {
        (
            Decision::Gommage {
                reason: format!(
                    "capability {} unresolved by all policy layers (fail-closed)",
                    unresolved.capability
                ),
                hard_stop: false,
            },
            None,
        )
    } else if caps.is_empty() {
        (
            Decision::Gommage {
                reason: "no capabilities to authorize (fail-closed)".to_string(),
                hard_stop: false,
            },
            None,
        )
    } else {
        aggregate_contributions(&contributions)
    };

    EvalResult {
        decision,
        matched_rule,
        capabilities: caps,
        policy_version: policy.version_hash.clone(),
        capability_provenance,
    }
}

/// Decision for a tool call when policy evaluation is bypassed
/// (`GOMMAGE_BYPASS=1`), given the capabilities already mapped for it. Compiled
/// hard-stops still deny — they are never bypassable — and everything else is
/// allowed with policy explicitly skipped.
///
/// The caller maps `caps` (the bypass path uses the bundled stdlib mappers, in
/// `gommage-stdlib`, so the kill-switch works even when the on-disk policy is
/// broken). Keeping the decision here, in core, makes it the single source of
/// truth shared by the `gommage-mcp` hook binary and the `gommage mcp` CLI
/// adapter, without core depending on the (unpublished) stdlib assets.
pub fn evaluate_bypass(caps: Vec<Capability>) -> EvalResult {
    let caps = sort_and_deduplicate(caps);
    if let Some(hit) = hardstop::check(&caps) {
        let decision = hard_stop_decision(&hit);
        let matched_rule = hard_stop_matched_rule(&hit);
        return EvalResult {
            decision: decision.clone(),
            matched_rule: Some(matched_rule.clone()),
            capability_provenance: hard_stop_provenance(
                &caps,
                &hit.capability,
                &decision,
                &matched_rule,
            ),
            capabilities: caps,
            policy_version: "bypass:compiled-hardstop".to_string(),
        };
    }
    let capability_provenance = caps
        .iter()
        .cloned()
        .map(|capability| CapabilityProvenance {
            capability,
            status: CapabilityProvenanceStatus::PolicyBypassed,
            effective_decision: Some(Decision::Allow),
            contributions: Vec::new(),
        })
        .collect();
    EvalResult {
        decision: Decision::Allow,
        matched_rule: None,
        capabilities: caps,
        policy_version: "bypass:policy-skipped".to_string(),
        capability_provenance,
    }
}

fn resolve_capability(
    capability: &Capability,
    caps: &[Capability],
    policy: &Policy,
) -> Vec<RuleContribution> {
    let mut contributions = Vec::new();
    let mut current_layer = None;
    let mut layer_resolved = false;

    for rule in &policy.rules {
        if current_layer != Some(rule.source.layer_index) {
            current_layer = Some(rule.source.layer_index);
            layer_resolved = false;
        }
        if layer_resolved {
            continue;
        }
        if rule.r#match.matches(caps) && rule.r#match.covers(capability) {
            contributions.push(contribution_from_rule(rule));
            layer_resolved = true;
        }
    }

    contributions
}

fn contribution_from_rule(rule: &Rule) -> RuleContribution {
    RuleContribution {
        layer: rule.source.layer.clone(),
        layer_index: rule.source.layer_index,
        file_index: rule.source.file_index,
        rule: matched_rule_from_rule(rule),
        decision: decision_from_rule(rule),
    }
}

fn matched_rule_from_rule(rule: &Rule) -> MatchedRule {
    MatchedRule {
        name: rule.name.clone(),
        file: rule.source.file.to_string_lossy().to_string(),
        index: rule.source.index,
    }
}

fn aggregate_contributions(
    contributions: &[impl std::borrow::Borrow<RuleContribution>],
) -> (Decision, Option<MatchedRule>) {
    let contributions: Vec<&RuleContribution> = contributions
        .iter()
        .map(std::borrow::Borrow::borrow)
        .collect();

    let denies: Vec<&RuleContribution> = contributions
        .iter()
        .copied()
        .filter(|entry| matches!(entry.decision, Decision::Gommage { .. }))
        .collect();
    if let Some(primary) = denies.first() {
        let reason = match &primary.decision {
            Decision::Gommage { reason, .. } => reason.clone(),
            _ => unreachable!("deny contribution changed kind"),
        };
        let hard_stop = denies.iter().any(|entry| {
            matches!(
                entry.decision,
                Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            )
        });
        return (
            Decision::Gommage { reason, hard_stop },
            Some(primary.rule.clone()),
        );
    }

    let asks: Vec<&RuleContribution> = contributions
        .iter()
        .copied()
        .filter(|entry| matches!(entry.decision, Decision::AskPicto { .. }))
        .collect();
    if let Some(primary) = asks.first() {
        let mut scopes: BTreeMap<String, (String, bool)> = BTreeMap::new();
        for contribution in &asks {
            let Decision::AskPicto {
                required_scope,
                reason,
                bind_input,
            } = &contribution.decision
            else {
                unreachable!("ask contribution changed kind");
            };
            let aggregate = scopes
                .entry(required_scope.clone())
                .or_insert_with(|| (reason.clone(), false));
            aggregate.1 |= bind_input;
        }

        if scopes.len() > 1 {
            let scopes = scopes.keys().cloned().collect::<Vec<_>>().join(", ");
            return (
                Decision::Gommage {
                    reason: format!(
                        "multiple Picto scopes required ({scopes}); split the call before requesting authorization"
                    ),
                    hard_stop: false,
                },
                Some(primary.rule.clone()),
            );
        }

        let (required_scope, (reason, bind_input)) = scopes
            .into_iter()
            .next()
            .expect("at least one ask contribution has one scope");
        return (
            Decision::AskPicto {
                required_scope,
                reason,
                bind_input,
            },
            Some(primary.rule.clone()),
        );
    }

    (
        Decision::Allow,
        contributions.first().map(|entry| entry.rule.clone()),
    )
}

fn compare_contributions(left: &RuleContribution, right: &RuleContribution) -> Ordering {
    left.layer_index
        .cmp(&right.layer_index)
        .then_with(|| left.file_index.cmp(&right.file_index))
        .then_with(|| left.rule.index.cmp(&right.rule.index))
        .then_with(|| left.layer.as_bytes().cmp(right.layer.as_bytes()))
        .then_with(|| left.rule.file.as_bytes().cmp(right.rule.file.as_bytes()))
        .then_with(|| left.rule.name.as_bytes().cmp(right.rule.name.as_bytes()))
}

fn sort_and_deduplicate(mut caps: Vec<Capability>) -> Vec<Capability> {
    caps.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    caps.dedup_by(|left, right| left.as_str() == right.as_str());
    caps
}

fn hard_stop_decision(hit: &hardstop::HardStopHit) -> Decision {
    Decision::Gommage {
        reason: format!(
            "hard-stop {}: pattern {:?} matched {}",
            hit.name, hit.pattern, hit.capability
        ),
        hard_stop: true,
    }
}

fn hard_stop_matched_rule(hit: &hardstop::HardStopHit) -> MatchedRule {
    MatchedRule {
        name: format!("<hardcoded:{}>", hit.name),
        file: "<compiled-in>".to_string(),
        index: 0,
    }
}

fn hard_stop_provenance(
    caps: &[Capability],
    hit: &Capability,
    decision: &Decision,
    matched_rule: &MatchedRule,
) -> Vec<CapabilityProvenance> {
    caps.iter()
        .cloned()
        .map(|capability| {
            if &capability == hit {
                CapabilityProvenance {
                    capability,
                    status: CapabilityProvenanceStatus::HardStop,
                    effective_decision: Some(decision.clone()),
                    contributions: vec![RuleContribution {
                        layer: "<compiled-in>".to_string(),
                        layer_index: 0,
                        file_index: 0,
                        rule: matched_rule.clone(),
                        decision: decision.clone(),
                    }],
                }
            } else {
                CapabilityProvenance {
                    capability,
                    status: CapabilityProvenanceStatus::SkippedDueToHardStop,
                    effective_decision: None,
                    contributions: Vec::new(),
                }
            }
        })
        .collect()
}

fn decision_from_rule(rule: &Rule) -> Decision {
    match rule.decision {
        RuleDecision::Allow => Decision::Allow,
        RuleDecision::Gommage => Decision::Gommage {
            reason: rule.reason.clone(),
            hard_stop: rule.hard_stop,
        },
        RuleDecision::AskPicto => Decision::AskPicto {
            required_scope: rule
                .required_scope
                .clone()
                .expect("ask_picto rule without required_scope survived compilation; bug"),
            reason: rule.reason.clone(),
            bind_input: rule.bind_input,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn p(yaml: &str) -> Policy {
        Policy::from_yaml_string(yaml, &HashMap::new(), "test.yaml").unwrap()
    }

    #[test]
    fn first_match_wins() {
        let pol = p(r#"
- name: first
  decision: allow
  match: { any_capability: ["fs.read:*"] }
  reason: ""
- name: second
  decision: gommage
  match: { any_capability: ["fs.read:*"] }
  reason: "never fires"
"#);
        let res = evaluate(&[Capability::new("fs.read:/tmp/x")], &pol);
        assert_eq!(res.decision, Decision::Allow);
    }

    #[test]
    fn fail_closed_on_no_match() {
        let pol = p(r#"
- name: only-git
  decision: allow
  match: { any_capability: ["git.push:*"] }
  reason: ""
"#);
        let res = evaluate(&[Capability::new("fs.read:/tmp/x")], &pol);
        assert!(matches!(res.decision, Decision::Gommage { .. }));
    }

    #[test]
    fn hardstop_wins_over_allow() {
        let pol = p(r#"
- name: allow-all
  decision: allow
  match: { any_capability: ["**"] }
  reason: ""
"#);
        let res = evaluate(&[Capability::new("proc.exec:rm -rf /")], &pol);
        let Decision::Gommage { hard_stop, .. } = res.decision else {
            panic!("expected gommage");
        };
        assert!(hard_stop);
    }

    #[test]
    fn bypass_allows_when_no_hardstop() {
        let eval = evaluate_bypass(vec![Capability::new("proc.exec:ls -la")]);
        assert_eq!(eval.decision, Decision::Allow);
        assert_eq!(eval.policy_version, "bypass:policy-skipped");
    }

    #[test]
    fn bypass_still_denies_compiled_hardstop() {
        let eval = evaluate_bypass(vec![Capability::new("proc.exec:rm -rf /")]);
        let Decision::Gommage { hard_stop, .. } = eval.decision else {
            panic!("expected gommage deny under bypass");
        };
        assert!(hard_stop, "compiled hard-stops are never bypassable");
    }

    #[test]
    fn ask_picto_surfaces_scope() {
        let pol = p(r#"
- name: gate-main
  decision: ask_picto
  required_scope: "git.push:main"
  match: { any_capability: ["git.push:refs/heads/main"] }
  reason: "main requires picto"
"#);
        let res = evaluate(&[Capability::new("git.push:refs/heads/main")], &pol);
        let Decision::AskPicto {
            required_scope,
            bind_input,
            ..
        } = res.decision
        else {
            panic!("expected ask_picto");
        };
        assert_eq!(required_scope, "git.push:main");
        assert!(!bind_input);
    }

    #[test]
    fn ask_picto_surfaces_input_binding() {
        let pol = p(r#"
- name: gate-exact-production
  decision: ask_picto
  required_scope: "deploy.production"
  bind_input: true
  match: { any_capability: ["deploy.production"] }
  reason: "production requires exact approval"
"#);
        let res = evaluate(&[Capability::new("deploy.production")], &pol);
        let Decision::AskPicto { bind_input, .. } = res.decision else {
            panic!("expected ask_picto");
        };
        assert!(bind_input);
    }
}
