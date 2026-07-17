//! Frozen reducer for signed `gommage.compositional-evaluation.v2` evidence.
//!
//! Do not change these semantics when the live evaluator evolves. Add a new
//! versioned reducer and dispatch new records to it instead; historical v2
//! records must retain the meaning they had when Authority signed them.

use super::{
    CapabilityProvenance, CapabilityProvenanceStatus, Decision, EvalResult, MatchedRule,
    RuleContribution,
};
use crate::Capability;
use std::{borrow::Borrow, cmp::Ordering, collections::BTreeMap};

pub(crate) fn reconstruct_evaluation_v2(
    capabilities: Vec<Capability>,
    capability_provenance: Vec<CapabilityProvenance>,
    policy_version: String,
) -> Result<EvalResult, String> {
    if sort_and_deduplicate_v2(capabilities.clone()) != capabilities {
        return Err("evaluation capabilities are not byte-sorted and unique".into());
    }
    if capability_provenance.len() != capabilities.len()
        || capability_provenance
            .iter()
            .zip(&capabilities)
            .any(|(provenance, capability)| provenance.capability != *capability)
    {
        return Err("evaluation provenance is not one-to-one with capabilities".into());
    }

    for provenance in &capability_provenance {
        if provenance.status == CapabilityProvenanceStatus::PolicyBypassed {
            return Err("reference Authority cannot record policy-bypassed evaluation".into());
        }
        validate_contribution_order_v2(&provenance.contributions)?;
        let effective =
            effective_decision_for_provenance_v2(provenance.status, &provenance.contributions)?;
        if provenance.effective_decision != effective {
            return Err("evaluation effective decision contradicts its provenance".into());
        }
    }

    let compiled_hard_stops: Vec<&CapabilityProvenance> = capability_provenance
        .iter()
        .filter(|entry| entry.status == CapabilityProvenanceStatus::HardStop)
        .collect();
    if !compiled_hard_stops.is_empty() {
        if compiled_hard_stops.len() != 1
            || capability_provenance.iter().any(|entry| {
                !matches!(
                    entry.status,
                    CapabilityProvenanceStatus::HardStop
                        | CapabilityProvenanceStatus::SkippedDueToHardStop
                )
            })
        {
            return Err("compiled hard-stop provenance has an invalid status shape".into());
        }
        let hit = compiled_hard_stops[0];
        if hit.contributions.len() != 1 {
            return Err("compiled hard-stop provenance must contain one contribution".into());
        }
        let contribution = &hit.contributions[0];
        if contribution.layer != "<compiled-in>"
            || contribution.layer_index != 0
            || contribution.file_index != 0
            || contribution.rule.file != "<compiled-in>"
            || contribution.rule.index != 0
            || !contribution.rule.name.starts_with("<hardcoded:")
            || !contribution.rule.name.ends_with('>')
            || !matches!(
                contribution.decision,
                Decision::Gommage {
                    hard_stop: true,
                    ..
                }
            )
        {
            return Err("compiled hard-stop provenance is not canonical".into());
        }
        return Ok(EvalResult {
            decision: contribution.decision.clone(),
            matched_rule: Some(contribution.rule.clone()),
            capabilities,
            policy_version,
            capability_provenance,
            authorization: None,
        });
    }
    if capability_provenance
        .iter()
        .any(|entry| entry.status == CapabilityProvenanceStatus::SkippedDueToHardStop)
    {
        return Err("skipped hard-stop provenance has no compiled hard-stop hit".into());
    }

    let unresolved = capability_provenance
        .iter()
        .find(|entry| entry.status == CapabilityProvenanceStatus::Unresolved);
    let mut contributions: Vec<&RuleContribution> = capability_provenance
        .iter()
        .flat_map(|entry| entry.contributions.iter())
        .collect();
    contributions.sort_by(|left, right| compare_contributions_v2(left, right));
    let policy_denies: Vec<&RuleContribution> = contributions
        .iter()
        .copied()
        .filter(|entry| matches!(entry.decision, Decision::Gommage { .. }))
        .collect();
    let (decision, matched_rule) = if !policy_denies.is_empty() {
        aggregate_contributions_v2(&policy_denies)
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
    } else if capabilities.is_empty() {
        (
            Decision::Gommage {
                reason: "no capabilities to authorize (fail-closed)".to_string(),
                hard_stop: false,
            },
            None,
        )
    } else {
        aggregate_contributions_v2(&contributions)
    };

    Ok(EvalResult {
        decision,
        matched_rule,
        capabilities,
        policy_version,
        capability_provenance,
        authorization: None,
    })
}

pub(crate) fn effective_decision_for_provenance_v2(
    status: CapabilityProvenanceStatus,
    contributions: &[RuleContribution],
) -> Result<Option<Decision>, String> {
    match status {
        CapabilityProvenanceStatus::Resolved => {
            if contributions.is_empty() {
                return Err("resolved provenance has no policy contribution".into());
            }
            Ok(Some(aggregate_contributions_v2(contributions).0))
        }
        CapabilityProvenanceStatus::Unresolved
        | CapabilityProvenanceStatus::SkippedDueToHardStop => {
            if !contributions.is_empty() {
                return Err("non-resolved provenance unexpectedly has contributions".into());
            }
            Ok(None)
        }
        CapabilityProvenanceStatus::HardStop => {
            if contributions.len() != 1 {
                return Err("compiled hard-stop provenance must contain one contribution".into());
            }
            Ok(Some(contributions[0].decision.clone()))
        }
        CapabilityProvenanceStatus::PolicyBypassed => {
            Err("reference Authority cannot record policy-bypassed evaluation".into())
        }
    }
}

fn aggregate_contributions_v2(
    contributions: &[impl Borrow<RuleContribution>],
) -> (Decision, Option<MatchedRule>) {
    let contributions: Vec<&RuleContribution> = contributions.iter().map(Borrow::borrow).collect();

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
            let scope_count = scopes.len();
            return (
                Decision::Gommage {
                    reason: format!(
                        "multiple Picto scopes required ({scope_count} distinct scopes); split the call before requesting authorization"
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

fn compare_contributions_v2(left: &RuleContribution, right: &RuleContribution) -> Ordering {
    left.layer_index
        .cmp(&right.layer_index)
        .then_with(|| left.file_index.cmp(&right.file_index))
        .then_with(|| left.rule.index.cmp(&right.rule.index))
        .then_with(|| left.layer.as_bytes().cmp(right.layer.as_bytes()))
        .then_with(|| left.rule.file.as_bytes().cmp(right.rule.file.as_bytes()))
        .then_with(|| left.rule.name.as_bytes().cmp(right.rule.name.as_bytes()))
}

fn validate_contribution_order_v2(contributions: &[RuleContribution]) -> Result<(), String> {
    if contributions
        .windows(2)
        .any(|pair| compare_contributions_v2(&pair[0], &pair[1]) != Ordering::Less)
        || contributions
            .windows(2)
            .any(|pair| pair[0].layer_index == pair[1].layer_index)
    {
        return Err("policy contributions are not strictly ordered by unique layer".into());
    }
    Ok(())
}

fn sort_and_deduplicate_v2(mut capabilities: Vec<Capability>) -> Vec<Capability> {
    capabilities.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    capabilities.dedup_by(|left, right| left.as_str() == right.as_str());
    capabilities
}
