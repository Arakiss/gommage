use super::{
    CapabilityProvenance, CapabilityProvenanceStatus, Decision, EvalResult, RuleContribution,
    aggregate_contributions, compare_contributions, hard_stop_decision, hard_stop_matched_rule,
    hard_stop_provenance, sort_and_deduplicate,
};
use crate::{Capability, hardstop};
use std::cmp::Ordering;

#[cfg(test)]
thread_local! {
    static LIVE_RECONSTRUCTION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_live_reconstruction_probe() {
    LIVE_RECONSTRUCTION_CALLS.set(0);
}

#[cfg(test)]
pub(crate) fn live_reconstruction_probe() -> usize {
    LIVE_RECONSTRUCTION_CALLS.get()
}

pub(crate) fn validate_reference_evaluation(evaluation: &EvalResult) -> Result<(), String> {
    validate_evaluation_shape(evaluation)?;

    match hardstop::check(&evaluation.capabilities) {
        Some(hit) => {
            let decision = hard_stop_decision(&hit);
            let matched_rule = hard_stop_matched_rule(&hit);
            let provenance = hard_stop_provenance(
                &evaluation.capabilities,
                &hit.capability,
                &decision,
                &matched_rule,
            );
            if evaluation.decision != decision
                || evaluation.matched_rule.as_ref() != Some(&matched_rule)
                || evaluation.capability_provenance != provenance
            {
                return Err(
                    "evaluation does not preserve the current compiled hard-stop result".into(),
                );
            }
        }
        None => {
            if evaluation.capability_provenance.iter().any(|entry| {
                matches!(
                    entry.status,
                    CapabilityProvenanceStatus::HardStop
                        | CapabilityProvenanceStatus::SkippedDueToHardStop
                )
            }) {
                return Err(
                    "evaluation claims compiled hard-stop provenance without a current hit".into(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn reconstruct_evaluation(
    capabilities: Vec<Capability>,
    capability_provenance: Vec<CapabilityProvenance>,
    policy_version: String,
) -> Result<EvalResult, String> {
    #[cfg(test)]
    LIVE_RECONSTRUCTION_CALLS.set(LIVE_RECONSTRUCTION_CALLS.get() + 1);

    if sort_and_deduplicate(capabilities.clone()) != capabilities {
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
        validate_contribution_order(&provenance.contributions)?;
        let effective =
            effective_decision_for_provenance(provenance.status, &provenance.contributions)?;
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
    } else if capabilities.is_empty() {
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

    Ok(EvalResult {
        decision,
        matched_rule,
        capabilities,
        policy_version,
        capability_provenance,
        authorization: None,
    })
}

pub(crate) fn effective_decision_for_provenance(
    status: CapabilityProvenanceStatus,
    contributions: &[RuleContribution],
) -> Result<Option<Decision>, String> {
    match status {
        CapabilityProvenanceStatus::Resolved => {
            if contributions.is_empty() {
                return Err("resolved provenance has no policy contribution".into());
            }
            Ok(Some(aggregate_contributions(contributions).0))
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

fn validate_evaluation_shape(evaluation: &EvalResult) -> Result<(), String> {
    if evaluation.authorization.is_some() {
        return Err("pre-Authority evaluation already contains authorization evidence".into());
    }
    let reconstructed = reconstruct_evaluation(
        evaluation.capabilities.clone(),
        evaluation.capability_provenance.clone(),
        evaluation.policy_version.clone(),
    )?;
    if reconstructed != *evaluation {
        return Err("evaluation summary contradicts its complete provenance".into());
    }
    Ok(())
}

fn validate_contribution_order(contributions: &[RuleContribution]) -> Result<(), String> {
    if contributions
        .windows(2)
        .any(|pair| compare_contributions(&pair[0], &pair[1]) != Ordering::Less)
        || contributions
            .windows(2)
            .any(|pair| pair[0].layer_index == pair[1].layer_index)
    {
        return Err("policy contributions are not strictly ordered by unique layer".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Policy, evaluate};
    use std::collections::HashMap;

    #[test]
    fn empty_fail_closed_evaluation_reconstructs_exactly() {
        let evaluation = reconstruct_evaluation(Vec::new(), Vec::new(), "policy".into()).unwrap();
        assert_eq!(
            evaluation.decision,
            Decision::Gommage {
                reason: "no capabilities to authorize (fail-closed)".into(),
                hard_stop: false,
            }
        );
        validate_reference_evaluation(&evaluation).unwrap();
    }

    #[test]
    fn policy_bypass_is_not_reference_evidence() {
        let evaluation = EvalResult {
            decision: Decision::Allow,
            matched_rule: None,
            capabilities: vec![Capability::new("proc.exec:true")],
            policy_version: "bypass:policy-skipped".into(),
            capability_provenance: vec![CapabilityProvenance {
                capability: Capability::new("proc.exec:true"),
                status: CapabilityProvenanceStatus::PolicyBypassed,
                effective_decision: Some(Decision::Allow),
                contributions: Vec::new(),
            }],
            authorization: None,
        };
        assert!(validate_reference_evaluation(&evaluation).is_err());
    }

    #[test]
    fn compiled_hard_stop_requires_the_canonical_rule_index() {
        let policy = Policy::from_yaml_string("[]", &HashMap::new(), "test.yaml").unwrap();
        let mut evaluation = evaluate(&[Capability::new("proc.exec:rm -rf /")], &policy);
        evaluation.capability_provenance[0].contributions[0]
            .rule
            .index = 1;
        assert!(
            reconstruct_evaluation(
                evaluation.capabilities,
                evaluation.capability_provenance,
                evaluation.policy_version,
            )
            .is_err()
        );
    }
}
