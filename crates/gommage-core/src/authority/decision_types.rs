use super::{
    AuthorityError, AuthorityGenerationV2, AuthorizationContextV2, MAX_CAPABILITIES,
    MAX_CAPABILITY_BYTES, MAX_INTEGRATION_BYTES, MAX_TOOL_BYTES,
};
use crate::{
    Capability, CapabilityProvenance, CapabilityProvenanceStatus, Decision, EvalResult,
    RuleContribution, SignedGrantStateV2, ToolCall,
    contracts::{
        MAX_APPROVAL_REASON_BYTES, MAX_DECISION_REASON_BYTES, MAX_EVIDENCE_LAYER_BYTES,
        MAX_EVIDENCE_RULE_FILE_BYTES, MAX_EVIDENCE_RULE_NAME_BYTES,
    },
    crypto_envelope::{MAX_SAFE_INTEGER, canonicalize},
    evaluator::{
        effective_decision_for_provenance_v2, reconstruct_evaluation_v2,
        validate_reference_evaluation,
    },
    grant_v2::{validate_hash, validate_text, validate_token},
    picto::validate_picto_scope,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_POLICY_CONTRIBUTIONS_PER_CAPABILITY: usize = 3;
const RECORDED_EVALUATION_SEMANTICS: &str = "gommage.compositional-evaluation.v2";

/// Maximum canonical size of one normalized signed decision record.
pub const MAX_DECISION_RECORD_BYTES: usize = 512 * 1_024;

/// Minimal observed call context retained by signed Authority decisions.
///
/// Build, policy, and capabilities are deliberately not duplicated here: they
/// are derived from the record's generation and normalized evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionContextV2 {
    integration: String,
    tool: String,
    input_hash: String,
}

impl DecisionContextV2 {
    pub(super) fn from_call(integration: &str, call: &ToolCall) -> Result<Self, AuthorityError> {
        validate_text(
            "decision integration",
            integration,
            MAX_INTEGRATION_BYTES,
            false,
        )?;
        validate_text("decision tool", &call.tool, MAX_TOOL_BYTES, false)?;
        let context = Self {
            integration: integration.to_owned(),
            tool: call.tool.clone(),
            input_hash: call
                .bounded_input_hash()
                .map_err(AuthorityError::InvalidInput)?,
        };
        context.validate()?;
        Ok(context)
    }

    /// Return the declared host integration that observed the call.
    pub fn integration(&self) -> &str {
        &self.integration
    }

    /// Return the exact host tool name.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Return the canonical complete-input commitment.
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        validate_text(
            "decision integration",
            &self.integration,
            MAX_INTEGRATION_BYTES,
            false,
        )?;
        validate_text("decision tool", &self.tool, MAX_TOOL_BYTES, false)?;
        validate_hash("decision input hash", &self.input_hash)?;
        Ok(())
    }
}

/// One capability's normalized, non-duplicating policy provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedCapabilityEvidenceV2 {
    status: CapabilityProvenanceStatus,
    contributions: Vec<RuleContribution>,
}

impl RecordedCapabilityEvidenceV2 {
    /// Return how this capability participated in evaluation.
    pub fn status(&self) -> CapabilityProvenanceStatus {
        self.status
    }

    /// Return the ordered first-match contribution from each policy layer.
    pub fn contributions(&self) -> &[RuleContribution] {
        &self.contributions
    }

    fn from_provenance(provenance: &CapabilityProvenance) -> Self {
        Self {
            status: provenance.status,
            contributions: provenance.contributions.clone(),
        }
    }

    fn into_provenance(self, capability: Capability) -> Result<CapabilityProvenance, String> {
        let effective_decision =
            effective_decision_for_provenance_v2(self.status, &self.contributions)?;
        Ok(CapabilityProvenance {
            capability,
            status: self.status,
            effective_decision,
            contributions: self.contributions,
        })
    }
}

/// Stable normalized Authority encoding of one attested evaluator result.
///
/// Capabilities appear exactly once. The aggregate decision, matched-rule
/// compatibility summary, effective per-capability decisions, policy identity,
/// and empty authorization field are reconstructed without loss. This records
/// the evaluator output and its declared provenance; it does not embed or
/// independently reproduce the policy or mapper artifacts named by generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEvaluationV2 {
    semantics: String,
    capabilities: Vec<Capability>,
    provenance: Vec<RecordedCapabilityEvidenceV2>,
}

impl RecordedEvaluationV2 {
    /// Return the immutable reducer semantics used to reconstruct this record.
    pub fn semantics(&self) -> &str {
        &self.semantics
    }

    /// Return the ordered, unique capability set evaluated by policy.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Return one normalized provenance record per capability.
    pub fn provenance(&self) -> &[RecordedCapabilityEvidenceV2] {
        &self.provenance
    }

    pub(super) fn from_evaluation(evaluation: &EvalResult) -> Result<Self, AuthorityError> {
        validate_evaluation_bounds(evaluation)?;
        validate_reference_evaluation(evaluation).map_err(AuthorityError::InvalidInput)?;
        let recorded = Self {
            semantics: RECORDED_EVALUATION_SEMANTICS.into(),
            capabilities: evaluation.capabilities.clone(),
            provenance: evaluation
                .capability_provenance
                .iter()
                .map(RecordedCapabilityEvidenceV2::from_provenance)
                .collect(),
        };
        let reconstructed = recorded.reconstruct(&evaluation.policy_version)?;
        if reconstructed != *evaluation {
            return Err(AuthorityError::InvalidInput(
                "normalized evaluation does not reconstruct the supplied result".into(),
            ));
        }
        Ok(recorded)
    }

    pub(super) fn reconstruct(&self, policy_identity: &str) -> Result<EvalResult, AuthorityError> {
        if self.semantics != RECORDED_EVALUATION_SEMANTICS {
            return Err(AuthorityError::InvalidInput(
                "unsupported recorded evaluation semantics".into(),
            ));
        }
        validate_text(
            "decision policy identity",
            policy_identity,
            super::MAX_IDENTITY_BYTES,
            false,
        )?;
        if self.capabilities.len() > MAX_CAPABILITIES
            || self.provenance.len() != self.capabilities.len()
            || self
                .capabilities
                .windows(2)
                .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
        {
            return Err(AuthorityError::InvalidInput(
                "recorded capabilities and provenance are not ordered, unique, and one-to-one"
                    .into(),
            ));
        }
        for capability in &self.capabilities {
            validate_text(
                "decision capability",
                capability.as_str(),
                MAX_CAPABILITY_BYTES,
                false,
            )?;
        }
        validate_recorded_contributions(&self.provenance)?;
        let provenance = self
            .provenance
            .clone()
            .into_iter()
            .zip(self.capabilities.iter().cloned())
            .map(|(evidence, capability)| evidence.into_provenance(capability))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AuthorityError::InvalidInput)?;
        reconstruct_evaluation_v2(
            self.capabilities.clone(),
            provenance,
            policy_identity.to_string(),
        )
        .map_err(AuthorityError::InvalidInput)
    }
}

/// Final Authority outcome committed for one pure evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityDecisionOutcomeV2 {
    /// Policy allowed the call without a grant.
    AllowedByPolicy,
    /// One exact signed grant was atomically spent.
    AllowedByGrant {
        /// Consumed grant identifier.
        grant_id: String,
        /// Approval request that produced the grant.
        request_id: String,
        /// Signed spent-state commitment.
        state_hash: String,
    },
    /// No exact grant existed and one open request represents the call.
    ApprovalRequired {
        /// Immutable approval request identifier.
        request_id: String,
        /// Immutable approval request commitment.
        request_hash: String,
    },
    /// Policy, unresolved capability, or a hard-stop denied the call.
    Denied,
}

impl AuthorityDecisionOutcomeV2 {
    fn validate(&self, evaluation: &EvalResult) -> Result<(), AuthorityError> {
        match (self, &evaluation.decision) {
            (Self::AllowedByPolicy, Decision::Allow) | (Self::Denied, Decision::Gommage { .. }) => {
                Ok(())
            }
            (
                Self::AllowedByGrant {
                    grant_id,
                    request_id,
                    state_hash,
                },
                Decision::AskPicto { .. },
            ) => {
                validate_token("decision grant id", grant_id, 160)?;
                validate_token("decision request id", request_id, 160)?;
                validate_hash("decision spent state hash", state_hash)?;
                Ok(())
            }
            (
                Self::ApprovalRequired {
                    request_id,
                    request_hash,
                },
                Decision::AskPicto { .. },
            ) => {
                validate_token("decision request id", request_id, 160)?;
                validate_hash("decision request hash", request_hash)?;
                Ok(())
            }
            _ => Err(AuthorityError::InvalidInput(
                "Authority outcome contradicts the recorded policy decision".into(),
            )),
        }
    }
}

/// Canonical signed Authority attestation of one normalized evaluator result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedDecisionV2 {
    context: DecisionContextV2,
    generation: AuthorityGenerationV2,
    evaluation: RecordedEvaluationV2,
    outcome: AuthorityDecisionOutcomeV2,
}

impl RecordedDecisionV2 {
    /// Return the minimal observed call context.
    pub fn context(&self) -> &DecisionContextV2 {
        &self.context
    }

    /// Return the exact generation under which policy evaluated the call.
    pub fn generation(&self) -> &AuthorityGenerationV2 {
        &self.generation
    }

    /// Return normalized evaluator output and provenance attested by Authority.
    pub fn evaluation(&self) -> &RecordedEvaluationV2 {
        &self.evaluation
    }

    /// Return the final Authority outcome.
    pub fn outcome(&self) -> &AuthorityDecisionOutcomeV2 {
        &self.outcome
    }

    pub(super) fn new(
        context: DecisionContextV2,
        generation: AuthorityGenerationV2,
        evaluation: RecordedEvaluationV2,
        outcome: AuthorityDecisionOutcomeV2,
    ) -> Result<Self, AuthorityError> {
        let record = Self {
            context,
            generation,
            evaluation,
            outcome,
        };
        record.validated_evaluation()?;
        Ok(record)
    }

    pub(super) fn authorization_context(&self) -> Result<AuthorizationContextV2, AuthorityError> {
        AuthorizationContextV2::new(
            self.generation.build_identity().into(),
            self.context.integration.clone(),
            self.context.tool.clone(),
            self.context.input_hash.clone(),
            self.generation.policy_identity().into(),
            self.evaluation
                .capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect(),
        )
    }

    pub(super) fn validated_evaluation(&self) -> Result<EvalResult, AuthorityError> {
        self.context.validate()?;
        self.generation.validate()?;
        let evaluation = self
            .evaluation
            .reconstruct(self.generation.policy_identity())?;
        validate_decision(&evaluation.decision)?;
        self.outcome.validate(&evaluation)?;
        self.authorization_context()?;
        let canonical = canonicalize(self)?;
        if canonical.len() > MAX_DECISION_RECORD_BYTES {
            return Err(AuthorityError::InvalidInput(format!(
                "canonical decision evidence exceeds {MAX_DECISION_RECORD_BYTES} bytes"
            )));
        }
        Ok(evaluation)
    }
}

/// Trusted in-process input to one generation-bound Authority decision commit.
///
/// The command is not an IPC wire type. The reference control plane must build
/// it only from its protected mapper and evaluator output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitDecisionCommandV2 {
    /// Exact generation against which the pure evaluation ran.
    pub evaluated_generation: AuthorityGenerationV2,
    /// Declared host integration that observed the call.
    pub integration: String,
    /// Complete observed tool call; only its canonical commitment is retained.
    pub call: ToolCall,
    /// Complete pure evaluation, with no pre-existing authorization evidence.
    pub evaluation: EvalResult,
}

/// Result returned only after signed decision evidence commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommittedDecisionV2 {
    /// Policy allowed the call and its evidence committed.
    AllowedByPolicy {
        /// Authority-generated decision event identifier.
        decision_event_id: String,
    },
    /// One exact grant was spent and both state and decision evidence committed.
    AllowedByGrant {
        /// Signed terminal spent state.
        state: SignedGrantStateV2,
        /// Authority-generated decision event identifier.
        decision_event_id: String,
    },
    /// No exact grant existed; a request and decision evidence committed.
    ApprovalRequired {
        /// Immutable approval request.
        request: Box<super::ApprovalRequestV2>,
        /// `true` only when this transaction created the request.
        created: bool,
        /// Authority-generated decision event identifier.
        decision_event_id: String,
    },
    /// Policy denied the call and its evidence committed.
    Denied {
        /// Authority-generated decision event identifier.
        decision_event_id: String,
    },
}

fn validate_recorded_contributions(
    provenance: &[RecordedCapabilityEvidenceV2],
) -> Result<(), AuthorityError> {
    let mut sources: BTreeMap<(usize, usize, usize), RuleContribution> = BTreeMap::new();
    let mut layers: BTreeMap<usize, String> = BTreeMap::new();
    let mut files: BTreeMap<(usize, usize), String> = BTreeMap::new();
    for evidence in provenance {
        if evidence.contributions.len() > MAX_POLICY_CONTRIBUTIONS_PER_CAPABILITY {
            return Err(AuthorityError::InvalidInput(
                "decision provenance exceeds the supported policy-layer count".into(),
            ));
        }
        for contribution in &evidence.contributions {
            validate_rule_contribution(contribution)?;
            if let Some(existing) = layers.get(&contribution.layer_index) {
                if existing != &contribution.layer {
                    return Err(AuthorityError::InvalidInput(
                        "one policy layer index has contradictory names".into(),
                    ));
                }
            } else {
                layers.insert(contribution.layer_index, contribution.layer.clone());
            }
            let file_coordinate = (contribution.layer_index, contribution.file_index);
            if let Some(existing) = files.get(&file_coordinate) {
                if existing != &contribution.rule.file {
                    return Err(AuthorityError::InvalidInput(
                        "one policy file index has contradictory paths".into(),
                    ));
                }
            } else {
                files.insert(file_coordinate, contribution.rule.file.clone());
            }
            let coordinate = (
                contribution.layer_index,
                contribution.file_index,
                contribution.rule.index,
            );
            if let Some(existing) = sources.get(&coordinate) {
                if existing != contribution {
                    return Err(AuthorityError::InvalidInput(
                        "one policy source has contradictory decision provenance".into(),
                    ));
                }
            } else {
                sources.insert(coordinate, contribution.clone());
            }
        }
    }
    Ok(())
}

fn validate_evaluation_bounds(evaluation: &EvalResult) -> Result<(), AuthorityError> {
    if evaluation.capabilities.len() > MAX_CAPABILITIES
        || evaluation.capability_provenance.len() != evaluation.capabilities.len()
    {
        return Err(AuthorityError::InvalidInput(
            "evaluation capability evidence is not one-to-one and bounded".into(),
        ));
    }
    for capability in &evaluation.capabilities {
        validate_text(
            "decision capability",
            capability.as_str(),
            MAX_CAPABILITY_BYTES,
            false,
        )?;
    }
    for provenance in &evaluation.capability_provenance {
        validate_text(
            "decision provenance capability",
            provenance.capability.as_str(),
            MAX_CAPABILITY_BYTES,
            false,
        )?;
        if provenance.contributions.len() > MAX_POLICY_CONTRIBUTIONS_PER_CAPABILITY {
            return Err(AuthorityError::InvalidInput(
                "decision provenance exceeds the supported policy-layer count".into(),
            ));
        }
        if let Some(effective_decision) = &provenance.effective_decision {
            validate_decision(effective_decision)?;
        }
        for contribution in &provenance.contributions {
            validate_rule_contribution(contribution)?;
        }
    }
    if let Some(matched_rule) = &evaluation.matched_rule {
        validate_matched_rule(matched_rule)?;
    }
    validate_decision(&evaluation.decision)
}

fn validate_rule_contribution(contribution: &RuleContribution) -> Result<(), AuthorityError> {
    validate_text(
        "policy layer",
        &contribution.layer,
        MAX_EVIDENCE_LAYER_BYTES,
        false,
    )?;
    validate_matched_rule(&contribution.rule)?;
    validate_safe_index("policy layer index", contribution.layer_index)?;
    validate_safe_index("policy file index", contribution.file_index)?;
    validate_decision(&contribution.decision)
}

fn validate_matched_rule(rule: &crate::MatchedRule) -> Result<(), AuthorityError> {
    validate_text(
        "matched rule name",
        &rule.name,
        MAX_EVIDENCE_RULE_NAME_BYTES,
        false,
    )?;
    validate_text(
        "matched rule file",
        &rule.file,
        MAX_EVIDENCE_RULE_FILE_BYTES,
        false,
    )?;
    validate_safe_index("policy rule index", rule.index)
}

fn validate_safe_index(label: &str, value: usize) -> Result<(), AuthorityError> {
    if u64::try_from(value).map_or(true, |value| value > MAX_SAFE_INTEGER) {
        return Err(AuthorityError::InvalidInput(format!(
            "{label} exceeds the I-JSON safe integer range"
        )));
    }
    Ok(())
}

fn validate_decision(decision: &Decision) -> Result<(), AuthorityError> {
    match decision {
        Decision::Allow => Ok(()),
        Decision::Gommage { reason, .. } => {
            validate_text("decision reason", reason, MAX_DECISION_REASON_BYTES, true)?;
            Ok(())
        }
        Decision::AskPicto {
            required_scope,
            reason,
            ..
        } => {
            validate_picto_scope(required_scope).map_err(AuthorityError::InvalidInput)?;
            validate_text("decision reason", reason, MAX_APPROVAL_REASON_BYTES, true)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MatchedRule,
        crypto_envelope::decode_canonical,
        evaluator::{live_reconstruction_probe, reset_live_reconstruction_probe},
    };
    use sha2::{Digest as _, Sha256};

    const HISTORICAL_V2_EVALUATION_JCS: &[u8] = br#"{"capabilities":["test.a","test.b"],"provenance":[{"contributions":[{"decision":{"kind":"ask_picto","reason":"approve alpha","required_scope":"scope.alpha"},"file_index":0,"layer":"project","layer_index":0,"rule":{"file":"policy.yaml","index":0,"name":"ask-alpha"}}],"status":"resolved"},{"contributions":[{"decision":{"bind_input":true,"kind":"ask_picto","reason":"approve beta","required_scope":"scope.beta"},"file_index":0,"layer":"project","layer_index":0,"rule":{"file":"policy.yaml","index":1,"name":"ask-beta"}}],"status":"resolved"}],"semantics":"gommage.compositional-evaluation.v2"}"#;

    fn contribution(
        layer: &str,
        file: &str,
        file_index: usize,
        rule_index: usize,
    ) -> RuleContribution {
        RuleContribution {
            layer: layer.into(),
            layer_index: 0,
            file_index,
            rule: MatchedRule {
                name: format!("rule-{file_index}-{rule_index}"),
                file: file.into(),
                index: rule_index,
            },
            decision: Decision::Allow,
        }
    }

    fn recorded_with(contributions: [RuleContribution; 2]) -> RecordedEvaluationV2 {
        RecordedEvaluationV2 {
            semantics: RECORDED_EVALUATION_SEMANTICS.into(),
            capabilities: vec![Capability::new("test.a"), Capability::new("test.b")],
            provenance: contributions
                .into_iter()
                .map(|contribution| RecordedCapabilityEvidenceV2 {
                    status: CapabilityProvenanceStatus::Resolved,
                    contributions: vec![contribution],
                })
                .collect(),
        }
    }

    #[test]
    fn one_layer_index_cannot_claim_multiple_names() {
        let recorded = recorded_with([
            contribution("org", "org-a.yaml", 0, 0),
            contribution("renamed-org", "org-b.yaml", 1, 0),
        ]);
        assert!(recorded.reconstruct("policy-v2").is_err());
    }

    #[test]
    fn one_file_coordinate_cannot_claim_multiple_paths() {
        let recorded = recorded_with([
            contribution("org", "org-a.yaml", 0, 0),
            contribution("org", "org-b.yaml", 0, 1),
        ]);
        assert!(recorded.reconstruct("policy-v2").is_err());
    }

    #[test]
    fn historical_v2_fixture_uses_the_frozen_reducer() {
        assert_eq!(
            hex::encode(Sha256::digest(HISTORICAL_V2_EVALUATION_JCS)),
            "37feb8910f2b0dd2e5ef1140c336013080366cfd190eb566f0789e45529d56dd"
        );
        let recorded: RecordedEvaluationV2 =
            decode_canonical(HISTORICAL_V2_EVALUATION_JCS).unwrap();
        reset_live_reconstruction_probe();
        let reconstructed = recorded.reconstruct("policy-v2").unwrap();
        assert_eq!(live_reconstruction_probe(), 0);

        assert_eq!(
            reconstructed.decision,
            Decision::Gommage {
                reason: "multiple Picto scopes required (2 distinct scopes); split the call before requesting authorization".into(),
                hard_stop: false,
            }
        );
        assert_eq!(
            reconstructed.matched_rule,
            Some(MatchedRule {
                name: "ask-alpha".into(),
                file: "policy.yaml".into(),
                index: 0,
            })
        );
        assert_eq!(
            reconstructed.capabilities,
            vec![Capability::new("test.a"), Capability::new("test.b")]
        );
        assert_eq!(reconstructed.capability_provenance.len(), 2);
        assert!(reconstructed.authorization.is_none());
    }
}
