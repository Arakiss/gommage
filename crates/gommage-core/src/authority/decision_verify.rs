use super::*;
use crate::{Decision, EvalResult};

enum GrantDecisionLink {
    Legacy {
        event_id: String,
        evidence: AllowEvidenceLink,
    },
    Recorded {
        event_id: String,
        seq: usize,
        timestamp: i64,
        build_identity: Option<String>,
        policy_identity: Option<String>,
        record: Box<RecordedDecisionV2>,
        evaluation: EvalResult,
        context: AuthorizationContextV2,
    },
}

pub(super) fn verify_decision_relations(
    entries: &[VerifiedLedgerEntryV2],
    events: &HashMap<String, LedgerEventLink>,
    runtime: &VerifiedRuntimeTimeline,
    requests: &HashMap<String, StoredRequest>,
    resolutions: &HashMap<String, ApprovalResolutionV2>,
    claims: &HashMap<String, (SignedGrantClaimV2, GrantClaimV2)>,
    states: &HashMap<String, Vec<(SignedGrantStateV2, GrantStateV2)>>,
) -> Result<HashSet<String>, AuthorityError> {
    let mut linked_decisions = HashSet::new();
    let mut decisions_by_state: HashMap<String, Vec<GrantDecisionLink>> = HashMap::new();
    let mut evidence_time_floor = i64::MIN;

    for (index, verified) in entries.iter().enumerate() {
        let seq = index + 1;
        if let LedgerPayloadV2::DecisionAllow {
            grant_id,
            required_scope,
            input_hash,
            context,
            generation,
            state_hash,
        } = verified.entry.payload()
        {
            decisions_by_state
                .entry(state_hash.clone())
                .or_default()
                .push(GrantDecisionLink::Legacy {
                    event_id: verified.entry.event_id().to_string(),
                    evidence: AllowEvidenceLink {
                        seq,
                        timestamp: verified.entry.timestamp(),
                        build_identity: verified.entry.build_identity().map(str::to_owned),
                        policy_identity: verified.entry.policy_identity().map(str::to_owned),
                        grant_id: grant_id.clone(),
                        required_scope: required_scope.clone(),
                        input_hash: input_hash.clone(),
                        context: context.clone(),
                        generation: generation.clone(),
                    },
                });
        }
        if let LedgerPayloadV2::DecisionRecorded { record } = verified.entry.payload() {
            if verified.entry.timestamp() < evidence_time_floor {
                return Err(AuthorityError::Corrupt(
                    "recorded decision timestamp regresses signed evidence time".into(),
                ));
            }
            let evaluation = record.validated_evaluation().map_err(|error| {
                AuthorityError::Corrupt(format!("recorded decision is invalid: {error}"))
            })?;
            let context = record.authorization_context().map_err(|error| {
                AuthorityError::Corrupt(format!("recorded decision context is invalid: {error}"))
            })?;
            if verified.entry.build_identity() != Some(record.generation().build_identity())
                || verified.entry.policy_identity() != Some(record.generation().policy_identity())
                || runtime.state_at(seq).is_none_or(|state| {
                    state.maintenance || state.active_generation != *record.generation()
                })
            {
                return Err(AuthorityError::Corrupt(
                    "recorded decision was not admitted under its exact active generation".into(),
                ));
            }
            match record.outcome() {
                AuthorityDecisionOutcomeV2::AllowedByPolicy
                | AuthorityDecisionOutcomeV2::Denied => {
                    linked_decisions.insert(verified.entry.event_id().to_string());
                }
                AuthorityDecisionOutcomeV2::ApprovalRequired {
                    request_id,
                    request_hash,
                } => {
                    verify_approval_required(
                        seq,
                        verified.entry.timestamp(),
                        record,
                        &evaluation,
                        &context,
                        request_id,
                        request_hash,
                        events,
                        requests,
                        resolutions,
                    )?;
                    linked_decisions.insert(verified.entry.event_id().to_string());
                }
                AuthorityDecisionOutcomeV2::AllowedByGrant { state_hash, .. } => {
                    decisions_by_state
                        .entry(state_hash.clone())
                        .or_default()
                        .push(GrantDecisionLink::Recorded {
                            event_id: verified.entry.event_id().to_string(),
                            seq,
                            timestamp: verified.entry.timestamp(),
                            build_identity: verified.entry.build_identity().map(str::to_owned),
                            policy_identity: verified.entry.policy_identity().map(str::to_owned),
                            record: Box::new(record.clone()),
                            evaluation,
                            context,
                        });
                }
            }
        }
        evidence_time_floor = evidence_time_floor.max(verified.entry.timestamp());
    }

    for (grant_id, (signed_claim, claim)) in claims {
        let revisions = states
            .get(grant_id)
            .ok_or_else(|| AuthorityError::Corrupt("grant claim has no state revision".into()))?;
        if revisions.is_empty() || revisions.len() > 2 {
            return Err(AuthorityError::Corrupt(
                "grant has an invalid number of state revisions".into(),
            ));
        }
        let (active_signed, active) = &revisions[0];
        if active.revision() != "0"
            || active.status() != GrantStatusV2::Active
            || active.uses() != 0
            || active.previous_state_hash().is_some()
            || active.claim_hash() != signed_claim.claim_hash()
            || active.transitioned_at() != claim.issued_at()
        {
            return Err(AuthorityError::Corrupt(
                "grant revision zero is not its signed active origin".into(),
            ));
        }
        let resolution = resolutions
            .get(claim.approval_request_id())
            .ok_or_else(|| AuthorityError::Corrupt("active grant resolution is missing".into()))?;
        let resolution_event = events
            .get(&resolution.event_id)
            .ok_or_else(|| AuthorityError::Corrupt("resolution event is missing".into()))?;
        let activation_event = events
            .get(active.transition_event_id())
            .ok_or_else(|| AuthorityError::Corrupt("activation event is missing".into()))?;
        if activation_event.seq != resolution_event.seq.saturating_add(1)
            || activation_event.build_identity != resolution_event.build_identity
            || activation_event.policy_identity != resolution_event.policy_identity
        {
            return Err(AuthorityError::Corrupt(
                "grant activation does not exactly and immediately follow its approval resolution"
                    .into(),
            ));
        }
        if revisions.len() == 2 {
            let (terminal_signed, terminal) = &revisions[1];
            terminal.verify_successor_of(active, active_signed.state_hash())?;
            let terminal_seq = events
                .get(terminal.transition_event_id())
                .map(|event| event.seq)
                .ok_or_else(|| AuthorityError::Corrupt("terminal state event is missing".into()))?;
            if terminal_seq <= activation_event.seq {
                return Err(AuthorityError::Corrupt(
                    "terminal grant state does not follow activation in the ledger".into(),
                ));
            }
            match terminal.status() {
                GrantStatusV2::Spent => {
                    let decisions = decisions_by_state
                        .get(terminal_signed.state_hash())
                        .ok_or_else(|| {
                            AuthorityError::Corrupt(
                                "spent state has no atomically linked allow evidence".into(),
                            )
                        })?;
                    if decisions.len() != 1
                        || !grant_decision_matches(
                            &decisions[0],
                            grant_id,
                            claim,
                            terminal_signed,
                            terminal,
                            terminal_seq,
                            runtime,
                            requests,
                        )?
                    {
                        return Err(AuthorityError::Corrupt(
                            "allow evidence does not exactly and consecutively follow spent state"
                                .into(),
                        ));
                    }
                    linked_decisions.insert(decisions[0].event_id().to_string());
                }
                GrantStatusV2::Revoked => {
                    if decisions_by_state.contains_key(terminal_signed.state_hash()) {
                        return Err(AuthorityError::Corrupt(
                            "revoked state cannot authorize an allow decision".into(),
                        ));
                    }
                }
                GrantStatusV2::Active => {
                    return Err(AuthorityError::Corrupt(
                        "revision one cannot remain active".into(),
                    ));
                }
            }
        }
    }
    for state_hash in decisions_by_state.keys() {
        let linked = states.values().flatten().any(|(signed, state)| {
            signed.state_hash() == state_hash && state.status() == GrantStatusV2::Spent
        });
        if !linked {
            return Err(AuthorityError::Corrupt(
                "allow decision references no verified spent state".into(),
            ));
        }
    }
    Ok(linked_decisions)
}

#[allow(clippy::too_many_arguments)]
fn verify_approval_required(
    decision_seq: usize,
    decision_timestamp: i64,
    record: &RecordedDecisionV2,
    evaluation: &EvalResult,
    context: &AuthorizationContextV2,
    request_id: &str,
    request_hash: &str,
    events: &HashMap<String, LedgerEventLink>,
    requests: &HashMap<String, StoredRequest>,
    resolutions: &HashMap<String, ApprovalResolutionV2>,
) -> Result<(), AuthorityError> {
    let request = requests.get(request_id).ok_or_else(|| {
        AuthorityError::Corrupt("recorded ask references a missing approval request".into())
    })?;
    let request_event = events
        .get(&request.event_id)
        .ok_or_else(|| AuthorityError::Corrupt("recorded ask request event is missing".into()))?;
    let resolution_seq = resolutions
        .get(request_id)
        .and_then(|resolution| events.get(&resolution.event_id))
        .map(|event| event.seq);
    let Decision::AskPicto {
        required_scope,
        reason,
        bind_input,
    } = &evaluation.decision
    else {
        return Err(AuthorityError::Corrupt(
            "approval-required evidence does not contain an ask evaluation".into(),
        ));
    };
    let binding = binding_for_decision(*bind_input, context.input_hash());
    if request.request_hash != request_hash
        || request.request.generation() != record.generation()
        || request.request.required_scope() != required_scope
        || request.request.binding() != binding
        || request.request.reason() != reason
        || request.request.created_at() > decision_timestamp
        || request_event.seq >= decision_seq
        || resolution_seq.is_some_and(|seq| seq <= decision_seq)
    {
        return Err(AuthorityError::Corrupt(
            "approval-required evidence does not match an open request at decision time".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn grant_decision_matches(
    decision: &GrantDecisionLink,
    grant_id: &str,
    claim: &GrantClaimV2,
    terminal_signed: &SignedGrantStateV2,
    terminal: &GrantStateV2,
    terminal_seq: usize,
    runtime: &VerifiedRuntimeTimeline,
    requests: &HashMap<String, StoredRequest>,
) -> Result<bool, AuthorityError> {
    let request = requests.get(claim.approval_request_id()).ok_or_else(|| {
        AuthorityError::Corrupt("allow decision approval request is missing".into())
    })?;
    Ok(match decision {
        GrantDecisionLink::Legacy { evidence, .. } => {
            evidence.timestamp == terminal.transitioned_at()
                && evidence.grant_id == grant_id
                && evidence.required_scope == claim.required_scope()
                && evidence.input_hash == claim.input_hash()
                && matches!(claim.binding(), PictoBinding::ExactInput { .. })
                && evidence.context == *request.request.context()
                && evidence.generation == *request.request.generation()
                && runtime.state_at(evidence.seq).is_some_and(|state| {
                    !state.maintenance && state.active_generation == evidence.generation
                })
                && evidence.build_identity.as_deref() == Some(evidence.context.build_identity())
                && evidence.policy_identity.as_deref() == Some(evidence.context.policy_identity())
                && evidence.seq == terminal_seq.saturating_add(1)
        }
        GrantDecisionLink::Recorded {
            seq,
            timestamp,
            build_identity,
            policy_identity,
            record,
            evaluation,
            context,
            ..
        } => {
            let AuthorityDecisionOutcomeV2::AllowedByGrant {
                grant_id: outcome_grant_id,
                request_id,
                state_hash,
            } = record.outcome()
            else {
                return Ok(false);
            };
            let Decision::AskPicto {
                required_scope,
                reason,
                bind_input,
            } = &evaluation.decision
            else {
                return Ok(false);
            };
            let binding = binding_for_decision(*bind_input, context.input_hash());
            *timestamp == terminal.transitioned_at()
                && outcome_grant_id == grant_id
                && request_id == claim.approval_request_id()
                && state_hash == terminal_signed.state_hash()
                && required_scope == claim.required_scope()
                && binding == claim.binding()
                && binding == request.request.binding()
                && reason == request.request.reason()
                && record.generation() == request.request.generation()
                && runtime.state_at(*seq).is_some_and(|state| {
                    !state.maintenance && state.active_generation == *record.generation()
                })
                && build_identity.as_deref() == Some(context.build_identity())
                && policy_identity.as_deref() == Some(context.policy_identity())
                && *seq == terminal_seq.saturating_add(1)
        }
    })
}

impl GrantDecisionLink {
    fn event_id(&self) -> &str {
        match self {
            Self::Legacy { event_id, .. } | Self::Recorded { event_id, .. } => event_id,
        }
    }
}
