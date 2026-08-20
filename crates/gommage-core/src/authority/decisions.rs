use super::*;
use crate::{Decision, EvalResult};

struct PreparedDecision {
    context: DecisionContextV2,
    authorization_context: AuthorizationContextV2,
    generation: AuthorityGenerationV2,
    evaluation: RecordedEvaluationV2,
    evaluated: EvalResult,
}

impl Authority {
    /// Commit one pure policy result under the exact generation that evaluated it.
    ///
    /// This is the sole reference runtime decision boundary. It verifies signed
    /// Authority state under `BEGIN IMMEDIATE`, rejects stale generations, owns
    /// time and evidence identifiers, records every outcome, and returns only
    /// after the complete state transition commits.
    pub fn commit_decision(
        &mut self,
        command: &CommitDecisionCommandV2,
    ) -> Result<CommittedDecisionV2, AuthorityError> {
        let prepared = prepare_decision(command)?;
        let grant_key = self.grant_key.clone();
        let ledger_key = self.ledger_key.clone();
        let grant_vk = self.grant_key.verifying_key();
        let runtime_source = Arc::clone(&self.runtime_source);
        self.retained_commit(|tx, verification| {
            ensure_decision_admitted(tx, &prepared.generation)?;
            let decided_at = authority_evidence_time(runtime_source.as_ref(), verification)?;

            let result = match &prepared.evaluated.decision {
                Decision::Allow => {
                    let decision_event_id = authority_id(runtime_source.as_ref(), "decision")?;
                    append_recorded_decision(
                        tx,
                        &ledger_key,
                        &decision_event_id,
                        decided_at,
                        &prepared,
                        AuthorityDecisionOutcomeV2::AllowedByPolicy,
                    )?;
                    CommittedDecisionV2::AllowedByPolicy { decision_event_id }
                }
                Decision::Gommage { .. } => {
                    let decision_event_id = authority_id(runtime_source.as_ref(), "decision")?;
                    append_recorded_decision(
                        tx,
                        &ledger_key,
                        &decision_event_id,
                        decided_at,
                        &prepared,
                        AuthorityDecisionOutcomeV2::Denied,
                    )?;
                    CommittedDecisionV2::Denied { decision_event_id }
                }
                Decision::AskPicto {
                    required_scope,
                    reason,
                    bind_input,
                } => {
                    let binding = binding_for_decision(*bind_input, prepared.context.input_hash());
                    let (selected, not_usable) = select_usable_grant(
                        tx,
                        GrantSelectionInput {
                            context: &prepared.authorization_context,
                            generation: &prepared.generation,
                            required_scope,
                            binding: &binding,
                            reason,
                            at: decided_at,
                        },
                        &grant_vk,
                    )?;
                    if let Some(selected) = selected {
                        let state_event_id = authority_id(runtime_source.as_ref(), "state_spend")?;
                        let decision_event_id = authority_id(runtime_source.as_ref(), "decision")?;
                        let recorded = spend_grant(
                            tx,
                            selected,
                            SpendGrantInput {
                                context: &prepared.authorization_context,
                                consumed_at: decided_at,
                                state_event_id: &state_event_id,
                            },
                            &grant_key,
                            &ledger_key,
                        )?;
                        append_recorded_decision(
                            tx,
                            &ledger_key,
                            &decision_event_id,
                            decided_at,
                            &prepared,
                            AuthorityDecisionOutcomeV2::AllowedByGrant {
                                grant_id: recorded.grant_id,
                                request_id: recorded.request_id,
                                state_hash: recorded.state.state_hash().to_string(),
                            },
                        )?;
                        CommittedDecisionV2::AllowedByGrant {
                            state: recorded.state,
                            decision_event_id,
                        }
                    } else {
                        if not_usable == GrantNotUsableReason::NotYetValid {
                            return Err(AuthorityError::RuntimeSource(
                                "matching grant validity begins after authoritative time".into(),
                            ));
                        }
                        let request_id = authority_id(runtime_source.as_ref(), "request")?;
                        let request_event_id =
                            authority_id(runtime_source.as_ref(), "approval_request")?;
                        let prepared_request = prepare_approval_request(&CreateRequestCommand {
                            request_id,
                            event_id: request_event_id,
                            created_at: decided_at,
                            context: prepared.authorization_context.clone(),
                            binding,
                            generation: prepared.generation.clone(),
                            required_scope: required_scope.clone(),
                            reason: reason.clone(),
                        })?;
                        let request = create_or_get_request_in_transaction(
                            tx,
                            &ledger_key,
                            prepared_request,
                        )?;
                        let (request, created) = match request {
                            CreateRequestResult::Created(request) => (request, true),
                            CreateRequestResult::Existing(request) => (request, false),
                        };
                        let stored = load_request(tx, request.request_id())?.ok_or_else(|| {
                            AuthorityError::Corrupt(
                                "committed approval request disappeared before decision evidence"
                                    .into(),
                            )
                        })?;
                        let decision_event_id = authority_id(runtime_source.as_ref(), "decision")?;
                        append_recorded_decision(
                            tx,
                            &ledger_key,
                            &decision_event_id,
                            decided_at,
                            &prepared,
                            AuthorityDecisionOutcomeV2::ApprovalRequired {
                                request_id: request.request_id().to_string(),
                                request_hash: stored.request_hash,
                            },
                        )?;
                        CommittedDecisionV2::ApprovalRequired {
                            request: Box::new(request),
                            created,
                            decision_event_id,
                        }
                    }
                }
            };

            ensure_decision_admitted(tx, &prepared.generation)?;
            Ok(result)
        })
    }
}

fn prepare_decision(command: &CommitDecisionCommandV2) -> Result<PreparedDecision, AuthorityError> {
    command.evaluated_generation.validate()?;
    if command.evaluation.policy_version != command.evaluated_generation.policy_identity() {
        return Err(AuthorityError::InvalidInput(
            "evaluation policy identity does not match its evaluated generation".into(),
        ));
    }
    let context = DecisionContextV2::from_call(&command.integration, &command.call)?;
    let evaluation = RecordedEvaluationV2::from_evaluation(&command.evaluation)?;
    let authorization_context = AuthorizationContextV2::new(
        command.evaluated_generation.build_identity().into(),
        context.integration().into(),
        context.tool().into(),
        context.input_hash().into(),
        command.evaluated_generation.policy_identity().into(),
        command
            .evaluation
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_string())
            .collect(),
    )?;
    Ok(PreparedDecision {
        context,
        authorization_context,
        generation: command.evaluated_generation.clone(),
        evaluation,
        evaluated: command.evaluation.clone(),
    })
}

fn append_recorded_decision(
    conn: &Connection,
    ledger_key: &SigningKey,
    event_id: &str,
    timestamp: i64,
    prepared: &PreparedDecision,
    outcome: AuthorityDecisionOutcomeV2,
) -> Result<(), AuthorityError> {
    let record = RecordedDecisionV2::new(
        prepared.context.clone(),
        prepared.generation.clone(),
        prepared.evaluation.clone(),
        outcome,
    )?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id: event_id.into(),
            subject: record.context().input_hash().into(),
            timestamp,
            build_identity: Some(record.generation().build_identity().into()),
            policy_identity: Some(record.generation().policy_identity().into()),
            payload: LedgerPayloadV2::DecisionRecorded { record },
        },
    )?;
    Ok(())
}
