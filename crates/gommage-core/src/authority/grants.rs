use super::*;

pub(super) fn load_claim(
    conn: &Connection,
    grant_id: &str,
    key: &VerifyingKey,
) -> Result<Option<(SignedGrantClaimV2, GrantClaimV2)>, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT claim_jcs, signature_b64, claim_hash, request_id
             FROM grant_claims WHERE grant_id = ?1",
            [grant_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(claim_jcs, signature_b64, claim_hash, request_id)| {
        let signed = SignedGrantClaimV2::from_stored(
            SignedJcs::from_stored(claim_jcs, signature_b64),
            claim_hash,
        );
        let claim = signed.verify(key)?;
        if claim.grant_id() != grant_id || claim.approval_request_id() != request_id {
            return Err(AuthorityError::Corrupt(
                "grant claim row does not match signed identifiers".into(),
            ));
        }
        Ok((signed, claim))
    })
    .transpose()
}

pub(super) fn load_latest_state(
    conn: &Connection,
    grant_id: &str,
    key: &VerifyingKey,
) -> Result<Option<(SignedGrantStateV2, GrantStateV2)>, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT revision, status, uses, state_jcs, signature_b64, state_hash,
                    transition_event_id
             FROM grant_states WHERE grant_id = ?1 ORDER BY revision DESC LIMIT 1",
            [grant_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(revision, status, uses, state_jcs, signature_b64, state_hash, transition_event_id)| {
            let signed = SignedGrantStateV2::from_stored(
                SignedJcs::from_stored(state_jcs, signature_b64),
                state_hash,
            );
            let state = signed.verify(key)?;
            if state.grant_id() != grant_id
                || state.revision() != revision.to_string()
                || state.uses() != uses as u8
                || state.transition_event_id() != transition_event_id
                || status_string(state.status()) != status
            {
                return Err(AuthorityError::Corrupt(
                    "grant state row does not match signed content".into(),
                ));
            }
            Ok((signed, state))
        },
    )
    .transpose()
}

pub(super) fn insert_state(
    conn: &Connection,
    state: &GrantStateV2,
    signed: &SignedGrantStateV2,
) -> Result<(), AuthorityError> {
    let revision = state
        .revision()
        .parse::<i64>()
        .map_err(|_| AuthorityError::Corrupt("state revision is not an integer".into()))?;
    conn.execute(
        "INSERT INTO grant_states (
            grant_id, revision, status, uses, state_jcs, signature_b64, state_hash,
            transition_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            state.grant_id(),
            revision,
            status_string(state.status()),
            i64::from(state.uses()),
            signed.envelope().jcs(),
            signed.envelope().signature_b64(),
            signed.state_hash(),
            state.transition_event_id(),
        ],
    )?;
    Ok(())
}

pub(super) fn status_string(status: GrantStatusV2) -> &'static str {
    match status {
        GrantStatusV2::Active => "active",
        GrantStatusV2::Spent => "spent",
        GrantStatusV2::Revoked => "revoked",
    }
}

pub(super) struct SelectedGrant {
    pub(super) grant_id: String,
    pub(super) signed_claim: SignedGrantClaimV2,
    pub(super) signed_previous: SignedGrantStateV2,
    pub(super) previous: GrantStateV2,
}

pub(super) fn select_usable_grant(
    conn: &Connection,
    context: &AuthorizationContextV2,
    generation: &AuthorityGenerationV2,
    required_scope: &str,
    at: i64,
    grant_key: &VerifyingKey,
) -> Result<(Option<SelectedGrant>, GrantNotUsableReason), AuthorityError> {
    let dedupe_jcs = canonicalize(&ApprovalDedupeV2 {
        domain: "gommage.approval.dedupe",
        version: FORMAT_VERSION,
        context,
        generation,
        required_scope,
    })?;
    let dedupe_hash = approval_dedupe_hash(&dedupe_jcs);
    let candidate_ids = {
        let mut statement = conn.prepare(
            "SELECT grant_claims.grant_id
             FROM grant_claims
             JOIN approval_requests
               ON approval_requests.request_id = grant_claims.request_id
             WHERE approval_requests.dedupe_hash = ?1
             ORDER BY grant_claims.grant_id",
        )?;
        statement
            .query_map([dedupe_hash], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut usable = Vec::new();
    let mut saw_terminal = false;
    let mut saw_not_yet_valid = false;
    let mut saw_expired = false;
    for grant_id in candidate_ids {
        let (signed_claim, claim) = load_claim(conn, &grant_id, grant_key)?
            .ok_or_else(|| AuthorityError::Corrupt("matching grant claim disappeared".into()))?;
        let stored_request = load_request(conn, claim.approval_request_id())?.ok_or_else(|| {
            AuthorityError::Corrupt("grant claim approval request is missing".into())
        })?;
        if stored_request.request.context() != context
            || stored_request.request.generation() != generation
            || stored_request.request.required_scope() != required_scope
        {
            continue;
        }
        let (signed_previous, previous) = load_latest_state(conn, &grant_id, grant_key)?
            .ok_or_else(|| AuthorityError::Corrupt("grant claim has no signed state".into()))?;
        if previous.status() != GrantStatusV2::Active {
            saw_terminal = true;
            continue;
        }
        if at < claim.not_before() {
            saw_not_yet_valid = true;
            continue;
        } else if at >= claim.expires_at() {
            saw_expired = true;
            continue;
        }
        usable.push(SelectedGrant {
            grant_id,
            signed_claim,
            signed_previous,
            previous,
        });
    }
    if usable.len() > 1 {
        return Err(AuthorityError::Corrupt(
            "multiple usable grants match the exact authorization context and scope".into(),
        ));
    }
    let not_usable = if saw_not_yet_valid {
        GrantNotUsableReason::NotYetValid
    } else if saw_expired {
        GrantNotUsableReason::Expired
    } else if saw_terminal {
        GrantNotUsableReason::Terminal
    } else {
        GrantNotUsableReason::Missing
    };
    Ok((usable.pop(), not_usable))
}

pub(super) struct RecordedAllow {
    pub(super) state: SignedGrantStateV2,
    pub(super) decision_event_id: String,
}

pub(super) struct AllowEventIds<'a> {
    pub(super) state: &'a str,
    pub(super) decision: &'a str,
}

pub(super) struct AllowRecordInput<'a> {
    pub(super) context: &'a AuthorizationContextV2,
    pub(super) generation: &'a AuthorityGenerationV2,
    pub(super) required_scope: &'a str,
    pub(super) consumed_at: i64,
    pub(super) event_ids: AllowEventIds<'a>,
}

pub(super) fn spend_grant_and_record_allow(
    conn: &Connection,
    selected: SelectedGrant,
    input: AllowRecordInput<'_>,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> Result<RecordedAllow, AuthorityError> {
    validate_token("state event id", input.event_ids.state, 160)?;
    validate_token("decision event id", input.event_ids.decision, 160)?;
    let SelectedGrant {
        grant_id,
        signed_claim,
        signed_previous,
        previous,
    } = selected;
    let spent = GrantStateV2::terminal(
        &previous,
        signed_previous.state_hash(),
        GrantStatusV2::Spent,
        input.event_ids.state.into(),
        input.consumed_at,
    )?;
    let signed_spent = SignedGrantStateV2::sign(&spent, grant_key)?;
    insert_state(conn, &spent, &signed_spent)?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id: input.event_ids.state.into(),
            subject: grant_id.clone(),
            timestamp: input.consumed_at,
            build_identity: Some(input.context.build_identity().into()),
            policy_identity: Some(input.context.policy_identity().into()),
            payload: LedgerPayloadV2::GrantStateChanged {
                grant_id: grant_id.clone(),
                claim_hash: signed_claim.claim_hash().into(),
                state_hash: signed_spent.state_hash().into(),
                revision: spent.revision().into(),
                status: GrantStatusV2::Spent,
                operator_principal: None,
                reason: None,
            },
        },
    )?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id: input.event_ids.decision.into(),
            subject: grant_id.clone(),
            timestamp: input.consumed_at,
            build_identity: Some(input.context.build_identity().into()),
            policy_identity: Some(input.context.policy_identity().into()),
            payload: LedgerPayloadV2::DecisionAllow {
                grant_id,
                required_scope: input.required_scope.into(),
                input_hash: input.context.input_hash().into(),
                context: input.context.clone(),
                generation: input.generation.clone(),
                state_hash: signed_spent.state_hash().into(),
            },
        },
    )?;
    Ok(RecordedAllow {
        state: signed_spent,
        decision_event_id: input.event_ids.decision.into(),
    })
}

pub(super) fn state_actor_fields_match(
    status: GrantStatusV2,
    operator_principal: &Option<String>,
    reason: &Option<String>,
) -> Result<bool, AuthorityError> {
    match (status, operator_principal, reason) {
        (GrantStatusV2::Active | GrantStatusV2::Spent, None, None) => Ok(true),
        (GrantStatusV2::Revoked, Some(operator), Some(reason)) => {
            validate_text("revocation operator", operator, 256, false)?;
            validate_text("revocation reason", reason, 1_024, true)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(super) fn validate_approval_actor(
    request_id: &str,
    operator_principal: &str,
    reason: &str,
    timestamp: i64,
) -> Result<(), AuthorityError> {
    validate_token("request id", request_id, 160)?;
    validate_text("operator principal", operator_principal, 256, false)?;
    validate_text("reason", reason, 1_024, true)?;
    validate_timestamp(timestamp)?;
    Ok(())
}
