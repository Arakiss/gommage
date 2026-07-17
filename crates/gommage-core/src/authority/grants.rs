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
    pub(super) request_id: String,
    pub(super) signed_claim: SignedGrantClaimV2,
    pub(super) signed_previous: SignedGrantStateV2,
    pub(super) previous: GrantStateV2,
}

pub(super) struct GrantSelectionInput<'a> {
    pub(super) context: &'a AuthorizationContextV2,
    pub(super) generation: &'a AuthorityGenerationV2,
    pub(super) required_scope: &'a str,
    pub(super) binding: &'a PictoBinding,
    pub(super) reason: &'a str,
    pub(super) at: i64,
}

pub(super) fn select_usable_grant(
    conn: &Connection,
    input: GrantSelectionInput<'_>,
    grant_key: &VerifyingKey,
) -> Result<(Option<SelectedGrant>, GrantNotUsableReason), AuthorityError> {
    let GrantSelectionInput {
        context,
        generation,
        required_scope,
        binding,
        reason,
        at,
    } = input;
    let dedupe_hashes = approval_dedupe_hashes(context, generation, required_scope, binding)?;
    let primary_hash = dedupe_hashes.first().ok_or_else(|| {
        AuthorityError::Corrupt("approval lookup produced no deduplication hash".into())
    })?;
    let compatibility_hash = dedupe_hashes.get(1).unwrap_or(primary_hash);
    let mut statement = conn.prepare(
        "SELECT grant_claims.grant_id
         FROM grant_claims
         JOIN approval_requests
           ON approval_requests.request_id = grant_claims.request_id
         WHERE approval_requests.dedupe_hash IN (?1, ?2)",
    )?;
    let mut candidates = statement.query(params![primary_hash, compatibility_hash])?;
    let mut usable = None;
    let mut saw_terminal = false;
    let mut saw_not_yet_valid = false;
    let mut saw_expired = false;
    while let Some(row) = candidates.next()? {
        let grant_id = row.get::<_, String>(0)?;
        let (signed_claim, claim) = load_claim(conn, &grant_id, grant_key)?
            .ok_or_else(|| AuthorityError::Corrupt("matching grant claim disappeared".into()))?;
        let stored_request = load_request(conn, claim.approval_request_id())?.ok_or_else(|| {
            AuthorityError::Corrupt("grant claim approval request is missing".into())
        })?;
        if stored_request.request.generation() != generation
            || stored_request.request.required_scope() != required_scope
            || stored_request.request.binding() != *binding
        {
            return Err(AuthorityError::Corrupt(
                "matching grant request contradicts its authorization boundary".into(),
            ));
        }
        if stored_request.request.reason() != reason {
            return Err(AuthorityError::InvalidInput(
                "matching grant request has a different policy reason".into(),
            ));
        }
        if claim.required_scope() != required_scope || claim.binding() != *binding {
            return Err(AuthorityError::Corrupt(
                "matching grant claim contradicts its signed approval binding".into(),
            ));
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
        } else if !claim.is_usable_for(required_scope, context.input_hash(), at) {
            return Err(AuthorityError::Corrupt(
                "matching grant is not usable for its indexed authorization boundary".into(),
            ));
        }
        if usable.is_some() {
            return Err(AuthorityError::Corrupt(
                "multiple usable grants match the exact authorization context and scope".into(),
            ));
        }
        usable = Some(SelectedGrant {
            grant_id,
            request_id: claim.approval_request_id().to_string(),
            signed_claim,
            signed_previous,
            previous,
        });
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
    Ok((usable, not_usable))
}

pub(super) struct RecordedSpend {
    pub(super) state: SignedGrantStateV2,
    pub(super) grant_id: String,
    pub(super) request_id: String,
}

pub(super) struct SpendGrantInput<'a> {
    pub(super) context: &'a AuthorizationContextV2,
    pub(super) consumed_at: i64,
    pub(super) state_event_id: &'a str,
}

pub(super) fn spend_grant(
    conn: &Connection,
    selected: SelectedGrant,
    input: SpendGrantInput<'_>,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> Result<RecordedSpend, AuthorityError> {
    validate_token("state event id", input.state_event_id, 160)?;
    let SelectedGrant {
        grant_id,
        request_id,
        signed_claim,
        signed_previous,
        previous,
    } = selected;
    let spent = GrantStateV2::terminal(
        &previous,
        signed_previous.state_hash(),
        GrantStatusV2::Spent,
        input.state_event_id.into(),
        input.consumed_at,
    )?;
    let signed_spent = SignedGrantStateV2::sign(&spent, grant_key)?;
    insert_state(conn, &spent, &signed_spent)?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id: input.state_event_id.into(),
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
    Ok(RecordedSpend {
        state: signed_spent,
        grant_id,
        request_id,
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
