use super::*;

pub(super) struct PreparedApprovalRequest {
    pub(super) request: ApprovalRequestV2,
    pub(super) request_jcs: String,
    pub(super) request_hash: String,
    pub(super) dedupe_hash: String,
    pub(super) lookup_hashes: Vec<String>,
    pub(super) event_id: String,
}

const BOUND_APPROVAL_DEDUPE_DOMAIN: &str = "gommage.approval.dedupe.bound";

pub(super) fn binding_for_decision(bind_input: bool, input_hash: &str) -> PictoBinding {
    if bind_input {
        PictoBinding::ExactInput {
            input_hash: input_hash.to_string(),
        }
    } else {
        PictoBinding::ScopeOnly
    }
}

pub(super) fn approval_dedupe_hashes(
    context: &AuthorizationContextV2,
    generation: &AuthorityGenerationV2,
    required_scope: &str,
    binding: &PictoBinding,
) -> Result<Vec<String>, AuthorityError> {
    let bounded_jcs = canonicalize(&BoundApprovalDedupeV2 {
        domain: BOUND_APPROVAL_DEDUPE_DOMAIN,
        version: FORMAT_VERSION,
        generation,
        required_scope,
        binding,
    })?;
    let mut hashes = vec![approval_dedupe_hash(&bounded_jcs)];
    if matches!(binding, PictoBinding::ExactInput { .. }) {
        let legacy_jcs = canonicalize(&ApprovalDedupeV2 {
            domain: "gommage.approval.dedupe",
            version: FORMAT_VERSION,
            context,
            generation,
            required_scope,
        })?;
        let legacy_hash = approval_dedupe_hash(&legacy_jcs);
        if legacy_hash != hashes[0] {
            hashes.push(legacy_hash);
        }
    }
    Ok(hashes)
}

pub(super) fn prepare_approval_request(
    command: &CreateRequestCommand,
) -> Result<PreparedApprovalRequest, AuthorityError> {
    validate_token("request id", &command.request_id, 160)?;
    validate_token("request event id", &command.event_id, 160)?;
    command.context.validate()?;
    let request = ApprovalRequestV2::from_command(command)?;
    let request_jcs = canonicalize(&request)?;
    let request_hash = approval_request_hash(&request_jcs);
    let lookup_hashes = approval_dedupe_hashes(
        request.context(),
        request.generation(),
        request.required_scope(),
        &request.binding(),
    )?;
    let dedupe_hash = lookup_hashes[0].clone();
    Ok(PreparedApprovalRequest {
        request,
        request_jcs: String::from_utf8(request_jcs).map_err(|error| {
            AuthorityError::Corrupt(format!("request JCS was not UTF-8: {error}"))
        })?,
        request_hash,
        dedupe_hash,
        lookup_hashes,
        event_id: command.event_id.clone(),
    })
}

pub(super) fn create_or_get_request_in_transaction(
    conn: &Connection,
    ledger_key: &SigningKey,
    prepared: PreparedApprovalRequest,
) -> Result<CreateRequestResult, AuthorityError> {
    let PreparedApprovalRequest {
        request,
        request_jcs,
        request_hash,
        dedupe_hash,
        lookup_hashes,
        event_id,
    } = prepared;
    let mut existing_request_ids = Vec::new();
    for lookup_hash in &lookup_hashes {
        let existing_request_id = conn
            .query_row(
                "SELECT request_id FROM open_approvals WHERE dedupe_hash = ?1",
                [lookup_hash],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_request_id) = existing_request_id
            && !existing_request_ids.contains(&existing_request_id)
        {
            existing_request_ids.push(existing_request_id);
        }
    }
    if existing_request_ids.len() > 1 {
        return Err(AuthorityError::Corrupt(
            "multiple open approvals match one authorization boundary".into(),
        ));
    }
    if let Some(existing_request_id) = existing_request_ids.pop() {
        let existing = load_request(conn, &existing_request_id)?.ok_or_else(|| {
            AuthorityError::Corrupt("open approval points to a missing request".into())
        })?;
        ensure_request_is_open(conn, &existing)?;
        ensure_approval_attempt_matches(&existing.request, &request)?;
        return Ok(CreateRequestResult::Existing(existing.request));
    }
    conn.execute(
        "INSERT INTO approval_requests (
            request_id, dedupe_hash, request_jcs, request_hash, event_id, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.request_id(),
            dedupe_hash,
            request_jcs,
            request_hash,
            event_id,
            request.created_at(),
        ],
    )?;
    conn.execute(
        "INSERT INTO open_approvals (dedupe_hash, request_id) VALUES (?1, ?2)",
        params![dedupe_hash, request.request_id()],
    )?;
    append_ledger_entry(
        conn,
        ledger_key,
        LedgerEventDraft {
            event_id,
            subject: request.request_id().into(),
            timestamp: request.created_at(),
            build_identity: Some(request.build_identity().into()),
            policy_identity: Some(request.policy_identity().into()),
            payload: LedgerPayloadV2::ApprovalRequested {
                request_id: request.request_id().into(),
                request_hash,
                dedupe_hash,
            },
        },
    )?;
    Ok(CreateRequestResult::Created(request))
}

pub(super) fn load_request(
    conn: &Connection,
    request_id: &str,
) -> Result<Option<StoredRequest>, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT request_jcs, request_hash, dedupe_hash, event_id, created_at
             FROM approval_requests WHERE request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(request_jcs, request_hash, dedupe_hash, event_id, created_at)| {
            let request: ApprovalRequestV2 = decode_canonical(request_jcs.as_bytes())?;
            request.validate()?;
            if request.request_id() != request_id
                || request.created_at() != created_at
                || approval_request_hash(request_jcs.as_bytes()) != request_hash
            {
                return Err(AuthorityError::Corrupt(
                    "approval request row does not match its canonical content".into(),
                ));
            }
            validate_hash("request hash", &request_hash)?;
            validate_hash("approval dedupe hash", &dedupe_hash)?;
            validate_token("request event id", &event_id, 160)?;
            let expected_hashes = approval_dedupe_hashes(
                request.context(),
                request.generation(),
                request.required_scope(),
                &request.binding(),
            )?;
            if !expected_hashes.contains(&dedupe_hash) {
                return Err(AuthorityError::Corrupt(
                    "approval request dedupe hash mismatch".into(),
                ));
            }
            Ok(StoredRequest {
                request,
                request_hash,
                dedupe_hash,
                event_id,
            })
        },
    )
    .transpose()
}

fn ensure_approval_attempt_matches(
    existing: &ApprovalRequestV2,
    attempted: &ApprovalRequestV2,
) -> Result<(), AuthorityError> {
    if existing.generation() != attempted.generation()
        || existing.required_scope() != attempted.required_scope()
        || existing.binding() != attempted.binding()
    {
        return Err(AuthorityError::Corrupt(
            "deduplicated approval does not match its authorization boundary".into(),
        ));
    }
    if existing.reason() != attempted.reason() {
        return Err(AuthorityError::InvalidInput(
            "matching approval boundary has a different policy reason".into(),
        ));
    }
    Ok(())
}

pub(super) fn load_resolution(
    conn: &Connection,
    request_id: &str,
) -> Result<Option<ApprovalResolutionV2>, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT outcome, operator_principal, reason, resolved_at, grant_id, event_id
             FROM approval_resolutions WHERE request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(outcome, operator_principal, reason, resolved_at, grant_id, event_id)| {
            let kind = match outcome.as_str() {
                "approved" if grant_id.is_some() => ApprovalResolutionKindV2::Approved,
                "denied" if grant_id.is_none() => ApprovalResolutionKindV2::Denied,
                _ => {
                    return Err(AuthorityError::Corrupt(
                        "approval resolution outcome/grant combination is invalid".into(),
                    ));
                }
            };
            validate_text("operator principal", &operator_principal, 256, false)?;
            validate_text("resolution reason", &reason, 1_024, true)?;
            validate_timestamp(resolved_at)?;
            validate_token("resolution event id", &event_id, 160)?;
            if let Some(grant_id) = &grant_id {
                validate_token("grant id", grant_id, 160)?;
            }
            Ok(ApprovalResolutionV2 {
                request_id: request_id.into(),
                kind,
                operator_principal,
                reason,
                resolved_at,
                grant_id,
                event_id,
            })
        },
    )
    .transpose()
}

pub(super) fn ensure_request_is_open(
    conn: &Connection,
    request: &StoredRequest,
) -> Result<(), AuthorityError> {
    let slot = conn
        .query_row(
            "SELECT dedupe_hash FROM open_approvals WHERE request_id = ?1",
            [request.request.request_id()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if slot.as_deref() != Some(request.dedupe_hash.as_str()) {
        return Err(AuthorityError::Corrupt(
            "unresolved request is missing its exact open dedupe slot".into(),
        ));
    }
    Ok(())
}
