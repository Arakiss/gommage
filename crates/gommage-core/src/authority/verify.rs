use super::*;

pub(super) fn verify_all(
    conn: &Connection,
    config: &AuthorityConfig,
    grant_key: &VerifyingKey,
    ledger_key: &VerifyingKey,
    trusted_checkpoint: Option<&SignedLedgerCheckpointV2>,
) -> Result<LedgerVerification, AuthorityError> {
    verify_pragmas(conn)?;
    let metadata = read_metadata(conn)?;
    let expected_grant_key_id = key_id(KeyPurpose::Grant, grant_key);
    let expected_ledger_key_id = key_id(KeyPurpose::Ledger, ledger_key);
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.instance_id != config.instance_id
        || metadata.epoch != config.epoch
        || metadata.genesis_generation != config.genesis_generation
        || metadata.grant_key_id != expected_grant_key_id
        || metadata.ledger_key_id != expected_ledger_key_id
        || metadata.cutover != CutoverStateV2::FreshV2NoLegacyActiveGrants
    {
        return Err(AuthorityError::Corrupt(
            "authority metadata does not match the trusted open parameters".into(),
        ));
    }
    let mut entries = Vec::new();
    let mut previous_hash = ZERO_HASH.to_string();
    let mut evidence_time_floor = None;
    {
        let mut statement = conn.prepare(
            "SELECT seq, event_id, entry_jcs, signature_b64, entry_hash
             FROM ledger_entries ORDER BY seq ASC",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let stored_seq = row.get::<_, i64>(0)?;
            let stored_event_id = row.get::<_, String>(1)?;
            let jcs = row.get::<_, String>(2)?;
            let signature_b64 = row.get::<_, String>(3)?;
            let stored_hash = row.get::<_, String>(4)?;
            let expected_seq = i64::try_from(entries.len() + 1)
                .map_err(|_| AuthorityError::Corrupt("ledger sequence overflow".into()))?;
            if stored_seq != expected_seq {
                return Err(AuthorityError::Corrupt(format!(
                    "ledger sequence gap: expected {expected_seq}, got {stored_seq}"
                )));
            }
            let envelope = SignedJcs::from_stored(jcs, signature_b64);
            let entry: LedgerEntryV2 =
                verify_payload(EnvelopeDomain::LedgerEntry, &envelope, ledger_key)?;
            entry.validate()?;
            if entry.seq() != expected_seq.to_string()
                || entry.event_id() != stored_event_id
                || entry.previous_hash() != previous_hash
            {
                return Err(AuthorityError::Corrupt(
                    "ledger row, sequence, event id, or previous hash mismatch".into(),
                ));
            }
            if evidence_time_floor.is_some_and(|floor| entry.timestamp() < floor) {
                return Err(AuthorityError::Corrupt(
                    "ledger evidence timestamp regresses before its predecessor".into(),
                ));
            }
            evidence_time_floor = Some(entry.timestamp());
            let raw_signature = signature_bytes(envelope.signature_b64())?;
            let computed_hash = ledger_entry_hash(envelope.jcs().as_bytes(), &raw_signature);
            if computed_hash != stored_hash {
                return Err(AuthorityError::Corrupt(
                    "ledger signature-inclusive entry hash mismatch".into(),
                ));
            }
            previous_hash = computed_hash.clone();
            entries.push(VerifiedLedgerEntryV2 {
                entry,
                envelope,
                entry_hash: computed_hash,
            });
        }
    }
    let evidence_time_floor = evidence_time_floor
        .ok_or_else(|| AuthorityError::Corrupt("ledger is missing its genesis entry".into()))?;
    verify_genesis(&entries[0], config, &metadata)?;
    let (stored_head_seq, stored_head_hash): (i64, String) = conn.query_row(
        "SELECT head_seq, head_hash FROM authority_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if stored_head_seq != entries.len() as i64 || stored_head_hash != previous_hash {
        return Err(AuthorityError::Corrupt(
            "metadata head does not match the fully verified ledger".into(),
        ));
    }
    verify_relations(conn, config, grant_key, &entries)?;
    let freshness = match trusted_checkpoint {
        None => FreshnessVerdict::Unanchored,
        Some(signed_checkpoint) => {
            let checkpoint = signed_checkpoint.verify(ledger_key)?;
            if checkpoint.authority_instance != config.instance_id
                || checkpoint.authority_epoch != config.epoch
            {
                return Err(AuthorityError::RollbackDetected(
                    "trusted checkpoint belongs to another authority instance or epoch".into(),
                ));
            }
            let checkpoint_seq = checkpoint
                .head_seq
                .parse::<usize>()
                .map_err(|_| AuthorityError::Corrupt("checkpoint sequence overflow".into()))?;
            if checkpoint_seq == 0 || checkpoint_seq > entries.len() {
                return Err(AuthorityError::RollbackDetected(format!(
                    "database head {} predates trusted checkpoint {}",
                    entries.len(),
                    checkpoint.head_seq
                )));
            }
            let checkpointed_entry = &entries[checkpoint_seq - 1];
            if checkpointed_entry.entry_hash != checkpoint.head_hash
                || checkpointed_entry.entry.timestamp() != checkpoint.evidence_time_floor()
            {
                return Err(AuthorityError::RollbackDetected(
                    "database chain contradicts the trusted checkpoint hash or evidence time"
                        .into(),
                ));
            }
            FreshnessVerdict::Anchored {
                checkpoint_seq: checkpoint.head_seq,
            }
        }
    };
    Ok(LedgerVerification {
        head_seq: stored_head_seq.to_string(),
        head_hash: stored_head_hash,
        evidence_time_floor,
        entries,
        freshness,
    })
}

fn verify_genesis(
    genesis: &VerifiedLedgerEntryV2,
    config: &AuthorityConfig,
    metadata: &AuthorityMetadata,
) -> Result<(), AuthorityError> {
    if genesis.entry.seq() != "1"
        || genesis.entry.event_id() != config.genesis_event_id
        || genesis.entry.subject() != "authority"
        || genesis.entry.timestamp() != config.genesis_at
        || genesis.entry.previous_hash() != ZERO_HASH
    {
        return Err(AuthorityError::Corrupt(
            "genesis envelope does not match configured origin".into(),
        ));
    }
    match genesis.entry.payload() {
        LedgerPayloadV2::Genesis {
            instance_id,
            epoch,
            schema_version,
            grant_key_id,
            ledger_key_id,
            semantic_version,
            generation,
            cutover_marker,
        } if instance_id == &metadata.instance_id
            && epoch == &metadata.epoch
            && *schema_version == SCHEMA_VERSION as u8
            && grant_key_id == &metadata.grant_key_id
            && ledger_key_id == &metadata.ledger_key_id
            && !semantic_version.is_empty()
            && semantic_version.len() <= 64
            && !semantic_version.chars().any(char::is_control)
            && generation == &metadata.genesis_generation
            && cutover_marker == CUTOVER_MARKER =>
        {
            Ok(())
        }
        _ => Err(AuthorityError::Corrupt(
            "genesis payload does not bind current metadata".into(),
        )),
    }
}

fn verify_authority_runtime(
    conn: &Connection,
    config: &AuthorityConfig,
    events: &HashMap<String, LedgerEventLink>,
) -> Result<VerifiedRuntimeTimeline, AuthorityError> {
    let generation_ids = query_strings(
        conn,
        "SELECT generation_id FROM authority_generations ORDER BY length(generation_id), generation_id",
    )?;
    let mut generations = HashMap::new();
    for generation_id in generation_ids {
        let generation = load_generation(conn, &generation_id)?.ok_or_else(|| {
            AuthorityError::Corrupt("authority generation disappeared during verification".into())
        })?;
        generations.insert(generation_id, generation);
    }
    let states = load_runtime_states(conn)?;
    if states.is_empty() || generations.is_empty() {
        return Err(AuthorityError::Corrupt(
            "authority generation or runtime-state history is empty".into(),
        ));
    }
    let genesis_state = &states[0];
    let genesis_generation = generations
        .get(config.genesis_generation.generation_id())
        .ok_or_else(|| {
            AuthorityError::Corrupt("configured genesis generation is missing".into())
        })?;
    if genesis_state.revision != "0"
        || genesis_state.active_generation != config.genesis_generation
        || genesis_state.maintenance
        || genesis_state.transition_event_id != config.genesis_event_id
        || genesis_state.transitioned_at != config.genesis_at
        || genesis_generation.generation != config.genesis_generation
        || genesis_generation.event_id != config.genesis_event_id
        || genesis_generation.activated_at != config.genesis_at
    {
        return Err(AuthorityError::Corrupt(
            "runtime-state genesis does not match the configured generation".into(),
        ));
    }

    let mut transition_events = HashSet::new();
    let mut activation_events = HashSet::new();
    let mut transitions = Vec::with_capacity(states.len());
    for (index, state) in states.iter().enumerate() {
        if state.revision != index.to_string()
            || !transition_events.insert(state.transition_event_id.clone())
        {
            return Err(AuthorityError::Corrupt(
                "runtime-state revisions or transition events are not unique and contiguous".into(),
            ));
        }
        let event = events.get(&state.transition_event_id).ok_or_else(|| {
            AuthorityError::Corrupt("runtime state has no signed ledger transition".into())
        })?;
        if event.timestamp != state.transitioned_at {
            return Err(AuthorityError::Corrupt(
                "runtime-state timestamp does not match its signed ledger event".into(),
            ));
        }
        if index == 0 {
            if !matches!(event.payload, LedgerPayloadV2::Genesis { .. }) {
                return Err(AuthorityError::Corrupt(
                    "runtime-state revision zero is not linked to genesis".into(),
                ));
            }
            transitions.push((event.seq, state.clone()));
            continue;
        }
        let previous = &states[index - 1];
        let previous_event = events.get(&previous.transition_event_id).ok_or_else(|| {
            AuthorityError::Corrupt("previous runtime-state event is missing".into())
        })?;
        if event.seq <= previous_event.seq {
            return Err(AuthorityError::Corrupt(
                "runtime-state transitions are not ordered by the signed ledger".into(),
            ));
        }
        match &event.payload {
            LedgerPayloadV2::GenerationActivated {
                previous_generation_id,
                generation,
                maintenance,
                operator_principal,
                reason,
            } if previous_generation_id == previous.active_generation.generation_id()
                && generation == &state.active_generation
                && state.maintenance == previous.maintenance
                && *maintenance == state.maintenance
                && generation_id_is_newer(
                    generation.generation_id(),
                    previous.active_generation.generation_id(),
                ) =>
            {
                validate_text(
                    "generation operator principal",
                    operator_principal,
                    256,
                    false,
                )?;
                validate_text("generation activation reason", reason, 1_024, true)?;
                let stored = generations.get(generation.generation_id()).ok_or_else(|| {
                    AuthorityError::Corrupt(
                        "runtime activation references an absent generation".into(),
                    )
                })?;
                if stored.generation != *generation
                    || stored.event_id != state.transition_event_id
                    || stored.activated_at != state.transitioned_at
                    || !activation_events.insert(state.transition_event_id.clone())
                {
                    return Err(AuthorityError::Corrupt(
                        "generation activation does not match its immutable stored generation"
                            .into(),
                    ));
                }
            }
            LedgerPayloadV2::MaintenanceChanged {
                generation,
                enabled,
                operator_principal,
                reason,
            } if generation == &state.active_generation
                && state.active_generation == previous.active_generation
                && *enabled == state.maintenance
                && state.maintenance != previous.maintenance =>
            {
                validate_text(
                    "maintenance operator principal",
                    operator_principal,
                    256,
                    false,
                )?;
                validate_text("maintenance reason", reason, 1_024, true)?;
            }
            _ => {
                return Err(AuthorityError::Corrupt(
                    "runtime-state transition is not a coherent generation or maintenance event"
                        .into(),
                ));
            }
        }
        transitions.push((event.seq, state.clone()));
    }
    if generations.len() != activation_events.len().saturating_add(1)
        || generations.values().any(|generation| {
            generation.event_id != config.genesis_event_id
                && !activation_events.contains(&generation.event_id)
        })
    {
        return Err(AuthorityError::Corrupt(
            "stored generation cardinality does not match signed activation transitions".into(),
        ));
    }
    Ok(VerifiedRuntimeTimeline {
        transition_events,
        transitions,
    })
}

fn verify_relations(
    conn: &Connection,
    config: &AuthorityConfig,
    grant_key: &VerifyingKey,
    entries: &[VerifiedLedgerEntryV2],
) -> Result<(), AuthorityError> {
    let events: HashMap<String, LedgerEventLink> = entries
        .iter()
        .enumerate()
        .map(|(index, verified)| {
            (
                verified.entry.event_id().into(),
                LedgerEventLink {
                    seq: index + 1,
                    timestamp: verified.entry.timestamp(),
                    build_identity: verified.entry.build_identity().map(str::to_owned),
                    policy_identity: verified.entry.policy_identity().map(str::to_owned),
                    payload: verified.entry.payload().clone(),
                },
            )
        })
        .collect();
    if events.len() != entries.len() {
        return Err(AuthorityError::Corrupt(
            "ledger contains duplicate event identifiers".into(),
        ));
    }
    let runtime = verify_authority_runtime(conn, config, &events)?;

    let request_ids = query_strings(conn, "SELECT request_id FROM approval_requests")?;
    let mut requests = HashMap::new();
    for request_id in request_ids {
        let stored = load_request(conn, &request_id)?.ok_or_else(|| {
            AuthorityError::Corrupt("approval request disappeared during verification".into())
        })?;
        let request_event = events.get(&stored.event_id);
        let request_generation_is_active = request_event
            .and_then(|event| runtime.state_at(event.seq))
            .is_some_and(|state| {
                !state.maintenance && state.active_generation == *stored.request.generation()
            });
        match request_event {
            Some(LedgerEventLink {
                timestamp: event_timestamp,
                build_identity,
                policy_identity,
                payload:
                    LedgerPayloadV2::ApprovalRequested {
                        request_id,
                        request_hash,
                        dedupe_hash,
                    },
                ..
            }) if *event_timestamp == stored.request.created_at()
                && build_identity.as_deref() == Some(stored.request.build_identity())
                && policy_identity.as_deref() == Some(stored.request.policy_identity())
                && request_id == stored.request.request_id()
                && request_hash == &stored.request_hash
                && dedupe_hash == &stored.dedupe_hash
                && request_generation_is_active => {}
            _ => {
                return Err(AuthorityError::Corrupt(
                    "approval request is not linked by its exact signed ledger event".into(),
                ));
            }
        }
        requests.insert(request_id, stored);
    }

    let open_rows = {
        let mut statement = conn.prepare("SELECT dedupe_hash, request_id FROM open_approvals")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let open_by_request: HashMap<String, String> = open_rows
        .into_iter()
        .map(|(dedupe, request)| (request, dedupe))
        .collect();

    let resolution_ids = query_strings(
        conn,
        "SELECT request_id FROM approval_resolutions ORDER BY request_id",
    )?;
    let mut resolutions = HashMap::new();
    for request_id in resolution_ids {
        let resolution = load_resolution(conn, &request_id)?.ok_or_else(|| {
            AuthorityError::Corrupt("approval resolution disappeared during verification".into())
        })?;
        let request = requests.get(&request_id).ok_or_else(|| {
            AuthorityError::Corrupt("approval resolution references a missing request".into())
        })?;
        if resolution.resolved_at < request.request.created_at() {
            return Err(AuthorityError::Corrupt(
                "approval resolution predates its immutable request".into(),
            ));
        }
        let claim_hash = match &resolution.grant_id {
            Some(grant_id) => conn
                .query_row(
                    "SELECT claim_hash FROM grant_claims WHERE grant_id = ?1",
                    [grant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?,
            None => None,
        };
        let request_seq = events
            .get(&request.event_id)
            .map(|event| event.seq)
            .ok_or_else(|| AuthorityError::Corrupt("request event is missing".into()))?;
        match events.get(&resolution.event_id) {
            Some(LedgerEventLink {
                seq: resolution_seq,
                timestamp: event_timestamp,
                build_identity,
                policy_identity,
                payload:
                    LedgerPayloadV2::ApprovalResolved {
                        request_id: event_request_id,
                        request_hash,
                        outcome,
                        grant_id,
                        claim_hash: event_claim_hash,
                        operator_principal,
                        reason,
                    },
                ..
            }) if *resolution_seq > request_seq
                && *event_timestamp == resolution.resolved_at
                && build_identity.as_deref() == Some(request.request.build_identity())
                && policy_identity.as_deref() == Some(request.request.policy_identity())
                && (resolution.kind != ApprovalResolutionKindV2::Approved
                    || runtime.state_at(*resolution_seq).is_some_and(|state| {
                        !state.maintenance
                            && state.active_generation == *request.request.generation()
                    }))
                && event_request_id == &request_id
                && request_hash == &request.request_hash
                && outcome == resolution.kind.as_str()
                && grant_id == &resolution.grant_id
                && event_claim_hash == &claim_hash
                && operator_principal == &resolution.operator_principal
                && reason == &resolution.reason => {}
            _ => {
                return Err(AuthorityError::Corrupt(
                    "approval resolution is not linked by its exact signed ledger event".into(),
                ));
            }
        }
        resolutions.insert(request_id, resolution);
    }
    for (request_id, request) in &requests {
        let open = open_by_request.get(request_id);
        let resolved = resolutions.contains_key(request_id);
        if (open.is_some() == resolved) || open.is_some_and(|hash| hash != &request.dedupe_hash) {
            return Err(AuthorityError::Corrupt(
                "request must be in exactly one open or resolved state".into(),
            ));
        }
    }
    if open_by_request
        .keys()
        .any(|request_id| !requests.contains_key(request_id))
    {
        return Err(AuthorityError::Corrupt(
            "open approval references a missing request".into(),
        ));
    }

    let grant_ids = query_strings(conn, "SELECT grant_id FROM grant_claims ORDER BY grant_id")?;
    let mut claims = HashMap::new();
    for grant_id in grant_ids {
        let (signed, claim) = load_claim(conn, &grant_id, grant_key)?.ok_or_else(|| {
            AuthorityError::Corrupt("grant claim disappeared during verification".into())
        })?;
        let request = requests
            .get(claim.approval_request_id())
            .ok_or_else(|| AuthorityError::Corrupt("claim request is missing".into()))?;
        let resolution = resolutions
            .get(claim.approval_request_id())
            .ok_or_else(|| AuthorityError::Corrupt("claim request is unresolved".into()))?;
        if resolution.kind != ApprovalResolutionKindV2::Approved
            || resolution.grant_id.as_deref() != Some(claim.grant_id())
            || claim.request_hash() != request.request_hash
            || claim.input_hash() != request.request.input_hash()
            || claim.binding() != request.request.binding()
            || claim.required_scope() != request.request.required_scope()
            || claim.operator_principal() != resolution.operator_principal
            || claim.reason() != resolution.reason
            || claim.issued_at() != resolution.resolved_at
            || claim.authority_instance() != config.instance_id
            || claim.authority_epoch() != config.epoch
        {
            return Err(AuthorityError::Corrupt(
                "grant claim is not an exact product of its signed approval".into(),
            ));
        }
        claims.insert(grant_id, (signed, claim));
    }
    for resolution in resolutions.values() {
        match resolution.kind {
            ApprovalResolutionKindV2::Approved
                if resolution
                    .grant_id
                    .as_ref()
                    .is_some_and(|grant_id| claims.contains_key(grant_id)) => {}
            ApprovalResolutionKindV2::Denied if resolution.grant_id.is_none() => {}
            _ => {
                return Err(AuthorityError::Corrupt(
                    "approval resolution and grant-claim cardinality mismatch".into(),
                ));
            }
        }
    }

    let raw_states = {
        let mut statement = conn.prepare(
            "SELECT grant_id, revision, status, uses, state_jcs, signature_b64,
                    state_hash, transition_event_id
             FROM grant_states ORDER BY grant_id, revision",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut states: HashMap<String, Vec<(SignedGrantStateV2, GrantStateV2)>> = HashMap::new();
    for (
        grant_id,
        revision,
        status,
        uses,
        state_jcs,
        signature_b64,
        state_hash,
        transition_event_id,
    ) in raw_states
    {
        let signed = SignedGrantStateV2::from_stored(
            SignedJcs::from_stored(state_jcs, signature_b64),
            state_hash,
        );
        let state = signed.verify(grant_key)?;
        let Some((signed_claim, claim)) = claims.get(&grant_id) else {
            return Err(AuthorityError::Corrupt(
                "grant state references a missing claim".into(),
            ));
        };
        let approval_request = requests
            .get(claim.approval_request_id())
            .ok_or_else(|| AuthorityError::Corrupt("state approval request is missing".into()))?;
        let approval_build = approval_request.request.build_identity();
        let approval_policy = approval_request.request.policy_identity();
        let approval_generation = approval_request.request.generation();
        if state.grant_id() != grant_id
            || state.revision() != revision.to_string()
            || status_string(state.status()) != status
            || i64::from(state.uses()) != uses
            || state.transition_event_id() != transition_event_id
            || state.claim_hash() != signed_claim.claim_hash()
            || state.authority_instance() != config.instance_id
            || state.authority_epoch() != config.epoch
            || state.grant_key_id() != claim.grant_key_id()
        {
            return Err(AuthorityError::Corrupt(
                "grant state row or authority binding mismatch".into(),
            ));
        }
        match events.get(state.transition_event_id()) {
            Some(LedgerEventLink {
                seq: state_seq,
                timestamp: event_timestamp,
                build_identity,
                policy_identity,
                payload:
                    LedgerPayloadV2::GrantStateChanged {
                        grant_id: event_grant_id,
                        claim_hash,
                        state_hash,
                        revision: event_revision,
                        status: event_status,
                        operator_principal,
                        reason,
                    },
                ..
            }) if *event_timestamp == state.transitioned_at()
                && event_grant_id == &grant_id
                && claim_hash == signed_claim.claim_hash()
                && state_hash == signed.state_hash()
                && event_revision == state.revision()
                && *event_status == state.status()
                && match state.status() {
                    GrantStatusV2::Active => {
                        build_identity.as_deref() == Some(approval_build)
                            && policy_identity.as_deref() == Some(approval_policy)
                            && runtime.state_at(*state_seq).is_some_and(|runtime_state| {
                                !runtime_state.maintenance
                                    && runtime_state.active_generation == *approval_generation
                            })
                    }
                    GrantStatusV2::Spent => {
                        build_identity.as_deref() == Some(approval_build)
                            && policy_identity.as_deref() == Some(approval_policy)
                    }
                    GrantStatusV2::Revoked => true,
                }
                && state_actor_fields_match(state.status(), operator_principal, reason)? => {}
            _ => {
                return Err(AuthorityError::Corrupt(
                    "grant state is not linked by its exact signed ledger event".into(),
                ));
            }
        }
        states.entry(grant_id).or_default().push((signed, state));
    }

    let decision_events = verify_decision_relations(
        entries,
        &events,
        &runtime,
        &requests,
        &resolutions,
        &claims,
        &states,
    )?;
    let request_events: HashSet<&str> = requests
        .values()
        .map(|request| request.event_id.as_str())
        .collect();
    let resolution_events: HashSet<&str> = resolutions
        .values()
        .map(|resolution| resolution.event_id.as_str())
        .collect();
    let state_events: HashSet<&str> = states
        .values()
        .flatten()
        .map(|(_, state)| state.transition_event_id())
        .collect();
    for (index, verified) in entries.iter().enumerate() {
        let linked = match verified.entry.payload() {
            LedgerPayloadV2::Genesis { .. } => {
                index == 0
                    && runtime
                        .transition_events
                        .contains(verified.entry.event_id())
            }
            LedgerPayloadV2::GenerationActivated { .. }
            | LedgerPayloadV2::MaintenanceChanged { .. } => runtime
                .transition_events
                .contains(verified.entry.event_id()),
            LedgerPayloadV2::ApprovalRequested { .. } => {
                request_events.contains(verified.entry.event_id())
            }
            LedgerPayloadV2::ApprovalResolved { .. } => {
                resolution_events.contains(verified.entry.event_id())
            }
            LedgerPayloadV2::GrantStateChanged { .. } => {
                state_events.contains(verified.entry.event_id())
            }
            LedgerPayloadV2::DecisionAllow { .. } | LedgerPayloadV2::DecisionRecorded { .. } => {
                decision_events.contains(verified.entry.event_id())
            }
        };
        if !linked {
            return Err(AuthorityError::Corrupt(
                "ledger contains an event with no canonical authority-state link".into(),
            ));
        }
    }
    Ok(())
}
