use super::*;

#[derive(Debug)]
pub(super) struct StoredRequest {
    pub(super) request: ApprovalRequestV2,
    pub(super) request_hash: String,
    pub(super) dedupe_hash: String,
    pub(super) event_id: String,
}

#[derive(Debug)]
pub(super) struct AllowEvidenceLink {
    pub(super) seq: usize,
    pub(super) timestamp: i64,
    pub(super) build_identity: Option<String>,
    pub(super) policy_identity: Option<String>,
    pub(super) grant_id: String,
    pub(super) required_scope: String,
    pub(super) input_hash: String,
    pub(super) context: AuthorizationContextV2,
    pub(super) generation: AuthorityGenerationV2,
}

#[derive(Debug, Clone)]
pub(super) struct LedgerEventLink {
    pub(super) seq: usize,
    pub(super) timestamp: i64,
    pub(super) build_identity: Option<String>,
    pub(super) policy_identity: Option<String>,
    pub(super) payload: LedgerPayloadV2,
}

#[derive(Debug, Clone)]
pub(super) struct StoredGeneration {
    pub(super) generation: AuthorityGenerationV2,
    pub(super) event_id: String,
    pub(super) activated_at: i64,
}

#[derive(Debug)]
pub(super) struct VerifiedRuntimeTimeline {
    pub(super) transition_events: HashSet<String>,
    pub(super) transitions: Vec<(usize, AuthorityRuntimeStateV2)>,
}

impl VerifiedRuntimeTimeline {
    pub(super) fn state_at(&self, ledger_seq: usize) -> Option<&AuthorityRuntimeStateV2> {
        self.transitions
            .iter()
            .rev()
            .find(|(transition_seq, _)| *transition_seq <= ledger_seq)
            .map(|(_, state)| state)
    }
}

pub(super) fn read_metadata(conn: &Connection) -> Result<AuthorityMetadata, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT schema_version, instance_id, epoch, grant_key_id, ledger_key_id,
                    genesis_generation_id, cutover_marker
             FROM authority_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| AuthorityError::Corrupt("authority metadata singleton is missing".into()))?;
    let cutover = match row.6.as_str() {
        CUTOVER_MARKER => CutoverStateV2::FreshV2NoLegacyActiveGrants,
        other => {
            return Err(AuthorityError::Corrupt(format!(
                "unknown cutover marker {other:?}"
            )));
        }
    };
    let genesis_generation = load_generation(conn, &row.5)?
        .ok_or_else(|| AuthorityError::Corrupt("metadata genesis generation is missing".into()))?;
    Ok(AuthorityMetadata {
        schema_version: row.0,
        instance_id: row.1,
        epoch: row.2,
        grant_key_id: row.3,
        ledger_key_id: row.4,
        genesis_generation: genesis_generation.generation,
        cutover,
    })
}

pub(super) fn load_generation(
    conn: &Connection,
    generation_id: &str,
) -> Result<Option<StoredGeneration>, AuthorityError> {
    let row = conn
        .query_row(
            "SELECT generation_jcs, event_id, activated_at
             FROM authority_generations WHERE generation_id = ?1",
            [generation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(generation_jcs, event_id, activated_at)| {
        let generation: AuthorityGenerationV2 = decode_canonical(generation_jcs.as_bytes())?;
        generation.validate()?;
        if generation.generation_id() != generation_id {
            return Err(AuthorityError::Corrupt(
                "generation row does not match its canonical identifier".into(),
            ));
        }
        validate_token("generation event id", &event_id, 160)?;
        validate_timestamp(activated_at)?;
        Ok(StoredGeneration {
            generation,
            event_id,
            activated_at,
        })
    })
    .transpose()
}

pub(super) fn load_runtime_states(
    conn: &Connection,
) -> Result<Vec<AuthorityRuntimeStateV2>, AuthorityError> {
    let rows = {
        let mut statement = conn.prepare(
            "SELECT revision, generation_id, maintenance, event_id, transitioned_at
             FROM authority_runtime_states ORDER BY revision ASC",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    rows.into_iter()
        .map(
            |(revision, generation_id, maintenance, transition_event_id, transitioned_at)| {
                if revision < 0 || !matches!(maintenance, 0 | 1) {
                    return Err(AuthorityError::Corrupt(
                        "runtime-state revision or maintenance flag is invalid".into(),
                    ));
                }
                let active_generation =
                    load_generation(conn, &generation_id)?.ok_or_else(|| {
                        AuthorityError::Corrupt(
                            "runtime state references a missing generation".into(),
                        )
                    })?;
                validate_token("runtime transition event id", &transition_event_id, 160)?;
                validate_timestamp(transitioned_at)?;
                Ok(AuthorityRuntimeStateV2 {
                    revision: revision.to_string(),
                    active_generation: active_generation.generation,
                    maintenance: maintenance == 1,
                    transition_event_id,
                    transitioned_at,
                })
            },
        )
        .collect()
}

pub(super) fn load_current_runtime_state(
    conn: &Connection,
) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
    load_runtime_states(conn)?
        .pop()
        .ok_or_else(|| AuthorityError::Corrupt("authority runtime state is missing".into()))
}

pub(super) fn insert_generation(
    conn: &Connection,
    generation: &AuthorityGenerationV2,
    event_id: &str,
    activated_at: i64,
) -> Result<(), AuthorityError> {
    generation.validate()?;
    validate_token("generation event id", event_id, 160)?;
    validate_timestamp(activated_at)?;
    let generation_jcs = canonicalize(generation)?;
    conn.execute(
        "INSERT INTO authority_generations (
            generation_id, generation_jcs, event_id, activated_at
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            generation.generation_id(),
            String::from_utf8(generation_jcs).map_err(|error| {
                AuthorityError::Corrupt(format!("generation JCS was not UTF-8: {error}"))
            })?,
            event_id,
            activated_at,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_runtime_state(
    conn: &Connection,
    revision: i64,
    generation_id: &str,
    maintenance: bool,
    event_id: &str,
    transitioned_at: i64,
) -> Result<(), AuthorityError> {
    if revision < 0 {
        return Err(AuthorityError::Corrupt(
            "runtime-state revision cannot be negative".into(),
        ));
    }
    validate_decimal("runtime-state generation id", generation_id)?;
    validate_token("runtime transition event id", event_id, 160)?;
    validate_timestamp(transitioned_at)?;
    conn.execute(
        "INSERT INTO authority_runtime_states (
            revision, generation_id, maintenance, event_id, transitioned_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            revision,
            generation_id,
            i64::from(maintenance),
            event_id,
            transitioned_at,
        ],
    )?;
    Ok(())
}

pub(super) fn generation_id_is_newer(candidate: &str, active: &str) -> bool {
    candidate.len() > active.len() || (candidate.len() == active.len() && candidate > active)
}

pub(super) fn ensure_decision_admitted(
    conn: &Connection,
    evaluated_generation: &AuthorityGenerationV2,
) -> Result<(), AuthorityError> {
    evaluated_generation.validate()?;
    let current = load_current_runtime_state(conn)?;
    if current.maintenance {
        return Err(AuthorityError::Maintenance);
    }
    if current.active_generation != *evaluated_generation {
        return Err(AuthorityError::StaleGeneration {
            evaluated_generation_id: evaluated_generation.generation_id().into(),
            active_generation_id: current.active_generation.generation_id().into(),
        });
    }
    Ok(())
}

pub(super) fn next_runtime_revision(
    current: &AuthorityRuntimeStateV2,
) -> Result<i64, AuthorityError> {
    current
        .revision
        .parse::<i64>()
        .map_err(|_| AuthorityError::Corrupt("runtime-state revision is not an integer".into()))?
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Corrupt("runtime-state revision overflow".into()))
}

pub(super) fn validate_admin_transition(
    operator_principal: &str,
    reason: &str,
) -> Result<(), AuthorityError> {
    validate_text("operator principal", operator_principal, 256, false)?;
    validate_text("administrative reason", reason, 1_024, true)?;
    Ok(())
}
