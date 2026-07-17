use super::*;

impl Authority {
    /// Activate one immutable successor generation through the serialized authority ledger.
    pub fn activate_generation(
        &mut self,
        command: &ActivateGenerationCommand,
    ) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
        command.generation.validate()?;
        validate_admin_transition(
            &command.event_id,
            &command.operator_principal,
            &command.reason,
            command.activated_at,
        )?;
        let ledger_key = self.ledger_key.clone();
        self.retained_commit(|tx, _| {
            let current = load_current_runtime_state(tx)?;
            if !generation_id_is_newer(
                command.generation.generation_id(),
                current.active_generation.generation_id(),
            ) {
                return Err(AuthorityError::InvalidInput(
                    "successor generation id must be strictly greater than the active id".into(),
                ));
            }
            if load_generation(tx, command.generation.generation_id())?.is_some() {
                return Err(AuthorityError::InvalidInput(
                    "generation id is already present".into(),
                ));
            }
            let revision = next_runtime_revision(&current)?;
            insert_generation(
                tx,
                &command.generation,
                &command.event_id,
                command.activated_at,
            )?;
            insert_runtime_state(
                tx,
                revision,
                command.generation.generation_id(),
                current.maintenance,
                &command.event_id,
                command.activated_at,
            )?;
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.event_id.clone(),
                    subject: "authority".into(),
                    timestamp: command.activated_at,
                    build_identity: Some(command.generation.build_identity().into()),
                    policy_identity: Some(command.generation.policy_identity().into()),
                    payload: LedgerPayloadV2::GenerationActivated {
                        previous_generation_id: current.active_generation.generation_id().into(),
                        generation: command.generation.clone(),
                        maintenance: current.maintenance,
                        operator_principal: command.operator_principal.clone(),
                        reason: command.reason.clone(),
                    },
                },
            )?;
            load_current_runtime_state(tx)
        })
    }

    /// Enter or leave fail-closed maintenance as one signed authority transition.
    pub fn set_maintenance(
        &mut self,
        command: &SetMaintenanceCommand,
    ) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
        validate_admin_transition(
            &command.event_id,
            &command.operator_principal,
            &command.reason,
            command.transitioned_at,
        )?;
        let ledger_key = self.ledger_key.clone();
        self.retained_commit(|tx, _| {
            let current = load_current_runtime_state(tx)?;
            if current.maintenance == command.enabled {
                return Err(AuthorityError::InvalidInput(format!(
                    "authority maintenance is already {}",
                    if command.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                )));
            }
            let revision = next_runtime_revision(&current)?;
            insert_runtime_state(
                tx,
                revision,
                current.active_generation.generation_id(),
                command.enabled,
                &command.event_id,
                command.transitioned_at,
            )?;
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.event_id.clone(),
                    subject: "authority".into(),
                    timestamp: command.transitioned_at,
                    build_identity: Some(current.active_generation.build_identity().into()),
                    policy_identity: Some(current.active_generation.policy_identity().into()),
                    payload: LedgerPayloadV2::MaintenanceChanged {
                        generation: current.active_generation.clone(),
                        enabled: command.enabled,
                        operator_principal: command.operator_principal.clone(),
                        reason: command.reason.clone(),
                    },
                },
            )?;
            load_current_runtime_state(tx)
        })
    }

    /// Resolve an open request as approved and atomically create its active grant.
    pub fn approve(&mut self, command: &ApproveCommand) -> Result<ApproveResult, AuthorityError> {
        validate_approval_actor(
            &command.request_id,
            &command.operator_principal,
            &command.reason,
            command.resolved_at,
        )?;
        validate_token("grant id", &command.grant_id, 160)?;
        validate_token("resolution event id", &command.resolution_event_id, 160)?;
        validate_token("activation event id", &command.activation_event_id, 160)?;
        if command.ttl_seconds <= 0 || command.ttl_seconds > MAX_GRANT_TTL_SECONDS {
            return Err(AuthorityError::InvalidInput(format!(
                "grant TTL must be between 1 and {MAX_GRANT_TTL_SECONDS} seconds"
            )));
        }
        let expires_at = command
            .resolved_at
            .checked_add(command.ttl_seconds)
            .ok_or_else(|| AuthorityError::InvalidInput("grant expiry overflow".into()))?;
        validate_timestamp(expires_at)?;
        let grant_key = self.grant_key.clone();
        let ledger_key = self.ledger_key.clone();
        let config = self.config.clone();
        let grant_key_id = self.grant_key_id.clone();
        self.retained_commit(|tx, _| {
            if let Some(resolution) = load_resolution(tx, &command.request_id)? {
                return Ok(ApproveResult::AlreadyResolved(resolution));
            }
            let stored = load_request(tx, &command.request_id)?
                .ok_or_else(|| AuthorityError::InvalidInput("approval request not found".into()))?;
            ensure_request_is_open(tx, &stored)?;
            ensure_decision_admitted(tx, stored.request.generation())?;
            if command.resolved_at < stored.request.created_at() {
                return Err(AuthorityError::InvalidInput(
                    "approval cannot predate its request".into(),
                ));
            }
            let request_generation = stored.request.generation().clone();
            let request_build_identity = stored.request.build_identity().to_owned();
            let claim = GrantClaimV2::new(GrantClaimFields {
                authority_instance: config.instance_id.clone(),
                authority_epoch: config.epoch.clone(),
                grant_id: command.grant_id.clone(),
                issued_at: command.resolved_at,
                not_before: command.resolved_at,
                expires_at,
                required_scope: stored.request.required_scope().into(),
                input_hash: stored.request.input_hash().into(),
                binding: stored.request.binding(),
                approval_request_id: stored.request.request_id().into(),
                request_hash: stored.request_hash.clone(),
                operator_principal: command.operator_principal.clone(),
                reason: command.reason.clone(),
                grant_key_id,
            })?;
            let signed_claim = SignedGrantClaimV2::sign(&claim, &grant_key)?;
            let active = GrantStateV2::active(
                &claim,
                signed_claim.claim_hash(),
                command.activation_event_id.clone(),
                command.resolved_at,
            )?;
            let signed_state = SignedGrantStateV2::sign(&active, &grant_key)?;
            tx.execute(
                "INSERT INTO approval_resolutions (
                request_id, outcome, operator_principal, reason, resolved_at, grant_id, event_id
             ) VALUES (?1, 'approved', ?2, ?3, ?4, ?5, ?6)",
                params![
                    command.request_id,
                    command.operator_principal,
                    command.reason,
                    command.resolved_at,
                    command.grant_id,
                    command.resolution_event_id,
                ],
            )?;
            tx.execute(
                "INSERT INTO grant_claims (
                grant_id, request_id, claim_jcs, signature_b64, claim_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    command.grant_id,
                    command.request_id,
                    signed_claim.envelope().jcs(),
                    signed_claim.envelope().signature_b64(),
                    signed_claim.claim_hash(),
                ],
            )?;
            insert_state(tx, &active, &signed_state)?;
            let deleted = tx.execute(
                "DELETE FROM open_approvals WHERE request_id = ?1",
                [&command.request_id],
            )?;
            if deleted != 1 {
                return Err(AuthorityError::Corrupt(
                    "approved request did not own exactly one open slot".into(),
                ));
            }
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.resolution_event_id.clone(),
                    subject: command.request_id.clone(),
                    timestamp: command.resolved_at,
                    build_identity: Some(request_build_identity.clone()),
                    policy_identity: Some(stored.request.policy_identity().into()),
                    payload: LedgerPayloadV2::ApprovalResolved {
                        request_id: command.request_id.clone(),
                        request_hash: stored.request_hash,
                        outcome: ApprovalResolutionKindV2::Approved.as_str().into(),
                        grant_id: Some(command.grant_id.clone()),
                        claim_hash: Some(signed_claim.claim_hash().into()),
                        operator_principal: command.operator_principal.clone(),
                        reason: command.reason.clone(),
                    },
                },
            )?;
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.activation_event_id.clone(),
                    subject: command.grant_id.clone(),
                    timestamp: command.resolved_at,
                    build_identity: Some(request_build_identity),
                    policy_identity: Some(stored.request.policy_identity().into()),
                    payload: LedgerPayloadV2::GrantStateChanged {
                        grant_id: command.grant_id.clone(),
                        claim_hash: signed_claim.claim_hash().into(),
                        state_hash: signed_state.state_hash().into(),
                        revision: active.revision().into(),
                        status: GrantStatusV2::Active,
                        operator_principal: None,
                        reason: None,
                    },
                },
            )?;
            ensure_decision_admitted(tx, &request_generation)?;
            Ok(ApproveResult::Approved {
                claim: signed_claim,
                state: signed_state,
            })
        })
    }

    /// Resolve an open request as denied without creating a grant.
    pub fn deny(&mut self, command: &DenyCommand) -> Result<DenyResult, AuthorityError> {
        validate_approval_actor(
            &command.request_id,
            &command.operator_principal,
            &command.reason,
            command.resolved_at,
        )?;
        validate_token("denial event id", &command.event_id, 160)?;
        let ledger_key = self.ledger_key.clone();
        self.retained_commit(|tx, _| {
            if let Some(resolution) = load_resolution(tx, &command.request_id)? {
                return Ok(DenyResult::AlreadyResolved(resolution));
            }
            let stored = load_request(tx, &command.request_id)?
                .ok_or_else(|| AuthorityError::InvalidInput("approval request not found".into()))?;
            ensure_request_is_open(tx, &stored)?;
            if command.resolved_at < stored.request.created_at() {
                return Err(AuthorityError::InvalidInput(
                    "denial cannot predate its request".into(),
                ));
            }
            tx.execute(
                "INSERT INTO approval_resolutions (
                request_id, outcome, operator_principal, reason, resolved_at, grant_id, event_id
             ) VALUES (?1, 'denied', ?2, ?3, ?4, NULL, ?5)",
                params![
                    command.request_id,
                    command.operator_principal,
                    command.reason,
                    command.resolved_at,
                    command.event_id,
                ],
            )?;
            let deleted = tx.execute(
                "DELETE FROM open_approvals WHERE request_id = ?1",
                [&command.request_id],
            )?;
            if deleted != 1 {
                return Err(AuthorityError::Corrupt(
                    "denied request did not own exactly one open slot".into(),
                ));
            }
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.event_id.clone(),
                    subject: command.request_id.clone(),
                    timestamp: command.resolved_at,
                    build_identity: Some(stored.request.build_identity().into()),
                    policy_identity: Some(stored.request.policy_identity().into()),
                    payload: LedgerPayloadV2::ApprovalResolved {
                        request_id: command.request_id.clone(),
                        request_hash: stored.request_hash,
                        outcome: ApprovalResolutionKindV2::Denied.as_str().into(),
                        grant_id: None,
                        claim_hash: None,
                        operator_principal: command.operator_principal.clone(),
                        reason: command.reason.clone(),
                    },
                },
            )?;
            let resolution = ApprovalResolutionV2 {
                request_id: command.request_id.clone(),
                kind: ApprovalResolutionKindV2::Denied,
                operator_principal: command.operator_principal.clone(),
                reason: command.reason.clone(),
                resolved_at: command.resolved_at,
                grant_id: None,
                event_id: command.event_id.clone(),
            };
            Ok(DenyResult::Denied(resolution))
        })
    }

    /// Revoke an active grant through the same serialized state boundary.
    pub fn revoke(&mut self, command: &RevokeCommand) -> Result<RevokeResult, AuthorityError> {
        validate_token("grant id", &command.grant_id, 160)?;
        validate_token("revocation event id", &command.event_id, 160)?;
        validate_text(
            "operator principal",
            &command.operator_principal,
            256,
            false,
        )?;
        validate_text("reason", &command.reason, 1_024, true)?;
        validate_timestamp(command.revoked_at)?;
        validate_text(
            "build identity",
            &command.build_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        let grant_key = self.grant_key.clone();
        let ledger_key = self.ledger_key.clone();
        let grant_vk = self.grant_key.verifying_key();
        self.retained_commit(|tx, _| {
            let Some((signed_claim, _claim)) = load_claim(tx, &command.grant_id, &grant_vk)? else {
                return Ok(RevokeResult::NotUsable(GrantNotUsableReason::Missing));
            };
            let (signed_previous, previous) = load_latest_state(tx, &command.grant_id, &grant_vk)?
                .ok_or_else(|| AuthorityError::Corrupt("grant claim has no signed state".into()))?;
            if previous.status() != GrantStatusV2::Active {
                return Ok(RevokeResult::NotUsable(GrantNotUsableReason::Terminal));
            }
            let revoked = GrantStateV2::terminal(
                &previous,
                signed_previous.state_hash(),
                GrantStatusV2::Revoked,
                command.event_id.clone(),
                command.revoked_at,
            )?;
            let signed_revoked = SignedGrantStateV2::sign(&revoked, &grant_key)?;
            insert_state(tx, &revoked, &signed_revoked)?;
            append_ledger_entry(
                tx,
                &ledger_key,
                LedgerEventDraft {
                    event_id: command.event_id.clone(),
                    subject: command.grant_id.clone(),
                    timestamp: command.revoked_at,
                    build_identity: Some(command.build_identity.clone()),
                    policy_identity: None,
                    payload: LedgerPayloadV2::GrantStateChanged {
                        grant_id: command.grant_id.clone(),
                        claim_hash: signed_claim.claim_hash().into(),
                        state_hash: signed_revoked.state_hash().into(),
                        revision: revoked.revision().into(),
                        status: GrantStatusV2::Revoked,
                        operator_principal: Some(command.operator_principal.clone()),
                        reason: Some(command.reason.clone()),
                    },
                },
            )?;
            Ok(RevokeResult::Revoked(signed_revoked))
        })
    }

    /// Read and verify one immutable request and its signed-ledger link.
    pub fn request(&self, request_id: &str) -> Result<Option<ApprovalRequestV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let request = load_request(&tx, request_id)?.map(|stored| stored.request);
        tx.commit()?;
        Ok(request)
    }

    /// Read one terminal request resolution, if present.
    pub fn resolution(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalResolutionV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let resolution = load_resolution(&tx, request_id)?;
        tx.commit()?;
        Ok(resolution)
    }

    /// Read and cryptographically verify one immutable grant claim.
    pub fn grant(&self, grant_id: &str) -> Result<Option<SignedGrantClaimV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let claim =
            load_claim(&tx, grant_id, &self.grant_key.verifying_key())?.map(|(signed, _)| signed);
        tx.commit()?;
        Ok(claim)
    }

    /// Read and verify the latest append-only state revision for one grant.
    pub fn latest_state(
        &self,
        grant_id: &str,
    ) -> Result<Option<SignedGrantStateV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let state = load_latest_state(&tx, grant_id, &self.grant_key.verifying_key())?
            .map(|(signed, _)| signed);
        tx.commit()?;
        Ok(state)
    }

    /// Return the fully verified active generation and maintenance state.
    pub fn runtime_state(&self) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        self.verify_ready(&tx)?;
        let state = load_current_runtime_state(&tx)?;
        tx.commit()?;
        Ok(state)
    }

    /// Verify every ledger, request, resolution, claim, state, and cross-link.
    ///
    /// Decision verification authenticates Authority's normalized evaluator
    /// attestation and its internal reduction. It does not replay the policy or
    /// mapper artifacts identified by the signed generation.
    ///
    /// Verification requires the database head to equal the durable active
    /// checkpoint owned by this Authority instance.
    pub fn verify_ledger(&self) -> Result<LedgerVerification, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        let verification = self.verify_ready(&tx)?;
        tx.commit()?;
        Ok(verification)
    }

    /// Return one bounded page from a signature-bound ledger snapshot.
    ///
    /// The first call omits `cursor` and fixes the current verified head as the
    /// traversal snapshot. Every continuation cursor is signed with the ledger
    /// key and commits that head plus the next sequence. A later append may grow
    /// the live ledger, but it cannot change the snapshot traversed by the cursor.
    /// Rollback or replacement of any snapshot prefix is rejected. Verification
    /// still walks the complete retained history; this method bounds response
    /// materialization, not the current reference verifier's linear work.
    pub fn ledger_page(
        &self,
        cursor: Option<&SignedLedgerCursorV2>,
        limit: usize,
    ) -> Result<LedgerPageV2, AuthorityError> {
        if limit == 0 || limit > MAX_LEDGER_PAGE_ENTRIES {
            return Err(AuthorityError::InvalidInput(format!(
                "ledger page limit must be between 1 and {MAX_LEDGER_PAGE_ENTRIES}"
            )));
        }
        let verification = self.verify_ledger()?;
        let (snapshot_head_seq, snapshot_head_hash, start_seq, cursor_time_floor) = match cursor {
            Some(signed) => {
                let cursor = signed.verify(&self.ledger_key.verifying_key())?;
                if cursor.authority_instance != self.config.instance_id
                    || cursor.authority_epoch != self.config.epoch
                    || cursor.ledger_key_id != self.ledger_key_id
                {
                    return Err(AuthorityError::InvalidInput(
                        "ledger cursor belongs to another authority".into(),
                    ));
                }
                let snapshot_head = cursor.snapshot_head_seq.parse::<usize>().map_err(|_| {
                    AuthorityError::Corrupt("cursor snapshot head sequence overflow".into())
                })?;
                let Some(snapshot_entry) = verification.entries.get(snapshot_head - 1) else {
                    return Err(AuthorityError::RollbackDetected(format!(
                        "database head {} predates cursor snapshot {}",
                        verification.head_seq, cursor.snapshot_head_seq
                    )));
                };
                if snapshot_entry.entry_hash != cursor.snapshot_head_hash {
                    return Err(AuthorityError::RollbackDetected(
                        "database chain contradicts the signed cursor snapshot".into(),
                    ));
                }
                (
                    cursor.snapshot_head_seq,
                    cursor.snapshot_head_hash,
                    cursor.next_seq.parse::<usize>().map_err(|_| {
                        AuthorityError::Corrupt("cursor next sequence overflow".into())
                    })?,
                    cursor.issued_at,
                )
            }
            None => (
                verification.head_seq.clone(),
                verification.head_hash.clone(),
                1,
                0,
            ),
        };
        let snapshot_head = snapshot_head_seq.parse::<usize>().map_err(|_| {
            AuthorityError::Corrupt("ledger snapshot head sequence overflow".into())
        })?;
        let start_index = start_seq - 1;
        let end_index = start_index.saturating_add(limit).min(snapshot_head);
        let entries = verification.entries[start_index..end_index].to_vec();
        let next_cursor = if end_index < snapshot_head {
            let issued_at = authority_now(self.runtime_source.as_ref())?;
            let evidence_time_floor = verification
                .entries
                .iter()
                .map(|entry| entry.entry.timestamp())
                .max()
                .ok_or_else(|| {
                    AuthorityError::Corrupt("authority ledger has no genesis entry".into())
                })?;
            let required_time_floor = evidence_time_floor.max(cursor_time_floor);
            if issued_at < required_time_floor {
                return Err(AuthorityError::RuntimeSource(format!(
                    "timestamp {issued_at} predates signed evidence time {required_time_floor}"
                )));
            }
            let cursor = LedgerCursorV2 {
                domain: CURSOR_DOMAIN.into(),
                version: FORMAT_VERSION,
                authority_instance: self.config.instance_id.clone(),
                authority_epoch: self.config.epoch.clone(),
                issued_at,
                snapshot_head_seq: snapshot_head_seq.clone(),
                snapshot_head_hash: snapshot_head_hash.clone(),
                next_seq: (end_index + 1).to_string(),
                ledger_key_id: self.ledger_key_id.clone(),
            };
            cursor.validate()?;
            Some(SignedLedgerCursorV2 {
                envelope: sign_payload(EnvelopeDomain::LedgerCursor, &cursor, &self.ledger_key)?,
            })
        } else {
            None
        };
        Ok(LedgerPageV2 {
            entries,
            snapshot_head_seq,
            snapshot_head_hash,
            freshness: verification.freshness,
            next_cursor,
        })
    }
}
