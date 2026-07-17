use super::*;

/// Typed payloads committed by the signed append-only authority ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LedgerPayloadV2 {
    /// Binds the database, schema, keys, build, and cutover boundary.
    Genesis {
        /// Authority instance identifier.
        instance_id: String,
        /// Authority epoch.
        epoch: String,
        /// SQLite schema version.
        schema_version: u8,
        /// Purpose-qualified grant key identifier.
        grant_key_id: String,
        /// Purpose-qualified ledger key identifier.
        ledger_key_id: String,
        /// Gommage core semantic version.
        semantic_version: String,
        /// Immutable release/build/policy/mapper/protocol generation.
        generation: AuthorityGenerationV2,
        /// Explicit migration boundary.
        cutover_marker: String,
    },
    /// Activates one immutable successor generation.
    GenerationActivated {
        /// Previously active generation identifier.
        previous_generation_id: String,
        /// Complete successor generation identity.
        generation: AuthorityGenerationV2,
        /// Maintenance state preserved across activation.
        maintenance: bool,
        /// Authenticated operator principal.
        operator_principal: String,
        /// Operator rationale.
        reason: String,
    },
    /// Enters or exits authoritative fail-closed maintenance.
    MaintenanceChanged {
        /// Complete generation active during the transition.
        generation: AuthorityGenerationV2,
        /// New maintenance state.
        enabled: bool,
        /// Authenticated operator principal.
        operator_principal: String,
        /// Operator rationale.
        reason: String,
    },
    /// Commits one immutable request and its deduplication slot.
    ApprovalRequested {
        /// Request identifier.
        request_id: String,
        /// Immutable request hash.
        request_hash: String,
        /// Open-slot deduplication hash.
        dedupe_hash: String,
    },
    /// Commits the unique terminal resolution of a request.
    ApprovalResolved {
        /// Request identifier.
        request_id: String,
        /// Immutable request hash.
        request_hash: String,
        /// `approved` or `denied`.
        outcome: String,
        /// Grant identifier when approved.
        grant_id: Option<String>,
        /// Signed claim hash when approved.
        claim_hash: Option<String>,
        /// Authenticated operator principal.
        operator_principal: String,
        /// Operator rationale committed with the terminal resolution.
        reason: String,
    },
    /// Commits one signed grant-state revision.
    GrantStateChanged {
        /// Grant identifier.
        grant_id: String,
        /// Signed claim hash.
        claim_hash: String,
        /// Signed state hash.
        state_hash: String,
        /// Decimal state revision.
        revision: String,
        /// New state status.
        status: GrantStatusV2,
        /// Authenticated operator for revocation; absent for activation/spend.
        operator_principal: Option<String>,
        /// Operator rationale for revocation; absent for activation/spend.
        reason: Option<String>,
    },
    /// Commits the allow result whose authorization and state already committed.
    DecisionAllow {
        /// Grant identifier consumed for this allow.
        grant_id: String,
        /// Exact required scope.
        required_scope: String,
        /// Exact complete-input hash.
        input_hash: String,
        /// Complete build/integration/tool/input/policy/capability context.
        context: AuthorizationContextV2,
        /// Exact generation that remained active through commit.
        generation: AuthorityGenerationV2,
        /// Signed spent-state hash.
        state_hash: String,
    },
    /// Commits one normalized result under the exact evaluated generation.
    DecisionRecorded {
        /// Self-contained normalized evaluation and final Authority outcome.
        record: RecordedDecisionV2,
    },
}

impl LedgerPayloadV2 {
    pub(super) fn event_type(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::GenerationActivated { .. } => "generation_activated",
            Self::MaintenanceChanged { enabled: true, .. } => "maintenance_entered",
            Self::MaintenanceChanged { enabled: false, .. } => "maintenance_exited",
            Self::ApprovalRequested { .. } => "approval_requested",
            Self::ApprovalResolved { .. } => "approval_resolved",
            Self::GrantStateChanged {
                status: GrantStatusV2::Active,
                ..
            } => "grant_activated",
            Self::GrantStateChanged {
                status: GrantStatusV2::Spent,
                ..
            } => "grant_spent",
            Self::GrantStateChanged {
                status: GrantStatusV2::Revoked,
                ..
            } => "grant_revoked",
            Self::DecisionAllow { .. } => "decision_allow",
            Self::DecisionRecorded { .. } => "decision_recorded",
        }
    }

    pub(super) fn subject(&self) -> &str {
        match self {
            Self::Genesis { .. }
            | Self::GenerationActivated { .. }
            | Self::MaintenanceChanged { .. } => "authority",
            Self::ApprovalRequested { request_id, .. }
            | Self::ApprovalResolved { request_id, .. } => request_id,
            Self::GrantStateChanged { grant_id, .. } | Self::DecisionAllow { grant_id, .. } => {
                grant_id
            }
            Self::DecisionRecorded { record } => record.context().input_hash(),
        }
    }

    pub(super) fn identity_shape_valid(
        &self,
        build_identity: Option<&str>,
        policy_identity: Option<&str>,
    ) -> bool {
        match self {
            Self::Genesis { generation, .. }
            | Self::GenerationActivated { generation, .. }
            | Self::MaintenanceChanged { generation, .. }
            | Self::DecisionAllow { generation, .. } => {
                build_identity == Some(generation.build_identity())
                    && policy_identity == Some(generation.policy_identity())
            }
            Self::DecisionRecorded { record } => {
                build_identity == Some(record.generation().build_identity())
                    && policy_identity == Some(record.generation().policy_identity())
            }
            Self::ApprovalRequested { .. } | Self::ApprovalResolved { .. } => {
                build_identity.is_some() && policy_identity.is_some()
            }
            Self::GrantStateChanged {
                status: GrantStatusV2::Active | GrantStatusV2::Spent,
                ..
            } => build_identity.is_some() && policy_identity.is_some(),
            Self::GrantStateChanged {
                status: GrantStatusV2::Revoked,
                ..
            } => build_identity.is_some() && policy_identity.is_none(),
        }
    }
}

/// Canonical signed content of one ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntryV2 {
    pub(super) domain: String,
    pub(super) version: u8,
    pub(super) seq: String,
    pub(super) event_id: String,
    pub(super) event_type: String,
    pub(super) subject: String,
    pub(super) timestamp: i64,
    pub(super) previous_hash: String,
    pub(super) build_identity: Option<String>,
    pub(super) policy_identity: Option<String>,
    pub(super) payload: LedgerPayloadV2,
    pub(super) ledger_key_id: String,
}

impl LedgerEntryV2 {
    /// Return the canonical decimal sequence number.
    pub fn seq(&self) -> &str {
        &self.seq
    }

    /// Return the unique event identifier.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Return the event type bound independently from the typed payload.
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Return the event subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Return the event timestamp.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Return the preceding signed entry hash.
    pub fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    /// Return the build identity attached to this event, when applicable.
    pub fn build_identity(&self) -> Option<&str> {
        self.build_identity.as_deref()
    }

    /// Return the policy identity attached to this event, when applicable.
    pub fn policy_identity(&self) -> Option<&str> {
        self.policy_identity.as_deref()
    }

    /// Return the typed event payload.
    pub fn payload(&self) -> &LedgerPayloadV2 {
        &self.payload
    }

    /// Return the purpose-qualified ledger signing key identifier.
    pub fn ledger_key_id(&self) -> &str {
        &self.ledger_key_id
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != LEDGER_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::Corrupt(
                "incorrect ledger domain or version".into(),
            ));
        }
        validate_decimal("ledger sequence", &self.seq)?;
        validate_token("ledger event id", &self.event_id, 160)?;
        validate_text("ledger event type", &self.event_type, 64, false)?;
        validate_text("ledger subject", &self.subject, 256, false)?;
        validate_timestamp(self.timestamp)?;
        validate_hash("previous ledger hash", &self.previous_hash)?;
        if let Some(build) = &self.build_identity {
            validate_text("build identity", build, MAX_IDENTITY_BYTES, false)?;
        }
        if let Some(policy) = &self.policy_identity {
            validate_text("policy identity", policy, MAX_IDENTITY_BYTES, false)?;
        }
        if self.event_type != self.payload.event_type() {
            return Err(AuthorityError::Corrupt(
                "ledger event type does not match typed payload".into(),
            ));
        }
        if self.subject != self.payload.subject()
            || !self.payload.identity_shape_valid(
                self.build_identity.as_deref(),
                self.policy_identity.as_deref(),
            )
        {
            return Err(AuthorityError::Corrupt(
                "ledger subject or build/policy identity shape does not match its payload".into(),
            ));
        }
        match &self.payload {
            LedgerPayloadV2::Genesis { generation, .. }
            | LedgerPayloadV2::GenerationActivated { generation, .. }
            | LedgerPayloadV2::MaintenanceChanged { generation, .. }
            | LedgerPayloadV2::DecisionAllow { generation, .. } => generation.validate()?,
            LedgerPayloadV2::DecisionRecorded { record } => {
                record.validated_evaluation()?;
            }
            LedgerPayloadV2::ApprovalRequested { .. }
            | LedgerPayloadV2::ApprovalResolved { .. }
            | LedgerPayloadV2::GrantStateChanged { .. } => {}
        }
        validate_key_identifier(&self.ledger_key_id, "ledger")?;
        Ok(())
    }
}

impl KeyBound for LedgerEntryV2 {
    fn key_id(&self) -> &str {
        &self.ledger_key_id
    }
}

/// A verified signed ledger row and its signature-inclusive hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLedgerEntryV2 {
    /// Parsed, canonical, signature-verified entry.
    pub entry: LedgerEntryV2,
    /// Canonical envelope retained by the database.
    pub envelope: SignedJcs,
    /// Hash over canonical bytes and raw Ed25519 signature.
    pub entry_hash: String,
}

/// Freshness statement produced by local-chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessVerdict {
    /// A bootstrap/internal verifier has no external rollback anchor.
    ///
    /// Public runtime Authority operations never return this verdict because
    /// they cannot open without a retained checkpoint.
    Unanchored,
    /// The chain contains and extends the supplied trusted checkpoint.
    ///
    /// This proves the prefix through `checkpoint_seq`. A rollback confined to
    /// later entries cannot be detected until a later checkpoint is retained
    /// outside the authority database and admitted by the runtime.
    Anchored {
        /// Trusted external checkpoint sequence.
        checkpoint_seq: String,
    },
}

/// Full-chain verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerVerification {
    /// Every verified entry in increasing sequence order.
    pub entries: Vec<VerifiedLedgerEntryV2>,
    /// Verified database head sequence encoded as decimal text.
    pub head_seq: String,
    /// Verified signature-inclusive database head hash.
    pub head_hash: String,
    /// Explicit bootstrap-only or externally anchored prefix result.
    pub freshness: FreshnessVerdict,
}

/// Signed checkpoint content intended for storage outside the authority database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCheckpointV2 {
    pub(super) domain: String,
    pub(super) version: u8,
    pub(super) checkpoint_id: String,
    pub(super) authority_instance: String,
    pub(super) authority_epoch: String,
    pub(super) created_at: i64,
    pub(super) head_seq: String,
    pub(super) head_hash: String,
    pub(super) ledger_key_id: String,
}

impl LedgerCheckpointV2 {
    /// Return the external checkpoint identifier.
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    /// Return the authority instance committed by the checkpoint.
    pub fn authority_instance(&self) -> &str {
        &self.authority_instance
    }

    /// Return the authority epoch committed by the checkpoint.
    pub fn authority_epoch(&self) -> &str {
        &self.authority_epoch
    }

    /// Return the checkpoint creation timestamp.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Return the checkpointed ledger sequence.
    pub fn head_seq(&self) -> &str {
        &self.head_seq
    }

    /// Return the checkpointed ledger head hash.
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }

    /// Return the purpose-qualified ledger key identifier.
    pub fn ledger_key_id(&self) -> &str {
        &self.ledger_key_id
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != CHECKPOINT_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::Corrupt(
                "incorrect checkpoint domain or version".into(),
            ));
        }
        validate_token("checkpoint id", &self.checkpoint_id, 160)?;
        validate_token("authority instance", &self.authority_instance, 160)?;
        validate_decimal("authority epoch", &self.authority_epoch)?;
        validate_timestamp(self.created_at)?;
        validate_decimal("checkpoint head sequence", &self.head_seq)?;
        validate_hash("checkpoint head hash", &self.head_hash)?;
        validate_key_identifier(&self.ledger_key_id, "ledger")?;
        Ok(())
    }
}

impl KeyBound for LedgerCheckpointV2 {
    fn key_id(&self) -> &str {
        &self.ledger_key_id
    }
}

/// Canonical checkpoint bytes and ledger-purpose signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLedgerCheckpointV2 {
    pub(super) envelope: SignedJcs,
}

impl SignedLedgerCheckpointV2 {
    /// Return the canonical signed checkpoint envelope.
    pub fn envelope(&self) -> &SignedJcs {
        &self.envelope
    }

    /// Reconstruct a stored checkpoint for subsequent verification.
    pub fn from_stored(envelope: SignedJcs) -> Self {
        Self { envelope }
    }

    /// Verify canonical bytes, ledger-key purpose, signature, and checkpoint fields.
    pub fn verify(&self, key: &VerifyingKey) -> Result<LedgerCheckpointV2, AuthorityError> {
        let checkpoint: LedgerCheckpointV2 =
            verify_payload(EnvelopeDomain::LedgerCheckpoint, &self.envelope, key)?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

/// Signed pagination position bound to one verified authority-ledger snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCursorV2 {
    pub(super) domain: String,
    pub(super) version: u8,
    pub(super) authority_instance: String,
    pub(super) authority_epoch: String,
    pub(super) issued_at: i64,
    pub(super) snapshot_head_seq: String,
    pub(super) snapshot_head_hash: String,
    pub(super) next_seq: String,
    pub(super) ledger_key_id: String,
}

impl LedgerCursorV2 {
    /// Return the authority instance that issued this cursor.
    pub fn authority_instance(&self) -> &str {
        &self.authority_instance
    }

    /// Return the authority epoch that issued this cursor.
    pub fn authority_epoch(&self) -> &str {
        &self.authority_epoch
    }

    /// Return when the authority issued this cursor.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Return the immutable snapshot head sequence.
    pub fn snapshot_head_seq(&self) -> &str {
        &self.snapshot_head_seq
    }

    /// Return the immutable snapshot head hash.
    pub fn snapshot_head_hash(&self) -> &str {
        &self.snapshot_head_hash
    }

    /// Return the first sequence requested by the next page.
    pub fn next_seq(&self) -> &str {
        &self.next_seq
    }

    /// Return the purpose-qualified ledger key identifier.
    pub fn ledger_key_id(&self) -> &str {
        &self.ledger_key_id
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != CURSOR_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::Corrupt(
                "incorrect ledger cursor domain or version".into(),
            ));
        }
        validate_token("authority instance", &self.authority_instance, 160)?;
        validate_decimal("authority epoch", &self.authority_epoch)?;
        validate_timestamp(self.issued_at)?;
        validate_decimal("cursor snapshot head sequence", &self.snapshot_head_seq)?;
        validate_hash("cursor snapshot head hash", &self.snapshot_head_hash)?;
        validate_decimal("cursor next sequence", &self.next_seq)?;
        validate_key_identifier(&self.ledger_key_id, "ledger")?;
        let head = self.snapshot_head_seq.parse::<u64>().map_err(|_| {
            AuthorityError::Corrupt("cursor snapshot head sequence overflow".into())
        })?;
        let next = self
            .next_seq
            .parse::<u64>()
            .map_err(|_| AuthorityError::Corrupt("cursor next sequence overflow".into()))?;
        if head == 0 || next == 0 || next > head {
            return Err(AuthorityError::Corrupt(
                "cursor sequence range is invalid".into(),
            ));
        }
        Ok(())
    }
}

impl KeyBound for LedgerCursorV2 {
    fn key_id(&self) -> &str {
        &self.ledger_key_id
    }
}

/// Canonical ledger cursor plus its ledger-purpose signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLedgerCursorV2 {
    pub(super) envelope: SignedJcs,
}

impl SignedLedgerCursorV2 {
    /// Return the canonical signed cursor envelope.
    pub fn envelope(&self) -> &SignedJcs {
        &self.envelope
    }

    /// Reconstruct a stored cursor before verification.
    pub fn from_stored(envelope: SignedJcs) -> Self {
        Self { envelope }
    }

    /// Verify canonical bytes, ledger-key purpose, signature, and cursor fields.
    pub fn verify(&self, key: &VerifyingKey) -> Result<LedgerCursorV2, AuthorityError> {
        let cursor: LedgerCursorV2 =
            verify_payload(EnvelopeDomain::LedgerCursor, &self.envelope, key)?;
        cursor.validate()?;
        Ok(cursor)
    }
}

/// Bounded, verified page from one immutable ledger snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerPageV2 {
    /// Verified entries in increasing sequence order, never above the page limit.
    pub entries: Vec<VerifiedLedgerEntryV2>,
    /// Snapshot head sequence shared by every page in this traversal.
    pub snapshot_head_seq: String,
    /// Snapshot head hash shared by every page in this traversal.
    pub snapshot_head_hash: String,
    /// Local-only or externally anchored freshness verdict for the current store.
    pub freshness: FreshnessVerdict,
    /// Signed continuation cursor, absent when the snapshot is exhausted.
    pub next_cursor: Option<SignedLedgerCursorV2>,
}
