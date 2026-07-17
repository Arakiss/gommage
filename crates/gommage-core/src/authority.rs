//! Transactional Authority v2 for the reference security profile.
//!
//! One SQLite writer boundary owns the active release/policy/mapper/protocol
//! generation, fail-closed maintenance, approval deduplication, exact single-use
//! grants, state transitions, and signed decision evidence. Every mutation is
//! serialized by `BEGIN IMMEDIATE` and returns an authorization result only after
//! the corresponding state and ledger entries commit.

use crate::{
    crypto_envelope::{
        CryptoEnvelopeError, EnvelopeDomain, KeyBound, KeyPurpose, SignedJcs, approval_dedupe_hash,
        approval_request_hash, canonicalize, decode_canonical, key_id, ledger_entry_hash,
        sign_payload, signature_bytes, verify_payload,
    },
    grant_v2::{
        GrantClaimFields, GrantClaimV2, GrantStateV2, GrantStatusV2, GrantV2Error,
        MAX_GRANT_TTL_SECONDS, SignedGrantClaimV2, SignedGrantStateV2, validate_decimal,
        validate_hash, validate_text, validate_token,
    },
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};
use thiserror::Error;

const APPLICATION_ID: i32 = 0x474f_4d32; // ASCII "GOM2".
const SCHEMA_VERSION: i32 = 2;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const REQUEST_DOMAIN: &str = "gommage.approval.request";
const GENERATION_DOMAIN: &str = "gommage.authority.generation";
const LEDGER_DOMAIN: &str = "gommage.ledger.entry";
const CHECKPOINT_DOMAIN: &str = "gommage.ledger.checkpoint";
const FORMAT_VERSION: u8 = 2;
const MAX_INTEGRATION_BYTES: usize = 128;
const MAX_TOOL_BYTES: usize = 256;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_CAPABILITY_BYTES: usize = 1_024;
const MAX_CAPABILITIES: usize = 512;
const CUTOVER_MARKER: &str = "fresh_v2_no_legacy_active_grants";

/// Immutable identities selected together as one authority generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGenerationV2 {
    domain: String,
    version: u8,
    generation_id: String,
    release_identity: String,
    build_identity: String,
    policy_identity: String,
    mapper_identity: String,
    protocol_identity: String,
}

impl AuthorityGenerationV2 {
    /// Construct one bounded canonical generation identity.
    pub fn new(
        generation_id: String,
        release_identity: String,
        build_identity: String,
        policy_identity: String,
        mapper_identity: String,
        protocol_identity: String,
    ) -> Result<Self, AuthorityError> {
        let generation = Self {
            domain: GENERATION_DOMAIN.into(),
            version: FORMAT_VERSION,
            generation_id,
            release_identity,
            build_identity,
            policy_identity,
            mapper_identity,
            protocol_identity,
        };
        generation.validate()?;
        Ok(generation)
    }

    /// Return the monotonic canonical generation identifier.
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Return the immutable release identity.
    pub fn release_identity(&self) -> &str {
        &self.release_identity
    }

    /// Return the immutable build identity.
    pub fn build_identity(&self) -> &str {
        &self.build_identity
    }

    /// Return the immutable policy semantic identity.
    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    /// Return the immutable mapper semantic identity.
    pub fn mapper_identity(&self) -> &str {
        &self.mapper_identity
    }

    /// Return the immutable managed protocol identity.
    pub fn protocol_identity(&self) -> &str {
        &self.protocol_identity
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != GENERATION_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::InvalidInput(
                "incorrect authority generation domain or version".into(),
            ));
        }
        validate_decimal("generation id", &self.generation_id)?;
        validate_text(
            "release identity",
            &self.release_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        validate_text(
            "generation build identity",
            &self.build_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        validate_text(
            "generation policy identity",
            &self.policy_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        validate_text(
            "mapper identity",
            &self.mapper_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        validate_text(
            "protocol identity",
            &self.protocol_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        Ok(())
    }
}

/// Fixed metadata supplied when a v2 authority is first created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfig {
    /// Stable identifier for this authority installation.
    pub instance_id: String,
    /// Monotonic installation epoch encoded as canonical decimal text.
    pub epoch: String,
    /// Immutable generation activated by genesis.
    pub genesis_generation: AuthorityGenerationV2,
    /// Deterministic ledger event identifier for genesis.
    pub genesis_event_id: String,
    /// Unix timestamp recorded on the genesis event.
    pub genesis_at: i64,
}

impl AuthorityConfig {
    /// Validate configuration before any database is created or opened.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_token("authority instance", &self.instance_id, 160)?;
        validate_decimal("authority epoch", &self.epoch)?;
        self.genesis_generation.validate()?;
        validate_token("genesis event id", &self.genesis_event_id, 160)?;
        validate_timestamp(self.genesis_at)?;
        Ok(())
    }
}

/// Migration boundary exposed to later control-plane integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverStateV2 {
    /// This database was created as v2 and contains no imported active v1 grant.
    FreshV2NoLegacyActiveGrants,
}

/// Verified metadata for an opened Authority v2 database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityMetadata {
    /// Schema version, currently two.
    pub schema_version: i32,
    /// Stable authority instance identifier.
    pub instance_id: String,
    /// Authority epoch encoded as decimal text.
    pub epoch: String,
    /// Purpose-qualified grant key identifier.
    pub grant_key_id: String,
    /// Purpose-qualified ledger key identifier.
    pub ledger_key_id: String,
    /// Immutable generation bound by genesis.
    pub genesis_generation: AuthorityGenerationV2,
    /// Explicit v1-to-v2 cutover state.
    pub cutover: CutoverStateV2,
}

/// Complete immutable fields for one approval request creation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequestCommand {
    /// Caller-generated unique request identifier.
    pub request_id: String,
    /// Caller-generated event identifier for the signed request event.
    pub event_id: String,
    /// Unix timestamp for request creation.
    pub created_at: i64,
    /// Complete immutable authorization context observed by the integration.
    pub context: AuthorizationContextV2,
    /// Exact active generation against which the decision was evaluated.
    pub generation: AuthorityGenerationV2,
    /// Exact approval scope required by policy.
    pub required_scope: String,
    /// Human-readable reason shown to an operator.
    pub reason: String,
}

/// Immutable context that an approval and its eventual consumption are bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContextV2 {
    build_identity: String,
    integration: String,
    tool: String,
    input_hash: String,
    policy_identity: String,
    capabilities: Vec<String>,
}

impl AuthorizationContextV2 {
    /// Construct and normalize a bounded authorization context.
    pub fn new(
        build_identity: String,
        integration: String,
        tool: String,
        input_hash: String,
        policy_identity: String,
        mut capabilities: Vec<String>,
    ) -> Result<Self, AuthorityError> {
        capabilities.sort();
        capabilities.dedup();
        let context = Self {
            build_identity,
            integration,
            tool,
            input_hash,
            policy_identity,
            capabilities,
        };
        context.validate()?;
        Ok(context)
    }

    /// Return the build that observed and mapped the request.
    pub fn build_identity(&self) -> &str {
        &self.build_identity
    }

    /// Return the named host integration.
    pub fn integration(&self) -> &str {
        &self.integration
    }

    /// Return the exact host tool name.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Return the canonical complete-input hash.
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }

    /// Return the exact evaluated policy identity.
    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    /// Return the sorted, unique relevant capability set.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        validate_text(
            "build identity",
            &self.build_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        validate_text(
            "integration",
            &self.integration,
            MAX_INTEGRATION_BYTES,
            false,
        )?;
        validate_text("tool", &self.tool, MAX_TOOL_BYTES, false)?;
        validate_hash("input hash", &self.input_hash)?;
        validate_text(
            "policy identity",
            &self.policy_identity,
            MAX_IDENTITY_BYTES,
            false,
        )?;
        if self.capabilities.is_empty()
            || self.capabilities.len() > MAX_CAPABILITIES
            || self.capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthorityError::InvalidInput(
                "capabilities are not sorted, unique, and bounded".into(),
            ));
        }
        for capability in &self.capabilities {
            validate_text("capability", capability, MAX_CAPABILITY_BYTES, false)?;
        }
        Ok(())
    }
}

/// An immutable v2 approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequestV2 {
    domain: String,
    version: u8,
    request_id: String,
    created_at: i64,
    context: AuthorizationContextV2,
    generation: AuthorityGenerationV2,
    required_scope: String,
    reason: String,
}

impl ApprovalRequestV2 {
    /// Return the request identifier.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Return the request creation timestamp.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Return the complete immutable authorization context.
    pub fn context(&self) -> &AuthorizationContextV2 {
        &self.context
    }

    /// Return the exact authority generation evaluated for this request.
    pub fn generation(&self) -> &AuthorityGenerationV2 {
        &self.generation
    }

    /// Return the build that observed and mapped the request.
    pub fn build_identity(&self) -> &str {
        self.context.build_identity()
    }

    /// Return the named host integration.
    pub fn integration(&self) -> &str {
        self.context.integration()
    }

    /// Return the host tool name.
    pub fn tool(&self) -> &str {
        self.context.tool()
    }

    /// Return the canonical complete-input hash.
    pub fn input_hash(&self) -> &str {
        self.context.input_hash()
    }

    /// Return the exact approval scope.
    pub fn required_scope(&self) -> &str {
        &self.required_scope
    }

    /// Return the evaluated policy identity.
    pub fn policy_identity(&self) -> &str {
        self.context.policy_identity()
    }

    /// Return the sorted, unique relevant capabilities.
    pub fn capabilities(&self) -> &[String] {
        self.context.capabilities()
    }

    /// Return the operator-facing request reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn from_command(command: &CreateRequestCommand) -> Result<Self, AuthorityError> {
        let request = Self {
            domain: REQUEST_DOMAIN.into(),
            version: FORMAT_VERSION,
            request_id: command.request_id.clone(),
            created_at: command.created_at,
            context: command.context.clone(),
            generation: command.generation.clone(),
            required_scope: command.required_scope.clone(),
            reason: command.reason.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != REQUEST_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::InvalidInput(
                "incorrect approval request domain or version".into(),
            ));
        }
        validate_token("request id", &self.request_id, 160)?;
        validate_timestamp(self.created_at)?;
        self.context.validate()?;
        self.generation.validate()?;
        if self.context.build_identity() != self.generation.build_identity()
            || self.context.policy_identity() != self.generation.policy_identity()
        {
            return Err(AuthorityError::InvalidInput(
                "authorization context does not match its declared generation".into(),
            ));
        }
        validate_text("required scope", &self.required_scope, 512, false)?;
        validate_text("reason", &self.reason, 1_024, true)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDedupeV2<'a> {
    domain: &'static str,
    version: u8,
    context: &'a AuthorizationContextV2,
    generation: &'a AuthorityGenerationV2,
    required_scope: &'a str,
}

/// Result of creating or deduplicating an open approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateRequestResult {
    /// A new immutable request and signed ledger event committed.
    Created(ApprovalRequestV2),
    /// An equivalent open request already existed and was returned unchanged.
    Existing(ApprovalRequestV2),
}

/// Final approval resolution kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResolutionKindV2 {
    /// The operator approved and atomically created an active grant.
    Approved,
    /// The operator denied without creating a grant.
    Denied,
}

impl ApprovalResolutionKindV2 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

/// Immutable resolution of one v2 approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalResolutionV2 {
    /// Resolved request identifier.
    pub request_id: String,
    /// Winning terminal outcome.
    pub kind: ApprovalResolutionKindV2,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator rationale.
    pub reason: String,
    /// Resolution timestamp.
    pub resolved_at: i64,
    /// Grant identifier for an approved request.
    pub grant_id: Option<String>,
    /// Signed ledger event that records the resolution.
    pub event_id: String,
}

/// Fields required to approve one open request and create its sole v2 grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveCommand {
    /// Open request identifier.
    pub request_id: String,
    /// Unique grant identifier.
    pub grant_id: String,
    /// Approval resolution event identifier.
    pub resolution_event_id: String,
    /// Active-state transition event identifier.
    pub activation_event_id: String,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator approval rationale.
    pub reason: String,
    /// Resolution and grant issue timestamp.
    pub resolved_at: i64,
    /// Bounded grant lifetime in seconds.
    pub ttl_seconds: i64,
}

/// Result of an approval attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveResult {
    /// This caller won resolution and committed exactly one active grant.
    Approved {
        /// Signed immutable grant claim.
        claim: SignedGrantClaimV2,
        /// Signed active state at revision zero.
        state: SignedGrantStateV2,
    },
    /// Another serialized operation had already resolved the request.
    AlreadyResolved(ApprovalResolutionV2),
}

/// Fields required to deny one open request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyCommand {
    /// Open request identifier.
    pub request_id: String,
    /// Unique denial ledger event identifier.
    pub event_id: String,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator denial rationale.
    pub reason: String,
    /// Resolution timestamp.
    pub resolved_at: i64,
}

/// Result of a denial attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyResult {
    /// This caller won resolution and committed a denial.
    Denied(ApprovalResolutionV2),
    /// Another serialized operation had already resolved the request.
    AlreadyResolved(ApprovalResolutionV2),
}

/// Fields required to atomically consume a grant and record an allow decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumeCommand {
    /// Exact approval scope required by the current decision.
    pub required_scope: String,
    /// Complete current context, which must equal the approved request context.
    pub context: AuthorizationContextV2,
    /// Exact active generation against which the decision was evaluated.
    pub generation: AuthorityGenerationV2,
    /// State-transition ledger event identifier.
    pub state_event_id: String,
    /// Final allow-decision ledger event identifier.
    pub decision_event_id: String,
    /// Current Unix timestamp.
    pub consumed_at: i64,
}

/// Administrative activation of one immutable successor generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateGenerationCommand {
    /// Complete successor generation identity.
    pub generation: AuthorityGenerationV2,
    /// Signed-ledger event identifier.
    pub event_id: String,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator rationale.
    pub reason: String,
    /// Activation timestamp.
    pub activated_at: i64,
}

/// Administrative transition into or out of fail-closed maintenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetMaintenanceCommand {
    /// `true` enters maintenance; `false` exits it.
    pub enabled: bool,
    /// Signed-ledger event identifier.
    pub event_id: String,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator rationale.
    pub reason: String,
    /// Transition timestamp.
    pub transitioned_at: i64,
}

/// Fully verified current generation and maintenance state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRuntimeStateV2 {
    revision: String,
    active_generation: AuthorityGenerationV2,
    maintenance: bool,
    transition_event_id: String,
    transitioned_at: i64,
}

impl AuthorityRuntimeStateV2 {
    /// Return the append-only runtime-state revision.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Return the currently active immutable generation.
    pub fn active_generation(&self) -> &AuthorityGenerationV2 {
        &self.active_generation
    }

    /// Return whether decision admission is fail-closed for maintenance.
    pub fn maintenance(&self) -> bool {
        self.maintenance
    }

    /// Return the signed ledger event that created this revision.
    pub fn transition_event_id(&self) -> &str {
        &self.transition_event_id
    }

    /// Return the transition timestamp.
    pub fn transitioned_at(&self) -> i64 {
        self.transitioned_at
    }
}

/// Why a syntactically valid consume request did not authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantNotUsableReason {
    /// No currently usable grant matches the exact context and required scope.
    Missing,
    /// The latest state is spent or revoked.
    Terminal,
    /// The grant is not valid yet.
    NotYetValid,
    /// The grant has expired.
    Expired,
    /// The required scope differs from the approved scope.
    ScopeMismatch,
    /// The complete input hash differs from the approved hash.
    InputMismatch,
    /// The build identity differs from the build that requested approval.
    BuildIdentityMismatch,
    /// The host integration differs from the approved integration.
    IntegrationMismatch,
    /// The host tool differs from the approved tool.
    ToolMismatch,
    /// The evaluated policy differs from the approved policy identity.
    PolicyMismatch,
    /// The normalized relevant capability set differs from the approved set.
    CapabilityMismatch,
}

/// Result of a consume-and-record transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    /// State revision one and the final allow evidence committed atomically.
    Consumed {
        /// Signed terminal spent state.
        state: SignedGrantStateV2,
        /// Signed allow-decision event identifier.
        decision_event_id: String,
    },
    /// No authorization occurred and no allow evidence was emitted.
    NotUsable(GrantNotUsableReason),
}

/// Fields required to revoke an active grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeCommand {
    /// Grant identifier.
    pub grant_id: String,
    /// Revocation/state-transition event identifier.
    pub event_id: String,
    /// Authenticated operator principal.
    pub operator_principal: String,
    /// Operator revocation rationale.
    pub reason: String,
    /// Revocation timestamp.
    pub revoked_at: i64,
    /// Build identity executing the revocation transaction.
    pub build_identity: String,
}

/// Result of a revoke attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeResult {
    /// A signed terminal revoked state committed.
    Revoked(SignedGrantStateV2),
    /// The grant was absent or already terminal.
    NotUsable(GrantNotUsableReason),
}

/// Typed payloads committed by the signed append-only authority ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
}

impl LedgerPayloadV2 {
    fn event_type(&self) -> &'static str {
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
        }
    }

    fn subject(&self) -> &str {
        match self {
            Self::Genesis { .. }
            | Self::GenerationActivated { .. }
            | Self::MaintenanceChanged { .. } => "authority",
            Self::ApprovalRequested { request_id, .. }
            | Self::ApprovalResolved { request_id, .. } => request_id,
            Self::GrantStateChanged { grant_id, .. } | Self::DecisionAllow { grant_id, .. } => {
                grant_id
            }
        }
    }

    fn identity_shape_valid(
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
    domain: String,
    version: u8,
    seq: String,
    event_id: String,
    event_type: String,
    subject: String,
    timestamp: i64,
    previous_hash: String,
    build_identity: Option<String>,
    policy_identity: Option<String>,
    payload: LedgerPayloadV2,
    ledger_key_id: String,
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

    fn validate(&self) -> Result<(), AuthorityError> {
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
    /// The local chain is internally valid but has no external rollback anchor.
    Unanchored,
    /// The chain contains and extends the supplied trusted checkpoint.
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
    /// Explicit local-only or externally anchored freshness result.
    pub freshness: FreshnessVerdict,
}

/// Signed checkpoint content intended for storage outside the authority database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCheckpointV2 {
    domain: String,
    version: u8,
    checkpoint_id: String,
    authority_instance: String,
    authority_epoch: String,
    created_at: i64,
    head_seq: String,
    head_hash: String,
    ledger_key_id: String,
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

    fn validate(&self) -> Result<(), AuthorityError> {
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
    envelope: SignedJcs,
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

/// Integrity, schema, cryptographic, and invalid-command failures.
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// SQLite failed or rejected a constrained write.
    #[error("sqlite authority error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Canonical envelope parsing or signature verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoEnvelopeError),
    /// Grant claim/state validation or verification failed.
    #[error(transparent)]
    Grant(#[from] GrantV2Error),
    /// A caller command violates the bounded Authority v2 contract.
    #[error("invalid authority input: {0}")]
    InvalidInput(String),
    /// Stored rows, hashes, signatures, or links are inconsistent.
    #[error("authority integrity failure: {0}")]
    Corrupt(String),
    /// The database predates or contradicts a trusted external checkpoint.
    #[error("authority rollback detected: {0}")]
    RollbackDetected(String),
    /// The file is not the supported Authority v2 schema.
    #[error("unsupported authority schema: {0}")]
    Schema(String),
    /// A decision was evaluated against a generation that is no longer active.
    #[error(
        "stale authority generation: evaluated {evaluated_generation_id}, active {active_generation_id}"
    )]
    StaleGeneration {
        /// Generation declared by the decision.
        evaluated_generation_id: String,
        /// Generation active at the serialized admission point.
        active_generation_id: String,
    },
    /// Decision admission is disabled by authoritative maintenance state.
    #[error("authority decisions are disabled during maintenance")]
    Maintenance,
}

/// File-backed reference-profile authorization authority.
///
/// Every mutation verifies the full signed history before writing, so mutation
/// cost is linear in ledger length. This favors a simple fail-closed reference
/// boundary; long-lived deployments should benchmark and later add verified
/// checkpoints or incremental proof caching without weakening the invariant.
pub struct Authority {
    conn: Connection,
    config: AuthorityConfig,
    grant_key: SigningKey,
    ledger_key: SigningKey,
    grant_key_id: String,
    ledger_key_id: String,
}

impl Authority {
    /// Open or initialize a file-backed Authority v2 database.
    ///
    /// Keys and paths are supplied by the managed control plane; the core never
    /// reads shared legacy key files or infers filesystem ownership.
    pub fn open(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
    ) -> Result<Self, AuthorityError> {
        config.validate()?;
        let path_text = path.to_string_lossy();
        if path.as_os_str().is_empty() || path_text == ":memory:" || path_text.starts_with("file:")
        {
            return Err(AuthorityError::InvalidInput(
                "reference authority requires a regular file path".into(),
            ));
        }
        if grant_key.verifying_key() == ledger_key.verifying_key() {
            return Err(AuthorityError::InvalidInput(
                "grant and ledger keys must be distinct".into(),
            ));
        }
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let mut conn = Connection::open(path)?;
        configure_connection(&conn)?;
        let current_application_id: i32 =
            conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let current_user_version: i32 =
            conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current_application_id == 0 && current_user_version == 0 {
            initialize_schema(
                &mut conn,
                &config,
                &grant_key_id,
                &ledger_key_id,
                &ledger_key,
            )?;
        } else if current_application_id != APPLICATION_ID || current_user_version != SCHEMA_VERSION
        {
            return Err(AuthorityError::Schema(format!(
                "expected application_id {APPLICATION_ID} and user_version {SCHEMA_VERSION}, got {current_application_id} and {current_user_version}"
            )));
        }
        let authority = Self {
            conn,
            config,
            grant_key,
            ledger_key,
            grant_key_id,
            ledger_key_id,
        };
        authority.verify_metadata()?;
        authority.verify_ledger(None)?;
        Ok(authority)
    }

    /// Return verified schema, key, instance, and migration-boundary metadata.
    pub fn metadata(&self) -> Result<AuthorityMetadata, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
        let metadata = read_metadata(&tx)?;
        tx.commit()?;
        Ok(metadata)
    }

    fn verify_metadata(&self) -> Result<(), AuthorityError> {
        verify_pragmas(&self.conn)?;
        let metadata = read_metadata(&self.conn)?;
        if metadata.instance_id != self.config.instance_id
            || metadata.epoch != self.config.epoch
            || metadata.genesis_generation != self.config.genesis_generation
            || metadata.grant_key_id != self.grant_key_id
            || metadata.ledger_key_id != self.ledger_key_id
            || metadata.cutover != CutoverStateV2::FreshV2NoLegacyActiveGrants
        {
            return Err(AuthorityError::Corrupt(
                "opened metadata does not match supplied instance, build, cutover, or keys".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StoredRequest {
    request: ApprovalRequestV2,
    request_hash: String,
    dedupe_hash: String,
    event_id: String,
}

#[derive(Debug)]
struct AllowEvidenceLink {
    seq: usize,
    timestamp: i64,
    build_identity: Option<String>,
    policy_identity: Option<String>,
    grant_id: String,
    required_scope: String,
    input_hash: String,
    context: AuthorizationContextV2,
    generation: AuthorityGenerationV2,
}

#[derive(Debug, Clone)]
struct LedgerEventLink {
    seq: usize,
    timestamp: i64,
    build_identity: Option<String>,
    policy_identity: Option<String>,
    payload: LedgerPayloadV2,
}

#[derive(Debug, Clone)]
struct StoredGeneration {
    generation: AuthorityGenerationV2,
    event_id: String,
    activated_at: i64,
}

#[derive(Debug)]
struct VerifiedRuntimeTimeline {
    transition_events: HashSet<String>,
    transitions: Vec<(usize, AuthorityRuntimeStateV2)>,
}

impl VerifiedRuntimeTimeline {
    fn state_at(&self, ledger_seq: usize) -> Option<&AuthorityRuntimeStateV2> {
        self.transitions
            .iter()
            .rev()
            .find(|(transition_seq, _)| *transition_seq <= ledger_seq)
            .map(|(_, state)| state)
    }
}

fn read_metadata(conn: &Connection) -> Result<AuthorityMetadata, AuthorityError> {
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

fn load_generation(
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

fn load_runtime_states(conn: &Connection) -> Result<Vec<AuthorityRuntimeStateV2>, AuthorityError> {
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

fn load_current_runtime_state(
    conn: &Connection,
) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
    load_runtime_states(conn)?
        .pop()
        .ok_or_else(|| AuthorityError::Corrupt("authority runtime state is missing".into()))
}

fn insert_generation(
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

fn insert_runtime_state(
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

fn generation_id_is_newer(candidate: &str, active: &str) -> bool {
    candidate.len() > active.len() || (candidate.len() == active.len() && candidate > active)
}

fn ensure_decision_admitted(
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

fn validate_context_generation(
    context: &AuthorizationContextV2,
    generation: &AuthorityGenerationV2,
) -> Result<(), AuthorityError> {
    context.validate()?;
    generation.validate()?;
    if context.build_identity() != generation.build_identity()
        || context.policy_identity() != generation.policy_identity()
    {
        return Err(AuthorityError::InvalidInput(
            "authorization context does not match its declared generation".into(),
        ));
    }
    Ok(())
}

fn next_runtime_revision(current: &AuthorityRuntimeStateV2) -> Result<i64, AuthorityError> {
    current
        .revision
        .parse::<i64>()
        .map_err(|_| AuthorityError::Corrupt("runtime-state revision is not an integer".into()))?
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Corrupt("runtime-state revision overflow".into()))
}

fn validate_admin_transition(
    event_id: &str,
    operator_principal: &str,
    reason: &str,
    timestamp: i64,
) -> Result<(), AuthorityError> {
    validate_token("administrative event id", event_id, 160)?;
    validate_text("operator principal", operator_principal, 256, false)?;
    validate_text("administrative reason", reason, 1_024, true)?;
    validate_timestamp(timestamp)?;
    Ok(())
}

struct LedgerEventDraft {
    event_id: String,
    subject: String,
    timestamp: i64,
    build_identity: Option<String>,
    policy_identity: Option<String>,
    payload: LedgerPayloadV2,
}

fn append_ledger_entry(
    conn: &Connection,
    ledger_key: &SigningKey,
    draft: LedgerEventDraft,
) -> Result<VerifiedLedgerEntryV2, AuthorityError> {
    validate_token("ledger event id", &draft.event_id, 160)?;
    validate_text("ledger subject", &draft.subject, 256, false)?;
    validate_timestamp(draft.timestamp)?;
    let (head_seq, previous_hash): (i64, String) = conn.query_row(
        "SELECT head_seq, head_hash FROM authority_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let seq = head_seq
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Corrupt("ledger sequence overflow".into()))?;
    let entry = LedgerEntryV2 {
        domain: LEDGER_DOMAIN.into(),
        version: FORMAT_VERSION,
        seq: seq.to_string(),
        event_id: draft.event_id,
        event_type: draft.payload.event_type().into(),
        subject: draft.subject,
        timestamp: draft.timestamp,
        previous_hash: previous_hash.clone(),
        build_identity: draft.build_identity,
        policy_identity: draft.policy_identity,
        payload: draft.payload,
        ledger_key_id: key_id(KeyPurpose::Ledger, &ledger_key.verifying_key()),
    };
    entry.validate()?;
    let envelope = sign_payload(EnvelopeDomain::LedgerEntry, &entry, ledger_key)?;
    let raw_signature = signature_bytes(envelope.signature_b64())?;
    let entry_hash = ledger_entry_hash(envelope.jcs().as_bytes(), &raw_signature);
    conn.execute(
        "INSERT INTO ledger_entries (seq, event_id, entry_jcs, signature_b64, entry_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            seq,
            entry.event_id(),
            envelope.jcs(),
            envelope.signature_b64(),
            entry_hash,
        ],
    )?;
    let updated = conn.execute(
        "UPDATE authority_meta SET head_seq = ?1, head_hash = ?2
         WHERE singleton = 1 AND head_seq = ?3 AND head_hash = ?4",
        params![seq, entry_hash, head_seq, previous_hash],
    )?;
    if updated != 1 {
        return Err(AuthorityError::Corrupt(
            "ledger head changed outside the serialized transaction".into(),
        ));
    }
    Ok(VerifiedLedgerEntryV2 {
        entry,
        envelope,
        entry_hash,
    })
}

fn load_request(
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
            let dedupe_jcs = canonicalize(&ApprovalDedupeV2 {
                domain: "gommage.approval.dedupe",
                version: FORMAT_VERSION,
                context: request.context(),
                generation: request.generation(),
                required_scope: request.required_scope(),
            })?;
            if approval_dedupe_hash(&dedupe_jcs) != dedupe_hash {
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

fn load_resolution(
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

fn ensure_request_is_open(
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

fn load_claim(
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

fn load_latest_state(
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

fn insert_state(
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

fn status_string(status: GrantStatusV2) -> &'static str {
    match status {
        GrantStatusV2::Active => "active",
        GrantStatusV2::Spent => "spent",
        GrantStatusV2::Revoked => "revoked",
    }
}

fn state_actor_fields_match(
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

fn validate_approval_actor(
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

fn validate_timestamp(timestamp: i64) -> Result<(), AuthorityError> {
    if timestamp.unsigned_abs() > crate::crypto_envelope::MAX_SAFE_INTEGER {
        return Err(AuthorityError::InvalidInput(
            "timestamp exceeds the I-JSON safe integer range".into(),
        ));
    }
    Ok(())
}

fn validate_key_identifier(value: &str, purpose: &str) -> Result<(), AuthorityError> {
    let prefix = format!("{purpose}:sha256:");
    let Some(fingerprint) = value.strip_prefix(&prefix) else {
        return Err(AuthorityError::Corrupt(
            "key identifier has incorrect purpose".into(),
        ));
    };
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AuthorityError::Corrupt(
            "key identifier fingerprint is not canonical".into(),
        ));
    }
    Ok(())
}

fn verify_all(
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
    let raw_rows = {
        let mut statement = conn.prepare(
            "SELECT seq, event_id, entry_jcs, signature_b64, entry_hash
             FROM ledger_entries ORDER BY seq ASC",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if raw_rows.is_empty() {
        return Err(AuthorityError::Corrupt(
            "ledger is missing its genesis entry".into(),
        ));
    }
    let mut entries = Vec::with_capacity(raw_rows.len());
    let mut previous_hash = ZERO_HASH.to_string();
    for (index, (stored_seq, stored_event_id, jcs, signature_b64, stored_hash)) in
        raw_rows.into_iter().enumerate()
    {
        let expected_seq = i64::try_from(index + 1)
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
            if entries[checkpoint_seq - 1].entry_hash != checkpoint.head_hash {
                return Err(AuthorityError::RollbackDetected(
                    "database chain contradicts the trusted checkpoint hash".into(),
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

    let decisions_by_state: HashMap<String, Vec<AllowEvidenceLink>> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, verified)| match verified.entry.payload() {
            LedgerPayloadV2::DecisionAllow {
                grant_id,
                required_scope,
                input_hash,
                context,
                generation,
                state_hash,
            } => Some((
                state_hash.clone(),
                AllowEvidenceLink {
                    seq: index + 1,
                    timestamp: verified.entry.timestamp(),
                    build_identity: verified.entry.build_identity().map(str::to_owned),
                    policy_identity: verified.entry.policy_identity().map(str::to_owned),
                    grant_id: grant_id.clone(),
                    required_scope: required_scope.clone(),
                    input_hash: input_hash.clone(),
                    context: context.clone(),
                    generation: generation.clone(),
                },
            )),
            _ => None,
        })
        .fold(HashMap::new(), |mut map, (hash, decision)| {
            map.entry(hash).or_default().push(decision);
            map
        });

    for (grant_id, (signed_claim, claim)) in &claims {
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
                        || decisions[0].timestamp != terminal.transitioned_at()
                        || decisions[0].grant_id != *grant_id
                        || decisions[0].required_scope != claim.required_scope()
                        || decisions[0].input_hash != claim.input_hash()
                        || &decisions[0].context
                            != requests
                                .get(claim.approval_request_id())
                                .ok_or_else(|| {
                                    AuthorityError::Corrupt(
                                        "allow decision approval request is missing".into(),
                                    )
                                })?
                                .request
                                .context()
                        || &decisions[0].generation
                            != requests
                                .get(claim.approval_request_id())
                                .ok_or_else(|| {
                                    AuthorityError::Corrupt(
                                        "allow decision approval request is missing".into(),
                                    )
                                })?
                                .request
                                .generation()
                        || runtime.state_at(decisions[0].seq).is_none_or(|state| {
                            state.maintenance || state.active_generation != decisions[0].generation
                        })
                        || decisions[0].build_identity.as_deref()
                            != Some(decisions[0].context.build_identity())
                        || decisions[0].policy_identity.as_deref()
                            != Some(decisions[0].context.policy_identity())
                        || decisions[0].seq != terminal_seq.saturating_add(1)
                    {
                        return Err(AuthorityError::Corrupt(
                            "allow evidence does not exactly and consecutively follow spent state"
                                .into(),
                        ));
                    }
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
            LedgerPayloadV2::DecisionAllow { state_hash, .. } => {
                decisions_by_state.contains_key(state_hash)
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

fn query_strings(conn: &Connection, sql: &str) -> Result<Vec<String>, AuthorityError> {
    let mut statement = conn.prepare(sql)?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?)
}

fn configure_connection(conn: &Connection) -> Result<(), AuthorityError> {
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

fn verify_pragmas(conn: &Connection) -> Result<(), AuthorityError> {
    let journal: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i32 = conn.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let foreign_keys: i32 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let trusted_schema: i32 = conn.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let application_id: i32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || application_id != APPLICATION_ID
        || user_version != SCHEMA_VERSION
    {
        return Err(AuthorityError::Schema(format!(
            "unsafe pragmas: journal={journal}, synchronous={synchronous}, foreign_keys={foreign_keys}, trusted_schema={trusted_schema}, application_id={application_id}, user_version={user_version}"
        )));
    }
    Ok(())
}

fn initialize_schema(
    conn: &mut Connection,
    config: &AuthorityConfig,
    grant_key_id: &str,
    ledger_key_id: &str,
    ledger_key: &SigningKey,
) -> Result<(), AuthorityError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.execute_batch(SCHEMA_SQL)?;
    tx.execute(
        "INSERT INTO authority_meta (
            singleton, schema_version, instance_id, epoch, head_seq, head_hash,
            grant_key_id, ledger_key_id, genesis_generation_id, cutover_marker
         ) VALUES (1, ?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)",
        params![
            SCHEMA_VERSION,
            config.instance_id,
            config.epoch,
            ZERO_HASH,
            grant_key_id,
            ledger_key_id,
            config.genesis_generation.generation_id(),
            CUTOVER_MARKER,
        ],
    )?;
    insert_generation(
        &tx,
        &config.genesis_generation,
        &config.genesis_event_id,
        config.genesis_at,
    )?;
    insert_runtime_state(
        &tx,
        0,
        config.genesis_generation.generation_id(),
        false,
        &config.genesis_event_id,
        config.genesis_at,
    )?;
    append_ledger_entry(
        &tx,
        ledger_key,
        LedgerEventDraft {
            event_id: config.genesis_event_id.clone(),
            subject: "authority".into(),
            timestamp: config.genesis_at,
            build_identity: Some(config.genesis_generation.build_identity().into()),
            policy_identity: Some(config.genesis_generation.policy_identity().into()),
            payload: LedgerPayloadV2::Genesis {
                instance_id: config.instance_id.clone(),
                epoch: config.epoch.clone(),
                schema_version: SCHEMA_VERSION as u8,
                grant_key_id: grant_key_id.into(),
                ledger_key_id: ledger_key_id.into(),
                semantic_version: env!("CARGO_PKG_VERSION").into(),
                generation: config.genesis_generation.clone(),
                cutover_marker: CUTOVER_MARKER.into(),
            },
        },
    )?;
    tx.commit()?;
    Ok(())
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE authority_meta (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version  INTEGER NOT NULL CHECK (schema_version = 2),
    instance_id     TEXT NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 160),
    epoch           TEXT NOT NULL CHECK (length(epoch) BETWEEN 1 AND 40),
    head_seq        INTEGER NOT NULL CHECK (head_seq >= 0),
    head_hash       TEXT NOT NULL CHECK (length(head_hash) = 71),
    grant_key_id    TEXT NOT NULL CHECK (length(grant_key_id) = 77),
    ledger_key_id   TEXT NOT NULL CHECK (length(ledger_key_id) = 78),
    genesis_generation_id TEXT NOT NULL CHECK (length(genesis_generation_id) BETWEEN 1 AND 40),
    cutover_marker  TEXT NOT NULL CHECK (cutover_marker = 'fresh_v2_no_legacy_active_grants')
) STRICT;

CREATE TABLE authority_generations (
    generation_id  TEXT PRIMARY KEY CHECK (length(generation_id) BETWEEN 1 AND 40),
    generation_jcs TEXT NOT NULL UNIQUE,
    event_id       TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    activated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE authority_runtime_states (
    revision        INTEGER PRIMARY KEY CHECK (revision >= 0),
    generation_id   TEXT NOT NULL REFERENCES authority_generations(generation_id),
    maintenance     INTEGER NOT NULL CHECK (maintenance IN (0, 1)),
    event_id        TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    transitioned_at INTEGER NOT NULL
) STRICT;

CREATE TABLE ledger_entries (
    seq             INTEGER PRIMARY KEY CHECK (seq > 0),
    event_id        TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 1 AND 160),
    entry_jcs       TEXT NOT NULL,
    signature_b64   TEXT NOT NULL CHECK (length(signature_b64) = 86),
    entry_hash      TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 71)
) STRICT;

CREATE TABLE approval_requests (
    request_id      TEXT PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 160),
    dedupe_hash     TEXT NOT NULL CHECK (length(dedupe_hash) = 71),
    request_jcs     TEXT NOT NULL,
    request_hash    TEXT NOT NULL UNIQUE CHECK (length(request_hash) = 71),
    event_id        TEXT NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE open_approvals (
    dedupe_hash     TEXT PRIMARY KEY CHECK (length(dedupe_hash) = 71),
    request_id      TEXT NOT NULL UNIQUE REFERENCES approval_requests(request_id)
) STRICT;

CREATE TABLE approval_resolutions (
    request_id          TEXT PRIMARY KEY REFERENCES approval_requests(request_id),
    outcome             TEXT NOT NULL CHECK (outcome IN ('approved', 'denied')),
    operator_principal  TEXT NOT NULL CHECK (length(operator_principal) BETWEEN 1 AND 256),
    reason              TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    resolved_at         INTEGER NOT NULL,
    grant_id            TEXT UNIQUE,
    event_id            TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE grant_claims (
    grant_id        TEXT PRIMARY KEY CHECK (length(grant_id) BETWEEN 1 AND 160),
    request_id      TEXT NOT NULL UNIQUE REFERENCES approval_requests(request_id),
    claim_jcs       TEXT NOT NULL,
    signature_b64   TEXT NOT NULL CHECK (length(signature_b64) = 86),
    claim_hash      TEXT NOT NULL UNIQUE CHECK (length(claim_hash) = 71)
) STRICT;

CREATE TABLE grant_states (
    grant_id            TEXT NOT NULL REFERENCES grant_claims(grant_id),
    revision            INTEGER NOT NULL CHECK (revision IN (0, 1)),
    status              TEXT NOT NULL CHECK (status IN ('active', 'spent', 'revoked')),
    uses                INTEGER NOT NULL CHECK (uses IN (0, 1)),
    state_jcs           TEXT NOT NULL,
    signature_b64       TEXT NOT NULL CHECK (length(signature_b64) = 86),
    state_hash          TEXT NOT NULL UNIQUE CHECK (length(state_hash) = 71),
    transition_event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (grant_id, revision)
) STRICT;

CREATE INDEX approval_requests_dedupe_idx ON approval_requests(dedupe_hash);
CREATE INDEX grant_states_latest_idx ON grant_states(grant_id, revision DESC);

CREATE TRIGGER authority_generations_no_update BEFORE UPDATE ON authority_generations
BEGIN SELECT RAISE(ABORT, 'authority generations are immutable'); END;
CREATE TRIGGER authority_generations_no_delete BEFORE DELETE ON authority_generations
BEGIN SELECT RAISE(ABORT, 'authority generations are immutable'); END;
CREATE TRIGGER authority_runtime_states_no_update BEFORE UPDATE ON authority_runtime_states
BEGIN SELECT RAISE(ABORT, 'authority runtime states are append-only'); END;
CREATE TRIGGER authority_runtime_states_no_delete BEFORE DELETE ON authority_runtime_states
BEGIN SELECT RAISE(ABORT, 'authority runtime states are append-only'); END;

CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END;
CREATE TRIGGER ledger_entries_no_delete BEFORE DELETE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are append-only'); END;
CREATE TRIGGER approval_requests_no_update BEFORE UPDATE ON approval_requests
BEGIN SELECT RAISE(ABORT, 'approval requests are immutable'); END;
CREATE TRIGGER approval_requests_no_delete BEFORE DELETE ON approval_requests
BEGIN SELECT RAISE(ABORT, 'approval requests are immutable'); END;
CREATE TRIGGER approval_resolutions_no_update BEFORE UPDATE ON approval_resolutions
BEGIN SELECT RAISE(ABORT, 'approval resolutions are immutable'); END;
CREATE TRIGGER approval_resolutions_no_delete BEFORE DELETE ON approval_resolutions
BEGIN SELECT RAISE(ABORT, 'approval resolutions are immutable'); END;
CREATE TRIGGER grant_claims_no_update BEFORE UPDATE ON grant_claims
BEGIN SELECT RAISE(ABORT, 'grant claims are immutable'); END;
CREATE TRIGGER grant_claims_no_delete BEFORE DELETE ON grant_claims
BEGIN SELECT RAISE(ABORT, 'grant claims are immutable'); END;
CREATE TRIGGER grant_states_no_update BEFORE UPDATE ON grant_states
BEGIN SELECT RAISE(ABORT, 'grant states are append-only'); END;
CREATE TRIGGER grant_states_no_delete BEFORE DELETE ON grant_states
BEGIN SELECT RAISE(ABORT, 'grant states are append-only'); END;
"#;

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
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        let current = load_current_runtime_state(&tx)?;
        if !generation_id_is_newer(
            command.generation.generation_id(),
            current.active_generation.generation_id(),
        ) {
            return Err(AuthorityError::InvalidInput(
                "successor generation id must be strictly greater than the active id".into(),
            ));
        }
        if load_generation(&tx, command.generation.generation_id())?.is_some() {
            return Err(AuthorityError::InvalidInput(
                "generation id is already present".into(),
            ));
        }
        let revision = next_runtime_revision(&current)?;
        insert_generation(
            &tx,
            &command.generation,
            &command.event_id,
            command.activated_at,
        )?;
        insert_runtime_state(
            &tx,
            revision,
            command.generation.generation_id(),
            current.maintenance,
            &command.event_id,
            command.activated_at,
        )?;
        append_ledger_entry(
            &tx,
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
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        let activated = load_current_runtime_state(&tx)?;
        tx.commit()?;
        Ok(activated)
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
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        let current = load_current_runtime_state(&tx)?;
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
            &tx,
            revision,
            current.active_generation.generation_id(),
            command.enabled,
            &command.event_id,
            command.transitioned_at,
        )?;
        append_ledger_entry(
            &tx,
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
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        let changed = load_current_runtime_state(&tx)?;
        tx.commit()?;
        Ok(changed)
    }

    /// Create one request or return the already-open equivalent request.
    pub fn create_or_get_request(
        &mut self,
        command: &CreateRequestCommand,
    ) -> Result<CreateRequestResult, AuthorityError> {
        validate_token("request id", &command.request_id, 160)?;
        validate_token("request event id", &command.event_id, 160)?;
        command.context.validate()?;
        let request = ApprovalRequestV2::from_command(command)?;
        let request_jcs = canonicalize(&request)?;
        let request_hash = approval_request_hash(&request_jcs);
        let dedupe_jcs = canonicalize(&ApprovalDedupeV2 {
            domain: "gommage.approval.dedupe",
            version: FORMAT_VERSION,
            context: request.context(),
            generation: request.generation(),
            required_scope: request.required_scope(),
        })?;
        let dedupe_hash = approval_dedupe_hash(&dedupe_jcs);
        let ledger_key = self.ledger_key.clone();
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        ensure_decision_admitted(&tx, &command.generation)?;
        let existing_request_id = tx
            .query_row(
                "SELECT request_id FROM open_approvals WHERE dedupe_hash = ?1",
                [&dedupe_hash],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_request_id) = existing_request_id {
            let existing = load_request(&tx, &existing_request_id)?.ok_or_else(|| {
                AuthorityError::Corrupt("open approval points to a missing request".into())
            })?;
            ensure_decision_admitted(&tx, &command.generation)?;
            tx.commit()?;
            return Ok(CreateRequestResult::Existing(existing.request));
        }
        tx.execute(
            "INSERT INTO approval_requests (
                request_id, dedupe_hash, request_jcs, request_hash, event_id, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.request_id(),
                dedupe_hash,
                String::from_utf8(request_jcs).map_err(|error| {
                    AuthorityError::Corrupt(format!("JCS was not UTF-8: {error}"))
                })?,
                request_hash,
                command.event_id,
                request.created_at(),
            ],
        )?;
        tx.execute(
            "INSERT INTO open_approvals (dedupe_hash, request_id) VALUES (?1, ?2)",
            params![dedupe_hash, request.request_id()],
        )?;
        append_ledger_entry(
            &tx,
            &ledger_key,
            LedgerEventDraft {
                event_id: command.event_id.clone(),
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
        ensure_decision_admitted(&tx, &command.generation)?;
        tx.commit()?;
        Ok(CreateRequestResult::Created(request))
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
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let grant_key_id = self.grant_key_id.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        if let Some(resolution) = load_resolution(&tx, &command.request_id)? {
            tx.commit()?;
            return Ok(ApproveResult::AlreadyResolved(resolution));
        }
        let stored = load_request(&tx, &command.request_id)?
            .ok_or_else(|| AuthorityError::InvalidInput("approval request not found".into()))?;
        ensure_request_is_open(&tx, &stored)?;
        ensure_decision_admitted(&tx, stored.request.generation())?;
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
        insert_state(&tx, &active, &signed_state)?;
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
            &tx,
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
            &tx,
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
        ensure_decision_admitted(&tx, &request_generation)?;
        tx.commit()?;
        Ok(ApproveResult::Approved {
            claim: signed_claim,
            state: signed_state,
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
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        if let Some(resolution) = load_resolution(&tx, &command.request_id)? {
            tx.commit()?;
            return Ok(DenyResult::AlreadyResolved(resolution));
        }
        let stored = load_request(&tx, &command.request_id)?
            .ok_or_else(|| AuthorityError::InvalidInput("approval request not found".into()))?;
        ensure_request_is_open(&tx, &stored)?;
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
            &tx,
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
        tx.commit()?;
        Ok(DenyResult::Denied(resolution))
    }

    /// Atomically spend a matching grant and record the final allow evidence.
    pub fn consume_and_record_allow(
        &mut self,
        command: &ConsumeCommand,
    ) -> Result<ConsumeResult, AuthorityError> {
        validate_text("required scope", &command.required_scope, 512, false)?;
        validate_context_generation(&command.context, &command.generation)?;
        validate_token("state event id", &command.state_event_id, 160)?;
        validate_token("decision event id", &command.decision_event_id, 160)?;
        validate_timestamp(command.consumed_at)?;
        let grant_key = self.grant_key.clone();
        let ledger_key = self.ledger_key.clone();
        let grant_vk = self.grant_key.verifying_key();
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        ensure_decision_admitted(&tx, &command.generation)?;

        let dedupe_jcs = canonicalize(&ApprovalDedupeV2 {
            domain: "gommage.approval.dedupe",
            version: FORMAT_VERSION,
            context: &command.context,
            generation: &command.generation,
            required_scope: &command.required_scope,
        })?;
        let dedupe_hash = approval_dedupe_hash(&dedupe_jcs);
        let candidate_ids = {
            let mut statement = tx.prepare(
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
        let mut temporal_reason = None;
        for grant_id in candidate_ids {
            let (signed_claim, claim) =
                load_claim(&tx, &grant_id, &grant_vk)?.ok_or_else(|| {
                    AuthorityError::Corrupt("matching grant claim disappeared".into())
                })?;
            let stored_request =
                load_request(&tx, claim.approval_request_id())?.ok_or_else(|| {
                    AuthorityError::Corrupt("grant claim approval request is missing".into())
                })?;
            if stored_request.request.context() != &command.context
                || stored_request.request.generation() != &command.generation
                || stored_request.request.required_scope() != command.required_scope.as_str()
            {
                continue;
            }
            let (signed_previous, previous) = load_latest_state(&tx, &grant_id, &grant_vk)?
                .ok_or_else(|| AuthorityError::Corrupt("grant claim has no signed state".into()))?;
            if previous.status() != GrantStatusV2::Active {
                continue;
            }
            let unusable = if command.consumed_at < claim.not_before() {
                Some(GrantNotUsableReason::NotYetValid)
            } else if command.consumed_at >= claim.expires_at() {
                Some(GrantNotUsableReason::Expired)
            } else {
                None
            };
            if let Some(reason) = unusable {
                temporal_reason = match temporal_reason {
                    None => Some(reason),
                    Some(previous_reason) if previous_reason == reason => Some(reason),
                    Some(_) => Some(GrantNotUsableReason::Missing),
                };
                continue;
            }
            usable.push((grant_id, signed_claim, signed_previous, previous));
        }
        if usable.len() > 1 {
            return Err(AuthorityError::Corrupt(
                "multiple usable grants match the exact authorization context and scope".into(),
            ));
        }
        let Some((grant_id, signed_claim, signed_previous, previous)) = usable.pop() else {
            ensure_decision_admitted(&tx, &command.generation)?;
            tx.commit()?;
            return Ok(ConsumeResult::NotUsable(
                temporal_reason.unwrap_or(GrantNotUsableReason::Missing),
            ));
        };
        let spent = GrantStateV2::terminal(
            &previous,
            signed_previous.state_hash(),
            GrantStatusV2::Spent,
            command.state_event_id.clone(),
            command.consumed_at,
        )?;
        let signed_spent = SignedGrantStateV2::sign(&spent, &grant_key)?;
        insert_state(&tx, &spent, &signed_spent)?;
        append_ledger_entry(
            &tx,
            &ledger_key,
            LedgerEventDraft {
                event_id: command.state_event_id.clone(),
                subject: grant_id.clone(),
                timestamp: command.consumed_at,
                build_identity: Some(command.context.build_identity().into()),
                policy_identity: Some(command.context.policy_identity().into()),
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
            &tx,
            &ledger_key,
            LedgerEventDraft {
                event_id: command.decision_event_id.clone(),
                subject: grant_id.clone(),
                timestamp: command.consumed_at,
                build_identity: Some(command.context.build_identity().into()),
                policy_identity: Some(command.context.policy_identity().into()),
                payload: LedgerPayloadV2::DecisionAllow {
                    grant_id,
                    required_scope: command.required_scope.clone(),
                    input_hash: command.context.input_hash().into(),
                    context: command.context.clone(),
                    generation: command.generation.clone(),
                    state_hash: signed_spent.state_hash().into(),
                },
            },
        )?;
        ensure_decision_admitted(&tx, &command.generation)?;
        tx.commit()?;
        Ok(ConsumeResult::Consumed {
            state: signed_spent,
            decision_event_id: command.decision_event_id.clone(),
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
        let ledger_vk = self.ledger_key.verifying_key();
        let config = self.config.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_all(&tx, &config, &grant_vk, &ledger_vk, None)?;
        let Some((signed_claim, _claim)) = load_claim(&tx, &command.grant_id, &grant_vk)? else {
            tx.commit()?;
            return Ok(RevokeResult::NotUsable(GrantNotUsableReason::Missing));
        };
        let (signed_previous, previous) = load_latest_state(&tx, &command.grant_id, &grant_vk)?
            .ok_or_else(|| AuthorityError::Corrupt("grant claim has no signed state".into()))?;
        if previous.status() != GrantStatusV2::Active {
            tx.commit()?;
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
        insert_state(&tx, &revoked, &signed_revoked)?;
        append_ledger_entry(
            &tx,
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
        tx.commit()?;
        Ok(RevokeResult::Revoked(signed_revoked))
    }

    /// Read and verify one immutable request and its signed-ledger link.
    pub fn request(&self, request_id: &str) -> Result<Option<ApprovalRequestV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
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
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
        let resolution = load_resolution(&tx, request_id)?;
        tx.commit()?;
        Ok(resolution)
    }

    /// Read and cryptographically verify one immutable grant claim.
    pub fn grant(&self, grant_id: &str) -> Result<Option<SignedGrantClaimV2>, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
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
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
        let state = load_latest_state(&tx, grant_id, &self.grant_key.verifying_key())?
            .map(|(signed, _)| signed);
        tx.commit()?;
        Ok(state)
    }

    /// Return the fully verified active generation and maintenance state.
    pub fn runtime_state(&self) -> Result<AuthorityRuntimeStateV2, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            None,
        )?;
        let state = load_current_runtime_state(&tx)?;
        tx.commit()?;
        Ok(state)
    }

    /// Verify every ledger, request, resolution, claim, state, and cross-link.
    ///
    /// Without `trusted_checkpoint`, the chain is internally authenticated but
    /// explicitly reported as [`FreshnessVerdict::Unanchored`].
    pub fn verify_ledger(
        &self,
        trusted_checkpoint: Option<&SignedLedgerCheckpointV2>,
    ) -> Result<LedgerVerification, AuthorityError> {
        let tx = self.conn.unchecked_transaction()?;
        let verification = verify_all(
            &tx,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            trusted_checkpoint,
        )?;
        tx.commit()?;
        Ok(verification)
    }

    /// Produce a ledger-purpose signed checkpoint for an external trust store.
    pub fn checkpoint(
        &self,
        checkpoint_id: &str,
        created_at: i64,
    ) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
        validate_token("checkpoint id", checkpoint_id, 160)?;
        validate_timestamp(created_at)?;
        let verification = self.verify_ledger(None)?;
        let checkpoint = LedgerCheckpointV2 {
            domain: CHECKPOINT_DOMAIN.into(),
            version: FORMAT_VERSION,
            checkpoint_id: checkpoint_id.into(),
            authority_instance: self.config.instance_id.clone(),
            authority_epoch: self.config.epoch.clone(),
            created_at,
            head_seq: verification.head_seq,
            head_hash: verification.head_hash,
            ledger_key_id: self.ledger_key_id.clone(),
        };
        checkpoint.validate()?;
        Ok(SignedLedgerCheckpointV2 {
            envelope: sign_payload(
                EnvelopeDomain::LedgerCheckpoint,
                &checkpoint,
                &self.ledger_key,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_utf8_request_fields_never_panic(
            integration in ".{0,300}",
            tool in ".{0,500}",
            scope in ".{0,800}",
            reason in ".{0,1400}",
            capabilities in prop::collection::vec(".{0,1200}", 0..12),
        ) {
            let context = AuthorizationContextV2::new(
                "gommage-property-build".into(),
                integration,
                tool,
                format!("sha256:{}", "1".repeat(64)),
                format!("sha256:{}", "2".repeat(64)),
                capabilities,
            );
            if let Ok(context) = context {
                let command = CreateRequestCommand {
                    request_id: "request_property".into(),
                    event_id: "event_property".into(),
                    created_at: 1_700_000_000,
                    generation: AuthorityGenerationV2::new(
                        "1".into(),
                        "gommage-property-release".into(),
                        "gommage-property-build".into(),
                        format!("sha256:{}", "2".repeat(64)),
                        format!("sha256:{}", "3".repeat(64)),
                        "gommage-managed-v2".into(),
                    )
                    .unwrap(),
                    context,
                    required_scope: scope,
                    reason,
                };
                let _ = ApprovalRequestV2::from_command(&command);
            }
        }
    }
}
