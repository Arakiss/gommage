use super::*;

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

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
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

/// Internal immutable fields for one approval request creation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CreateRequestCommand {
    /// Caller-generated unique request identifier.
    pub request_id: String,
    /// Caller-generated event identifier for the signed request event.
    pub event_id: String,
    /// Unix timestamp for request creation.
    pub created_at: i64,
    /// Complete immutable authorization context observed by the integration.
    pub context: AuthorizationContextV2,
    /// Scope-only or exact-input authority requested by policy.
    pub binding: PictoBinding,
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
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(AuthorityError::InvalidInput(format!(
                "authorization context exceeds {MAX_CAPABILITIES} input capabilities"
            )));
        }
        for capability in &capabilities {
            validate_text("capability", capability, MAX_CAPABILITY_BYTES, false)?;
        }
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

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
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
        if self.capabilities.len() > MAX_CAPABILITIES
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<PictoBinding>,
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

    /// Return the signed scope-only or exact-input authority boundary.
    ///
    /// Requests written before the explicit field existed are exact-input
    /// bound to the already-signed observed input hash.
    pub fn binding(&self) -> PictoBinding {
        self.binding
            .clone()
            .unwrap_or_else(|| PictoBinding::ExactInput {
                input_hash: self.context.input_hash.clone(),
            })
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

    pub(super) fn from_command(command: &CreateRequestCommand) -> Result<Self, AuthorityError> {
        let request = Self {
            domain: REQUEST_DOMAIN.into(),
            version: FORMAT_VERSION,
            request_id: command.request_id.clone(),
            created_at: command.created_at,
            context: command.context.clone(),
            binding: Some(command.binding.clone()),
            generation: command.generation.clone(),
            required_scope: command.required_scope.clone(),
            reason: command.reason.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        if self.domain != REQUEST_DOMAIN || self.version != FORMAT_VERSION {
            return Err(AuthorityError::InvalidInput(
                "incorrect approval request domain or version".into(),
            ));
        }
        validate_token("request id", &self.request_id, 160)?;
        validate_timestamp(self.created_at)?;
        self.context.validate()?;
        if let Some(PictoBinding::ExactInput { input_hash }) = self.binding.as_ref() {
            validate_hash("approval exact-input binding hash", input_hash)?;
            if input_hash != self.context.input_hash() {
                return Err(AuthorityError::InvalidInput(
                    "approval exact-input binding does not match the observed input".into(),
                ));
            }
        }
        if self.context.capabilities().is_empty() {
            return Err(AuthorityError::InvalidInput(
                "approval requests require at least one capability".into(),
            ));
        }
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
pub(super) struct ApprovalDedupeV2<'a> {
    pub(super) domain: &'static str,
    pub(super) version: u8,
    pub(super) context: &'a AuthorizationContextV2,
    pub(super) generation: &'a AuthorityGenerationV2,
    pub(super) required_scope: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BoundApprovalDedupeV2<'a> {
    pub(super) domain: &'static str,
    pub(super) version: u8,
    pub(super) generation: &'a AuthorityGenerationV2,
    pub(super) required_scope: &'a str,
    pub(super) binding: &'a PictoBinding,
}

/// Internal result of creating or deduplicating an open approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CreateRequestResult {
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
    pub(super) fn as_str(self) -> &'static str {
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
    pub(super) revision: String,
    pub(super) active_generation: AuthorityGenerationV2,
    pub(super) maintenance: bool,
    pub(super) transition_event_id: String,
    pub(super) transitioned_at: i64,
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
