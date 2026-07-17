//! gommage-core — policy, capability mapping, and authorization authority.
//!
//! This crate is intentionally free of runtime dependencies (no tokio, no clap, no I/O
//! beyond SQLite authorization stores). Its job is to be a testable kernel:
//! `(ToolCall, Policy) → Decision` with deterministic semantics.

pub mod approval;
pub mod approval_webhook;
pub mod authority;
pub mod capability;
pub mod crypto_envelope;
pub mod error;
pub mod evaluator;
pub mod grant_v2;
pub mod hardstop;
pub mod mapper;
pub mod picto;
pub mod policy;
pub mod runtime;
pub(crate) mod shell;
pub mod toolcall;
pub mod webhook_signature;

pub use approval::{
    ApprovalRequest, ApprovalResolution, ApprovalState, ApprovalStatus, ApprovalStore,
};
pub use approval_webhook::{
    ApprovalWebhookDeadLetter, ApprovalWebhookDeadLetterStore, ApprovalWebhookDeliveryKind,
    ApprovalWebhookDeliveryOutcome, ApprovalWebhookDeliverySettings, ApprovalWebhookSource,
    PreparedApprovalWebhook, approval_callback_nonce, approval_webhook_generic_payload,
    deliver_prepared_approval_webhook, prepare_approval_webhook,
};
pub use authority::{
    ActivateGenerationCommand, ApprovalRequestV2, ApprovalResolutionKindV2, ApprovalResolutionV2,
    ApproveCommand, ApproveResult, Authority, AuthorityConfig, AuthorityError,
    AuthorityGenerationV2, AuthorityMetadata, AuthorityRuntimeStateV2, AuthorizationContextV2,
    ConsumeCommand, ConsumeResult, CreateRequestCommand, CreateRequestResult, CutoverStateV2,
    DenyCommand, DenyResult, FreshnessVerdict, GrantNotUsableReason, LedgerCheckpointV2,
    LedgerEntryV2, LedgerPayloadV2, LedgerVerification, RevokeCommand, RevokeResult,
    SetMaintenanceCommand, SignedLedgerCheckpointV2, VerifiedLedgerEntryV2,
};
pub use capability::Capability;
pub use crypto_envelope::{
    CryptoEnvelopeError, EnvelopeDomain, KeyBound, KeyPurpose, MAX_CANONICAL_BYTES, SignedJcs,
};
pub use error::GommageError;
pub use evaluator::{
    AuthorizationEvidence, CapabilityProvenance, CapabilityProvenanceStatus, Decision, EvalResult,
    MatchedRule, RuleContribution, evaluate, evaluate_bypass,
};
pub use grant_v2::{
    DEFAULT_GRANT_TTL_SECONDS, GrantClaimFields, GrantClaimV2, GrantStateV2, GrantStatusV2,
    GrantV2Error, MAX_GRANT_TTL_SECONDS, SignedGrantClaimV2, SignedGrantStateV2,
};
pub use hardstop::HardStopHit;
pub use mapper::CapabilityMapper;
pub use picto::{
    Picto, PictoBinding, PictoConsume, PictoLookup, PictoReadStore, PictoStatus, PictoStore,
};
pub use policy::{Match, Policy, PolicyLayer, PolicyLayerKind, Rule, RuleDecision, RuleSource};
pub use shell::shell_write_targets;
pub use toolcall::ToolCall;
