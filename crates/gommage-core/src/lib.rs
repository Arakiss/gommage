//! gommage-core — the policy engine, capability mapper, and picto store.
//!
//! This crate is intentionally free of runtime dependencies (no tokio, no clap, no I/O
//! beyond SQLite for the picto store). Its job is to be a pure, testable kernel:
//! `(ToolCall, Policy) → Decision` with deterministic semantics.

pub mod approval;
pub mod approval_webhook;
pub mod capability;
pub mod error;
pub mod evaluator;
pub mod hardstop;
pub mod mapper;
pub mod picto;
pub mod policy;
pub mod runtime;
pub mod toolcall;
pub mod webhook_signature;

pub use approval::{
    ApprovalRequest, ApprovalResolution, ApprovalState, ApprovalStatus, ApprovalStore,
};
pub use approval_webhook::{
    ApprovalWebhookDeadLetter, ApprovalWebhookDeadLetterStore, ApprovalWebhookDeliveryKind,
    ApprovalWebhookDeliveryOutcome, ApprovalWebhookDeliverySettings, ApprovalWebhookSource,
    PreparedApprovalWebhook, approval_webhook_generic_payload, deliver_prepared_approval_webhook,
    prepare_approval_webhook,
};
pub use capability::Capability;
pub use error::GommageError;
pub use evaluator::{Decision, EvalResult, MatchedRule, evaluate};
pub use hardstop::HardStopHit;
pub use mapper::CapabilityMapper;
pub use picto::{Picto, PictoConsume, PictoLookup, PictoStatus, PictoStore};
pub use policy::{Match, Policy, Rule, RuleDecision};
pub use toolcall::ToolCall;
