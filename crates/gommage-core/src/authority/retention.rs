use super::*;
use std::fmt;

/// Durable checkpoint state owned by a host-provided retention adapter.
///
/// The state describes protocol progress only. Gommage does not claim that a
/// backend is independent from the Authority database's rollback domain; that
/// deployment property must be established by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointRetentionStateV2 {
    /// No authority root or pending bootstrap checkpoint is retained.
    Empty,
    /// Genesis was staged, while SQLite commit or promotion may be incomplete.
    BootstrapPending(SignedLedgerCheckpointV2),
    /// The checkpoint is the active durable rollback anchor.
    Active(SignedLedgerCheckpointV2),
    /// A successor was durably staged but has not been durably promoted.
    ActiveWithPending {
        /// Previously active checkpoint used as the stage compare-and-swap input.
        active: SignedLedgerCheckpointV2,
        /// Durably staged successor checkpoint.
        pending: SignedLedgerCheckpointV2,
    },
}

/// Retention failures classified by whether retry/recovery can assume no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointRetentionErrorV2 {
    /// The adapter definitively rejected the operation without changing state.
    #[error("checkpoint retention rejected the operation without effects")]
    Rejected,
    /// The adapter cannot determine whether the durable operation took effect.
    #[error("checkpoint retention outcome is indeterminate")]
    Indeterminate,
}

/// Bounded operation context attached by Authority to retention failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRetentionOperationV2 {
    /// Read durable retention state during bootstrap or recovery.
    Load,
    /// Durably stage one compare-and-swap successor before SQLite commit.
    Stage,
    /// Durably promote a staged successor after SQLite commit.
    Promote,
}

impl fmt::Display for CheckpointRetentionOperationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Load => "load",
            Self::Stage => "stage",
            Self::Promote => "promote",
        })
    }
}

/// Host-neutral durable checkpoint retention protocol for Authority v2.
///
/// Implementations must make successful `stage` and `promote` calls durable
/// before returning. Both operations are idempotent compare-and-swap
/// transitions. `expected_active = None` requires an empty/bootstrap state;
/// `Some(active)` requires that exact active envelope. Repeating a transition
/// succeeds only while its exact successor is still pending or active. A stale
/// promotion must return [`Rejected`](CheckpointRetentionErrorV2::Rejected)
/// without changing a newer active checkpoint. A successful stage must
/// subsequently load as `BootstrapPending` or `ActiveWithPending` unless that
/// exact successor is already active. A successful promotion must subsequently
/// load that exact successor as `Active`. A definitive `Rejected` result
/// guarantees no state change; `Indeterminate` makes no such guarantee.
pub trait CheckpointRetentionV2: Send {
    /// Load the complete durable protocol state.
    fn load(&self) -> Result<CheckpointRetentionStateV2, CheckpointRetentionErrorV2>;

    /// Durably stage `pending` under the exact expected active checkpoint.
    fn stage(
        &mut self,
        expected_active: Option<&SignedLedgerCheckpointV2>,
        pending: &SignedLedgerCheckpointV2,
    ) -> Result<(), CheckpointRetentionErrorV2>;

    /// Durably and idempotently promote the exact staged checkpoint.
    fn promote(
        &mut self,
        expected_active: Option<&SignedLedgerCheckpointV2>,
        pending: &SignedLedgerCheckpointV2,
    ) -> Result<(), CheckpointRetentionErrorV2>;
}
