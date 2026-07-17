//! Shared bounds for policy evaluation and signed Authority evidence.

pub(crate) const MAX_EVIDENCE_LAYER_BYTES: usize = 128;
pub(crate) const MAX_EVIDENCE_RULE_NAME_BYTES: usize = 256;
pub(crate) const MAX_EVIDENCE_RULE_FILE_BYTES: usize = 4_096;
pub(crate) const MAX_DECISION_REASON_BYTES: usize = 4_096;
pub(crate) const MAX_APPROVAL_REASON_BYTES: usize = 1_024;
