//! Exact-input, single-use grants for the Authority v2 reference profile.

use crate::crypto_envelope::{
    CryptoEnvelopeError, EnvelopeDomain, KeyBound, SignedJcs, grant_claim_hash, grant_state_hash,
    sign_payload, verify_payload,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default lifetime for a reference-profile grant.
pub const DEFAULT_GRANT_TTL_SECONDS: i64 = 600;
/// Absolute lifetime ceiling for a reference-profile grant.
pub const MAX_GRANT_TTL_SECONDS: i64 = 3_600;

const CLAIM_DOMAIN: &str = "gommage.grant.claim";
const STATE_DOMAIN: &str = "gommage.grant.state";
const VERSION: u8 = 2;
const MAX_ID_BYTES: usize = 160;
const MAX_SCOPE_BYTES: usize = 512;
const MAX_PRINCIPAL_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 1_024;

/// Input fields for a new exact-input grant claim.
#[derive(Debug, Clone)]
pub struct GrantClaimFields {
    /// Stable authority instance identifier.
    pub authority_instance: String,
    /// Monotonic authority epoch encoded as a decimal string.
    pub authority_epoch: String,
    /// Unique grant identifier.
    pub grant_id: String,
    /// Unix timestamp at which the claim was issued.
    pub issued_at: i64,
    /// Earliest Unix timestamp at which the claim may be consumed.
    pub not_before: i64,
    /// Unix timestamp at which the claim ceases to be usable.
    pub expires_at: i64,
    /// Exact approval scope.
    pub required_scope: String,
    /// Canonical `sha256:` digest of the complete tool input.
    pub input_hash: String,
    /// Approval request that authorized this claim.
    pub approval_request_id: String,
    /// Canonical hash of the immutable approval request.
    pub request_hash: String,
    /// Authenticated operator identity.
    pub operator_principal: String,
    /// Human approval rationale.
    pub reason: String,
    /// Purpose-qualified grant signing key identifier.
    pub grant_key_id: String,
}

/// Immutable grant claims covered by the grant-purpose Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaimV2 {
    domain: String,
    version: u8,
    authority_instance: String,
    authority_epoch: String,
    grant_id: String,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
    max_uses: u8,
    required_scope: String,
    input_hash: String,
    approval_request_id: String,
    request_hash: String,
    operator_principal: String,
    reason: String,
    grant_key_id: String,
}

impl GrantClaimV2 {
    /// Construct and validate a reference-profile claim.
    pub fn new(fields: GrantClaimFields) -> Result<Self, GrantV2Error> {
        let claim = Self {
            domain: CLAIM_DOMAIN.into(),
            version: VERSION,
            authority_instance: fields.authority_instance,
            authority_epoch: fields.authority_epoch,
            grant_id: fields.grant_id,
            issued_at: fields.issued_at,
            not_before: fields.not_before,
            expires_at: fields.expires_at,
            max_uses: 1,
            required_scope: fields.required_scope,
            input_hash: fields.input_hash,
            approval_request_id: fields.approval_request_id,
            request_hash: fields.request_hash,
            operator_principal: fields.operator_principal,
            reason: fields.reason,
            grant_key_id: fields.grant_key_id,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Return the authority instance that created the grant.
    pub fn authority_instance(&self) -> &str {
        &self.authority_instance
    }

    /// Return the authority epoch in which the grant was created.
    pub fn authority_epoch(&self) -> &str {
        &self.authority_epoch
    }

    /// Return the unique grant identifier.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// Return the issue timestamp.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Return the not-before timestamp.
    pub fn not_before(&self) -> i64 {
        self.not_before
    }

    /// Return the expiry timestamp.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Return the invariant maximum use count, always one.
    pub fn max_uses(&self) -> u8 {
        self.max_uses
    }

    /// Return the exact approval scope.
    pub fn required_scope(&self) -> &str {
        &self.required_scope
    }

    /// Return the exact canonical input hash.
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }

    /// Return the authorizing approval request identifier.
    pub fn approval_request_id(&self) -> &str {
        &self.approval_request_id
    }

    /// Return the immutable approval request hash.
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    /// Return the authenticated operator principal.
    pub fn operator_principal(&self) -> &str {
        &self.operator_principal
    }

    /// Return the approval reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Return the purpose-qualified grant key identifier.
    pub fn grant_key_id(&self) -> &str {
        &self.grant_key_id
    }

    /// Report whether the exact scope, input, and time satisfy this claim.
    pub fn is_usable_for(&self, scope: &str, input_hash: &str, now: i64) -> bool {
        self.required_scope == scope
            && self.input_hash == input_hash
            && now >= self.not_before
            && now < self.expires_at
    }

    fn validate(&self) -> Result<(), GrantV2Error> {
        if self.domain != CLAIM_DOMAIN || self.version != VERSION {
            return Err(GrantV2Error::InvalidClaim(
                "incorrect claim domain or version".into(),
            ));
        }
        validate_token("authority instance", &self.authority_instance, MAX_ID_BYTES)?;
        validate_decimal("authority epoch", &self.authority_epoch)?;
        validate_token("grant id", &self.grant_id, MAX_ID_BYTES)?;
        validate_safe_timestamp("issued_at", self.issued_at)?;
        validate_safe_timestamp("not_before", self.not_before)?;
        validate_safe_timestamp("expires_at", self.expires_at)?;
        if self.not_before < self.issued_at || self.expires_at <= self.not_before {
            return Err(GrantV2Error::InvalidClaim(
                "grant timestamps are not ordered".into(),
            ));
        }
        if self.expires_at - self.issued_at > MAX_GRANT_TTL_SECONDS {
            return Err(GrantV2Error::InvalidClaim(format!(
                "grant lifetime exceeds {MAX_GRANT_TTL_SECONDS} seconds"
            )));
        }
        if self.max_uses != 1 {
            return Err(GrantV2Error::InvalidClaim(
                "reference grants must have exactly one use".into(),
            ));
        }
        validate_text("scope", &self.required_scope, MAX_SCOPE_BYTES, false)?;
        validate_hash("input hash", &self.input_hash)?;
        validate_token(
            "approval request id",
            &self.approval_request_id,
            MAX_ID_BYTES,
        )?;
        validate_hash("request hash", &self.request_hash)?;
        validate_text(
            "operator principal",
            &self.operator_principal,
            MAX_PRINCIPAL_BYTES,
            false,
        )?;
        validate_text("reason", &self.reason, MAX_REASON_BYTES, true)?;
        validate_key_id(&self.grant_key_id, "grant")?;
        Ok(())
    }
}

impl KeyBound for GrantClaimV2 {
    fn key_id(&self) -> &str {
        &self.grant_key_id
    }
}

/// A claim together with its canonical bytes, signature, and domain hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrantClaimV2 {
    envelope: SignedJcs,
    claim_hash: String,
}

impl SignedGrantClaimV2 {
    /// Sign a validated claim with the grant-purpose key.
    pub fn sign(claim: &GrantClaimV2, key: &SigningKey) -> Result<Self, GrantV2Error> {
        claim.validate()?;
        let envelope = sign_payload(EnvelopeDomain::GrantClaim, claim, key)?;
        let claim_hash = grant_claim_hash(envelope.jcs().as_bytes());
        Ok(Self {
            envelope,
            claim_hash,
        })
    }

    /// Reconstruct a stored signed claim for subsequent verification.
    pub fn from_stored(envelope: SignedJcs, claim_hash: String) -> Self {
        Self {
            envelope,
            claim_hash,
        }
    }

    /// Verify signature, key purpose, canonical bytes, hash, and claim invariants.
    pub fn verify(&self, key: &VerifyingKey) -> Result<GrantClaimV2, GrantV2Error> {
        validate_hash("claim hash", &self.claim_hash)?;
        if grant_claim_hash(self.envelope.jcs().as_bytes()) != self.claim_hash {
            return Err(GrantV2Error::HashMismatch);
        }
        let claim: GrantClaimV2 = verify_payload(EnvelopeDomain::GrantClaim, &self.envelope, key)?;
        claim.validate()?;
        Ok(claim)
    }

    /// Return the canonical signed envelope.
    pub fn envelope(&self) -> &SignedJcs {
        &self.envelope
    }

    /// Return the domain-separated claim hash.
    pub fn claim_hash(&self) -> &str {
        &self.claim_hash
    }
}

/// Terminal and nonterminal grant-state values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatusV2 {
    /// The grant may be consumed once while its claim is otherwise usable.
    Active,
    /// The grant's sole use has been consumed.
    Spent,
    /// The operator invalidated the grant before consumption.
    Revoked,
}

/// A signed append-only revision of mutable grant state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantStateV2 {
    domain: String,
    version: u8,
    authority_instance: String,
    authority_epoch: String,
    grant_id: String,
    claim_hash: String,
    revision: String,
    status: GrantStatusV2,
    uses: u8,
    previous_state_hash: Option<String>,
    transition_event_id: String,
    transitioned_at: i64,
    grant_key_id: String,
}

impl GrantStateV2 {
    /// Construct revision zero for a newly approved claim.
    pub fn active(
        claim: &GrantClaimV2,
        claim_hash: &str,
        transition_event_id: String,
        transitioned_at: i64,
    ) -> Result<Self, GrantV2Error> {
        let state = Self {
            domain: STATE_DOMAIN.into(),
            version: VERSION,
            authority_instance: claim.authority_instance.clone(),
            authority_epoch: claim.authority_epoch.clone(),
            grant_id: claim.grant_id.clone(),
            claim_hash: claim_hash.into(),
            revision: "0".into(),
            status: GrantStatusV2::Active,
            uses: 0,
            previous_state_hash: None,
            transition_event_id,
            transitioned_at,
            grant_key_id: claim.grant_key_id.clone(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Construct the only possible terminal revision after an active state.
    pub fn terminal(
        previous: &Self,
        previous_state_hash: &str,
        status: GrantStatusV2,
        transition_event_id: String,
        transitioned_at: i64,
    ) -> Result<Self, GrantV2Error> {
        if previous.status != GrantStatusV2::Active || previous.revision != "0" {
            return Err(GrantV2Error::InvalidTransition(
                "only active revision zero may transition".into(),
            ));
        }
        if !matches!(status, GrantStatusV2::Spent | GrantStatusV2::Revoked) {
            return Err(GrantV2Error::InvalidTransition(
                "terminal revision must be spent or revoked".into(),
            ));
        }
        let state = Self {
            domain: STATE_DOMAIN.into(),
            version: VERSION,
            authority_instance: previous.authority_instance.clone(),
            authority_epoch: previous.authority_epoch.clone(),
            grant_id: previous.grant_id.clone(),
            claim_hash: previous.claim_hash.clone(),
            revision: "1".into(),
            status,
            uses: u8::from(status == GrantStatusV2::Spent),
            previous_state_hash: Some(previous_state_hash.into()),
            transition_event_id,
            transitioned_at,
            grant_key_id: previous.grant_key_id.clone(),
        };
        state.validate()?;
        state.verify_successor_of(previous, previous_state_hash)?;
        Ok(state)
    }

    /// Return the authority instance.
    pub fn authority_instance(&self) -> &str {
        &self.authority_instance
    }

    /// Return the authority epoch.
    pub fn authority_epoch(&self) -> &str {
        &self.authority_epoch
    }

    /// Return the grant identifier.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// Return the immutable claim hash.
    pub fn claim_hash(&self) -> &str {
        &self.claim_hash
    }

    /// Return the decimal revision number.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Return the state status.
    pub fn status(&self) -> GrantStatusV2 {
        self.status
    }

    /// Return the consumed use count.
    pub fn uses(&self) -> u8 {
        self.uses
    }

    /// Return the preceding revision hash, if this is not revision zero.
    pub fn previous_state_hash(&self) -> Option<&str> {
        self.previous_state_hash.as_deref()
    }

    /// Return the ledger event that commits this transition.
    pub fn transition_event_id(&self) -> &str {
        &self.transition_event_id
    }

    /// Return the transition timestamp.
    pub fn transitioned_at(&self) -> i64 {
        self.transitioned_at
    }

    /// Return the purpose-qualified grant key identifier.
    pub fn grant_key_id(&self) -> &str {
        &self.grant_key_id
    }

    /// Verify this state as the immediate successor of `previous`.
    pub fn verify_successor_of(
        &self,
        previous: &Self,
        previous_hash: &str,
    ) -> Result<(), GrantV2Error> {
        if self.revision != "1"
            || previous.revision != "0"
            || previous.status != GrantStatusV2::Active
            || !matches!(self.status, GrantStatusV2::Spent | GrantStatusV2::Revoked)
            || self.previous_state_hash.as_deref() != Some(previous_hash)
            || self.authority_instance != previous.authority_instance
            || self.authority_epoch != previous.authority_epoch
            || self.grant_id != previous.grant_id
            || self.claim_hash != previous.claim_hash
            || self.grant_key_id != previous.grant_key_id
            || self.transitioned_at < previous.transitioned_at
        {
            return Err(GrantV2Error::InvalidTransition(
                "state revision does not immediately and monotonically follow its predecessor"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), GrantV2Error> {
        if self.domain != STATE_DOMAIN || self.version != VERSION {
            return Err(GrantV2Error::InvalidState(
                "incorrect state domain or version".into(),
            ));
        }
        validate_token("authority instance", &self.authority_instance, MAX_ID_BYTES)?;
        validate_decimal("authority epoch", &self.authority_epoch)?;
        validate_token("grant id", &self.grant_id, MAX_ID_BYTES)?;
        validate_hash("claim hash", &self.claim_hash)?;
        validate_decimal("revision", &self.revision)?;
        validate_token(
            "transition event id",
            &self.transition_event_id,
            MAX_ID_BYTES,
        )?;
        validate_safe_timestamp("transitioned_at", self.transitioned_at)?;
        validate_key_id(&self.grant_key_id, "grant")?;
        match (
            self.revision.as_str(),
            self.status,
            self.uses,
            self.previous_state_hash.as_deref(),
        ) {
            ("0", GrantStatusV2::Active, 0, None)
            | ("1", GrantStatusV2::Spent, 1, Some(_))
            | ("1", GrantStatusV2::Revoked, 0, Some(_)) => {}
            _ => {
                return Err(GrantV2Error::InvalidState(
                    "invalid revision/status/use/previous-hash combination".into(),
                ));
            }
        }
        if let Some(hash) = &self.previous_state_hash {
            validate_hash("previous state hash", hash)?;
        }
        Ok(())
    }
}

impl KeyBound for GrantStateV2 {
    fn key_id(&self) -> &str {
        &self.grant_key_id
    }
}

/// A state revision with its canonical bytes, signature, and domain hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrantStateV2 {
    envelope: SignedJcs,
    state_hash: String,
}

impl SignedGrantStateV2 {
    /// Sign a validated state revision with the grant-purpose key.
    pub fn sign(state: &GrantStateV2, key: &SigningKey) -> Result<Self, GrantV2Error> {
        state.validate()?;
        let envelope = sign_payload(EnvelopeDomain::GrantState, state, key)?;
        let state_hash = grant_state_hash(envelope.jcs().as_bytes());
        Ok(Self {
            envelope,
            state_hash,
        })
    }

    /// Reconstruct a stored signed revision for subsequent verification.
    pub fn from_stored(envelope: SignedJcs, state_hash: String) -> Self {
        Self {
            envelope,
            state_hash,
        }
    }

    /// Verify signature, key purpose, canonical bytes, hash, and state invariants.
    pub fn verify(&self, key: &VerifyingKey) -> Result<GrantStateV2, GrantV2Error> {
        validate_hash("state hash", &self.state_hash)?;
        if grant_state_hash(self.envelope.jcs().as_bytes()) != self.state_hash {
            return Err(GrantV2Error::HashMismatch);
        }
        let state: GrantStateV2 = verify_payload(EnvelopeDomain::GrantState, &self.envelope, key)?;
        state.validate()?;
        Ok(state)
    }

    /// Return the canonical signed envelope.
    pub fn envelope(&self) -> &SignedJcs {
        &self.envelope
    }

    /// Return the domain-separated state hash.
    pub fn state_hash(&self) -> &str {
        &self.state_hash
    }
}

/// Validation and verification failures for Authority v2 grants.
#[derive(Debug, Error)]
pub enum GrantV2Error {
    /// A claim violates the exact-input, one-use reference contract.
    #[error("invalid grant claim: {0}")]
    InvalidClaim(String),
    /// A state revision violates the two-revision state machine.
    #[error("invalid grant state: {0}")]
    InvalidState(String),
    /// A state transition does not immediately follow its predecessor.
    #[error("invalid grant transition: {0}")]
    InvalidTransition(String),
    /// Stored canonical bytes do not match their declared domain hash.
    #[error("signed payload hash mismatch")]
    HashMismatch,
    /// Canonical envelope validation or signature verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoEnvelopeError),
}

pub(crate) fn validate_hash(label: &str, value: &str) -> Result<(), GrantV2Error> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} must use sha256: form"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} is not a canonical lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

pub(crate) fn validate_token(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), GrantV2Error> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} is empty, oversized, or contains unsupported characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_text(
    label: &str,
    value: &str,
    max_bytes: usize,
    allow_newlines: bool,
) -> Result<(), GrantV2Error> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} is empty or exceeds {max_bytes} bytes"
        )));
    }
    if value.chars().any(|character| {
        character == '\0'
            || (character.is_control()
                && !(allow_newlines && matches!(character, '\n' | '\r' | '\t')))
    }) {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} contains unsupported control characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_decimal(label: &str, value: &str) -> Result<(), GrantV2Error> {
    if value.is_empty()
        || value.len() > 40
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} is not bounded canonical unsigned decimal text"
        )));
    }
    Ok(())
}

fn validate_safe_timestamp(label: &str, value: i64) -> Result<(), GrantV2Error> {
    if value.unsigned_abs() > crate::crypto_envelope::MAX_SAFE_INTEGER {
        return Err(GrantV2Error::InvalidClaim(format!(
            "{label} exceeds the I-JSON safe integer range"
        )));
    }
    Ok(())
}

fn validate_key_id(value: &str, purpose: &str) -> Result<(), GrantV2Error> {
    let prefix = format!("{purpose}:sha256:");
    let Some(fingerprint) = value.strip_prefix(&prefix) else {
        return Err(GrantV2Error::InvalidClaim(
            "key id has the wrong purpose".into(),
        ));
    };
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GrantV2Error::InvalidClaim(
            "key id fingerprint is not canonical".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_envelope::{KeyPurpose, canonicalize, key_id};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32])
    }

    fn claim_fields() -> GrantClaimFields {
        let key = key();
        GrantClaimFields {
            authority_instance: "authority_test".into(),
            authority_epoch: "1".into(),
            grant_id: "grant_test".into(),
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 1_600,
            required_scope: "deploy:staging".into(),
            input_hash: format!("sha256:{}", "1".repeat(64)),
            approval_request_id: "request_test".into(),
            request_hash: format!("sha256:{}", "2".repeat(64)),
            operator_principal: "uid:501".into(),
            reason: "Reviewed\nfor a bounded deployment".into(),
            grant_key_id: key_id(KeyPurpose::Grant, &key.verifying_key()),
        }
    }

    fn claim() -> GrantClaimV2 {
        GrantClaimV2::new(claim_fields()).unwrap()
    }

    #[test]
    fn exact_input_claim_round_trips_and_transitions_once() {
        let key = key();
        let claim = claim();
        let signed_claim = SignedGrantClaimV2::sign(&claim, &key).unwrap();
        assert_eq!(signed_claim.verify(&key.verifying_key()).unwrap(), claim);

        let active = GrantStateV2::active(
            &claim,
            signed_claim.claim_hash(),
            "event_active".into(),
            1_001,
        )
        .unwrap();
        let signed_active = SignedGrantStateV2::sign(&active, &key).unwrap();
        let spent = GrantStateV2::terminal(
            &active,
            signed_active.state_hash(),
            GrantStatusV2::Spent,
            "event_spent".into(),
            1_002,
        )
        .unwrap();
        spent
            .verify_successor_of(&active, signed_active.state_hash())
            .unwrap();
        assert!(
            GrantStateV2::terminal(
                &spent,
                SignedGrantStateV2::sign(&spent, &key).unwrap().state_hash(),
                GrantStatusV2::Revoked,
                "event_invalid".into(),
                1_003,
            )
            .is_err()
        );
    }

    #[test]
    fn delimiter_collision_witness_is_distinct_under_jcs() {
        #[derive(Serialize)]
        struct Pair<'a> {
            left: &'a str,
            right: &'a str,
        }
        let a = Pair {
            left: "a\nb",
            right: "c",
        };
        let b = Pair {
            left: "a",
            right: "b\nc",
        };
        assert_eq!(
            format!("{}\n{}", a.left, a.right),
            format!("{}\n{}", b.left, b.right)
        );
        let a_jcs = canonicalize(&a).unwrap();
        let b_jcs = canonicalize(&b).unwrap();
        assert_ne!(a_jcs, b_jcs);
        assert_ne!(grant_claim_hash(&a_jcs), grant_claim_hash(&b_jcs));
    }

    #[test]
    fn rejects_oversized_and_wrongly_bounded_claims() {
        let mut lifetime = claim_fields();
        lifetime.expires_at = lifetime.issued_at + MAX_GRANT_TTL_SECONDS + 1;
        assert!(GrantClaimV2::new(lifetime).is_err());

        let mut scope = claim_fields();
        scope.required_scope = "x".repeat(MAX_SCOPE_BYTES + 1);
        assert!(GrantClaimV2::new(scope).is_err());

        let mut principal = claim_fields();
        principal.operator_principal = "x".repeat(MAX_PRINCIPAL_BYTES + 1);
        assert!(GrantClaimV2::new(principal).is_err());

        let mut reason = claim_fields();
        reason.reason = "x".repeat(MAX_REASON_BYTES + 1);
        assert!(GrantClaimV2::new(reason).is_err());

        let mut hash = claim_fields();
        hash.input_hash = format!("SHA256:{}", "A".repeat(64));
        assert!(GrantClaimV2::new(hash).is_err());
    }
}
