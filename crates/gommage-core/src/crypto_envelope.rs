//! Canonical, purpose-bound cryptographic envelopes for Authority v2.
//!
//! The signed bytes are RFC 8785 JSON Canonicalization Scheme (JCS) bytes
//! prefixed by a versioned Gommage domain. Verification deliberately parses
//! untrusted JSON through a duplicate-detecting I-JSON reader before comparing
//! the stored bytes with a fresh canonicalization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::{collections::HashSet, fmt};
use thiserror::Error;

/// Largest integer that round-trips exactly through an I-JSON binary64 number.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum canonical payload size accepted by an Authority v2 envelope.
pub const MAX_CANONICAL_BYTES: usize = 1_048_576;

const GRANT_CLAIM_DOMAIN: &[u8] = b"GOMMAGE\0GRANT_CLAIM\0V2\0";
const GRANT_STATE_DOMAIN: &[u8] = b"GOMMAGE\0GRANT_STATE\0V2\0";
const LEDGER_ENTRY_DOMAIN: &[u8] = b"GOMMAGE\0LEDGER_ENTRY\0V2\0";
const LEDGER_CHECKPOINT_DOMAIN: &[u8] = b"GOMMAGE\0LEDGER_CHECKPOINT\0V2\0";

const GRANT_CLAIM_HASH_DOMAIN: &[u8] = b"GOMMAGE\0GRANT_CLAIM_HASH\0V2\0";
const GRANT_STATE_HASH_DOMAIN: &[u8] = b"GOMMAGE\0GRANT_STATE_HASH\0V2\0";
const LEDGER_ENTRY_HASH_DOMAIN: &[u8] = b"GOMMAGE\0LEDGER_ENTRY_HASH\0V2\0";
const APPROVAL_REQUEST_HASH_DOMAIN: &[u8] = b"GOMMAGE\0APPROVAL_REQUEST_HASH\0V2\0";
const APPROVAL_DEDUPE_HASH_DOMAIN: &[u8] = b"GOMMAGE\0APPROVAL_DEDUPE_HASH\0V2\0";

/// The exclusive purpose assigned to an Authority v2 signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Signs grant claims and grant-state revisions.
    Grant,
    /// Signs ledger entries and externally retained checkpoints.
    Ledger,
}

impl KeyPurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Ledger => "ledger",
        }
    }
}

/// A fixed Authority v2 signature domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeDomain {
    /// A grant claim.
    GrantClaim,
    /// A grant-state revision.
    GrantState,
    /// An append-only ledger entry.
    LedgerEntry,
    /// A ledger checkpoint intended for an external trust store.
    LedgerCheckpoint,
}

impl EnvelopeDomain {
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::GrantClaim => GRANT_CLAIM_DOMAIN,
            Self::GrantState => GRANT_STATE_DOMAIN,
            Self::LedgerEntry => LEDGER_ENTRY_DOMAIN,
            Self::LedgerCheckpoint => LEDGER_CHECKPOINT_DOMAIN,
        }
    }

    fn purpose(self) -> KeyPurpose {
        match self {
            Self::GrantClaim | Self::GrantState => KeyPurpose::Grant,
            Self::LedgerEntry | Self::LedgerCheckpoint => KeyPurpose::Ledger,
        }
    }
}

/// A canonical JSON payload and its detached Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJcs {
    jcs: String,
    signature_b64: String,
}

impl SignedJcs {
    /// Return the exact canonical bytes covered by the signature.
    pub fn jcs(&self) -> &str {
        &self.jcs
    }

    /// Return the canonical URL-safe, unpadded signature text.
    pub fn signature_b64(&self) -> &str {
        &self.signature_b64
    }

    /// Reconstruct an envelope from stored, untrusted fields.
    ///
    /// Verification must still be performed before the payload is trusted.
    pub fn from_stored(jcs: String, signature_b64: String) -> Self {
        Self { jcs, signature_b64 }
    }
}

/// A signed payload that embeds the exact identifier of its signing key.
pub trait KeyBound {
    /// Return the embedded purpose-qualified public-key fingerprint.
    fn key_id(&self) -> &str;
}

/// Failures while parsing, canonicalizing, signing, or verifying an envelope.
#[derive(Debug, Error)]
pub enum CryptoEnvelopeError {
    /// The JSON representation is malformed or violates the strict input rules.
    #[error("invalid canonical JSON: {0}")]
    InvalidJson(String),
    /// A value is not in the signed Authority v2 data model.
    #[error("invalid signed value: {0}")]
    InvalidValue(String),
    /// Stored bytes are valid JSON but are not the unique JCS representation.
    #[error("stored JSON is not canonical")]
    NonCanonical,
    /// The embedded key identifier does not match the required key and purpose.
    #[error("incorrect signing key purpose or fingerprint")]
    IncorrectKeyPurpose,
    /// Signature text is malformed or the Ed25519 verification failed.
    #[error("signature verification failed")]
    BadSignature,
}

/// Return the canonical purpose-qualified identifier for a verifying key.
pub fn key_id(purpose: KeyPurpose, key: &VerifyingKey) -> String {
    let fingerprint = Sha256::digest(key.as_bytes());
    format!("{}:sha256:{}", purpose.label(), hex::encode(fingerprint))
}

/// Canonicalize a typed value after enforcing the no-float, I-JSON integer guard.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoEnvelopeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| CryptoEnvelopeError::InvalidValue(error.to_string()))?;
    validate_value(&value)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| CryptoEnvelopeError::InvalidValue(error.to_string()))?;
    if canonical.len() > MAX_CANONICAL_BYTES {
        return Err(CryptoEnvelopeError::InvalidValue(format!(
            "canonical payload exceeds {MAX_CANONICAL_BYTES} bytes"
        )));
    }
    Ok(canonical)
}

/// Strictly decode bytes and require that they already are the unique JCS form.
pub(crate) fn decode_canonical<T>(bytes: &[u8]) -> Result<T, CryptoEnvelopeError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(CryptoEnvelopeError::InvalidJson(format!(
            "canonical payload exceeds {MAX_CANONICAL_BYTES} bytes"
        )));
    }
    let value = strict_json_value(bytes)?;
    validate_value(&value)?;
    let payload: T = serde_json::from_value(value)
        .map_err(|error| CryptoEnvelopeError::InvalidJson(error.to_string()))?;
    if canonicalize(&payload)? != bytes {
        return Err(CryptoEnvelopeError::NonCanonical);
    }
    Ok(payload)
}

/// Sign a typed payload in a fixed, purpose-bound domain.
pub fn sign_payload<T: Serialize + KeyBound>(
    domain: EnvelopeDomain,
    payload: &T,
    key: &SigningKey,
) -> Result<SignedJcs, CryptoEnvelopeError> {
    let expected_key_id = key_id(domain.purpose(), &key.verifying_key());
    if payload.key_id() != expected_key_id {
        return Err(CryptoEnvelopeError::IncorrectKeyPurpose);
    }
    let jcs = canonicalize(payload)?;
    let signature = key.sign(&domain_message(domain, &jcs));
    Ok(SignedJcs {
        jcs: String::from_utf8(jcs)
            .map_err(|error| CryptoEnvelopeError::InvalidValue(error.to_string()))?,
        signature_b64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

/// Strictly parse and verify a stored canonical envelope.
pub fn verify_payload<T>(
    domain: EnvelopeDomain,
    envelope: &SignedJcs,
    key: &VerifyingKey,
) -> Result<T, CryptoEnvelopeError>
where
    T: DeserializeOwned + Serialize + KeyBound,
{
    let payload: T = decode_canonical(envelope.jcs.as_bytes())?;
    let canonical = envelope.jcs.as_bytes();
    if payload.key_id() != key_id(domain.purpose(), key) {
        return Err(CryptoEnvelopeError::IncorrectKeyPurpose);
    }
    let signature = decode_signature(&envelope.signature_b64)?;
    key.verify(&domain_message(domain, canonical), &signature)
        .map_err(|_| CryptoEnvelopeError::BadSignature)?;
    Ok(payload)
}

/// Hash canonical bytes with the fixed grant-claim hash domain.
pub(crate) fn grant_claim_hash(jcs: &[u8]) -> String {
    prefixed_hash(GRANT_CLAIM_HASH_DOMAIN, &[jcs])
}

/// Hash canonical bytes with the fixed grant-state hash domain.
pub(crate) fn grant_state_hash(jcs: &[u8]) -> String {
    prefixed_hash(GRANT_STATE_HASH_DOMAIN, &[jcs])
}

/// Hash a ledger entry over its canonical bytes and raw signature.
pub(crate) fn ledger_entry_hash(jcs: &[u8], raw_signature: &[u8]) -> String {
    prefixed_hash(LEDGER_ENTRY_HASH_DOMAIN, &[jcs, raw_signature])
}

/// Hash an immutable approval request.
pub(crate) fn approval_request_hash(jcs: &[u8]) -> String {
    prefixed_hash(APPROVAL_REQUEST_HASH_DOMAIN, &[jcs])
}

/// Hash the canonical fields that define an open-approval deduplication slot.
pub(crate) fn approval_dedupe_hash(jcs: &[u8]) -> String {
    prefixed_hash(APPROVAL_DEDUPE_HASH_DOMAIN, &[jcs])
}

/// Decode a signature while requiring the single canonical text form.
pub(crate) fn signature_bytes(text: &str) -> Result<[u8; 64], CryptoEnvelopeError> {
    if text.len() != 86 {
        return Err(CryptoEnvelopeError::BadSignature);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CryptoEnvelopeError::BadSignature)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(CryptoEnvelopeError::BadSignature);
    }
    bytes
        .try_into()
        .map_err(|_| CryptoEnvelopeError::BadSignature)
}

fn decode_signature(text: &str) -> Result<Signature, CryptoEnvelopeError> {
    Ok(Signature::from_bytes(&signature_bytes(text)?))
}

fn domain_message(domain: EnvelopeDomain, jcs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.prefix().len() + jcs.len());
    message.extend_from_slice(domain.prefix());
    message.extend_from_slice(jcs);
    message
}

fn prefixed_hash(prefix: &[u8], parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(prefix);
    for part in parts {
        digest.update(part);
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn validate_value(value: &Value) -> Result<(), CryptoEnvelopeError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => validate_number(number),
        Value::Array(values) => values.iter().try_for_each(validate_value),
        Value::Object(values) => values.values().try_for_each(validate_value),
    }
}

fn validate_number(number: &Number) -> Result<(), CryptoEnvelopeError> {
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_INTEGER {
            return Err(CryptoEnvelopeError::InvalidValue(
                "integer exceeds the I-JSON safe range".into(),
            ));
        }
        return Ok(());
    }
    if let Some(value) = number.as_i64() {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CryptoEnvelopeError::InvalidValue(
                "integer exceeds the I-JSON safe range".into(),
            ));
        }
        return Ok(());
    }
    Err(CryptoEnvelopeError::InvalidValue(
        "floating-point values are not permitted in signed payloads".into(),
    ))
}

fn strict_json_value(bytes: &[u8]) -> Result<Value, CryptoEnvelopeError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| CryptoEnvelopeError::InvalidJson(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| CryptoEnvelopeError::InvalidJson(error.to_string()))?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> serde::de::Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict I-JSON without duplicate keys or floating-point values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer exceeds the I-JSON safe range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("integer exceeds the I-JSON safe range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(
            "floating-point values are not permitted in signed payloads",
        ))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object member {key:?}"
                )));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        key_id: String,
        value: String,
    }

    impl KeyBound for Payload {
        fn key_id(&self) -> &str {
            &self.key_id
        }
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn signs_and_verifies_only_in_the_bound_domain() {
        let key = key(7);
        let other_key = SigningKey::from_bytes(&[10; 32]);
        let payload = Payload {
            key_id: key_id(KeyPurpose::Grant, &key.verifying_key()),
            value: "test".into(),
        };
        let signed = sign_payload(EnvelopeDomain::GrantClaim, &payload, &key).unwrap();
        let verified: Payload =
            verify_payload(EnvelopeDomain::GrantClaim, &signed, &key.verifying_key()).unwrap();
        assert_eq!(verified, payload);
        assert!(matches!(
            verify_payload::<Payload>(EnvelopeDomain::LedgerEntry, &signed, &key.verifying_key()),
            Err(CryptoEnvelopeError::IncorrectKeyPurpose) | Err(CryptoEnvelopeError::BadSignature)
        ));
        assert!(matches!(
            verify_payload::<Payload>(
                EnvelopeDomain::GrantClaim,
                &signed,
                &other_key.verifying_key()
            ),
            Err(CryptoEnvelopeError::IncorrectKeyPurpose) | Err(CryptoEnvelopeError::BadSignature)
        ));
    }

    #[test]
    fn rejects_duplicate_unknown_noncanonical_float_and_unsafe_integer_json() {
        let key = key(8);
        let id = key_id(KeyPurpose::Grant, &key.verifying_key());
        for jcs in [
            format!(r#"{{"key_id":"{id}","key_id":"{id}","value":"x"}}"#),
            format!(r#"{{"key_id":"{id}","unknown":true,"value":"x"}}"#),
            format!(r#"{{ "key_id":"{id}","value":"x"}}"#),
            format!(r#"{{"key_id":"{id}","value":"x","number":1.5}}"#),
            format!(r#"{{"key_id":"{id}","value":"x","number":9007199254740992}}"#),
        ] {
            let envelope = SignedJcs::from_stored(jcs, URL_SAFE_NO_PAD.encode([0_u8; 64]));
            assert!(
                verify_payload::<Payload>(
                    EnvelopeDomain::GrantClaim,
                    &envelope,
                    &key.verifying_key()
                )
                .is_err()
            );
        }
        assert!(canonicalize(&1.5_f64).is_err());
        assert!(canonicalize(&(MAX_SAFE_INTEGER + 1)).is_err());
    }

    #[test]
    fn rfc_8785_canonicalization_vector() {
        let value: Value = serde_json::from_str(
            r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000f\nA'B\"\\\"/"}"#,
        )
        .unwrap();
        let canonical = serde_json_canonicalizer::to_string(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\"/"}"#
        );
    }

    #[test]
    fn strict_reader_rejects_invalid_utf8() {
        assert!(matches!(
            strict_json_value(&[0xff, 0xfe]),
            Err(CryptoEnvelopeError::InvalidJson(_))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_utf8_envelopes_never_panic(
            jcs in ".{0,4096}",
            signature in ".{0,256}",
        ) {
            let envelope = SignedJcs::from_stored(jcs, signature);
            let _ = verify_payload::<Payload>(
                EnvelopeDomain::GrantClaim,
                &envelope,
                &key(9).verifying_key(),
            );
        }
    }
}
