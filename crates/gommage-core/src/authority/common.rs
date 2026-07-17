use super::*;

pub(super) fn validate_timestamp(timestamp: i64) -> Result<(), AuthorityError> {
    if timestamp.unsigned_abs() > crate::crypto_envelope::MAX_SAFE_INTEGER {
        return Err(AuthorityError::InvalidInput(
            "timestamp exceeds the I-JSON safe integer range".into(),
        ));
    }
    Ok(())
}

pub(super) fn authority_now(source: &dyn AuthorityRuntimeSource) -> Result<i64, AuthorityError> {
    let timestamp = source.unix_timestamp()?;
    validate_timestamp(timestamp)?;
    Ok(timestamp)
}

pub(super) fn authority_id(
    source: &dyn AuthorityRuntimeSource,
    prefix: &str,
) -> Result<String, AuthorityError> {
    validate_token("authority id prefix", prefix, 32)?;
    let nonce = source.identifier_nonce()?;
    validate_token("authority identifier nonce", &nonce, 120)?;
    let identifier = format!("{prefix}_{nonce}");
    validate_token("authority-generated id", &identifier, 160)?;
    Ok(identifier)
}

pub(super) fn validate_key_identifier(value: &str, purpose: &str) -> Result<(), AuthorityError> {
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

pub(super) fn sign_checkpoint(
    config: &AuthorityConfig,
    ledger_key_id: &str,
    ledger_key: &SigningKey,
    checkpoint_id: &str,
    created_at: i64,
    head_seq: String,
    head_hash: String,
) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
    validate_token("checkpoint id", checkpoint_id, 160)?;
    validate_timestamp(created_at)?;
    let checkpoint = LedgerCheckpointV2 {
        domain: CHECKPOINT_DOMAIN.into(),
        version: FORMAT_VERSION,
        checkpoint_id: checkpoint_id.into(),
        authority_instance: config.instance_id.clone(),
        authority_epoch: config.epoch.clone(),
        created_at,
        head_seq,
        head_hash,
        ledger_key_id: ledger_key_id.into(),
    };
    checkpoint.validate()?;
    Ok(SignedLedgerCheckpointV2 {
        envelope: sign_payload(EnvelopeDomain::LedgerCheckpoint, &checkpoint, ledger_key)?,
    })
}
