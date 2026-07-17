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
