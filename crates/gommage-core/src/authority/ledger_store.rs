use super::*;

pub(super) struct LedgerEventDraft {
    pub(super) event_id: String,
    pub(super) subject: String,
    pub(super) timestamp: i64,
    pub(super) build_identity: Option<String>,
    pub(super) policy_identity: Option<String>,
    pub(super) payload: LedgerPayloadV2,
}

pub(super) fn append_ledger_entry(
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
