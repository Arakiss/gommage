use super::recovery::{checkpoint_seq, reconcile_retention};
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthorityHealthV2 {
    Ready,
    Poisoned,
}

impl Authority {
    pub(super) fn ensure_ready(&self) -> Result<(), AuthorityError> {
        if self.health == AuthorityHealthV2::Poisoned {
            return Err(AuthorityError::Poisoned);
        }
        Ok(())
    }

    pub(super) fn verify_ready(
        &self,
        conn: &Connection,
    ) -> Result<LedgerVerification, AuthorityError> {
        self.ensure_ready()?;
        self.storage.verify()?;
        self.require_cached_checkpoint_is_durably_active()?;
        let verification = verify_all(
            conn,
            &self.config,
            &self.grant_key.verifying_key(),
            &self.ledger_key.verifying_key(),
            Some(&self.active_checkpoint),
        )?;
        require_checkpoint_at_head(
            &self.active_checkpoint,
            &verification,
            &self.config,
            &self.ledger_key.verifying_key(),
        )?;
        self.require_cached_checkpoint_is_durably_active()?;
        self.storage.verify()?;
        Ok(verification)
    }

    fn require_cached_checkpoint_is_durably_active(&self) -> Result<(), AuthorityError> {
        let state = self
            .retention
            .load()
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Load,
                outcome,
            })?;
        match state {
            CheckpointRetentionStateV2::Active(active) if active == self.active_checkpoint => {
                Ok(())
            }
            CheckpointRetentionStateV2::Active(_) => Err(AuthorityError::RollbackDetected(
                "cached checkpoint is not the durable active checkpoint".into(),
            )),
            CheckpointRetentionStateV2::Empty
            | CheckpointRetentionStateV2::BootstrapPending(_)
            | CheckpointRetentionStateV2::ActiveWithPending { .. } => {
                Err(AuthorityError::RecoveryAmbiguous(
                    "reads require one exact durable active checkpoint".into(),
                ))
            }
        }
    }

    pub(super) fn retained_commit<T>(
        &mut self,
        operation: impl FnOnce(&Connection, &LedgerVerification) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        self.ensure_ready()?;
        self.verify_storage_or_poison()?;
        let config = self.config.clone();
        let grant_key = self.grant_key.clone();
        let ledger_key = self.ledger_key.clone();
        let ledger_key_id = self.ledger_key_id.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retained_state =
            self.retention
                .load()
                .map_err(|outcome| AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Load,
                    outcome,
                })?;
        let active = match reconcile_retention(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            retained_state,
            self.retention.as_mut(),
        ) {
            Ok(active) => active,
            Err(error) => {
                if matches!(
                    &error,
                    AuthorityError::Retention {
                        operation: CheckpointRetentionOperationV2::Promote,
                        ..
                    }
                ) {
                    self.health = AuthorityHealthV2::Poisoned;
                }
                return Err(error);
            }
        };
        self.active_checkpoint = active.clone();
        let before = verify_all(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            Some(&active),
        )?;
        require_checkpoint_at_head(&active, &before, &config, &ledger_key.verifying_key())?;

        let result = match operation(&tx, &before) {
            Ok(result) => result,
            Err(error) => {
                if tx.rollback().is_err() {
                    self.health = AuthorityHealthV2::Poisoned;
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                self.verify_storage_or_poison()?;
                return Err(error);
            }
        };
        let after = match verify_all(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            Some(&active),
        ) {
            Ok(after) => after,
            Err(error) => {
                if tx.rollback().is_err() {
                    self.health = AuthorityHealthV2::Poisoned;
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                self.verify_storage_or_poison()?;
                return Err(error);
            }
        };
        if after.head_seq == before.head_seq && after.head_hash == before.head_hash {
            if tx.commit().is_err() {
                self.health = AuthorityHealthV2::Poisoned;
                return Err(AuthorityError::CommitOutcomeIndeterminate);
            }
            self.verify_storage_or_poison()?;
            return Ok(result);
        }

        let next = match sign_head_checkpoint(&config, &ledger_key_id, &ledger_key, &after)
            .and_then(|next| {
                validate_successor_checkpoint(&active, &next, &ledger_key.verifying_key())?;
                Ok(next)
            }) {
            Ok(next) => next,
            Err(error) => {
                if tx.rollback().is_err() {
                    self.health = AuthorityHealthV2::Poisoned;
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                self.verify_storage_or_poison()?;
                return Err(error);
            }
        };
        match self.retention.stage(Some(&active), &next) {
            Ok(()) => {}
            Err(CheckpointRetentionErrorV2::Rejected) => {
                if tx.rollback().is_err() {
                    self.health = AuthorityHealthV2::Poisoned;
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                self.verify_storage_or_poison()?;
                return Err(AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Stage,
                    outcome: CheckpointRetentionErrorV2::Rejected,
                });
            }
            Err(CheckpointRetentionErrorV2::Indeterminate) => {
                self.health = AuthorityHealthV2::Poisoned;
                if tx.rollback().is_err() {
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                return Err(AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Stage,
                    outcome: CheckpointRetentionErrorV2::Indeterminate,
                });
            }
        }

        if tx.commit().is_err() {
            self.health = AuthorityHealthV2::Poisoned;
            return Err(AuthorityError::CommitOutcomeIndeterminate);
        }
        if let Err(error) = self.retention.promote(Some(&active), &next) {
            self.health = AuthorityHealthV2::Poisoned;
            return Err(AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Promote,
                outcome: error,
            });
        }
        self.active_checkpoint = next;
        self.verify_storage_or_poison()?;
        Ok(result)
    }

    fn verify_storage_or_poison(&mut self) -> Result<(), AuthorityError> {
        if let Err(error) = self.storage.verify() {
            self.health = AuthorityHealthV2::Poisoned;
            return Err(error);
        }
        Ok(())
    }
}

fn validate_successor_checkpoint(
    active: &SignedLedgerCheckpointV2,
    next: &SignedLedgerCheckpointV2,
    ledger_key: &VerifyingKey,
) -> Result<(), AuthorityError> {
    let active = active.verify(ledger_key)?;
    let next = next.verify(ledger_key)?;
    if checkpoint_seq(&next)? <= checkpoint_seq(&active)? {
        return Err(AuthorityError::Corrupt(
            "successor checkpoint does not strictly advance the active sequence".into(),
        ));
    }
    Ok(())
}

pub(super) fn sign_head_checkpoint(
    config: &AuthorityConfig,
    ledger_key_id: &str,
    ledger_key: &SigningKey,
    verification: &LedgerVerification,
) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
    let last = verification
        .entries
        .last()
        .ok_or_else(|| AuthorityError::Corrupt("authority ledger has no genesis entry".into()))?;
    let checkpoint_id = checkpoint_id_for_head(&verification.head_seq, &verification.head_hash)?;
    sign_checkpoint(
        config,
        ledger_key_id,
        ledger_key,
        &checkpoint_id,
        last.entry.timestamp(),
        verification.head_seq.clone(),
        verification.head_hash.clone(),
    )
}

pub(super) fn require_checkpoint_at_head(
    signed: &SignedLedgerCheckpointV2,
    verification: &LedgerVerification,
    config: &AuthorityConfig,
    ledger_key: &VerifyingKey,
) -> Result<LedgerCheckpointV2, AuthorityError> {
    let checkpoint =
        require_checkpoint_for_verified_prefix(signed, verification, config, ledger_key)?;
    if checkpoint.head_seq() != verification.head_seq
        || checkpoint.head_hash() != verification.head_hash
    {
        return Err(AuthorityError::RollbackDetected(
            "active checkpoint does not equal the verified database head".into(),
        ));
    }
    Ok(checkpoint)
}

pub(super) fn require_checkpoint_for_verified_prefix(
    signed: &SignedLedgerCheckpointV2,
    verification: &LedgerVerification,
    config: &AuthorityConfig,
    ledger_key: &VerifyingKey,
) -> Result<LedgerCheckpointV2, AuthorityError> {
    let checkpoint = signed.verify(ledger_key)?;
    let expected_ledger_key_id = key_id(KeyPurpose::Ledger, ledger_key);
    if checkpoint.authority_instance() != config.instance_id
        || checkpoint.authority_epoch() != config.epoch
        || checkpoint.ledger_key_id() != expected_ledger_key_id
    {
        return Err(AuthorityError::RollbackDetected(
            "checkpoint identity does not match the verified authority".into(),
        ));
    }
    let expected_checkpoint_id =
        checkpoint_id_for_head(checkpoint.head_seq(), checkpoint.head_hash())?;
    if checkpoint.checkpoint_id() != expected_checkpoint_id {
        return Err(AuthorityError::RollbackDetected(
            "checkpoint id is not the deterministic authority head id".into(),
        ));
    }
    let sequence = usize::try_from(checkpoint_seq(&checkpoint)?)
        .map_err(|_| AuthorityError::Corrupt("checkpoint sequence overflow".into()))?;
    let entry = sequence
        .checked_sub(1)
        .and_then(|index| verification.entries.get(index))
        .ok_or_else(|| {
            AuthorityError::RollbackDetected(
                "checkpoint sequence is outside the verified database prefix".into(),
            )
        })?;
    if entry.entry_hash != checkpoint.head_hash()
        || entry.entry.timestamp() != checkpoint.created_at()
    {
        return Err(AuthorityError::RollbackDetected(
            "checkpoint hash or timestamp contradicts its verified ledger entry".into(),
        ));
    }
    Ok(checkpoint)
}

pub(super) fn checkpoint_id_for_head(
    head_seq: &str,
    head_hash: &str,
) -> Result<String, AuthorityError> {
    let hash_suffix = head_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| AuthorityError::Corrupt("ledger head hash is not canonical".into()))?;
    Ok(format!("head:{head_seq}:{hash_suffix}"))
}
