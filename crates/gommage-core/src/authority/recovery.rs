use super::*;
use rusqlite::OpenFlags;
use std::fs::OpenOptions;

impl Authority {
    /// Exclusively create, durably anchor, and return a usable Authority v2.
    ///
    /// Retention must load as empty. Bootstrap stages the signed genesis head,
    /// commits SQLite, and promotes the checkpoint before returning an Authority.
    pub fn bootstrap(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        retention: Box<dyn CheckpointRetentionV2>,
    ) -> Result<Self, AuthorityError> {
        Self::bootstrap_with_runtime_source(
            path,
            config,
            grant_key,
            ledger_key,
            retention,
            Arc::new(SystemAuthorityRuntimeSource),
        )
    }

    /// Bootstrap with an explicitly selected trusted runtime source.
    pub fn bootstrap_with_runtime_source(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        mut retention: Box<dyn CheckpointRetentionV2>,
        runtime_source: Arc<dyn AuthorityRuntimeSource>,
    ) -> Result<Self, AuthorityError> {
        if retention
            .load()
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Load,
                outcome,
            })?
            != CheckpointRetentionStateV2::Empty
        {
            return Err(AuthorityError::RecoveryAmbiguous(
                "bootstrap requires empty checkpoint retention".into(),
            ));
        }
        validate_authority_inputs(path, &config, &grant_key, &ledger_key)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                AuthorityError::InvalidInput(format!(
                    "bootstrap requires a new authority database path: {error}"
                ))
            })?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        let current_application_id: i32 =
            conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let current_user_version: i32 =
            conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current_application_id != 0 || current_user_version != 0 {
            return Err(AuthorityError::Schema(
                "bootstrap path changed before schema initialization".into(),
            ));
        }

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        initialize_schema_in_transaction(&tx, &config, &grant_key_id, &ledger_key_id, &ledger_key)?;
        let verification = verify_all(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            None,
        )?;
        let genesis = sign_head_checkpoint(&config, &ledger_key_id, &ledger_key, &verification)?;
        match retention.stage(None, &genesis) {
            Ok(()) => {}
            Err(error @ CheckpointRetentionErrorV2::Rejected) => {
                if tx.rollback().is_err() {
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                return Err(AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Stage,
                    outcome: error,
                });
            }
            Err(error @ CheckpointRetentionErrorV2::Indeterminate) => {
                if tx.rollback().is_err() {
                    return Err(AuthorityError::CommitOutcomeIndeterminate);
                }
                return Err(AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Stage,
                    outcome: error,
                });
            }
        }
        tx.commit()
            .map_err(|_| AuthorityError::CommitOutcomeIndeterminate)?;
        retention
            .promote(None, &genesis)
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Promote,
                outcome,
            })?;

        Ok(Self {
            conn,
            config,
            grant_key,
            ledger_key,
            grant_key_id,
            ledger_key_id,
            active_checkpoint: genesis,
            retention,
            health: AuthorityHealthV2::Ready,
            runtime_source,
        })
    }

    /// Open and reconcile an Authority against its durable retention state.
    pub fn open(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        retention: Box<dyn CheckpointRetentionV2>,
    ) -> Result<Self, AuthorityError> {
        Self::open_with_runtime_source(
            path,
            config,
            grant_key,
            ledger_key,
            retention,
            Arc::new(SystemAuthorityRuntimeSource),
        )
    }

    /// Open and reconcile with an explicitly selected trusted runtime source.
    pub fn open_with_runtime_source(
        path: &Path,
        config: AuthorityConfig,
        grant_key: SigningKey,
        ledger_key: SigningKey,
        mut retention: Box<dyn CheckpointRetentionV2>,
        runtime_source: Arc<dyn AuthorityRuntimeSource>,
    ) -> Result<Self, AuthorityError> {
        validate_authority_inputs(path, &config, &grant_key, &ledger_key)?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        verify_open_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_open_metadata(&tx, &config, &grant_key_id, &ledger_key_id)?;
        let retained_state = retention
            .load()
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Load,
                outcome,
            })?;
        let active = reconcile_retention(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            retained_state,
            retention.as_mut(),
        )?;
        tx.commit()?;

        Ok(Self {
            conn,
            config,
            grant_key,
            ledger_key,
            grant_key_id,
            ledger_key_id,
            active_checkpoint: active,
            retention,
            health: AuthorityHealthV2::Ready,
            runtime_source,
        })
    }
}

pub(super) fn reconcile_retention(
    conn: &Connection,
    config: &AuthorityConfig,
    grant_key: &VerifyingKey,
    ledger_key: &VerifyingKey,
    state: CheckpointRetentionStateV2,
    retention: &mut dyn CheckpointRetentionV2,
) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
    if state == CheckpointRetentionStateV2::Empty {
        return Err(AuthorityError::RecoveryAmbiguous(
            "an initialized database cannot open with empty retention".into(),
        ));
    }
    let verification = verify_all(conn, config, grant_key, ledger_key, None)?;
    match state {
        CheckpointRetentionStateV2::Empty => unreachable!(),
        CheckpointRetentionStateV2::Active(active) => {
            verify_all(conn, config, grant_key, ledger_key, Some(&active))?;
            require_checkpoint_at_head(&active, &verification, config, ledger_key)?;
            Ok(active)
        }
        CheckpointRetentionStateV2::BootstrapPending(pending) => {
            verify_all(conn, config, grant_key, ledger_key, Some(&pending))?;
            require_checkpoint_at_head(&pending, &verification, config, ledger_key)?;
            retention
                .promote(None, &pending)
                .map_err(|outcome| AuthorityError::Retention {
                    operation: CheckpointRetentionOperationV2::Promote,
                    outcome,
                })?;
            Ok(pending)
        }
        CheckpointRetentionStateV2::ActiveWithPending { active, pending } => {
            let active_checkpoint = active.verify(ledger_key)?;
            let pending_checkpoint = pending.verify(ledger_key)?;
            validate_checkpoint_identity(&active_checkpoint, config, ledger_key)?;
            validate_checkpoint_identity(&pending_checkpoint, config, ledger_key)?;
            let active_seq = checkpoint_seq(&active_checkpoint)?;
            let pending_seq = checkpoint_seq(&pending_checkpoint)?;
            if pending_seq <= active_seq {
                return Err(AuthorityError::RecoveryAmbiguous(
                    "pending checkpoint does not strictly advance active retention".into(),
                ));
            }
            if pending_checkpoint.head_seq() == verification.head_seq
                && pending_checkpoint.head_hash() == verification.head_hash
            {
                verify_all(conn, config, grant_key, ledger_key, Some(&active))?;
                verify_all(conn, config, grant_key, ledger_key, Some(&pending))?;
                require_checkpoint_for_verified_prefix(&active, &verification, config, ledger_key)?;
                require_checkpoint_at_head(&pending, &verification, config, ledger_key)?;
                retention
                    .promote(Some(&active), &pending)
                    .map_err(|outcome| AuthorityError::Retention {
                        operation: CheckpointRetentionOperationV2::Promote,
                        outcome,
                    })?;
                Ok(pending)
            } else if active_checkpoint.head_seq() == verification.head_seq
                && active_checkpoint.head_hash() == verification.head_hash
            {
                Err(AuthorityError::RecoveryAmbiguous(
                    "pending retention with a database at the active head is ambiguous".into(),
                ))
            } else {
                Err(AuthorityError::RollbackDetected(
                    "database head matches neither active nor pending retention".into(),
                ))
            }
        }
    }
}

fn validate_checkpoint_identity(
    checkpoint: &LedgerCheckpointV2,
    config: &AuthorityConfig,
    ledger_key: &VerifyingKey,
) -> Result<(), AuthorityError> {
    let expected_ledger_key_id = key_id(KeyPurpose::Ledger, ledger_key);
    let expected_checkpoint_id =
        checkpoint_id_for_head(checkpoint.head_seq(), checkpoint.head_hash())?;
    if checkpoint.authority_instance() != config.instance_id
        || checkpoint.authority_epoch() != config.epoch
        || checkpoint.ledger_key_id() != expected_ledger_key_id
        || checkpoint.checkpoint_id() != expected_checkpoint_id
    {
        return Err(AuthorityError::RollbackDetected(
            "retained checkpoint belongs to another authority".into(),
        ));
    }
    Ok(())
}

pub(super) fn checkpoint_seq(checkpoint: &LedgerCheckpointV2) -> Result<u64, AuthorityError> {
    checkpoint
        .head_seq()
        .parse::<u64>()
        .map_err(|_| AuthorityError::Corrupt("checkpoint sequence overflow".into()))
}

fn verify_open_schema(conn: &Connection) -> Result<(), AuthorityError> {
    let current_application_id: i32 =
        conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let current_user_version: i32 =
        conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current_application_id != APPLICATION_ID || current_user_version != SCHEMA_VERSION {
        return Err(AuthorityError::Schema(format!(
            "expected application_id {APPLICATION_ID} and user_version {SCHEMA_VERSION}, got {current_application_id} and {current_user_version}"
        )));
    }
    Ok(())
}

fn verify_open_metadata(
    conn: &Connection,
    config: &AuthorityConfig,
    grant_key_id: &str,
    ledger_key_id: &str,
) -> Result<(), AuthorityError> {
    verify_pragmas(conn)?;
    let metadata = read_metadata(conn)?;
    if metadata.instance_id != config.instance_id
        || metadata.epoch != config.epoch
        || metadata.genesis_generation != config.genesis_generation
        || metadata.grant_key_id != grant_key_id
        || metadata.ledger_key_id != ledger_key_id
        || metadata.cutover != CutoverStateV2::FreshV2NoLegacyActiveGrants
    {
        return Err(AuthorityError::Corrupt(
            "opened metadata does not match supplied instance, build, cutover, or keys".into(),
        ));
    }
    Ok(())
}

fn validate_authority_inputs(
    path: &Path,
    config: &AuthorityConfig,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
) -> Result<(), AuthorityError> {
    config.validate()?;
    let path_text = path.to_string_lossy();
    if path.as_os_str().is_empty() || path_text == ":memory:" || path_text.starts_with("file:") {
        return Err(AuthorityError::InvalidInput(
            "reference authority requires a regular file path".into(),
        ));
    }
    if grant_key.verifying_key() == ledger_key.verifying_key() {
        return Err(AuthorityError::InvalidInput(
            "grant and ledger keys must be distinct".into(),
        ));
    }
    Ok(())
}
