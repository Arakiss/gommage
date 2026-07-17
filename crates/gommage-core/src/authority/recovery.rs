use super::*;
use rusqlite::OpenFlags;

impl Authority {
    /// Exclusively create, durably anchor, and return a usable Authority v2.
    ///
    /// Retention must load as empty or as the exact pending genesis from an
    /// interrupted bootstrap. Genesis is committed and synced at a private
    /// sibling path, durably staged, published without replacing the final
    /// pathname, and promoted before an Authority can be returned.
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
        validate_authority_inputs(path, &config, &grant_key, &ledger_key)?;
        let writer = AuthorityWriterGuard::acquire(path)?;
        let retained_state = retention
            .load()
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Load,
                outcome,
            })?;
        if !matches!(
            retained_state,
            CheckpointRetentionStateV2::Empty | CheckpointRetentionStateV2::BootstrapPending(_)
        ) {
            return Err(AuthorityError::RecoveryAmbiguous(
                "bootstrap requires empty retention or one pending genesis".into(),
            ));
        }
        writer.ensure_database_absent()?;
        let (bootstrap_path, database) = writer.prepare_bootstrap_database()?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let mut bootstrap_conn = Connection::open_with_flags(
            &bootstrap_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_connection(&bootstrap_conn)?;
        let genesis = initialize_or_resume_bootstrap(
            &mut bootstrap_conn,
            &config,
            &grant_key,
            &ledger_key,
            &grant_key_id,
            &ledger_key_id,
            &retained_state,
            retention.as_mut(),
        )?;
        checkpoint_and_close_bootstrap(bootstrap_conn)?;
        writer.sync_bootstrap_database(&bootstrap_path, &database)?;
        writer.publish_bootstrap_database(&bootstrap_path, &database)?;

        let mut conn = Connection::open_with_flags(
            writer.database_path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        writer.verify_database(&database)?;
        configure_connection(&conn)?;
        verify_open_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_open_metadata(&tx, &config, &grant_key_id, &ledger_key_id)?;
        let retained_state = load_retention(retention.as_ref())?;
        let active = reconcile_retention(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            retained_state,
            retention.as_mut(),
        )?;
        if active != genesis {
            return Err(AuthorityError::RollbackDetected(
                "bootstrap promotion did not retain the exact prepared genesis".into(),
            ));
        }
        tx.commit()?;
        require_retention_active(retention.as_ref(), &active)?;
        writer.verify_database(&database)?;
        let storage = writer.bind_database(database)?;

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
            storage,
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
        let writer = AuthorityWriterGuard::acquire(path)?;
        let retained_state = load_retention(retention.as_ref())?;
        writer.recover_bootstrap_publication(&retained_state)?;
        let database = writer.open_database()?;
        let grant_key_id = key_id(KeyPurpose::Grant, &grant_key.verifying_key());
        let ledger_key_id = key_id(KeyPurpose::Ledger, &ledger_key.verifying_key());
        let mut conn = Connection::open_with_flags(
            writer.database_path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        writer.verify_database(&database)?;
        configure_connection(&conn)?;
        verify_open_schema(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_open_metadata(&tx, &config, &grant_key_id, &ledger_key_id)?;
        let active = reconcile_retention(
            &tx,
            &config,
            &grant_key.verifying_key(),
            &ledger_key.verifying_key(),
            retained_state,
            retention.as_mut(),
        )?;
        tx.commit()?;
        require_retention_active(retention.as_ref(), &active)?;
        writer.verify_database(&database)?;
        let storage = writer.bind_database(database)?;

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
            storage,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn initialize_or_resume_bootstrap(
    conn: &mut Connection,
    config: &AuthorityConfig,
    grant_key: &SigningKey,
    ledger_key: &SigningKey,
    grant_key_id: &str,
    ledger_key_id: &str,
    retained_state: &CheckpointRetentionStateV2,
    retention: &mut dyn CheckpointRetentionV2,
) -> Result<SignedLedgerCheckpointV2, AuthorityError> {
    let application_id: i32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let uninitialized = application_id == 0 && user_version == 0;
    if !uninitialized && (application_id != APPLICATION_ID || user_version != SCHEMA_VERSION) {
        return Err(AuthorityError::Schema(format!(
            "bootstrap preparation has application_id {application_id} and user_version {user_version}"
        )));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if uninitialized {
        initialize_schema_in_transaction(&tx, config, grant_key_id, ledger_key_id, ledger_key)?;
    } else {
        verify_open_metadata(&tx, config, grant_key_id, ledger_key_id)?;
    }
    let verification = verify_all(
        &tx,
        config,
        &grant_key.verifying_key(),
        &ledger_key.verifying_key(),
        None,
    )?;
    if verification.head_seq != "1" {
        return Err(AuthorityError::Corrupt(
            "bootstrap preparation contains state beyond genesis".into(),
        ));
    }
    let genesis = sign_head_checkpoint(config, ledger_key_id, ledger_key, &verification)?;

    let admission = match retained_state {
        CheckpointRetentionStateV2::Empty if uninitialized => retention
            .stage(None, &genesis)
            .map_err(|outcome| AuthorityError::Retention {
                operation: CheckpointRetentionOperationV2::Stage,
                outcome,
            }),
        CheckpointRetentionStateV2::Empty => Err(AuthorityError::RecoveryAmbiguous(
            "initialized bootstrap preparation cannot be anchored from empty retention".into(),
        )),
        CheckpointRetentionStateV2::BootstrapPending(pending) if pending == &genesis => {
            verify_all(
                &tx,
                config,
                &grant_key.verifying_key(),
                &ledger_key.verifying_key(),
                Some(pending),
            )?;
            Ok(())
        }
        CheckpointRetentionStateV2::BootstrapPending(_) => Err(AuthorityError::RollbackDetected(
            "bootstrap preparation does not match the durably pending genesis".into(),
        )),
        CheckpointRetentionStateV2::Active(_)
        | CheckpointRetentionStateV2::ActiveWithPending { .. } => {
            Err(AuthorityError::RecoveryAmbiguous(
                "bootstrap cannot run after retention has an active checkpoint".into(),
            ))
        }
    };
    if let Err(error) = admission {
        if tx.rollback().is_err() {
            return Err(AuthorityError::CommitOutcomeIndeterminate);
        }
        return Err(error);
    }
    tx.commit()
        .map_err(|_| AuthorityError::CommitOutcomeIndeterminate)?;
    Ok(genesis)
}

fn checkpoint_and_close_bootstrap(conn: Connection) -> Result<(), AuthorityError> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(AuthorityError::Storage(format!(
            "bootstrap WAL did not checkpoint completely: busy={busy}, log={log_frames}, checkpointed={checkpointed_frames}"
        )));
    }
    conn.close().map_err(|(_, error)| error.into())
}

fn load_retention(
    retention: &dyn CheckpointRetentionV2,
) -> Result<CheckpointRetentionStateV2, AuthorityError> {
    retention
        .load()
        .map_err(|outcome| AuthorityError::Retention {
            operation: CheckpointRetentionOperationV2::Load,
            outcome,
        })
}

fn require_retention_active(
    retention: &dyn CheckpointRetentionV2,
    expected: &SignedLedgerCheckpointV2,
) -> Result<(), AuthorityError> {
    match load_retention(retention)? {
        CheckpointRetentionStateV2::Active(active) if &active == expected => Ok(()),
        CheckpointRetentionStateV2::Active(_) => Err(AuthorityError::RollbackDetected(
            "durable active checkpoint changed before Authority open completed".into(),
        )),
        _ => Err(AuthorityError::RecoveryAmbiguous(
            "Authority open did not finish with one exact active checkpoint".into(),
        )),
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
