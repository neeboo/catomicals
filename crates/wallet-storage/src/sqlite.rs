use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use uuid::Uuid;

use crate::{
    ApprovalCeremony, ApprovalDecision, AuditContext, AuditEvent, CredentialMetadata,
    NewApprovalCeremony, NewNonceClaim, NewTransactionIntent, NonceClaim, RestoreState, Result,
    SecretBackend, SecretRef, SqliteSettings, StorageError, TransactionIntent,
    TransactionIntentStatus, WalletMetadata, migrations,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct WalletStorage {
    connection: Connection,
    _owner_lock: File,
}

impl std::fmt::Debug for WalletStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletStorage")
            .finish_non_exhaustive()
    }
}

impl WalletStorage {
    pub fn initialize(path: impl AsRef<Path>, wallet_id: Uuid, now: i64) -> Result<Self> {
        let mut storage = Self::connect(path)?;
        let tx = storage
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO wallet_metadata
             (singleton, wallet_id, epoch, restore_state, created_at, updated_at)
             VALUES (1, ?1, 1, 'normal', ?2, ?2)",
            (wallet_id.to_string(), now),
        )?;
        if inserted == 0 {
            return Err(StorageError::AlreadyInitialized);
        }
        append_audit(
            &tx,
            &WalletMetadata {
                wallet_id,
                epoch: 1,
                restore_state: RestoreState::Normal,
                created_at: now,
                updated_at: now,
            },
            "wallet.initialized",
            Some(wallet_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(storage)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let storage = Self::connect(path)?;
        if !storage.is_initialized()? {
            return Err(StorageError::NotInitialized);
        }
        Ok(storage)
    }

    fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let owner_lock = acquire_owner_lock(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrations::migrate(&mut connection)?;
        Ok(Self {
            connection,
            _owner_lock: owner_lock,
        })
    }

    fn is_initialized(&self) -> Result<bool> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM wallet_metadata WHERE singleton = 1",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn settings(&self) -> Result<SqliteSettings> {
        let foreign_keys = self
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?;
        let journal_mode = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
        let synchronous_code = self
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))?;
        let synchronous = match synchronous_code {
            2 => "full".to_owned(),
            other => other.to_string(),
        };
        let busy_millis = self
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get::<_, u64>(0))?;
        Ok(SqliteSettings {
            foreign_keys,
            journal_mode: journal_mode.to_ascii_lowercase(),
            synchronous,
            busy_timeout: Duration::from_millis(busy_millis),
        })
    }

    pub fn schema_version(&self) -> Result<i32> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn wallet_metadata(&self) -> Result<WalletMetadata> {
        self.connection
            .query_row(
                "SELECT wallet_id, epoch, restore_state, created_at, updated_at
                 FROM wallet_metadata WHERE singleton = 1",
                [],
                |row| {
                    let wallet_id: String = row.get(0)?;
                    let state: String = row.get(2)?;
                    let wallet_id = Uuid::parse_str(&wallet_id).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    let restore_state = RestoreState::parse(&state).ok_or_else(|| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            format!("unknown restore state: {state}").into(),
                        )
                    })?;
                    Ok(WalletMetadata {
                        wallet_id,
                        epoch: row.get(1)?,
                        restore_state,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)
    }

    pub fn create_transaction_intent(&mut self, intent: NewTransactionIntent) -> Result<()> {
        self.create_transaction_intent_with_audit(intent, &AuditContext::default())
    }

    pub fn create_transaction_intent_with_audit(
        &mut self,
        intent: NewTransactionIntent,
        audit_context: &AuditContext,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        tx.execute(
            "INSERT INTO transaction_intents
             (id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
              expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?8)",
            params![
                intent.id.to_string(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                intent.tx_digest.as_slice(),
                intent.policy_hash.as_slice(),
                intent.session_id.as_slice(),
                intent.expires_at,
                intent.created_at,
            ],
        )?;
        append_audit_with_context(
            &tx,
            &metadata,
            "transaction_intent.created",
            Some(intent.id.to_string()),
            intent.created_at,
            Some(intent.id),
            Some(intent.policy_hash),
            audit_context,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn transaction_intent(&self, id: Uuid) -> Result<Option<TransactionIntent>> {
        self.connection
            .query_row(
                "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                        expires_at, created_at, updated_at
                 FROM transaction_intents WHERE id = ?1",
                [id.to_string()],
                map_transaction_intent,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_transaction_intents(&self) -> Result<Vec<TransactionIntent>> {
        let mut statement = self.connection.prepare(
            "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                    expires_at, created_at, updated_at
             FROM transaction_intents ORDER BY created_at ASC, id ASC",
        )?;
        let rows = statement.query_map([], map_transaction_intent)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn transition_transaction_intent(
        &mut self,
        id: Uuid,
        expected: TransactionIntentStatus,
        next: TransactionIntentStatus,
        now: i64,
    ) -> Result<()> {
        if !expected.may_transition_to(next) {
            return Err(StorageError::InvalidIntentTransition {
                from: expected.as_str().to_owned(),
                to: next.as_str().to_owned(),
            });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let changed = tx.execute(
            "UPDATE transaction_intents SET status = ?1, updated_at = ?2
             WHERE id = ?3 AND wallet_id = ?4 AND epoch = ?5 AND status = ?6",
            params![
                next.as_str(),
                now,
                id.to_string(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                expected.as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            &format!("transaction_intent.{}", next.as_str()),
            Some(id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_credential(&mut self, credential: CredentialMetadata) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let prior_sign_count = tx
            .query_row(
                "SELECT sign_count FROM credential_metadata WHERE credential_id = ?1",
                [&credential.credential_id],
                |row| row.get::<_, u64>(0),
            )
            .optional()?;
        if prior_sign_count.is_some_and(|prior| credential.sign_count < prior) {
            return Err(StorageError::CredentialCounterRollback);
        }
        tx.execute(
            "INSERT INTO credential_metadata
             (credential_id, wallet_id, label, cose_public_key, sign_count, enrolled_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(credential_id) DO UPDATE SET
               label = excluded.label,
               cose_public_key = excluded.cose_public_key,
               sign_count = excluded.sign_count,
               updated_at = excluded.updated_at",
            params![
                credential.credential_id,
                metadata.wallet_id.to_string(),
                credential.label,
                credential.cose_public_key,
                credential.sign_count,
                credential.enrolled_at,
                credential.updated_at,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "credential.upserted",
            Some(credential.credential_id),
            credential.updated_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn credential(&self, credential_id: &str) -> Result<Option<CredentialMetadata>> {
        self.connection
            .query_row(
                "SELECT credential_id, label, cose_public_key, sign_count, enrolled_at, updated_at
                 FROM credential_metadata WHERE credential_id = ?1",
                [credential_id],
                |row| {
                    Ok(CredentialMetadata {
                        credential_id: row.get(0)?,
                        label: row.get(1)?,
                        cose_public_key: row.get(2)?,
                        sign_count: row.get(3)?,
                        enrolled_at: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_secret_ref(&mut self, secret: SecretRef) -> Result<()> {
        validate_secret_handle(secret.backend, &secret.handle)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        tx.execute(
            "INSERT INTO secret_refs
             (id, wallet_id, backend, handle, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               backend = excluded.backend,
               handle = excluded.handle,
               updated_at = excluded.updated_at",
            params![
                secret.id.to_string(),
                metadata.wallet_id.to_string(),
                secret.backend.as_str(),
                secret.handle,
                secret.created_at,
                secret.updated_at,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "secret_ref.upserted",
            Some(secret.id.to_string()),
            secret.updated_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn secret_ref(&self, id: Uuid) -> Result<Option<SecretRef>> {
        self.connection
            .query_row(
                "SELECT id, backend, handle, created_at, updated_at FROM secret_refs WHERE id = ?1",
                [id.to_string()],
                |row| {
                    let backend: String = row.get(1)?;
                    Ok(SecretRef {
                        id: uuid_column(row, 0)?,
                        backend: SecretBackend::parse(&backend).ok_or_else(|| {
                            conversion_error(1, format!("unknown secret backend: {backend}"))
                        })?,
                        handle: row.get(2)?,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn consume_authorization(
        &mut self,
        authorization_id: Uuid,
        epoch: u64,
        now: i64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if epoch != metadata.epoch {
            return Err(StorageError::StaleEpoch {
                current: metadata.epoch,
                provided: epoch,
            });
        }
        let changed = tx.execute(
            "UPDATE one_time_authorizations SET consumed_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND consumed_at IS NULL
               AND invalidated_at IS NULL AND expires_at >= ?1",
            params![now, authorization_id.to_string(), epoch],
        )?;
        if changed != 1 {
            return Err(StorageError::AuthorizationUnavailable);
        }
        append_audit(
            &tx,
            &metadata,
            "authorization.consumed",
            Some(authorization_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn claim_nonce(&mut self, claim: NewNonceClaim) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let inserted = tx.execute(
            "INSERT INTO nonce_claims
             (fingerprint, wallet_id, epoch, session_id, claimed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                claim.fingerprint.as_slice(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                claim.session_id.as_slice(),
                claim.claimed_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::NonceAlreadyClaimed);
            }
            return Err(error.into());
        }
        append_audit(&tx, &metadata, "nonce.claimed", None, claim.claimed_at)?;
        tx.commit()?;
        Ok(())
    }

    pub fn nonce_claim(&self, fingerprint: [u8; 32]) -> Result<Option<NonceClaim>> {
        self.connection
            .query_row(
                "SELECT fingerprint, session_id, epoch, claimed_at, invalidated_at
                 FROM nonce_claims WHERE fingerprint = ?1",
                [fingerprint.as_slice()],
                |row| {
                    Ok(NonceClaim {
                        fingerprint: array32_column(row, 0)?,
                        session_id: array32_column(row, 1)?,
                        epoch: row.get(2)?,
                        claimed_at: row.get(3)?,
                        invalidated_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn begin_approval_ceremony_atomic(&mut self, ceremony: NewApprovalCeremony) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let intent =
            pending_intent_facts(&tx, ceremony.intent_id, metadata.epoch, ceremony.started_at)?;
        if ceremony.expires_at <= ceremony.started_at {
            return Err(StorageError::ApprovalCeremonyExpired);
        }
        if ceremony.expires_at > intent.expires_at {
            return Err(StorageError::ApprovalCeremonyExceedsIntentExpiry);
        }
        tx.execute(
            "INSERT INTO approval_ceremonies
             (id, wallet_id, intent_id, epoch, started_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ceremony.id.to_string(),
                metadata.wallet_id.to_string(),
                ceremony.intent_id.to_string(),
                metadata.epoch,
                ceremony.started_at,
                ceremony.expires_at,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "approval_ceremony.started",
            Some(ceremony.id.to_string()),
            ceremony.started_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn approve_and_issue_authorization(
        &mut self,
        decision: ApprovalDecision,
        audit_context: &AuditContext,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let ceremony = tx
            .query_row(
                "SELECT intent_id, epoch, expires_at, completed_at, invalidated_at
                 FROM approval_ceremonies WHERE id = ?1",
                [decision.ceremony_id.to_string()],
                |row| {
                    Ok((
                        uuid_column(row, 0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::ApprovalCeremonyUnavailable)?;
        let authorization_exists = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM one_time_authorizations WHERE intent_id = ?1)",
            [ceremony.0.to_string()],
            |row| row.get::<_, bool>(0),
        )?;
        if authorization_exists {
            return Err(StorageError::AuthorizationAlreadyExists);
        }
        if ceremony.1 != metadata.epoch || ceremony.3.is_some() || ceremony.4.is_some() {
            return Err(StorageError::ApprovalCeremonyUnavailable);
        }
        let intent = pending_intent_facts(&tx, ceremony.0, metadata.epoch, decision.approved_at)?;
        if decision.approved_at > ceremony.2 {
            return Err(StorageError::ApprovalCeremonyExpired);
        }
        if decision.authorization_expires_at < decision.approved_at {
            return Err(StorageError::AuthorizationExpiresBeforeApproval);
        }
        if decision.authorization_expires_at > intent.expires_at {
            return Err(StorageError::AuthorizationExceedsIntentExpiry);
        }
        let ceremony_changed = tx.execute(
            "UPDATE approval_ceremonies SET completed_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND completed_at IS NULL
               AND invalidated_at IS NULL AND expires_at >= ?1",
            params![
                decision.approved_at,
                decision.ceremony_id.to_string(),
                metadata.epoch,
            ],
        )?;
        let intent_changed = tx.execute(
            "UPDATE transaction_intents SET status = 'approved', updated_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND status = 'pending'",
            params![decision.approved_at, ceremony.0.to_string(), metadata.epoch],
        )?;
        if ceremony_changed != 1 || intent_changed != 1 {
            return Err(StorageError::IntentNotApprovable);
        }
        let inserted = tx.execute(
            "INSERT INTO one_time_authorizations
             (id, wallet_id, intent_id, epoch, binding_digest, expires_at, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                decision.authorization_id.to_string(),
                metadata.wallet_id.to_string(),
                ceremony.0.to_string(),
                metadata.epoch,
                decision.binding_digest.as_slice(),
                decision.authorization_expires_at,
                decision.approved_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::AuthorizationAlreadyExists);
            }
            return Err(error.into());
        }
        append_audit_with_context(
            &tx,
            &metadata,
            "approval.completed",
            Some(decision.ceremony_id.to_string()),
            decision.approved_at,
            Some(ceremony.0),
            Some(intent.policy_hash),
            audit_context,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn approval_ceremony(&self, id: Uuid) -> Result<Option<ApprovalCeremony>> {
        self.connection
            .query_row(
                "SELECT id, intent_id, epoch, started_at, expires_at, completed_at, invalidated_at
                 FROM approval_ceremonies WHERE id = ?1",
                [id.to_string()],
                |row| {
                    Ok(ApprovalCeremony {
                        id: uuid_column(row, 0)?,
                        intent_id: uuid_column(row, 1)?,
                        epoch: row.get(2)?,
                        started_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        completed_at: row.get(5)?,
                        invalidated_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, wallet_id, epoch, event_type, subject_id, payload_json, created_at
             FROM audit_events ORDER BY sequence ASC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as u64], map_audit_event)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn recent_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, wallet_id, epoch, event_type, subject_id, payload_json, created_at
             FROM (
                 SELECT sequence, wallet_id, epoch, event_type, subject_id, payload_json, created_at
                 FROM audit_events ORDER BY sequence DESC LIMIT ?1
             ) recent
             ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([limit as u64], map_audit_event)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn begin_restore_precheck(&mut self, now: i64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut metadata = metadata_in(&tx)?;
        require_restore_state(
            metadata.restore_state,
            RestoreState::Normal,
            RestoreState::RestorePrecheck,
        )?;
        tx.execute(
            "UPDATE approval_ceremonies SET invalidated_at = ?1
             WHERE epoch = ?2 AND completed_at IS NULL AND invalidated_at IS NULL",
            params![now, metadata.epoch],
        )?;
        tx.execute(
            "UPDATE wallet_metadata
             SET restore_state = 'restore_precheck', updated_at = ?1 WHERE singleton = 1",
            [now],
        )?;
        metadata.restore_state = RestoreState::RestorePrecheck;
        metadata.updated_at = now;
        append_audit(&tx, &metadata, "restore.restore_precheck", None, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn begin_snapshot(&mut self, now: i64) -> Result<()> {
        self.transition_restore(RestoreState::Normal, RestoreState::Snapshotting, now)
    }

    pub fn finish_snapshot(&mut self, now: i64) -> Result<()> {
        self.transition_restore(RestoreState::Snapshotting, RestoreState::Normal, now)
    }

    pub fn cutover_restore(&mut self, now: i64) -> Result<u64> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = metadata_in(&tx)?;
        require_restore_state(
            old.restore_state,
            RestoreState::RestorePrecheck,
            RestoreState::Cutover,
        )?;
        let new_epoch = old
            .epoch
            .checked_add(1)
            .ok_or_else(|| StorageError::InvalidStoredValue("wallet epoch overflow".to_owned()))?;
        tx.execute(
            "UPDATE wallet_metadata SET epoch = ?1, restore_state = 'cutover', updated_at = ?2
             WHERE singleton = 1",
            params![new_epoch, now],
        )?;
        tx.execute(
            "UPDATE approval_ceremonies SET invalidated_at = ?1
             WHERE epoch < ?2 AND completed_at IS NULL AND invalidated_at IS NULL",
            params![now, new_epoch],
        )?;
        tx.execute(
            "UPDATE one_time_authorizations SET invalidated_at = ?1
             WHERE epoch < ?2 AND consumed_at IS NULL AND invalidated_at IS NULL",
            params![now, new_epoch],
        )?;
        tx.execute(
            "UPDATE nonce_claims SET invalidated_at = ?1
             WHERE epoch < ?2 AND invalidated_at IS NULL",
            params![now, new_epoch],
        )?;
        tx.execute(
            "UPDATE transaction_intents SET status = 'invalidated', updated_at = ?1
             WHERE epoch < ?2 AND status IN ('pending', 'approved', 'signing')",
            params![now, new_epoch],
        )?;
        let current = WalletMetadata {
            epoch: new_epoch,
            restore_state: RestoreState::Cutover,
            updated_at: now,
            ..old
        };
        append_audit(&tx, &current, "restore.cutover", None, now)?;
        tx.commit()?;
        Ok(new_epoch)
    }

    pub fn begin_recovering(&mut self, now: i64) -> Result<()> {
        self.transition_restore(RestoreState::Cutover, RestoreState::Recovering, now)
    }

    pub fn finish_recovery(&mut self, now: i64) -> Result<()> {
        self.transition_restore(RestoreState::Recovering, RestoreState::Normal, now)
    }

    fn transition_restore(&mut self, from: RestoreState, to: RestoreState, now: i64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut metadata = metadata_in(&tx)?;
        require_restore_state(metadata.restore_state, from, to)?;
        tx.execute(
            "UPDATE wallet_metadata SET restore_state = ?1, updated_at = ?2 WHERE singleton = 1",
            params![to.as_str(), now],
        )?;
        metadata.restore_state = to;
        metadata.updated_at = now;
        append_audit(
            &tx,
            &metadata,
            &format!("restore.{}", to.as_str()),
            None,
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn metadata_in(tx: &Transaction<'_>) -> Result<WalletMetadata> {
    tx.query_row(
        "SELECT wallet_id, epoch, restore_state, created_at, updated_at
         FROM wallet_metadata WHERE singleton = 1",
        [],
        |row| {
            let state: String = row.get(2)?;
            Ok(WalletMetadata {
                wallet_id: uuid_column(row, 0)?,
                epoch: row.get(1)?,
                restore_state: RestoreState::parse(&state).ok_or_else(|| {
                    conversion_error(2, format!("unknown restore state: {state}"))
                })?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
    .optional()?
    .ok_or(StorageError::NotInitialized)
}

fn append_audit(
    tx: &Transaction<'_>,
    metadata: &WalletMetadata,
    event_type: &str,
    subject_id: Option<String>,
    now: i64,
) -> Result<()> {
    append_audit_with_context(
        tx,
        metadata,
        event_type,
        subject_id,
        now,
        None,
        None,
        &AuditContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn append_audit_with_context(
    tx: &Transaction<'_>,
    metadata: &WalletMetadata,
    event_type: &str,
    subject_id: Option<String>,
    now: i64,
    intent_id: Option<Uuid>,
    policy_hash: Option<[u8; 32]>,
    audit_context: &AuditContext,
) -> Result<()> {
    let payload = serde_json::json!({
        "component_version": audit_context.component_version,
        "schema_version": migrations::CURRENT_SCHEMA_VERSION,
        "wallet_id": metadata.wallet_id,
        "intent_id": intent_id,
        "policy_hash": policy_hash.map(hex::encode),
        "node_snapshot_id": audit_context.node_snapshot_id,
        "actor_ref": audit_context.actor.redacted_ref(),
    });
    tx.execute(
        "INSERT INTO audit_events
         (wallet_id, epoch, event_type, subject_id, payload_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            metadata.wallet_id.to_string(),
            metadata.epoch,
            event_type,
            subject_id,
            payload.to_string(),
            now,
        ],
    )?;
    Ok(())
}

struct PendingIntentFacts {
    expires_at: i64,
    policy_hash: [u8; 32],
}

fn pending_intent_facts(
    tx: &Transaction<'_>,
    intent_id: Uuid,
    current_epoch: u64,
    now: i64,
) -> Result<PendingIntentFacts> {
    let facts = tx
        .query_row(
            "SELECT status, expires_at, policy_hash
             FROM transaction_intents WHERE id = ?1 AND epoch = ?2",
            params![intent_id.to_string(), current_epoch],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    array32_column(row, 2)?,
                ))
            },
        )
        .optional()?;
    let Some((status, expires_at, policy_hash)) = facts else {
        return Err(StorageError::IntentNotApprovable);
    };
    if status != "pending" {
        return Err(StorageError::IntentNotApprovable);
    }
    if now > expires_at {
        return Err(StorageError::IntentExpired);
    }
    Ok(PendingIntentFacts {
        expires_at,
        policy_hash,
    })
}

fn ensure_mutations_allowed(metadata: &WalletMetadata) -> Result<()> {
    match metadata.restore_state {
        RestoreState::Normal | RestoreState::Snapshotting => Ok(()),
        state => Err(StorageError::MutationBlocked {
            state: state.as_str().to_owned(),
        }),
    }
}

fn require_restore_state(
    actual: RestoreState,
    expected: RestoreState,
    to: RestoreState,
) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(StorageError::InvalidRestoreTransition {
            from: actual.as_str().to_owned(),
            to: to.as_str().to_owned(),
        })
    }
}

fn validate_secret_handle(backend: SecretBackend, handle: &str) -> Result<()> {
    if handle.starts_with(backend.required_prefix())
        && handle.len() > backend.required_prefix().len()
    {
        Ok(())
    } else {
        Err(StorageError::InvalidSecretHandle {
            backend: backend.as_str(),
        })
    }
}

fn map_transaction_intent(row: &Row<'_>) -> rusqlite::Result<TransactionIntent> {
    let status: String = row.get(6)?;
    Ok(TransactionIntent {
        id: uuid_column(row, 0)?,
        wallet_id: uuid_column(row, 1)?,
        epoch: row.get(2)?,
        tx_digest: array32_column(row, 3)?,
        policy_hash: array32_column(row, 4)?,
        session_id: array32_column(row, 5)?,
        status: TransactionIntentStatus::parse(&status)
            .ok_or_else(|| conversion_error(6, format!("unknown intent status: {status}")))?,
        expires_at: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn map_audit_event(row: &Row<'_>) -> rusqlite::Result<AuditEvent> {
    let payload: String = row.get(5)?;
    Ok(AuditEvent {
        sequence: row.get(0)?,
        wallet_id: uuid_column(row, 1)?,
        epoch: row.get(2)?,
        event_type: row.get(3)?,
        subject_id: row.get(4)?,
        payload: serde_json::from_str(&payload).map_err(|error| conversion_error(5, error))?,
        created_at: row.get(6)?,
    })
}

fn uuid_column(row: &Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    let value: String = row.get(index)?;
    Uuid::parse_str(&value).map_err(|error| conversion_error(index, error))
}

fn array32_column(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; 32]> {
    let value: Vec<u8> = row.get(index)?;
    value.try_into().map_err(|value: Vec<u8>| {
        conversion_error(index, format!("expected 32 bytes, got {}", value.len()))
    })
}

fn conversion_error(index: usize, error: impl ToString) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn acquire_owner_lock(database_path: &Path) -> Result<File> {
    let lock_path = owner_lock_path(database_path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(StorageError::WriterAlreadyActive)
        }
        Err(error) => Err(error.into()),
    }
}

fn owner_lock_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(".owner.lock");
    PathBuf::from(path)
}
