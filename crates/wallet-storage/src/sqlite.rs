use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use catomicals_signing_domain::{
    SignerBackendRequirement, SigningSuiteId, require_executable_suite,
};
use catomicals_threshold::{
    DeviceHealth, DeviceStatus, ProviderError, ProviderIdentity, ProviderReplayStore,
    SignerDeviceRecord, SignerProviderKind, SignerRequestContext,
};
use fs2::FileExt;
use rusqlite::{
    Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    ApprovalCeremony, ApprovalDecision, ApprovalNonce, AuditContext, AuditEvent,
    AuthorizationRecord, ChainExecutorClaim, CredentialMetadata, CredentialState,
    FrostNonceAuthorizationClaim, IntentAction, IntentCursor, IntentMaterial, IntentMaterialKind,
    IntentNetwork, NewAddressBinding, NewApprovalCeremony, NewNonceClaim,
    NewPasskeyApprovalCeremony, NewPasskeyRecord, NewPersonalSigningOperation,
    NewSignerCatalogEntry, NewSignerProfile, NewSigningJob, NewTransactionIntent,
    NewTransactionIntentV2, NonceClaim, PasskeyApprovalCompletion, PasskeyRecord,
    PersonalSigningOperation, PersonalSigningOperationStatus, PersonalSigningReceipt,
    PersonalSigningRound, RestoreState, Result, SecretBackend, SecretRef,
    SignerCatalogInstallOutcome, SignerProfileInventoryRecord, SignerProfileRecord,
    SigningJobStatus, SqliteSettings, StorageError, StoredAddressBinding, StoredSigningJob,
    TransactionIntent, TransactionIntentStatus, TransactionIntentV2, WalletMetadata,
    WebauthnProfile, migrations,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Durable wallet authority storage.
///
/// Personal signing operations cannot be inserted without consuming their
/// approved one-time authorization:
///
/// ```compile_fail
/// use catomicals_wallet_storage::{NewPersonalSigningOperation, WalletStorage};
/// let mut storage: WalletStorage = todo!();
/// let operation: NewPersonalSigningOperation = todo!();
/// storage.create_personal_signing_operation(operation).unwrap();
/// ```
pub struct WalletStorage {
    pub(crate) connection: Connection,
    _owner_lock: File,
    startup_invalidated_ceremonies: u64,
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
        let path = path.as_ref();
        let owner_lock = acquire_owner_lock(path)?;
        let recovery = crate::backup::recover_interrupted_cutover(path)?;
        let (connection, startup_invalidated_ceremonies) = open_database_connection(path)?;
        let mut storage =
            Self::from_retained_owner_lock(connection, owner_lock, startup_invalidated_ceremonies);
        if let Some(recovery) = recovery {
            storage.record_cutover_recovery(recovery)?;
            crate::backup::complete_interrupted_cutover(path, recovery)?;
        }
        Ok(storage)
    }

    fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let owner_lock = acquire_owner_lock(path)?;
        let recovery = crate::backup::recover_interrupted_cutover(path)?;
        let connection = if path.exists() {
            connect_existing_database(path)?
        } else {
            connect_new_database(path)?
        };
        let mut storage = Self::from_retained_owner_lock(connection, owner_lock, 0);
        if let Some(recovery) = recovery {
            storage.record_cutover_recovery(recovery)?;
            crate::backup::complete_interrupted_cutover(path, recovery)?;
            return Err(StorageError::AlreadyInitialized);
        }
        Ok(storage)
    }

    pub(crate) fn open_database_connection(path: &Path) -> Result<(Connection, u64)> {
        open_database_connection(path)
    }

    pub(crate) fn open_staged_database(path: &Path) -> Result<Self> {
        let owner_lock = acquire_owner_lock(path)?;
        let (connection, startup_invalidated_ceremonies) = open_database_connection(path)?;
        Ok(Self::from_retained_owner_lock(
            connection,
            owner_lock,
            startup_invalidated_ceremonies,
        ))
    }

    pub(crate) fn from_retained_owner_lock(
        connection: Connection,
        owner_lock: File,
        startup_invalidated_ceremonies: u64,
    ) -> Self {
        Self {
            connection,
            _owner_lock: owner_lock,
            startup_invalidated_ceremonies,
        }
    }

    pub(crate) fn into_owner_lock(self) -> File {
        let Self {
            connection,
            _owner_lock,
            startup_invalidated_ceremonies: _,
        } = self;
        drop(connection);
        _owner_lock
    }

    /// Number of incomplete approval ceremonies invalidated by this open.
    pub fn startup_invalidated_ceremonies(&self) -> u64 {
        self.startup_invalidated_ceremonies
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

    pub fn create_transaction_intent_v2(
        &mut self,
        intent: NewTransactionIntentV2,
        material: IntentMaterial,
    ) -> Result<()> {
        validate_new_v2_intent(&intent, &material)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        tx.execute(
            "INSERT INTO transaction_intents
             (id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
              expires_at, created_at, updated_at, network, protocol_version, action,
              signer_id, approval_nonce, intent_schema_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?8, ?9, ?10,
                     ?11, ?12, ?13, 2)",
            params![
                intent.id.to_string(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                intent.tx_digest.as_slice(),
                intent.policy_hash.as_slice(),
                intent.session_id.as_slice(),
                intent.expires_at,
                intent.created_at,
                intent.network.as_str(),
                intent.protocol_version,
                intent.action.as_str(),
                intent.signer_id,
                intent.approval_nonce.0.as_slice(),
            ],
        )?;
        tx.execute(
            "INSERT INTO intent_materials
             (intent_id, kind, payload_json, payload_hash, node_snapshot_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                material.intent_id.to_string(),
                material.kind.as_str(),
                material.payload_json.to_string(),
                material.payload_hash.as_slice(),
                material.node_snapshot_id,
            ],
        )?;
        let context = AuditContext {
            node_snapshot_id: Some(material.node_snapshot_id.clone()),
            ..AuditContext::default()
        };
        append_audit_with_context(
            &tx,
            &metadata,
            "transaction_intent.v2_created",
            Some(intent.id.to_string()),
            intent.created_at,
            Some(intent.id),
            Some(intent.policy_hash),
            &context,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn transaction_intent_v2(&self, id: Uuid) -> Result<Option<TransactionIntentV2>> {
        self.connection
            .query_row(
                "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                        expires_at, created_at, updated_at, network, protocol_version, action,
                        signer_id, approval_nonce, intent_schema_version
                 FROM transaction_intents WHERE id = ?1 AND intent_schema_version = 2",
                [id.to_string()],
                map_transaction_intent_v2,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn latest_transaction_intent_v2(&self) -> Result<Option<TransactionIntentV2>> {
        let metadata = self.wallet_metadata()?;
        self.connection
            .query_row(
                "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                        expires_at, created_at, updated_at, network, protocol_version, action,
                        signer_id, approval_nonce, intent_schema_version
                 FROM transaction_intents
                 WHERE wallet_id = ?1 AND epoch = ?2 AND intent_schema_version = 2
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![metadata.wallet_id.to_string(), metadata.epoch],
                map_transaction_intent_v2,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn intent_material(&self, intent_id: Uuid) -> Result<Option<IntentMaterial>> {
        self.connection
            .query_row(
                "SELECT intent_id, kind, payload_json, payload_hash, node_snapshot_id
                 FROM intent_materials WHERE intent_id = ?1 ORDER BY kind LIMIT 1",
                [intent_id.to_string()],
                map_intent_material,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Recovery cursor for one material kind across current-epoch v2 intents.
    /// This keeps durable startup to a bounded number of queries instead of
    /// issuing one material lookup per intent.
    pub fn list_intent_materials(&self, kind: IntentMaterialKind) -> Result<Vec<IntentMaterial>> {
        let metadata = self.wallet_metadata()?;
        let mut statement = self.connection.prepare(
            "SELECT material.intent_id, material.kind, material.payload_json,
                    material.payload_hash, material.node_snapshot_id
             FROM intent_materials AS material
             JOIN transaction_intents AS intent ON intent.id = material.intent_id
             WHERE intent.wallet_id = ?1 AND intent.epoch = ?2
               AND intent.intent_schema_version = 2 AND material.kind = ?3
             ORDER BY intent.created_at ASC, intent.id ASC",
        )?;
        let rows = statement.query_map(
            params![
                metadata.wallet_id.to_string(),
                metadata.epoch,
                kind.as_str()
            ],
            map_intent_material,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn transaction_intents_v2_page(
        &self,
        status: TransactionIntentStatus,
        cursor: Option<IntentCursor>,
        limit: usize,
    ) -> Result<Vec<TransactionIntentV2>> {
        if limit == 0 || limit > 500 {
            return Err(StorageError::InvalidV2Intent(
                "page limit must be between 1 and 500".to_owned(),
            ));
        }
        let metadata = self.wallet_metadata()?;
        let (cursor_created_at, cursor_id) = cursor
            .map(|cursor| (cursor.created_at, cursor.id.to_string()))
            .unwrap_or((i64::MIN, String::new()));
        let mut statement = self.connection.prepare(
            "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                    expires_at, created_at, updated_at, network, protocol_version, action,
                    signer_id, approval_nonce, intent_schema_version
             FROM transaction_intents
             WHERE wallet_id = ?1 AND epoch = ?2 AND status = ?3
               AND intent_schema_version = 2
               AND (created_at > ?4 OR (created_at = ?4 AND id > ?5))
             ORDER BY created_at ASC, id ASC LIMIT ?6",
        )?;
        let rows = statement.query_map(
            params![
                metadata.wallet_id.to_string(),
                metadata.epoch,
                status.as_str(),
                cursor_created_at,
                cursor_id,
                limit as u64,
            ],
            map_transaction_intent_v2,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Recovery cursor for all current-epoch v2 intents.
    pub fn list_transaction_intents_v2(&self) -> Result<Vec<TransactionIntentV2>> {
        let metadata = self.wallet_metadata()?;
        let mut statement = self.connection.prepare(
            "SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                    expires_at, created_at, updated_at, network, protocol_version, action,
                    signer_id, approval_nonce, intent_schema_version
             FROM transaction_intents
             WHERE wallet_id = ?1 AND epoch = ?2 AND intent_schema_version = 2
             ORDER BY created_at ASC, id ASC",
        )?;
        let rows = statement.query_map(
            params![metadata.wallet_id.to_string(), metadata.epoch],
            map_transaction_intent_v2,
        )?;
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
        if expected == TransactionIntentStatus::Approved && next == TransactionIntentStatus::Signing
        {
            let is_v2: bool = tx.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM transaction_intents
                     WHERE id = ?1 AND wallet_id = ?2 AND epoch = ?3
                       AND intent_schema_version = 2
                 )",
                params![
                    id.to_string(),
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                ],
                |row| row.get(0),
            )?;
            if is_v2 {
                return Err(StorageError::LegacyApiRejectedForV2);
            }
        }
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

    pub fn set_webauthn_profile(&mut self, profile: WebauthnProfile) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if profile.wallet_id != metadata.wallet_id {
            return Err(StorageError::WebauthnProfileMismatch);
        }
        let existing = tx
            .query_row(
                "SELECT user_id, rp_id, rp_origin, record_version
                 FROM webauthn_profiles WHERE wallet_id = ?1",
                [metadata.wallet_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((user_id, rp_id, rp_origin, record_version)) = existing {
            if user_id != profile.user_id
                || rp_id != profile.rp_id
                || rp_origin != profile.rp_origin
                || profile.record_version <= record_version
            {
                return Err(StorageError::WebauthnProfileMismatch);
            }
            tx.execute(
                "UPDATE webauthn_profiles SET record_version = ?1, updated_at = ?2
                 WHERE wallet_id = ?3 AND record_version = ?4",
                params![
                    profile.record_version,
                    profile.updated_at,
                    metadata.wallet_id.to_string(),
                    record_version,
                ],
            )?;
        } else {
            if profile.record_version != 1
                || profile.user_id.is_empty()
                || profile.rp_id.is_empty()
                || profile.rp_origin.is_empty()
            {
                return Err(StorageError::WebauthnProfileMismatch);
            }
            tx.execute(
                "INSERT INTO webauthn_profiles
                 (wallet_id, user_id, rp_id, rp_origin, record_version, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    metadata.wallet_id.to_string(),
                    profile.user_id,
                    profile.rp_id,
                    profile.rp_origin,
                    profile.updated_at,
                ],
            )?;
        }
        append_audit(
            &tx,
            &metadata,
            "webauthn.profile_persisted",
            Some(metadata.wallet_id.to_string()),
            profile.updated_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn webauthn_profile(&self) -> Result<Option<WebauthnProfile>> {
        self.connection
            .query_row(
                "SELECT wallet_id, user_id, rp_id, rp_origin, record_version, updated_at
                 FROM webauthn_profiles LIMIT 1",
                [],
                |row| {
                    Ok(WebauthnProfile {
                        wallet_id: uuid_column(row, 0)?,
                        user_id: row.get(1)?,
                        rp_id: row.get(2)?,
                        rp_origin: row.get(3)?,
                        record_version: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn insert_passkey_record(&mut self, record: NewPasskeyRecord) -> Result<()> {
        if record.credential_state != CredentialState::Active
            || record.credential_id.is_empty()
            || record.format.is_empty()
            || serde_json::from_str::<serde_json::Value>(&record.passkey_json).is_err()
        {
            return Err(StorageError::CredentialUnavailable);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let has_profile: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM webauthn_profiles WHERE wallet_id = ?1)",
            [metadata.wallet_id.to_string()],
            |row| row.get(0),
        )?;
        if !has_profile {
            return Err(StorageError::WebauthnProfileMismatch);
        }
        tx.execute(
            "INSERT INTO credential_metadata
             (credential_id, wallet_id, label, cose_public_key, sign_count, enrolled_at,
              updated_at, passkey_json, passkey_format, credential_record_version,
              credential_state)
             VALUES (?1, ?2, ?3, '', 0, ?4, ?4, ?5, ?6, 1, ?7)",
            params![
                record.credential_id,
                metadata.wallet_id.to_string(),
                record.label,
                record.enrolled_at,
                record.passkey_json,
                record.format,
                record.credential_state.as_str(),
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            "credential.passkey_enrolled",
            Some(record.credential_id),
            record.enrolled_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_passkey_record_cas(
        &mut self,
        credential_id: &str,
        expected_record_version: u64,
        updated_passkey_json: &str,
        now: i64,
    ) -> Result<()> {
        if serde_json::from_str::<serde_json::Value>(updated_passkey_json).is_err() {
            return Err(StorageError::CredentialUnavailable);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let changed = update_passkey_record_in(
            &tx,
            credential_id,
            expected_record_version,
            updated_passkey_json,
            now,
        )?;
        if changed != 1 {
            return Err(StorageError::CredentialVersionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "credential.passkey_updated",
            Some(credential_id.to_owned()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn passkey_record(&self, credential_id: &str) -> Result<Option<PasskeyRecord>> {
        self.connection
            .query_row(
                "SELECT credential_id, wallet_id, label, passkey_json, passkey_format,
                        credential_record_version, credential_state, enrolled_at, updated_at
                 FROM credential_metadata WHERE credential_id = ?1
                   AND credential_state = 'active'",
                [credential_id],
                map_passkey_record,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Recovery cursor for active Passkey public credential records.
    pub fn list_passkey_records(&self) -> Result<Vec<PasskeyRecord>> {
        let metadata = self.wallet_metadata()?;
        let mut statement = self.connection.prepare(
            "SELECT credential_id, wallet_id, label, passkey_json, passkey_format,
                    credential_record_version, credential_state, enrolled_at, updated_at
             FROM credential_metadata
             WHERE wallet_id = ?1 AND credential_state = 'active'
             ORDER BY credential_id ASC",
        )?;
        let rows = statement.query_map([metadata.wallet_id.to_string()], map_passkey_record)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
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

    pub fn register_signer_profile(&mut self, profile: NewSignerProfile) -> Result<()> {
        validate_new_signer_profile(&profile)?;
        let scope_json = serde_json::to_string(&profile.chain_scope)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != profile.wallet_id {
            return Err(StorageError::InvalidSignerProfile);
        }
        let secret_wallet: Option<String> = tx
            .query_row(
                "SELECT wallet_id FROM secret_refs WHERE id = ?1",
                [profile.secret_ref_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if secret_wallet != Some(metadata.wallet_id.to_string()) {
            return Err(StorageError::InvalidSignerProfile);
        }
        let inserted = tx.execute(
            "INSERT INTO signer_profiles
             (profile_id, wallet_id, chain_scope_json, signing_suite_id,
              backend_requirement, signer_set_id, authorization_signer_id,
              signer_epoch, threshold, max_signers, verification_key,
              secret_ref_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                profile.profile_id.to_string(),
                profile.wallet_id.to_string(),
                scope_json,
                profile.signing_suite_id.as_str(),
                profile.backend_requirement.as_str(),
                profile.signer_set_id,
                profile.authorization_signer_id,
                profile.signer_epoch,
                profile.threshold,
                profile.max_signers,
                profile.verification_key,
                profile.secret_ref_id.to_string(),
                profile.created_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::ImmutableConflict("signer_profile"));
            }
            return Err(error.into());
        }
        append_audit(
            &tx,
            &metadata,
            "signer_profile.registered",
            Some(profile.profile_id.to_string()),
            profile.created_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn signer_profile(&self, profile_id: Uuid) -> Result<Option<SignerProfileRecord>> {
        self.connection
            .query_row(
                "SELECT profile_id, wallet_id, chain_scope_json, signing_suite_id,
                        backend_requirement, signer_set_id, authorization_signer_id,
                        signer_epoch, threshold, max_signers, verification_key,
                        secret_ref_id, created_at
                 FROM signer_profiles WHERE profile_id = ?1",
                [profile_id.to_string()],
                map_signer_profile,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn bind_signer_address(&mut self, binding: NewAddressBinding) -> Result<()> {
        if binding.address.is_empty() || binding.address.len() > 512 {
            return Err(StorageError::InvalidSignerProfile);
        }
        let scope_json = serde_json::to_string(&binding.chain_scope)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let profile: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT chain_scope_json, verification_key FROM signer_profiles
                 WHERE profile_id = ?1 AND wallet_id = ?2",
                params![
                    binding.profile_id.to_string(),
                    metadata.wallet_id.to_string()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((profile_scope, verification_key)) = profile else {
            return Err(StorageError::InvalidSignerProfile);
        };
        let expected_verification_key_digest: [u8; 32] = Sha256::digest(verification_key).into();
        if profile_scope != scope_json
            || binding.verification_key_digest != expected_verification_key_digest
        {
            return Err(StorageError::InvalidSignerProfile);
        }
        let inserted = tx.execute(
            "INSERT INTO signer_address_bindings
             (binding_id, profile_id, chain_scope_json, address,
              verification_key_digest, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                binding.binding_id.to_string(),
                binding.profile_id.to_string(),
                scope_json,
                binding.address,
                binding.verification_key_digest.as_slice(),
                binding.created_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::ImmutableConflict("signer_address_binding"));
            }
            return Err(error.into());
        }
        append_audit(
            &tx,
            &metadata,
            "signer_address.bound",
            Some(binding.binding_id.to_string()),
            binding.created_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn install_signer_catalog(
        &mut self,
        catalog: &[NewSignerCatalogEntry],
    ) -> Result<SignerCatalogInstallOutcome> {
        let metadata = self.wallet_metadata()?;
        validate_signer_catalog(catalog, metadata.wallet_id)?;
        let existing = self.signer_profile_inventory(metadata.wallet_id)?;
        let stored_secret_ref_count: usize = self.connection.query_row(
            "SELECT COUNT(*) FROM secret_refs WHERE wallet_id = ?1",
            params![metadata.wallet_id.to_string()],
            |row| row.get(0),
        )?;
        if stored_secret_ref_count != existing.len() {
            return Err(StorageError::ImmutableConflict("signer_catalog"));
        }
        if !existing.is_empty() {
            return if signer_catalog_matches(self, catalog, &existing)? {
                Ok(SignerCatalogInstallOutcome::AlreadyPresent)
            } else {
                Err(StorageError::ImmutableConflict("signer_catalog"))
            };
        }
        for entry in catalog {
            if self.secret_ref(entry.secret_ref.id)?.is_some() {
                return Err(StorageError::ImmutableConflict("signer_catalog"));
            }
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        for entry in catalog {
            tx.execute(
                "INSERT INTO secret_refs
                 (id, wallet_id, backend, handle, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    entry.secret_ref.id.to_string(),
                    metadata.wallet_id.to_string(),
                    entry.secret_ref.backend.as_str(),
                    entry.secret_ref.handle,
                    entry.secret_ref.created_at,
                    entry.secret_ref.updated_at,
                ],
            )
            .map_err(|error| catalog_constraint(error, "secret_ref"))?;
            let scope_json = serde_json::to_string(&entry.profile.chain_scope)
                .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
            tx.execute(
                "INSERT INTO signer_profiles
                 (profile_id, wallet_id, chain_scope_json, signing_suite_id,
                  backend_requirement, signer_set_id, authorization_signer_id,
                  signer_epoch, threshold, max_signers, verification_key,
                  secret_ref_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    entry.profile.profile_id.to_string(),
                    entry.profile.wallet_id.to_string(),
                    scope_json,
                    entry.profile.signing_suite_id.as_str(),
                    entry.profile.backend_requirement.as_str(),
                    entry.profile.signer_set_id,
                    entry.profile.authorization_signer_id,
                    entry.profile.signer_epoch,
                    entry.profile.threshold,
                    entry.profile.max_signers,
                    entry.profile.verification_key,
                    entry.profile.secret_ref_id.to_string(),
                    entry.profile.created_at,
                ],
            )
            .map_err(|error| catalog_constraint(error, "signer_profile"))?;
            for binding in &entry.address_bindings {
                let scope_json = serde_json::to_string(&binding.chain_scope)
                    .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
                tx.execute(
                    "INSERT INTO signer_address_bindings
                     (binding_id, profile_id, chain_scope_json, address,
                      verification_key_digest, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        binding.binding_id.to_string(),
                        binding.profile_id.to_string(),
                        scope_json,
                        binding.address,
                        binding.verification_key_digest.as_slice(),
                        binding.created_at,
                    ],
                )
                .map_err(|error| catalog_constraint(error, "signer_address_binding"))?;
            }
        }
        append_audit(
            &tx,
            &metadata,
            "signer_catalog.installed",
            None,
            catalog[0].profile.created_at,
        )?;
        tx.commit()?;
        Ok(SignerCatalogInstallOutcome::Installed)
    }

    pub fn address_bindings(&self, profile_id: Uuid) -> Result<Vec<StoredAddressBinding>> {
        let mut statement = self.connection.prepare(
            "SELECT binding_id, profile_id, chain_scope_json, address,
                    verification_key_digest, created_at
             FROM signer_address_bindings WHERE profile_id = ?1
             ORDER BY created_at ASC, binding_id ASC",
        )?;
        let rows = statement.query_map([profile_id.to_string()], map_address_binding)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Returns the complete public signer inventory for this wallet in a
    /// deterministic order. The only secret-related value exposed here is an
    /// opaque backend handle; private keys and threshold shares are never
    /// stored in these tables.
    pub fn signer_profile_inventory(
        &self,
        wallet_id: Uuid,
    ) -> Result<Vec<SignerProfileInventoryRecord>> {
        let metadata = self.wallet_metadata()?;
        if wallet_id != metadata.wallet_id {
            return Err(StorageError::InvalidSignerProfile);
        }

        let mut profile_statement = self.connection.prepare(
            "SELECT p.profile_id, p.wallet_id, p.chain_scope_json, p.signing_suite_id,
                    p.backend_requirement, p.signer_set_id, p.authorization_signer_id,
                    p.signer_epoch, p.threshold, p.max_signers, p.verification_key,
                    p.secret_ref_id, p.created_at, s.handle
             FROM signer_profiles p
             JOIN secret_refs s ON s.id = p.secret_ref_id AND s.wallet_id = p.wallet_id
             WHERE p.wallet_id = ?1
             ORDER BY p.created_at ASC, p.profile_id ASC",
        )?;
        let profiles = profile_statement
            .query_map([wallet_id.to_string()], |row| {
                Ok((map_signer_profile(row)?, row.get::<_, String>(13)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut bindings_statement = self.connection.prepare(
            "SELECT b.binding_id, b.profile_id, b.chain_scope_json, b.address,
                    b.verification_key_digest, b.created_at
             FROM signer_address_bindings b
             JOIN signer_profiles p ON p.profile_id = b.profile_id
             WHERE p.wallet_id = ?1
             ORDER BY p.created_at ASC, p.profile_id ASC, b.created_at ASC, b.binding_id ASC",
        )?;
        let binding_rows = bindings_statement
            .query_map([wallet_id.to_string()], map_address_binding)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut bindings_by_profile = std::collections::HashMap::new();
        for binding in binding_rows {
            bindings_by_profile
                .entry(binding.profile_id)
                .or_insert_with(Vec::new)
                .push(binding);
        }

        Ok(profiles
            .into_iter()
            .map(|(profile, secret_ref)| SignerProfileInventoryRecord {
                address_bindings: bindings_by_profile
                    .remove(&profile.profile_id)
                    .unwrap_or_default(),
                profile,
                secret_ref,
            })
            .collect())
    }

    /// Atomically consumes the approved one-time authorization, claims the
    /// operation binding, moves the matching intent into signing, and creates
    /// the durable chain-signing job. No execution path may insert a signing
    /// job without this authorization transition.
    pub fn create_signing_job(
        &mut self,
        authorization_id: Uuid,
        job: NewSigningJob,
        operation_binding_digest: [u8; 32],
        now: i64,
    ) -> Result<StoredSigningJob> {
        validate_new_signing_job(&job)?;
        if job.created_at != now || now > job.expires_at {
            return Err(StorageError::InvalidSigningJob);
        }
        let scope_json = serde_json::to_string(&job.chain_scope)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        let parties_json = serde_json::to_string(&job.selected_parties)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        let review_artifact_json = serde_json::to_string(&job.review_artifact)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != job.wallet_id {
            return Err(StorageError::InvalidSigningJob);
        }
        let authorization_signer_id: Option<String> = tx
            .query_row(
                "SELECT authorization_signer_id FROM signer_profiles
             WHERE profile_id = ?1 AND wallet_id = ?2
               AND chain_scope_json = ?3 AND signing_suite_id = ?4
               AND backend_requirement = ?5",
                params![
                    job.profile_id.to_string(),
                    job.wallet_id.to_string(),
                    scope_json,
                    job.signing_suite_id.as_str(),
                    job.backend_requirement.as_str(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let authorization_signer_id =
            authorization_signer_id.ok_or(StorageError::InvalidSigningJob)?;
        if authorization_signer_id.is_empty() {
            return Err(StorageError::InvalidSigningJob);
        }
        let authorization = tx
            .query_row(
                "SELECT auth.binding_digest, auth.expires_at, auth.consumed_at,
                    auth.invalidated_at, intent.session_id, intent.status,
                    intent.signer_id, intent.tx_digest, intent.policy_hash,
                    intent.expires_at
             FROM one_time_authorizations auth
             JOIN transaction_intents intent ON intent.id = auth.intent_id
             WHERE auth.id = ?1 AND auth.intent_id = ?2
               AND auth.wallet_id = ?3 AND auth.epoch = ?4
               AND intent.intent_schema_version = 2",
                params![
                    authorization_id.to_string(),
                    job.intent_id.to_string(),
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::AuthorizationUnavailable)?;
        if authorization.0 != operation_binding_digest
            || authorization.1 < now
            || authorization.2.is_some()
            || authorization.3.is_some()
            || authorization.4 != job.session_id
            || authorization.5 != "approved"
            || authorization.6 != authorization_signer_id
            || authorization.7 != job.signing_message_digest
            || authorization.8 != job.policy_snapshot_digest
            || authorization.9 != job.expires_at
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        let inserted = tx.execute(
            "INSERT INTO signing_jobs
             (job_id, wallet_id, profile_id, intent_id, chain_scope_json,
              signing_suite_id, backend_requirement, review_schema_version,
              review_artifact_json, review_digest, signing_message_digest, policy_snapshot_digest,
              chain_snapshot_digest, session_id, selected_parties_json, receiver,
              operation_binding_digest, status, expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                     ?14, ?15, ?16, ?17, 'signing', ?18, ?19, ?19)",
            params![
                job.job_id.to_string(),
                job.wallet_id.to_string(),
                job.profile_id.to_string(),
                job.intent_id.to_string(),
                scope_json,
                job.signing_suite_id.as_str(),
                job.backend_requirement.as_str(),
                job.review_schema_version,
                review_artifact_json,
                job.review_digest.as_slice(),
                job.signing_message_digest.as_slice(),
                job.policy_snapshot_digest.as_slice(),
                job.chain_snapshot_digest.as_slice(),
                job.session_id.as_slice(),
                parties_json,
                job.receiver,
                operation_binding_digest.as_slice(),
                job.expires_at,
                job.created_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::SigningJobConflict);
            }
            return Err(error.into());
        }
        if tx.execute(
            "UPDATE one_time_authorizations SET consumed_at = ?1
             WHERE id = ?2 AND consumed_at IS NULL AND invalidated_at IS NULL
               AND expires_at >= ?1",
            params![now, authorization_id.to_string()],
        )? != 1
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        tx.execute(
            "INSERT INTO nonce_claims
             (fingerprint, wallet_id, epoch, session_id, claimed_at,
              authorization_id, intent_id, signer_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                operation_binding_digest.as_slice(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                job.session_id.as_slice(),
                now,
                authorization_id.to_string(),
                job.intent_id.to_string(),
                authorization.6,
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                StorageError::NonceAlreadyClaimed
            } else {
                error.into()
            }
        })?;
        if tx.execute(
            "UPDATE transaction_intents SET status = 'signing', updated_at = ?1
             WHERE id = ?2 AND wallet_id = ?3 AND epoch = ?4
               AND status = 'approved' AND intent_schema_version = 2",
            params![
                now,
                job.intent_id.to_string(),
                metadata.wallet_id.to_string(),
                metadata.epoch
            ],
        )? != 1
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "chain_signing.authorized_started",
            Some(job.job_id.to_string()),
            now,
        )?;
        tx.commit()?;
        self.signing_job(job.job_id)?
            .ok_or(StorageError::SigningJobConflict)
    }

    pub fn signing_job(&self, job_id: Uuid) -> Result<Option<StoredSigningJob>> {
        self.connection
            .query_row(
                "SELECT job_id, wallet_id, profile_id, intent_id, chain_scope_json,
                    signing_suite_id, backend_requirement, review_schema_version,
                    review_artifact_json, review_digest, signing_message_digest, policy_snapshot_digest,
                    chain_snapshot_digest, session_id, selected_parties_json, receiver,
                    operation_binding_digest, status, final_signature, terminal_reason,
                    expires_at, created_at, updated_at
             FROM signing_jobs WHERE job_id = ?1",
                [job_id.to_string()],
                map_signing_job,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Atomically claims the provider-I/O boundary for one authorized chain
    /// signing job. The matching job remains the lifecycle source of truth;
    /// this append-only row only prevents a second execution after restart.
    pub fn claim_chain_executor(&mut self, claim: ChainExecutorClaim) -> Result<()> {
        if claim.wallet_id.is_nil()
            || claim.profile_id.is_nil()
            || claim.session_id == [0; 32]
            || claim.review_domain_digest == [0; 32]
            || claim.signing_message_digest == [0; 32]
            || claim.operation_binding_digest == [0; 32]
        {
            return Err(StorageError::InvalidSigningJob);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != claim.wallet_id {
            return Err(StorageError::SigningJobBindingDrift);
        }
        let job_id: Option<String> = tx
            .query_row(
                "SELECT job_id FROM signing_jobs
                 WHERE wallet_id = ?1 AND profile_id = ?2
                   AND signing_suite_id = ?3 AND backend_requirement = ?4
                   AND session_id = ?5 AND signing_message_digest = ?6
                   AND operation_binding_digest = ?7 AND status = 'signing'
                   AND expires_at >= ?8",
                params![
                    claim.wallet_id.to_string(),
                    claim.profile_id.to_string(),
                    claim.signing_suite_id.as_str(),
                    claim.backend_requirement.as_str(),
                    claim.session_id.as_slice(),
                    claim.signing_message_digest.as_slice(),
                    claim.operation_binding_digest.as_slice(),
                    claim.claimed_at,
                ],
                |row| row.get(0),
            )
            .optional()?;
        let job_id = job_id.ok_or(StorageError::SigningJobBindingDrift)?;
        let inserted = tx.execute(
            "INSERT INTO chain_executor_claims
             (job_id, wallet_id, profile_id, signing_suite_id,
              backend_requirement, session_id, review_domain_digest,
              signing_message_digest, operation_binding_digest, claimed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                job_id,
                claim.wallet_id.to_string(),
                claim.profile_id.to_string(),
                claim.signing_suite_id.as_str(),
                claim.backend_requirement.as_str(),
                claim.session_id.as_slice(),
                claim.review_domain_digest.as_slice(),
                claim.signing_message_digest.as_slice(),
                claim.operation_binding_digest.as_slice(),
                claim.claimed_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::SigningJobConflict);
            }
            return Err(error.into());
        }
        append_audit(
            &tx,
            &metadata,
            "chain_executor.claimed",
            Some(job_id),
            claim.claimed_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn complete_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        final_signature: Vec<u8>,
        now: i64,
    ) -> Result<()> {
        if final_signature.is_empty() || final_signature.len() > 4096 {
            return Err(StorageError::InvalidSigningJob);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let intent_id: Option<String> = tx
            .query_row(
                "SELECT intent_id FROM signing_jobs WHERE job_id = ?1
               AND wallet_id = ?2 AND operation_binding_digest = ?3
               AND status = 'signing' AND expires_at >= ?4",
                params![
                    job_id.to_string(),
                    metadata.wallet_id.to_string(),
                    operation_binding_digest.as_slice(),
                    now
                ],
                |row| row.get(0),
            )
            .optional()?;
        let intent_id = intent_id.ok_or(StorageError::SigningJobBindingDrift)?;
        if tx.execute(
            "UPDATE signing_jobs SET status = 'finalized', final_signature = ?1, updated_at = ?2
             WHERE job_id = ?3 AND status = 'signing'",
            params![final_signature, now, job_id.to_string()],
        )? != 1
        {
            return Err(StorageError::SigningJobConflict);
        }
        if tx.execute(
            "UPDATE transaction_intents SET status = 'signed', updated_at = ?1
             WHERE id = ?2 AND wallet_id = ?3 AND epoch = ?4 AND status = 'signing'",
            params![
                now,
                intent_id,
                metadata.wallet_id.to_string(),
                metadata.epoch
            ],
        )? != 1
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "chain_signing.finalized",
            Some(job_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn terminate_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        status: SigningJobStatus,
        reason: &str,
        now: i64,
    ) -> Result<()> {
        if !matches!(
            status,
            SigningJobStatus::Aborted | SigningJobStatus::Expired | SigningJobStatus::Failed
        ) || reason.is_empty()
            || reason.len() > 128
        {
            return Err(StorageError::InvalidSigningJob);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let intent_id: Option<String> = tx
            .query_row(
                "SELECT intent_id FROM signing_jobs WHERE job_id = ?1
                   AND wallet_id = ?2 AND operation_binding_digest = ?3
                   AND status = 'signing'",
                params![
                    job_id.to_string(),
                    metadata.wallet_id.to_string(),
                    operation_binding_digest.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let intent_id = intent_id.ok_or(StorageError::SigningJobBindingDrift)?;
        if tx.execute(
            "UPDATE signing_jobs SET status = ?1, terminal_reason = ?2, updated_at = ?3
             WHERE job_id = ?4 AND status = 'signing'",
            params![
                match status {
                    SigningJobStatus::Aborted => "aborted",
                    SigningJobStatus::Expired => "expired",
                    SigningJobStatus::Failed => "failed",
                    _ => unreachable!(),
                },
                reason,
                now,
                job_id.to_string(),
            ],
        )? != 1
        {
            return Err(StorageError::SigningJobConflict);
        }
        if tx.execute(
            "UPDATE transaction_intents SET status = 'invalidated', updated_at = ?1
             WHERE id = ?2 AND wallet_id = ?3 AND epoch = ?4 AND status = 'signing'",
            params![
                now,
                intent_id,
                metadata.wallet_id.to_string(),
                metadata.epoch,
            ],
        )? != 1
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "chain_signing.terminated",
            Some(job_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
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
        let v2_schema_version = tx
            .query_row(
                "SELECT intent.intent_schema_version
                 FROM one_time_authorizations authorization
                 JOIN transaction_intents intent ON intent.id = authorization.intent_id
                 WHERE authorization.id = ?1 AND authorization.epoch = ?2",
                params![authorization_id.to_string(), epoch],
                |row| row.get::<_, Option<u32>>(0),
            )
            .optional()?;
        if v2_schema_version.flatten() == Some(2) {
            return Err(StorageError::LegacyApiRejectedForV2);
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

    /// Atomically consumes one approved Passkey authorization, claims the
    /// operation binding as its replay fingerprint, moves the intent into
    /// signing, and creates the public personal-signing operation.
    pub fn consume_authorization_and_create_personal_signing_operation(
        &mut self,
        authorization_id: Uuid,
        operation: NewPersonalSigningOperation,
        now: i64,
    ) -> Result<PersonalSigningOperation> {
        validate_new_personal_operation(&operation)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != operation.wallet_id
            || operation.created_at != now
            || now > operation.expires_at
        {
            return Err(StorageError::InvalidPersonalSigningOperation);
        }
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT operation_binding_digest FROM personal_signing_operations
                 WHERE operation_id = ?1",
                [operation.operation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == operation.operation_binding_digest {
                Err(StorageError::PersonalSigningOperationConflict)
            } else {
                Err(StorageError::PersonalSigningOperationBindingDrift)
            };
        }
        let authorization = tx
            .query_row(
                "SELECT auth.expires_at, auth.consumed_at, auth.invalidated_at,
                        intent.session_id, intent.status, intent.signer_id,
                        intent.tx_digest, intent.policy_hash, intent.expires_at,
                        material.payload_json, material.payload_hash
                 FROM one_time_authorizations auth
                 JOIN transaction_intents intent ON intent.id = auth.intent_id
                 JOIN intent_materials material ON material.intent_id = intent.id
                    AND material.kind = 'policy_input'
                 WHERE auth.id = ?1 AND auth.intent_id = ?2
                   AND auth.wallet_id = ?3 AND auth.epoch = ?4
                   AND intent.intent_schema_version = 2",
                params![
                    authorization_id.to_string(),
                    operation.intent_id.to_string(),
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::AuthorizationUnavailable)?;
        if authorization.0 < now
            || authorization.1.is_some()
            || authorization.2.is_some()
            || authorization.3 != operation.session_id
            || authorization.4 != "approved"
            || authorization.5 != "frost:participant-0"
            || authorization.6 != operation.taproot_sighash
            || authorization.7 != operation.policy_digest
            || authorization.8 != operation.expires_at
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        validate_personal_operation_material(&authorization.9, &authorization.10, &operation)?;
        let allowed = encode_participants(&operation.allowed_participants);
        let selected = encode_participants(&operation.selected_participants);
        tx.execute(
            "INSERT INTO personal_signing_operations
             (operation_id, wallet_id, profile_id, signer_set_id, signer_epoch,
              intent_id, session_id, taproot_sighash, policy_digest,
              chain_snapshot_digest, group_pubkey_xonly, profile_binding_digest,
              operation_binding_digest, allowed_participants, selected_participants,
              threshold, max_signers, status, expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, 'collecting_commitments', ?18, ?19, ?19)",
            params![
                operation.operation_id.to_string(),
                operation.wallet_id.to_string(),
                operation.profile_id.to_string(),
                operation.signer_set_id.to_string(),
                operation.signer_epoch,
                operation.intent_id.to_string(),
                operation.session_id.as_slice(),
                operation.taproot_sighash.as_slice(),
                operation.policy_digest.as_slice(),
                operation.chain_snapshot_digest.as_slice(),
                operation.group_pubkey_xonly.as_slice(),
                operation.profile_binding_digest.as_slice(),
                operation.operation_binding_digest.as_slice(),
                allowed,
                selected,
                operation.threshold,
                operation.max_signers,
                operation.expires_at,
                operation.created_at,
            ],
        )?;
        if tx.execute(
            "UPDATE one_time_authorizations SET consumed_at = ?1
             WHERE id = ?2 AND consumed_at IS NULL AND invalidated_at IS NULL
               AND expires_at >= ?1",
            params![now, authorization_id.to_string()],
        )? != 1
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        tx.execute(
            "INSERT INTO nonce_claims
             (fingerprint, wallet_id, epoch, session_id, claimed_at,
              authorization_id, intent_id, signer_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                operation.operation_binding_digest.as_slice(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                operation.session_id.as_slice(),
                now,
                authorization_id.to_string(),
                operation.intent_id.to_string(),
                authorization.5,
            ],
        )?;
        if tx.execute(
            "UPDATE transaction_intents SET status = 'signing', updated_at = ?1
             WHERE id = ?2 AND wallet_id = ?3 AND epoch = ?4
               AND status = 'approved' AND intent_schema_version = 2",
            params![
                now,
                operation.intent_id.to_string(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
            ],
        )? != 1
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "personal_signing.authorized_started",
            Some(operation.operation_id.to_string()),
            now,
        )?;
        tx.commit()?;
        self.personal_signing_operation(operation.operation_id)?
            .ok_or(StorageError::PersonalSigningOperationConflict)
    }

    pub fn personal_signing_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<PersonalSigningOperation>> {
        self.connection
            .query_row(
                "SELECT operation_id, wallet_id, profile_id, signer_set_id, signer_epoch,
                        intent_id, session_id, taproot_sighash, policy_digest,
                        chain_snapshot_digest, group_pubkey_xonly, profile_binding_digest,
                        operation_binding_digest, allowed_participants, selected_participants,
                        threshold, max_signers, status, signing_package, final_signature,
                        terminal_reason, expires_at, created_at, updated_at
                 FROM personal_signing_operations WHERE operation_id = ?1",
                [operation_id.to_string()],
                map_personal_signing_operation,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn personal_signing_receipts(
        &self,
        operation_id: Uuid,
    ) -> Result<Vec<PersonalSigningReceipt>> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, signer_id, round, device_id, device_generation,
                    request_binding_digest, payload, received_at
             FROM personal_signing_receipts WHERE operation_id = ?1
             ORDER BY CASE round WHEN 'commitment' THEN 1 ELSE 2 END, signer_id",
        )?;
        let rows = statement.query_map([operation_id.to_string()], map_personal_signing_receipt)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn record_personal_signing_receipt(
        &mut self,
        receipt: PersonalSigningReceipt,
    ) -> Result<()> {
        if receipt.signer_id == 0
            || receipt.signer_id > 3
            || receipt.device_generation == 0
            || receipt.payload.is_empty()
            || receipt.payload.len() > 16 * 1024
        {
            return Err(StorageError::InvalidPersonalSigningOperation);
        }
        if let Some(existing) = self
            .personal_signing_receipts(receipt.operation_id)?
            .into_iter()
            .find(|item| item.signer_id == receipt.signer_id && item.round == receipt.round)
        {
            return if existing.operation_id == receipt.operation_id
                && existing.signer_id == receipt.signer_id
                && existing.round == receipt.round
                && existing.device_id == receipt.device_id
                && existing.device_generation == receipt.device_generation
                && existing.request_binding_digest == receipt.request_binding_digest
                && existing.payload == receipt.payload
            {
                Ok(())
            } else {
                Err(StorageError::PersonalSigningReceiptConflict)
            };
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let (status, selected, expires_at): (String, Vec<u8>, i64) = tx
            .query_row(
                "SELECT status, selected_participants, expires_at
                 FROM personal_signing_operations
                 WHERE operation_id = ?1 AND wallet_id = ?2",
                params![
                    receipt.operation_id.to_string(),
                    metadata.wallet_id.to_string()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(StorageError::InvalidPersonalSigningOperation)?;
        let selected = decode_participants::<2>(&selected, 1)?;
        let expected_status = match receipt.round {
            PersonalSigningRound::Commitment => "collecting_commitments",
            PersonalSigningRound::SignatureShare => "collecting_shares",
        };
        if status != expected_status
            || !selected.contains(&receipt.signer_id)
            || receipt.received_at > expires_at
        {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        tx.execute(
            "INSERT INTO personal_signing_receipts
             (operation_id, signer_id, round, device_id, device_generation,
              request_binding_digest, payload, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                receipt.operation_id.to_string(),
                receipt.signer_id,
                receipt.round.as_str(),
                receipt.device_id.to_string(),
                receipt.device_generation,
                receipt.request_binding_digest.as_slice(),
                receipt.payload,
                receipt.received_at,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            match receipt.round {
                PersonalSigningRound::Commitment => "personal_signing.commitment_received",
                PersonalSigningRound::SignatureShare => "personal_signing.share_received",
            },
            Some(receipt.operation_id.to_string()),
            receipt.received_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn freeze_personal_signing_operation(
        &mut self,
        operation_id: Uuid,
        operation_binding_digest: [u8; 32],
        signing_package: Vec<u8>,
        now: i64,
    ) -> Result<()> {
        if signing_package.is_empty() || signing_package.len() > 16 * 1024 {
            return Err(StorageError::InvalidPersonalSigningOperation);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let commitment_count: u16 = tx.query_row(
            "SELECT COUNT(*) FROM personal_signing_receipts
             WHERE operation_id = ?1 AND round = 'commitment'",
            [operation_id.to_string()],
            |row| row.get(0),
        )?;
        if commitment_count < 2 {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        let changed = tx.execute(
            "UPDATE personal_signing_operations
             SET status = 'collecting_shares', signing_package = ?1, updated_at = ?2
             WHERE operation_id = ?3 AND wallet_id = ?4
               AND operation_binding_digest = ?5
               AND status = 'collecting_commitments' AND expires_at >= ?2",
            params![
                signing_package,
                now,
                operation_id.to_string(),
                metadata.wallet_id.to_string(),
                operation_binding_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "personal_signing.commitments_frozen",
            Some(operation_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn complete_personal_signing_operation(
        &mut self,
        operation_id: Uuid,
        operation_binding_digest: [u8; 32],
        signature: [u8; 64],
        now: i64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let share_count: u16 = tx.query_row(
            "SELECT COUNT(*) FROM personal_signing_receipts
             WHERE operation_id = ?1 AND round = 'signature_share'",
            [operation_id.to_string()],
            |row| row.get(0),
        )?;
        if share_count < 2 {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        let changed = tx.execute(
            "UPDATE personal_signing_operations
             SET status = 'finalized', final_signature = ?1, updated_at = ?2
             WHERE operation_id = ?3 AND wallet_id = ?4
               AND operation_binding_digest = ?5
               AND status = 'collecting_shares' AND expires_at >= ?2",
            params![
                signature.as_slice(),
                now,
                operation_id.to_string(),
                metadata.wallet_id.to_string(),
                operation_binding_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "personal_signing.finalized",
            Some(operation_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn terminate_personal_signing_operation(
        &mut self,
        operation_id: Uuid,
        operation_binding_digest: [u8; 32],
        status: PersonalSigningOperationStatus,
        reason: &str,
        now: i64,
    ) -> Result<()> {
        if !matches!(
            status,
            PersonalSigningOperationStatus::Aborted
                | PersonalSigningOperationStatus::Expired
                | PersonalSigningOperationStatus::Failed
        ) || reason.is_empty()
            || reason.len() > 64
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(StorageError::InvalidPersonalSigningOperation);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let changed = tx.execute(
            "UPDATE personal_signing_operations
             SET status = ?1, terminal_reason = ?2, updated_at = ?3
             WHERE operation_id = ?4 AND wallet_id = ?5
               AND operation_binding_digest = ?6
               AND status IN ('collecting_commitments', 'collecting_shares')",
            params![
                status.as_str(),
                reason,
                now,
                operation_id.to_string(),
                metadata.wallet_id.to_string(),
                operation_binding_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::PersonalSigningOperationConflict);
        }
        append_audit(
            &tx,
            &metadata,
            "personal_signing.terminated",
            Some(operation_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically persists the signer-provider request nonce before a local or
    /// HSM backend can create a commitment or signature share.
    pub fn claim_signer_request_nonce(
        &mut self,
        identity: &ProviderIdentity,
        context: &SignerRequestContext,
        claimed_at: i64,
    ) -> Result<()> {
        if identity.wallet_id != context.wallet_id
            || identity.signer_set_id != context.signer_set_id
            || identity.signer_epoch != context.signer_epoch
            || identity.signer_id != context.signer_id
            || identity.device_id != context.device_id
            || identity.device_generation != context.device_generation
            || identity.group_pubkey_xonly != context.group_pubkey_xonly
            || identity.verifying_share_digest != context.verifying_share_digest
        {
            return Err(StorageError::InvalidStoredValue(
                "signer provider identity drift".to_owned(),
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != identity.wallet_id {
            return Err(StorageError::InvalidStoredValue(
                "signer provider belongs to a different wallet".to_owned(),
            ));
        }
        let operation_binding = context.operation_binding_digest();
        let prior_operation_binding = tx
            .query_row(
                "SELECT operation_binding_digest FROM signer_request_nonces
                 WHERE wallet_id = ?1 AND signer_set_id = ?2 AND signer_epoch = ?3
                   AND signer_id = ?4 AND operation_id = ?5
                 LIMIT 1",
                params![
                    identity.wallet_id.to_string(),
                    identity.signer_set_id.to_string(),
                    identity.signer_epoch,
                    identity.signer_id,
                    context.operation_id.to_string(),
                ],
                |row| array32_column(row, 0),
            )
            .optional()?;
        if prior_operation_binding.is_some_and(|prior| prior != operation_binding) {
            return Err(StorageError::SignerOperationBindingDrift);
        }
        let inserted = tx.execute(
            "INSERT INTO signer_request_nonces
             (wallet_id, signer_set_id, signer_epoch, signer_id, device_id,
              device_generation, request_nonce, operation_id, intent_id, session_id,
              taproot_sighash, policy_digest, operation_binding_digest, claimed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                identity.wallet_id.to_string(),
                identity.signer_set_id.to_string(),
                identity.signer_epoch,
                identity.signer_id,
                identity.device_id.to_string(),
                identity.device_generation,
                context.request_nonce.as_slice(),
                context.operation_id.to_string(),
                context.intent_id.to_string(),
                context.session_id.as_slice(),
                context.taproot_sighash.as_slice(),
                context.policy_digest.as_slice(),
                operation_binding.as_slice(),
                claimed_at,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::NonceAlreadyClaimed);
            }
            return Err(error.into());
        }
        append_audit(
            &tx,
            &metadata,
            "signer.request_nonce_claimed",
            Some(context.operation_id.to_string()),
            claimed_at,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Append a device registration, rotation, or revocation with a strict
    /// generation compare-and-swap. Health probes are deliberately not
    /// persisted as proof of availability; reopened devices start offline.
    pub fn persist_signer_device_transition(
        &mut self,
        wallet_id: Uuid,
        signer_set_id: Uuid,
        signer_epoch: u64,
        expected_generation: u64,
        record: &SignerDeviceRecord,
        now: i64,
    ) -> Result<()> {
        let device_id = record.device_id.ok_or_else(|| {
            StorageError::InvalidStoredValue("configured signer device id is missing".to_owned())
        })?;
        let provider = match record.provider {
            Some(SignerProviderKind::RemoteMtls) => "remote_mtls",
            Some(SignerProviderKind::HsmAdapter) => "hsm_adapter",
            _ => {
                return Err(StorageError::InvalidStoredValue(
                    "remote signer provider kind is invalid".to_owned(),
                ));
            }
        };
        let identity_key = decode_hex32(
            record.identity_public_key_hex.as_deref().ok_or_else(|| {
                StorageError::InvalidStoredValue(
                    "configured signer identity key is missing".to_owned(),
                )
            })?,
            "signer identity key",
        )?;
        let certificate = record
            .mtls_spki_sha256_hex
            .as_deref()
            .map(|value| decode_hex32(value, "signer mTLS SPKI digest"))
            .transpose()?;
        if record.provider == Some(SignerProviderKind::RemoteMtls) && certificate.is_none() {
            return Err(StorageError::InvalidStoredValue(
                "remote signer SPKI digest is missing".to_owned(),
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        if metadata.wallet_id != wallet_id || signer_epoch == 0 {
            return Err(StorageError::InvalidStoredValue(
                "signer device belongs to a different wallet or epoch".to_owned(),
            ));
        }
        let prior = tx
            .query_row(
                "SELECT device_generation, device_id, event_type
                 FROM signer_device_events
                 WHERE wallet_id = ?1 AND signer_set_id = ?2 AND signer_epoch = ?3
                   AND signer_id = ?4
                 ORDER BY sequence DESC LIMIT 1",
                params![
                    wallet_id.to_string(),
                    signer_set_id.to_string(),
                    signer_epoch,
                    record.signer_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let event_type = match prior {
            None if expected_generation == 0
                && record.generation == 1
                && record.status == DeviceStatus::Active =>
            {
                "registered"
            }
            Some((_generation, _, ref prior_event)) if prior_event == "revoked" => {
                return Err(StorageError::InvalidStoredValue(
                    "revoked signer device cannot be replaced in the same signer epoch".to_owned(),
                ));
            }
            Some((generation, _, _))
                if generation == expected_generation
                    && record.generation == generation + 1
                    && record.status == DeviceStatus::Active =>
            {
                "rotated"
            }
            Some((generation, ref prior_device, _))
                if generation == expected_generation
                    && record.generation == generation
                    && prior_device == &device_id.to_string()
                    && record.status == DeviceStatus::Revoked =>
            {
                "revoked"
            }
            _ => {
                return Err(StorageError::InvalidStoredValue(
                    "signer device generation or lifecycle transition drifted".to_owned(),
                ));
            }
        };
        tx.execute(
            "INSERT INTO signer_device_events
             (wallet_id, signer_set_id, signer_epoch, signer_id, device_id,
              device_generation, provider, identity_public_key, mtls_spki_sha256,
              event_type, occurred_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                wallet_id.to_string(),
                signer_set_id.to_string(),
                signer_epoch,
                record.signer_id,
                device_id.to_string(),
                record.generation,
                provider,
                identity_key.as_slice(),
                certificate.as_ref().map(|value| value.as_slice()),
                event_type,
                now,
            ],
        )?;
        append_audit(
            &tx,
            &metadata,
            &format!("signer.device_{event_type}"),
            Some(device_id.to_string()),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn signer_device_records(
        &self,
        wallet_id: Uuid,
        signer_set_id: Uuid,
        signer_epoch: u64,
    ) -> Result<Vec<SignerDeviceRecord>> {
        let metadata = self.wallet_metadata()?;
        if metadata.wallet_id != wallet_id {
            return Err(StorageError::InvalidStoredValue(
                "signer device inventory belongs to a different wallet".to_owned(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT current.signer_id, current.device_id, current.device_generation,
                    current.provider, current.identity_public_key,
                    current.mtls_spki_sha256, current.event_type,
                    (SELECT MIN(first.occurred_at) FROM signer_device_events first
                     WHERE first.wallet_id = current.wallet_id
                       AND first.signer_set_id = current.signer_set_id
                       AND first.signer_epoch = current.signer_epoch
                       AND first.signer_id = current.signer_id),
                    (SELECT MAX(rotated.occurred_at) FROM signer_device_events rotated
                     WHERE rotated.wallet_id = current.wallet_id
                       AND rotated.signer_set_id = current.signer_set_id
                       AND rotated.signer_epoch = current.signer_epoch
                       AND rotated.signer_id = current.signer_id
                       AND rotated.event_type = 'rotated'),
                    (SELECT MAX(revoked.occurred_at) FROM signer_device_events revoked
                     WHERE revoked.wallet_id = current.wallet_id
                       AND revoked.signer_set_id = current.signer_set_id
                       AND revoked.signer_epoch = current.signer_epoch
                       AND revoked.signer_id = current.signer_id
                       AND revoked.event_type = 'revoked')
             FROM signer_device_events current
             WHERE current.wallet_id = ?1 AND current.signer_set_id = ?2
               AND current.signer_epoch = ?3
               AND current.sequence = (
                   SELECT MAX(latest.sequence) FROM signer_device_events latest
                   WHERE latest.wallet_id = current.wallet_id
                     AND latest.signer_set_id = current.signer_set_id
                     AND latest.signer_epoch = current.signer_epoch
                     AND latest.signer_id = current.signer_id
               )
             ORDER BY current.signer_id",
        )?;
        let rows = statement.query_map(
            params![
                wallet_id.to_string(),
                signer_set_id.to_string(),
                signer_epoch,
            ],
            |row| {
                let provider: String = row.get(3)?;
                let event_type: String = row.get(6)?;
                let identity: Vec<u8> = row.get(4)?;
                let certificate: Option<Vec<u8>> = row.get(5)?;
                Ok(SignerDeviceRecord {
                    signer_id: row.get(0)?,
                    device_id: Some(uuid_column(row, 1)?),
                    generation: row.get(2)?,
                    provider: Some(match provider.as_str() {
                        "remote_mtls" => SignerProviderKind::RemoteMtls,
                        "hsm_adapter" => SignerProviderKind::HsmAdapter,
                        _ => return Err(conversion_error(3, "unknown signer provider")),
                    }),
                    identity_public_key_hex: Some(hex::encode(identity)),
                    mtls_spki_sha256_hex: certificate.map(hex::encode),
                    status: if event_type == "revoked" {
                        DeviceStatus::Revoked
                    } else {
                        DeviceStatus::Active
                    },
                    registered_at: row.get(7)?,
                    rotated_at: row.get(8)?,
                    revoked_at: row.get(9)?,
                    health: DeviceHealth::default(),
                })
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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
                "SELECT ceremony.intent_id, ceremony.epoch, ceremony.expires_at,
                        ceremony.completed_at, ceremony.invalidated_at,
                        intent.intent_schema_version
                 FROM approval_ceremonies ceremony
                 JOIN transaction_intents intent ON intent.id = ceremony.intent_id
                 WHERE ceremony.id = ?1",
                [decision.ceremony_id.to_string()],
                |row| {
                    Ok((
                        uuid_column(row, 0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<u32>>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::ApprovalCeremonyUnavailable)?;
        if ceremony.5 == Some(2) {
            return Err(StorageError::LegacyApiRejectedForV2);
        }
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

    pub fn begin_passkey_approval(&mut self, ceremony: NewPasskeyApprovalCeremony) -> Result<()> {
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
        let active_credential: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM credential_metadata
                 WHERE credential_id = ?1 AND wallet_id = ?2
                   AND credential_state = 'active'
             )",
            params![ceremony.credential_id, metadata.wallet_id.to_string(),],
            |row| row.get(0),
        )?;
        if !active_credential {
            return Err(StorageError::CredentialUnavailable);
        }
        tx.execute(
            "INSERT INTO approval_ceremonies
             (id, wallet_id, intent_id, epoch, started_at, expires_at,
              binding_digest, credential_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ceremony.id.to_string(),
                metadata.wallet_id.to_string(),
                ceremony.intent_id.to_string(),
                metadata.epoch,
                ceremony.started_at,
                ceremony.expires_at,
                ceremony.binding_digest.as_slice(),
                ceremony.credential_id,
            ],
        )?;
        append_audit_with_context(
            &tx,
            &metadata,
            "approval.passkey_started",
            Some(ceremony.id.to_string()),
            ceremony.started_at,
            Some(ceremony.intent_id),
            Some(intent.policy_hash),
            &AuditContext::default(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn complete_passkey_approval_atomic(
        &mut self,
        completion: PasskeyApprovalCompletion,
    ) -> Result<AuthorizationRecord> {
        if serde_json::from_str::<serde_json::Value>(&completion.updated_passkey_json).is_err() {
            return Err(StorageError::CredentialUnavailable);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let profile_match: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM webauthn_profiles
                 WHERE wallet_id = ?1 AND rp_id = ?2 AND rp_origin = ?3
             )",
            params![
                metadata.wallet_id.to_string(),
                completion.rp_id,
                completion.rp_origin,
            ],
            |row| row.get(0),
        )?;
        if !profile_match {
            return Err(StorageError::WebauthnProfileMismatch);
        }
        let ceremony = tx
            .query_row(
                "SELECT intent_id, epoch, expires_at, completed_at, invalidated_at,
                        binding_digest, credential_id
                 FROM approval_ceremonies WHERE id = ?1",
                [completion.ceremony_id.to_string()],
                |row| {
                    Ok((
                        uuid_column(row, 0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        array32_column(row, 5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::ApprovalCeremonyUnavailable)?;
        if ceremony.0 != completion.intent_id
            || ceremony.1 != metadata.epoch
            || ceremony.3.is_some()
            || ceremony.4.is_some()
        {
            return Err(StorageError::ApprovalCeremonyUnavailable);
        }
        if ceremony.5 != completion.binding_digest || ceremony.6 != completion.credential_id {
            return Err(StorageError::ApprovalBindingMismatch);
        }
        if completion.approved_at > ceremony.2 {
            return Err(StorageError::ApprovalCeremonyExpired);
        }
        let intent = pending_intent_facts(
            &tx,
            completion.intent_id,
            metadata.epoch,
            completion.approved_at,
        )?;
        if completion.authorization_expires_at < completion.approved_at {
            return Err(StorageError::AuthorizationExpiresBeforeApproval);
        }
        if completion.authorization_expires_at > intent.expires_at {
            return Err(StorageError::AuthorizationExceedsIntentExpiry);
        }
        if update_passkey_record_in(
            &tx,
            &completion.credential_id,
            completion.expected_credential_record_version,
            &completion.updated_passkey_json,
            completion.approved_at,
        )? != 1
        {
            return Err(StorageError::CredentialVersionConflict);
        }
        if tx.execute(
            "UPDATE approval_ceremonies SET completed_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND completed_at IS NULL
               AND invalidated_at IS NULL AND expires_at >= ?1",
            params![
                completion.approved_at,
                completion.ceremony_id.to_string(),
                metadata.epoch,
            ],
        )? != 1
        {
            return Err(StorageError::ApprovalCeremonyUnavailable);
        }
        if tx.execute(
            "UPDATE transaction_intents SET status = 'approved', updated_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND status = 'pending'
               AND intent_schema_version = 2",
            params![
                completion.approved_at,
                completion.intent_id.to_string(),
                metadata.epoch,
            ],
        )? != 1
        {
            return Err(StorageError::IntentNotApprovable);
        }
        let inserted = tx.execute(
            "INSERT INTO one_time_authorizations
             (id, wallet_id, intent_id, epoch, binding_digest, expires_at, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                completion.authorization_id.to_string(),
                metadata.wallet_id.to_string(),
                completion.intent_id.to_string(),
                metadata.epoch,
                completion.binding_digest.as_slice(),
                completion.authorization_expires_at,
                completion.approved_at,
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
            "approval.passkey_completed",
            Some(completion.ceremony_id.to_string()),
            completion.approved_at,
            Some(completion.intent_id),
            Some(intent.policy_hash),
            &AuditContext::default(),
        )?;
        let authorization = AuthorizationRecord {
            id: completion.authorization_id,
            intent_id: completion.intent_id,
            epoch: metadata.epoch,
            binding_digest: completion.binding_digest,
            expires_at: completion.authorization_expires_at,
            issued_at: completion.approved_at,
            consumed_at: None,
            invalidated_at: None,
        };
        tx.commit()?;
        Ok(authorization)
    }

    pub fn available_authorization(
        &self,
        intent_id: Uuid,
        now: i64,
    ) -> Result<Option<AuthorizationRecord>> {
        let metadata = self.wallet_metadata()?;
        self.connection
            .query_row(
                "SELECT id, intent_id, epoch, binding_digest, expires_at, issued_at,
                        consumed_at, invalidated_at
                 FROM one_time_authorizations
                 WHERE wallet_id = ?1 AND epoch = ?2 AND intent_id = ?3
                   AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at >= ?4",
                params![
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                    intent_id.to_string(),
                    now,
                ],
                map_authorization_record,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Recovery cursor for all nonce fingerprints in the current epoch.
    pub fn list_nonce_claims(&self) -> Result<Vec<NonceClaim>> {
        let metadata = self.wallet_metadata()?;
        let mut statement = self.connection.prepare(
            "SELECT fingerprint, session_id, epoch, claimed_at, invalidated_at
             FROM nonce_claims
             WHERE wallet_id = ?1 AND epoch = ?2
             ORDER BY claimed_at ASC, fingerprint ASC",
        )?;
        let rows = statement.query_map(
            params![metadata.wallet_id.to_string(), metadata.epoch],
            |row| {
                Ok(NonceClaim {
                    fingerprint: array32_column(row, 0)?,
                    session_id: array32_column(row, 1)?,
                    epoch: row.get(2)?,
                    claimed_at: row.get(3)?,
                    invalidated_at: row.get(4)?,
                })
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Recovery cursor for current, unconsumed authorizations.
    pub fn list_available_authorizations(&self, now: i64) -> Result<Vec<AuthorizationRecord>> {
        let metadata = self.wallet_metadata()?;
        let mut statement = self.connection.prepare(
            "SELECT id, intent_id, epoch, binding_digest, expires_at, issued_at,
                    consumed_at, invalidated_at
             FROM one_time_authorizations
             WHERE wallet_id = ?1 AND epoch = ?2
               AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at >= ?3
             ORDER BY issued_at ASC, id ASC",
        )?;
        let rows = statement.query_map(
            params![metadata.wallet_id.to_string(), metadata.epoch, now],
            map_authorization_record,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn consume_authorization_and_claim_frost_nonce(
        &mut self,
        claim: FrostNonceAuthorizationClaim,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = metadata_in(&tx)?;
        ensure_mutations_allowed(&metadata)?;
        let authorization = tx
            .query_row(
                "SELECT id, intent_id, epoch, binding_digest, expires_at, issued_at,
                        consumed_at, invalidated_at
                 FROM one_time_authorizations
                 WHERE id = ?1 AND wallet_id = ?2 AND epoch = ?3",
                params![
                    claim.authorization_id.to_string(),
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                ],
                map_authorization_record,
            )
            .optional()?
            .ok_or(StorageError::AuthorizationUnavailable)?;
        if authorization.intent_id != claim.intent_id
            || authorization.consumed_at.is_some()
            || authorization.invalidated_at.is_some()
            || authorization.expires_at < claim.claimed_at
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        let intent_binding = tx
            .query_row(
                "SELECT signer_id, session_id, status FROM transaction_intents
                 WHERE id = ?1 AND wallet_id = ?2 AND epoch = ?3
                   AND intent_schema_version = 2",
                params![
                    claim.intent_id.to_string(),
                    metadata.wallet_id.to_string(),
                    metadata.epoch,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        array32_column(row, 1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::IntentTransitionConflict)?;
        if intent_binding.0 != claim.signer_id
            || intent_binding.1 != claim.session_id
            || intent_binding.2 != "approved"
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        if tx.execute(
            "UPDATE one_time_authorizations SET consumed_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND consumed_at IS NULL
               AND invalidated_at IS NULL AND expires_at >= ?1",
            params![
                claim.claimed_at,
                claim.authorization_id.to_string(),
                metadata.epoch,
            ],
        )? != 1
        {
            return Err(StorageError::AuthorizationUnavailable);
        }
        let inserted = tx.execute(
            "INSERT INTO nonce_claims
             (fingerprint, wallet_id, epoch, session_id, claimed_at,
              authorization_id, intent_id, signer_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                claim.fingerprint.as_slice(),
                metadata.wallet_id.to_string(),
                metadata.epoch,
                claim.session_id.as_slice(),
                claim.claimed_at,
                claim.authorization_id.to_string(),
                claim.intent_id.to_string(),
                claim.signer_id,
            ],
        );
        if let Err(error) = inserted {
            if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                return Err(StorageError::NonceAlreadyClaimed);
            }
            return Err(error.into());
        }
        if tx.execute(
            "UPDATE transaction_intents SET status = 'signing', updated_at = ?1
             WHERE id = ?2 AND epoch = ?3 AND status = 'approved'
               AND intent_schema_version = 2",
            params![
                claim.claimed_at,
                claim.intent_id.to_string(),
                metadata.epoch
            ],
        )? != 1
        {
            return Err(StorageError::IntentTransitionConflict);
        }
        append_audit_with_context(
            &tx,
            &metadata,
            "authorization.consumed_nonce_claimed",
            Some(claim.authorization_id.to_string()),
            claim.claimed_at,
            Some(claim.intent_id),
            None,
            &AuditContext::default(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn invalidate_unfinished_ceremonies_on_startup(&mut self, now: i64) -> Result<u64> {
        invalidate_unfinished_ceremonies_on_startup_in(&mut self.connection, now)
    }

    fn record_cutover_recovery(
        &mut self,
        recovery: crate::backup::CrashRecoveryOutcome,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut metadata = metadata_in(&tx)?;
        let subject_id = recovery.recovery_id().map(|id| id.to_string());
        let already_recorded = if let Some(subject_id) = subject_id.as_deref() {
            tx.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM audit_events WHERE event_type = ?1 AND subject_id = ?2
                 )",
                params![recovery.event_type(), subject_id],
                |row| row.get::<_, bool>(0),
            )?
        } else {
            false
        };
        if already_recorded {
            tx.commit()?;
            return Ok(());
        }
        let event_type = recovery.event_type();
        let now = recovery.occurred_at();
        if event_type == "restore.crash_rolled_back"
            && metadata.restore_state == RestoreState::RestorePrecheck
        {
            tx.execute(
                "UPDATE wallet_metadata SET restore_state = 'normal', updated_at = ?1
                 WHERE singleton = 1",
                [now],
            )?;
            metadata.restore_state = RestoreState::Normal;
            metadata.updated_at = now;
        }
        append_audit(&tx, &metadata, event_type, subject_id, now)?;
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
        tx.execute(
            "DELETE FROM intent_materials WHERE kind = 'node_snapshot'",
            [],
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

fn configure_database(mut connection: Connection) -> Result<Connection> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    migrations::migrate(&mut connection)?;
    Ok(connection)
}

fn connect_new_database(path: &Path) -> Result<Connection> {
    if path.exists() {
        return Err(StorageError::AlreadyInitialized);
    }
    create_private_database_file(path)?;
    configure_database(Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?)
}

#[cfg(unix)]
fn create_private_database_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map(drop)
}

#[cfg(not(unix))]
fn create_private_database_file(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .map(drop)
}

fn connect_existing_database(path: &Path) -> Result<Connection> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StorageError::NotInitialized
        } else {
            StorageError::Io(error)
        }
    })?;
    if !metadata.is_file() {
        return Err(StorageError::NotInitialized);
    }
    configure_database(Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?)
}

fn open_database_connection(path: &Path) -> Result<(Connection, u64)> {
    let mut connection = connect_existing_database(path)?;
    if !is_initialized_in(&connection)? {
        return Err(StorageError::NotInitialized);
    }
    let now = connection.query_row("SELECT unixepoch()", [], |row| row.get::<_, i64>(0))?;
    let invalidated = invalidate_unfinished_ceremonies_on_startup_in(&mut connection, now)?;
    Ok((connection, invalidated))
}

fn is_initialized_in(connection: &Connection) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM wallet_metadata WHERE singleton = 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn invalidate_unfinished_ceremonies_on_startup_in(
    connection: &mut Connection,
    now: i64,
) -> Result<u64> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let metadata = metadata_in(&tx)?;
    let changed = tx.execute(
        "UPDATE approval_ceremonies SET invalidated_at = ?1
         WHERE wallet_id = ?2 AND epoch = ?3 AND completed_at IS NULL
           AND invalidated_at IS NULL",
        params![now, metadata.wallet_id.to_string(), metadata.epoch],
    )? as u64;
    if changed > 0 {
        append_audit(&tx, &metadata, "approval.startup_invalidated", None, now)?;
    }
    tx.commit()?;
    Ok(changed)
}

pub(crate) fn metadata_in(tx: &Transaction<'_>) -> Result<WalletMetadata> {
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

pub(crate) fn append_audit(
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

pub(crate) fn ensure_mutations_allowed(metadata: &WalletMetadata) -> Result<()> {
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

fn validate_signer_catalog(catalog: &[NewSignerCatalogEntry], wallet_id: Uuid) -> Result<()> {
    if catalog.is_empty() {
        return Err(StorageError::InvalidSignerProfile);
    }
    let mut secret_ids = std::collections::HashSet::new();
    let mut profile_ids = std::collections::HashSet::new();
    let mut binding_ids = std::collections::HashSet::new();
    let mut scopes = std::collections::HashSet::new();
    for entry in catalog {
        validate_secret_handle(entry.secret_ref.backend, &entry.secret_ref.handle)?;
        validate_new_signer_profile(&entry.profile)?;
        let scope = serde_json::to_string(&entry.profile.chain_scope)
            .map_err(|error| StorageError::InvalidStoredValue(error.to_string()))?;
        if entry.secret_ref.id.is_nil()
            || entry.profile.profile_id.is_nil()
            || entry.profile.wallet_id != wallet_id
            || entry.profile.secret_ref_id != entry.secret_ref.id
            || entry.address_bindings.is_empty()
            || !secret_ids.insert(entry.secret_ref.id)
            || !profile_ids.insert(entry.profile.profile_id)
            || !scopes.insert(scope)
        {
            return Err(StorageError::InvalidSignerProfile);
        }
        let expected_digest: [u8; 32] = Sha256::digest(&entry.profile.verification_key).into();
        for binding in &entry.address_bindings {
            if binding.binding_id.is_nil()
                || binding.profile_id != entry.profile.profile_id
                || binding.chain_scope != entry.profile.chain_scope
                || binding.address.is_empty()
                || binding.address.len() > 512
                || binding.verification_key_digest != expected_digest
                || !binding_ids.insert(binding.binding_id)
            {
                return Err(StorageError::InvalidSignerProfile);
            }
        }
    }
    Ok(())
}

fn signer_catalog_matches(
    storage: &WalletStorage,
    catalog: &[NewSignerCatalogEntry],
    existing: &[SignerProfileInventoryRecord],
) -> Result<bool> {
    if existing.len() != catalog.len() {
        return Ok(false);
    }
    for entry in catalog {
        let Some(stored) = existing
            .iter()
            .find(|stored| stored.profile.profile_id == entry.profile.profile_id)
        else {
            return Ok(false);
        };
        let profile = &stored.profile;
        if profile.wallet_id != entry.profile.wallet_id
            || profile.chain_scope != entry.profile.chain_scope
            || profile.signing_suite_id != entry.profile.signing_suite_id
            || profile.backend_requirement != entry.profile.backend_requirement
            || profile.signer_set_id != entry.profile.signer_set_id
            || profile.authorization_signer_id != entry.profile.authorization_signer_id
            || profile.signer_epoch != entry.profile.signer_epoch
            || profile.threshold != entry.profile.threshold
            || profile.max_signers != entry.profile.max_signers
            || profile.verification_key != entry.profile.verification_key
            || profile.secret_ref_id != entry.profile.secret_ref_id
            || profile.created_at != entry.profile.created_at
            || stored.secret_ref != entry.secret_ref.handle
            || storage.secret_ref(entry.secret_ref.id)?.as_ref() != Some(&entry.secret_ref)
        {
            return Ok(false);
        }
        let mut expected = entry.address_bindings.clone();
        expected.sort_by_key(|binding| (binding.created_at, binding.binding_id));
        if stored.address_bindings.len() != expected.len()
            || stored
                .address_bindings
                .iter()
                .zip(expected.iter())
                .any(|(actual, expected)| {
                    actual.binding_id != expected.binding_id
                        || actual.profile_id != expected.profile_id
                        || actual.chain_scope != expected.chain_scope
                        || actual.address != expected.address
                        || actual.verification_key_digest != expected.verification_key_digest
                        || actual.created_at != expected.created_at
                })
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn catalog_constraint(error: rusqlite::Error, row: &'static str) -> StorageError {
    if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
        StorageError::ImmutableConflict(row)
    } else {
        error.into()
    }
}

fn validate_new_v2_intent(
    intent: &NewTransactionIntentV2,
    material: &IntentMaterial,
) -> Result<()> {
    if intent.intent_schema_version != 2 {
        return Err(StorageError::InvalidV2Intent(
            "intent_schema_version must be 2".to_owned(),
        ));
    }
    if intent.protocol_version == 0 || intent.signer_id.is_empty() {
        return Err(StorageError::InvalidV2Intent(
            "protocol_version and signer_id are required".to_owned(),
        ));
    }
    if intent.expires_at <= intent.created_at {
        return Err(StorageError::InvalidV2Intent(
            "intent expiry must follow creation".to_owned(),
        ));
    }
    if material.intent_id != intent.id || material.node_snapshot_id.is_empty() {
        return Err(StorageError::IntentMaterialMismatch);
    }
    Ok(())
}

fn update_passkey_record_in(
    tx: &Transaction<'_>,
    credential_id: &str,
    expected_record_version: u64,
    updated_passkey_json: &str,
    now: i64,
) -> Result<usize> {
    tx.execute(
        "UPDATE credential_metadata
         SET passkey_json = ?1, credential_record_version = credential_record_version + 1,
             updated_at = ?2
         WHERE credential_id = ?3 AND credential_state = 'active'
           AND credential_record_version = ?4",
        params![
            updated_passkey_json,
            now,
            credential_id,
            expected_record_version,
        ],
    )
    .map_err(Into::into)
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

fn map_transaction_intent_v2(row: &Row<'_>) -> rusqlite::Result<TransactionIntentV2> {
    let status: String = row.get(6)?;
    let network: String = row.get(10)?;
    let action: String = row.get(12)?;
    let schema_version: u32 = row.get(15)?;
    if schema_version != 2 {
        return Err(conversion_error(15, "v2 intent schema version is not 2"));
    }
    Ok(TransactionIntentV2 {
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
        network: IntentNetwork::parse(&network)
            .ok_or_else(|| conversion_error(10, format!("unknown network: {network}")))?,
        protocol_version: row.get(11)?,
        action: IntentAction::parse(&action)
            .ok_or_else(|| conversion_error(12, format!("unknown action: {action}")))?,
        signer_id: row.get(13)?,
        approval_nonce: ApprovalNonce(array32_column(row, 14)?),
        intent_schema_version: schema_version,
        material: None,
    })
}

fn map_intent_material(row: &Row<'_>) -> rusqlite::Result<IntentMaterial> {
    let kind: String = row.get(1)?;
    let payload: String = row.get(2)?;
    Ok(IntentMaterial {
        intent_id: uuid_column(row, 0)?,
        kind: IntentMaterialKind::parse(&kind)
            .ok_or_else(|| conversion_error(1, format!("unknown material kind: {kind}")))?,
        payload_json: serde_json::from_str(&payload).map_err(|error| conversion_error(2, error))?,
        payload_hash: array32_column(row, 3)?,
        node_snapshot_id: row.get(4)?,
    })
}

fn map_passkey_record(row: &Row<'_>) -> rusqlite::Result<PasskeyRecord> {
    let state: String = row.get(6)?;
    Ok(PasskeyRecord {
        credential_id: row.get(0)?,
        wallet_id: uuid_column(row, 1)?,
        label: row.get(2)?,
        passkey_json: row.get(3)?,
        format: row.get(4)?,
        record_version: row.get(5)?,
        credential_state: CredentialState::parse(&state)
            .ok_or_else(|| conversion_error(6, format!("unknown credential state: {state}")))?,
        enrolled_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn map_authorization_record(row: &Row<'_>) -> rusqlite::Result<AuthorizationRecord> {
    Ok(AuthorizationRecord {
        id: uuid_column(row, 0)?,
        intent_id: uuid_column(row, 1)?,
        epoch: row.get(2)?,
        binding_digest: array32_column(row, 3)?,
        expires_at: row.get(4)?,
        issued_at: row.get(5)?,
        consumed_at: row.get(6)?,
        invalidated_at: row.get(7)?,
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

fn map_personal_signing_operation(row: &Row<'_>) -> rusqlite::Result<PersonalSigningOperation> {
    let status: String = row.get(17)?;
    let allowed: Vec<u8> = row.get(13)?;
    let selected: Vec<u8> = row.get(14)?;
    let final_signature = row
        .get::<_, Option<Vec<u8>>>(19)?
        .map(|value| {
            value.try_into().map_err(|value: Vec<u8>| {
                conversion_error(19, format!("expected 64 bytes, got {}", value.len()))
            })
        })
        .transpose()?;
    Ok(PersonalSigningOperation {
        operation_id: uuid_column(row, 0)?,
        wallet_id: uuid_column(row, 1)?,
        profile_id: uuid_column(row, 2)?,
        signer_set_id: uuid_column(row, 3)?,
        signer_epoch: row.get(4)?,
        intent_id: uuid_column(row, 5)?,
        session_id: array32_column(row, 6)?,
        taproot_sighash: array32_column(row, 7)?,
        policy_digest: array32_column(row, 8)?,
        chain_snapshot_digest: array32_column(row, 9)?,
        group_pubkey_xonly: array32_column(row, 10)?,
        profile_binding_digest: array32_column(row, 11)?,
        operation_binding_digest: array32_column(row, 12)?,
        allowed_participants: decode_participants(&allowed, 13)?,
        selected_participants: decode_participants(&selected, 14)?,
        threshold: row.get(15)?,
        max_signers: row.get(16)?,
        status: PersonalSigningOperationStatus::parse(&status)
            .ok_or_else(|| conversion_error(17, format!("unknown operation status: {status}")))?,
        signing_package: row.get(18)?,
        final_signature,
        terminal_reason: row.get(20)?,
        expires_at: row.get(21)?,
        created_at: row.get(22)?,
        updated_at: row.get(23)?,
    })
}

fn map_signer_profile(row: &Row<'_>) -> rusqlite::Result<SignerProfileRecord> {
    let scope_json: String = row.get(2)?;
    let suite_id: String = row.get(3)?;
    let backend: String = row.get(4)?;
    Ok(SignerProfileRecord {
        profile_id: uuid_column(row, 0)?,
        wallet_id: uuid_column(row, 1)?,
        chain_scope: serde_json::from_str(&scope_json)
            .map_err(|error| conversion_error(2, error))?,
        signing_suite_id: SigningSuiteId::from_str(&suite_id)
            .map_err(|error| conversion_error(3, error))?,
        backend_requirement: parse_backend_requirement(&backend)
            .ok_or_else(|| conversion_error(4, format!("unknown signer backend: {backend}")))?,
        signer_set_id: row.get(5)?,
        authorization_signer_id: row.get(6)?,
        signer_epoch: row.get(7)?,
        threshold: row.get(8)?,
        max_signers: row.get(9)?,
        verification_key: row.get(10)?,
        secret_ref_id: uuid_column(row, 11)?,
        created_at: row.get(12)?,
    })
}

fn map_address_binding(row: &Row<'_>) -> rusqlite::Result<StoredAddressBinding> {
    let scope_json: String = row.get(2)?;
    Ok(StoredAddressBinding {
        binding_id: uuid_column(row, 0)?,
        profile_id: uuid_column(row, 1)?,
        chain_scope: serde_json::from_str(&scope_json)
            .map_err(|error| conversion_error(2, error))?,
        address: row.get(3)?,
        verification_key_digest: array32_column(row, 4)?,
        created_at: row.get(5)?,
    })
}

fn map_signing_job(row: &Row<'_>) -> rusqlite::Result<StoredSigningJob> {
    let scope_json: String = row.get(4)?;
    let suite_id: String = row.get(5)?;
    let backend: String = row.get(6)?;
    let review_artifact_json: String = row.get(8)?;
    let parties_json: String = row.get(14)?;
    let operation_binding_digest = row
        .get::<_, Option<Vec<u8>>>(16)?
        .map(|value| vec_to_array32(16, value))
        .transpose()?;
    let status: String = row.get(17)?;
    Ok(StoredSigningJob {
        job_id: uuid_column(row, 0)?,
        wallet_id: uuid_column(row, 1)?,
        profile_id: uuid_column(row, 2)?,
        intent_id: uuid_column(row, 3)?,
        chain_scope: serde_json::from_str(&scope_json)
            .map_err(|error| conversion_error(4, error))?,
        signing_suite_id: SigningSuiteId::from_str(&suite_id)
            .map_err(|error| conversion_error(5, error))?,
        backend_requirement: parse_backend_requirement(&backend)
            .ok_or_else(|| conversion_error(6, format!("unknown signer backend: {backend}")))?,
        review_schema_version: row.get(7)?,
        review_artifact: serde_json::from_str(&review_artifact_json)
            .map_err(|error| conversion_error(8, error))?,
        review_digest: array32_column(row, 9)?,
        signing_message_digest: array32_column(row, 10)?,
        policy_snapshot_digest: array32_column(row, 11)?,
        chain_snapshot_digest: array32_column(row, 12)?,
        session_id: array32_column(row, 13)?,
        selected_parties: serde_json::from_str(&parties_json)
            .map_err(|error| conversion_error(14, error))?,
        receiver: row.get(15)?,
        operation_binding_digest,
        status: SigningJobStatus::parse(&status)
            .ok_or_else(|| conversion_error(17, format!("unknown signing job status: {status}")))?,
        final_signature: row.get(18)?,
        terminal_reason: row.get(19)?,
        expires_at: row.get(20)?,
        created_at: row.get(21)?,
        updated_at: row.get(22)?,
    })
}

fn parse_backend_requirement(value: &str) -> Option<SignerBackendRequirement> {
    SignerBackendRequirement::ALL
        .into_iter()
        .find(|requirement| requirement.as_str() == value)
}

fn validate_new_signer_profile(profile: &NewSignerProfile) -> Result<()> {
    let descriptor = require_executable_suite(&profile.chain_scope, profile.signing_suite_id)
        .map_err(|_| StorageError::InvalidSignerProfile)?;
    if descriptor.backend_requirement != profile.backend_requirement
        || profile.signer_set_id.is_empty()
        || profile.signer_set_id.len() > 128
        || profile.authorization_signer_id.is_empty()
        || profile.authorization_signer_id.len() > 128
        || profile.signer_epoch == 0
        || profile.threshold == 0
        || profile.threshold > profile.max_signers
        || profile.verification_key.is_empty()
        || profile.verification_key.len() > 256
    {
        return Err(StorageError::InvalidSignerProfile);
    }
    Ok(())
}

fn validate_new_signing_job(job: &NewSigningJob) -> Result<()> {
    let descriptor = require_executable_suite(&job.chain_scope, job.signing_suite_id)
        .map_err(|_| StorageError::InvalidSigningJob)?;
    if descriptor.backend_requirement != job.backend_requirement
        || job.review_schema_version == 0
        || job.review_artifact.schema_version != job.review_schema_version
        || job.review_artifact.scope != job.chain_scope
        || job.review_artifact.review_digest != job.review_digest
        || job.review_artifact.signing_message_digest != job.signing_message_digest
        || job.selected_parties[0].is_empty()
        || job.selected_parties[1].is_empty()
        || job.selected_parties[0] == job.selected_parties[1]
        || !job.selected_parties.contains(&job.receiver)
        || job.receiver.len() > 64
        || job.expires_at <= job.created_at
    {
        return Err(StorageError::InvalidSigningJob);
    }
    Ok(())
}

fn vec_to_array32(index: usize, value: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    value.try_into().map_err(|value: Vec<u8>| {
        conversion_error(index, format!("expected 32 bytes, got {}", value.len()))
    })
}

fn map_personal_signing_receipt(row: &Row<'_>) -> rusqlite::Result<PersonalSigningReceipt> {
    let round: String = row.get(2)?;
    Ok(PersonalSigningReceipt {
        operation_id: uuid_column(row, 0)?,
        signer_id: row.get(1)?,
        round: PersonalSigningRound::parse(&round)
            .ok_or_else(|| conversion_error(2, format!("unknown signing round: {round}")))?,
        device_id: uuid_column(row, 3)?,
        device_generation: row.get(4)?,
        request_binding_digest: array32_column(row, 5)?,
        payload: row.get(6)?,
        received_at: row.get(7)?,
    })
}

fn validate_new_personal_operation(operation: &NewPersonalSigningOperation) -> Result<()> {
    let selected = operation.selected_participants;
    if operation.signer_epoch == 0
        || operation.threshold != 2
        || operation.max_signers != 3
        || operation.allowed_participants != [1, 2, 3]
        || selected[0] >= selected[1]
        || selected
            .iter()
            .any(|signer_id| !(1..=3).contains(signer_id))
        || operation.expires_at <= operation.created_at
    {
        return Err(StorageError::InvalidPersonalSigningOperation);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct PersistedPersonalIntent {
    personal_signing_policy: PersistedPersonalSigningPolicy,
}

#[derive(serde::Deserialize)]
struct PersistedPersonalSigningPolicy {
    profile_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    group_pubkey_xonly: String,
    allowed_participants: [u16; 3],
    threshold: u16,
    policy_digest: String,
    chain_snapshot_digest: String,
}

fn validate_personal_operation_material(
    payload_json: &str,
    payload_hash: &[u8],
    operation: &NewPersonalSigningOperation,
) -> Result<()> {
    let computed_hash: [u8; 32] = Sha256::digest(payload_json.as_bytes()).into();
    if computed_hash != payload_hash {
        return Err(StorageError::InvalidPersonalSigningOperation);
    }
    let material: PersistedPersonalIntent = serde_json::from_str(payload_json)
        .map_err(|_| StorageError::InvalidPersonalSigningOperation)?;
    let policy = material.personal_signing_policy;
    let group_pubkey_xonly = decode_hex32(&policy.group_pubkey_xonly, "group_pubkey_xonly")
        .map_err(|_| StorageError::InvalidPersonalSigningOperation)?;
    let policy_digest = decode_hex32(&policy.policy_digest, "policy_digest")
        .map_err(|_| StorageError::InvalidPersonalSigningOperation)?;
    let chain_snapshot_digest =
        decode_hex32(&policy.chain_snapshot_digest, "chain_snapshot_digest")
            .map_err(|_| StorageError::InvalidPersonalSigningOperation)?;
    if policy.profile_id != operation.profile_id
        || policy.signer_set_id != operation.signer_set_id
        || policy.signer_epoch != operation.signer_epoch
        || group_pubkey_xonly != operation.group_pubkey_xonly
        || policy.allowed_participants != operation.allowed_participants
        || policy.threshold != operation.threshold
        || policy_digest != operation.policy_digest
        || chain_snapshot_digest != operation.chain_snapshot_digest
    {
        return Err(StorageError::InvalidPersonalSigningOperation);
    }
    Ok(())
}

fn encode_participants<const N: usize>(participants: &[u16; N]) -> Vec<u8> {
    participants
        .iter()
        .flat_map(|participant| participant.to_be_bytes())
        .collect()
}

fn decode_participants<const N: usize>(value: &[u8], column: usize) -> rusqlite::Result<[u16; N]> {
    if value.len() != N * 2 {
        return Err(conversion_error(
            column,
            format!("expected {} participant bytes, got {}", N * 2, value.len()),
        ));
    }
    let participants =
        std::array::from_fn(|index| u16::from_be_bytes([value[index * 2], value[index * 2 + 1]]));
    Ok(participants)
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

fn decode_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .map_err(|_| StorageError::InvalidStoredValue(format!("{field} is not hexadecimal")))?
        .try_into()
        .map_err(|_| StorageError::InvalidStoredValue(format!("{field} must be 32 bytes")))
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
    let file = open_private_owner_lock(&lock_path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(StorageError::WriterAlreadyActive)
        }
        Err(error) => Err(error.into()),
    }
}

impl ProviderReplayStore for WalletStorage {
    fn claim_request_nonce(
        &mut self,
        identity: &ProviderIdentity,
        context: &SignerRequestContext,
        claimed_at: i64,
    ) -> std::result::Result<(), ProviderError> {
        match self.claim_signer_request_nonce(identity, context, claimed_at) {
            Ok(()) => Ok(()),
            Err(StorageError::NonceAlreadyClaimed) => Err(ProviderError::Replay),
            Err(StorageError::SignerOperationBindingDrift) => {
                Err(ProviderError::RoundBindingMismatch)
            }
            Err(_) => Err(ProviderError::BackendUnavailable),
        }
    }
}

#[cfg(unix)]
fn open_private_owner_lock(lock_path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Ok(metadata) = std::fs::symlink_metadata(lock_path)
        && !metadata.file_type().is_file()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wallet owner lock must be a regular file",
        ));
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    let path_metadata = std::fs::symlink_metadata(lock_path)?;
    if !path_metadata.file_type().is_file() || !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wallet owner lock must be a regular file",
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_owner_lock(lock_path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
}

fn owner_lock_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(".owner.lock");
    PathBuf::from(path)
}
