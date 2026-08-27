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
    ApprovalCeremony, ApprovalDecision, ApprovalNonce, AuditContext, AuditEvent,
    AuthorizationRecord, CredentialMetadata, CredentialState, FrostNonceAuthorizationClaim,
    IntentAction, IntentCursor, IntentMaterial, IntentMaterialKind, IntentNetwork,
    NewApprovalCeremony, NewNonceClaim, NewPasskeyApprovalCeremony, NewPasskeyRecord,
    NewTransactionIntent, NewTransactionIntentV2, NonceClaim, PasskeyApprovalCompletion,
    PasskeyRecord, RestoreState, Result, SecretBackend, SecretRef, SqliteSettings, StorageError,
    TransactionIntent, TransactionIntentStatus, TransactionIntentV2, WalletMetadata,
    WebauthnProfile, migrations,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
        let (connection, startup_invalidated_ceremonies) = open_database_connection(path)?;
        Ok(Self::from_retained_owner_lock(
            connection,
            owner_lock,
            startup_invalidated_ceremonies,
        ))
    }

    fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let owner_lock = acquire_owner_lock(path)?;
        let connection = connect_database(path)?;
        Ok(Self::from_retained_owner_lock(connection, owner_lock, 0))
    }

    pub(crate) fn open_database_connection(path: &Path) -> Result<(Connection, u64)> {
        open_database_connection(path)
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

fn connect_database(path: &Path) -> Result<Connection> {
    let mut connection = Connection::open(path)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    migrations::migrate(&mut connection)?;
    Ok(connection)
}

fn open_database_connection(path: &Path) -> Result<(Connection, u64)> {
    let mut connection = connect_database(path)?;
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
