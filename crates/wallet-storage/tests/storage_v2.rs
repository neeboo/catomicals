use catomicals_wallet_storage::{
    ApprovalDecision, ApprovalNonce, AuditContext, CURRENT_SCHEMA_VERSION, CredentialState,
    FrostNonceAuthorizationClaim, IntentAction, IntentMaterial, IntentMaterialKind, IntentNetwork,
    NewPasskeyApprovalCeremony, NewPasskeyRecord, NewTransactionIntent, NewTransactionIntentV2,
    PasskeyApprovalCompletion, StorageError, TransactionIntentStatus, WalletStorage,
    WebauthnProfile,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

const V1_SQL: &str = include_str!("../migrations/0001_initial.sql");
const V1_SHA256: &str = "c97c2df36eba2efe0a6452d2107d40f8e95819b8b9d81bdc71e9539324706413";

fn v2_intent(id: Uuid, nonce: [u8; 32], created_at: i64) -> NewTransactionIntentV2 {
    NewTransactionIntentV2 {
        id,
        tx_digest: [0x11; 32],
        policy_hash: [0x22; 32],
        session_id: [0x33; 32],
        network: IntentNetwork::Signet,
        protocol_version: 1,
        action: IntentAction::Transfer,
        signer_id: "frost:participant-1".to_owned(),
        approval_nonce: ApprovalNonce(nonce),
        intent_schema_version: 2,
        expires_at: created_at + 10_000,
        created_at,
    }
}

fn material(intent_id: Uuid) -> IntentMaterial {
    IntentMaterial {
        intent_id,
        kind: IntentMaterialKind::UnsignedTransaction,
        payload_json: serde_json::json!({"psbt": "opaque"}),
        payload_hash: [0x44; 32],
        node_snapshot_id: "snapshot-42".to_owned(),
    }
}

fn initialized() -> (tempfile::TempDir, std::path::PathBuf, WalletStorage, Uuid) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    let storage = WalletStorage::initialize(&path, wallet_id, 1_700_000_000).unwrap();
    (dir, path, storage, wallet_id)
}

fn create_v1_database(path: &std::path::Path, wallet_id: Uuid) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(V1_SQL).unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, checksum) VALUES (1, ?1)",
            [V1_SHA256],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    connection
        .execute(
            "INSERT INTO wallet_metadata
             (singleton, wallet_id, epoch, restore_state, created_at, updated_at)
             VALUES (1, ?1, 1, 'normal', 1, 1)",
            [wallet_id.to_string()],
        )
        .unwrap();
}

#[test]
fn v1_migration_checksum_is_immutable() {
    let canonical = V1_SQL.replace("\r\n", "\n");
    assert_eq!(hex::encode(Sha256::digest(canonical.as_bytes())), V1_SHA256);
}

#[test]
fn v1_database_upgrades_through_v3_and_invalidates_legacy_security_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    create_v1_database(&path, wallet_id);
    let raw = Connection::open(&path).unwrap();
    raw.execute(
        "INSERT INTO transaction_intents
         (id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
          expires_at, created_at, updated_at)
         VALUES (?1, ?2, 1, ?3, ?4, ?5, 'approved', 100, 1, 1)",
        params![
            Uuid::new_v4().to_string(),
            wallet_id.to_string(),
            [1_u8; 32].as_slice(),
            [2_u8; 32].as_slice(),
            [3_u8; 32].as_slice(),
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO credential_metadata
         (credential_id, wallet_id, label, cose_public_key, sign_count, enrolled_at, updated_at)
         VALUES ('legacy', ?1, 'legacy', 'legacy-cose', 0, 1, 1)",
        [wallet_id.to_string()],
    )
    .unwrap();
    drop(raw);

    let storage = WalletStorage::open(&path).unwrap();
    assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert!(storage.passkey_record("legacy").unwrap().is_none());
    drop(storage);
    let raw = Connection::open(path).unwrap();
    let ledger: Vec<i64> = raw
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(ledger, vec![1, 2, 3, 4, 5, 6]);
    let status: String = raw
        .query_row("SELECT status FROM transaction_intents", [], |row| {
            row.get(0)
        })
        .unwrap();
    let credential_state: String = raw
        .query_row(
            "SELECT credential_state FROM credential_metadata",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "invalidated");
    assert_eq!(credential_state, "legacy_unusable");
}

#[test]
fn tampered_v1_checksum_is_rejected_before_v2_changes_are_applied() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    create_v1_database(&path, wallet_id);
    let raw = Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE schema_migrations SET checksum = ?1 WHERE version = 1",
        ["0".repeat(64)],
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
    let raw = Connection::open(path).unwrap();
    let version: i32 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let v2_table: bool = raw
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'intent_materials')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 1);
    assert!(!v2_table);
}

#[test]
fn fresh_database_runs_all_migrations_and_validates_current_schema() {
    let (_dir, path, storage, _) = initialized();
    assert_eq!(CURRENT_SCHEMA_VERSION, 6);
    drop(storage);
    let raw = Connection::open(path).unwrap();
    let ledger_count: u64 = raw
        .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(ledger_count, 6);
    for name in [
        "intent_materials",
        "webauthn_profiles",
        "transaction_intents_v2_status_page",
        "transaction_intents_v2_approval_nonce",
        "transaction_intents_v2_immutable",
        "signer_request_nonces",
    ] {
        let exists: bool = raw
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing {name}");
    }
}

#[test]
fn recovery_cursors_expose_current_epoch_authority_state_and_startup_invalidation() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();

    let pending_id = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(pending_id, [0x77; 32], 20), material(pending_id))
        .unwrap();
    let unfinished_id = Uuid::new_v4();
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: unfinished_id,
            intent_id: pending_id,
            credential_id: "cred-1".to_owned(),
            binding_digest: [0x88; 32],
            started_at: 21,
            expires_at: 80,
        })
        .unwrap();
    drop(storage);

    let reopened = WalletStorage::open(&path).unwrap();
    assert_eq!(reopened.startup_invalidated_ceremonies(), 1);
    assert_eq!(reopened.list_transaction_intents_v2().unwrap().len(), 2);
    assert_eq!(
        reopened
            .list_intent_materials(IntentMaterialKind::UnsignedTransaction)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(reopened.list_passkey_records().unwrap().len(), 1);
    assert_eq!(
        reopened.list_available_authorizations(13).unwrap()[0].id,
        authorization_id
    );
    assert!(
        reopened
            .approval_ceremony(unfinished_id)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
}

#[test]
fn v2_intent_and_material_round_trip_without_collapsing_policy_hash() {
    let (_dir, path, mut storage, _) = initialized();
    let id = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(id, [0x55; 32], 10), material(id))
        .unwrap();
    drop(storage);

    let storage = WalletStorage::open(path).unwrap();
    let persisted = storage.transaction_intent_v2(id).unwrap().unwrap();
    assert_eq!(persisted.policy_hash, [0x22; 32]);
    assert_eq!(persisted.tx_digest, [0x11; 32]);
    assert_ne!(persisted.policy_hash, persisted.tx_digest);
    assert_eq!(persisted.network, IntentNetwork::Signet);
    assert_eq!(persisted.protocol_version, 1);
    assert_eq!(persisted.action, IntentAction::Transfer);
    assert_eq!(persisted.signer_id, "frost:participant-1");
    assert_eq!(persisted.approval_nonce, ApprovalNonce([0x55; 32]));
    assert_eq!(persisted.intent_schema_version, 2);
    let persisted_material = storage.intent_material(id).unwrap().unwrap();
    assert_eq!(persisted_material.payload_hash, [0x44; 32]);
    assert_eq!(persisted_material.node_snapshot_id, "snapshot-42");
}

#[test]
fn legacy_approval_api_cannot_complete_a_v2_passkey_ceremony() {
    let (_dir, _path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);

    let result = storage.approve_and_issue_authorization(
        ApprovalDecision {
            ceremony_id,
            authorization_id,
            binding_digest: binding,
            authorization_expires_at: 90,
            approved_at: 12,
        },
        &AuditContext::default(),
    );

    assert!(matches!(result, Err(StorageError::LegacyApiRejectedForV2)));
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Pending
    );
    assert_eq!(
        storage
            .passkey_record("cred-1")
            .unwrap()
            .unwrap()
            .record_version,
        1
    );
    assert!(
        storage
            .available_authorization(intent_id, 13)
            .unwrap()
            .is_none()
    );
}

#[test]
fn legacy_intent_cannot_be_promoted_to_v2_without_complete_security_fields() {
    let (_dir, path, mut storage, _) = initialized();
    let id = Uuid::new_v4();
    storage
        .create_transaction_intent(NewTransactionIntent {
            id,
            tx_digest: [1; 32],
            policy_hash: [2; 32],
            session_id: [3; 32],
            expires_at: 100,
            created_at: 1,
        })
        .unwrap();
    let raw = Connection::open(path).unwrap();

    assert!(
        raw.execute(
            "UPDATE transaction_intents SET intent_schema_version = 2 WHERE id = ?1",
            [id.to_string()],
        )
        .is_err()
    );
    assert!(storage.transaction_intent_v2(id).unwrap().is_none());
}

#[test]
fn reopen_rejects_weakened_v2_required_trigger_with_the_same_name() {
    let (_dir, path, storage, _) = initialized();
    drop(storage);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "DROP TRIGGER transaction_intents_v2_required;
         CREATE TRIGGER transaction_intents_v2_required
         BEFORE INSERT ON transaction_intents
         BEGIN SELECT 1; END;",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn partially_bound_v2_nonce_claim_is_rejected_by_the_schema() {
    let (_dir, path, storage, wallet_id) = initialized();
    drop(storage);
    let raw = Connection::open(path).unwrap();
    let result = raw.execute(
        "INSERT INTO nonce_claims
         (fingerprint, wallet_id, epoch, session_id, claimed_at, authorization_id)
         VALUES (?1, ?2, 1, ?3, 4, ?4)",
        params![
            [0xc1_u8; 32].as_slice(),
            wallet_id.to_string(),
            [0xc2_u8; 32].as_slice(),
            Uuid::new_v4().to_string(),
        ],
    );
    assert!(result.is_err());
}

#[test]
fn v2_intent_creation_is_atomic_and_approval_nonce_is_unique_per_wallet() {
    let (_dir, _path, mut storage, _) = initialized();
    let first = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(first, [0x66; 32], 10), material(first))
        .unwrap();
    let second = Uuid::new_v4();
    assert!(
        storage
            .create_transaction_intent_v2(v2_intent(second, [0x66; 32], 11), material(second))
            .is_err()
    );
    assert!(storage.transaction_intent_v2(second).unwrap().is_none());
    assert!(storage.intent_material(second).unwrap().is_none());
}

#[test]
fn latest_v2_intent_uses_the_hot_path_without_loading_material() {
    let (_dir, _path, mut storage, _) = initialized();
    let older = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(older, [0x67; 32], 10), material(older))
        .unwrap();
    let newer = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(newer, [0x68; 32], 11), material(newer))
        .unwrap();

    let latest = storage.latest_transaction_intent_v2().unwrap().unwrap();
    assert_eq!(latest.id, newer);
    assert!(latest.material.is_none());
}

#[test]
fn v2_security_fields_are_immutable_and_missing_fields_fail_closed() {
    let (_dir, path, mut storage, _) = initialized();
    let id = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(v2_intent(id, [0x77; 32], 10), material(id))
        .unwrap();
    let raw = Connection::open(&path).unwrap();
    assert!(
        raw.execute(
            "UPDATE transaction_intents SET policy_hash = ?1 WHERE id = ?2",
            params![[0x99_u8; 32].as_slice(), id.to_string()],
        )
        .is_err()
    );
    assert!(
        raw.execute(
            "UPDATE transaction_intents SET expires_at = expires_at + 1 WHERE id = ?1",
            [id.to_string()],
        )
        .is_err()
    );
    raw.execute("DROP TRIGGER transaction_intents_v2_required", [])
        .unwrap();
    raw.execute("DROP TRIGGER transaction_intents_v2_immutable", [])
        .unwrap();
    assert!(
        raw.execute(
            "UPDATE transaction_intents SET network = NULL WHERE id = ?1",
            [id.to_string()],
        )
        .is_err()
    );
    assert!(storage.transaction_intent_v2(id).unwrap().is_some());
}

#[test]
fn reopen_rejects_weakened_v2_security_index_with_the_same_name() {
    let (_dir, path, storage, _) = initialized();
    drop(storage);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "DROP INDEX transaction_intents_v2_approval_nonce;
         CREATE INDEX transaction_intents_v2_approval_nonce
         ON transaction_intents(wallet_id);",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn passkey_profile_is_stable_and_record_updates_use_cas() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    storage
        .set_webauthn_profile(WebauthnProfile {
            wallet_id,
            user_id: "user-1".to_owned(),
            rp_id: "wallet.example".to_owned(),
            rp_origin: "https://wallet.example".to_owned(),
            record_version: 1,
            updated_at: 10,
        })
        .unwrap();
    let mismatch = storage.set_webauthn_profile(WebauthnProfile {
        wallet_id,
        user_id: "user-1".to_owned(),
        rp_id: "evil.example".to_owned(),
        rp_origin: "https://evil.example".to_owned(),
        record_version: 2,
        updated_at: 11,
    });
    assert!(matches!(
        mismatch,
        Err(StorageError::WebauthnProfileMismatch)
    ));

    storage
        .insert_passkey_record(NewPasskeyRecord {
            credential_id: "cred-1".to_owned(),
            label: "Mac".to_owned(),
            passkey_json: r#"{"counter":0}"#.to_owned(),
            format: "webauthn-rs-passkey-json".to_owned(),
            credential_state: CredentialState::Active,
            enrolled_at: 12,
        })
        .unwrap();
    storage
        .update_passkey_record_cas("cred-1", 1, r#"{"counter":1}"#, 13)
        .unwrap();
    assert!(matches!(
        storage.update_passkey_record_cas("cred-1", 1, r#"{"counter":2}"#, 14),
        Err(StorageError::CredentialVersionConflict)
    ));
    drop(storage);
    let storage = WalletStorage::open(path).unwrap();
    let record = storage.passkey_record("cred-1").unwrap().unwrap();
    assert_eq!(record.passkey_json, r#"{"counter":1}"#);
    assert_eq!(record.record_version, 2);
}

fn setup_approval(storage: &mut WalletStorage, wallet_id: Uuid) -> (Uuid, Uuid, Uuid, [u8; 32]) {
    storage
        .set_webauthn_profile(WebauthnProfile {
            wallet_id,
            user_id: "user-1".to_owned(),
            rp_id: "wallet.example".to_owned(),
            rp_origin: "https://wallet.example".to_owned(),
            record_version: 1,
            updated_at: 2,
        })
        .unwrap();
    storage
        .insert_passkey_record(NewPasskeyRecord {
            credential_id: "cred-1".to_owned(),
            label: "Mac".to_owned(),
            passkey_json: r#"{"counter":0}"#.to_owned(),
            format: "webauthn-rs-passkey-json".to_owned(),
            credential_state: CredentialState::Active,
            enrolled_at: 3,
        })
        .unwrap();
    let intent_id = Uuid::new_v4();
    let ceremony_id = Uuid::new_v4();
    let authorization_id = Uuid::new_v4();
    let binding = [0x88; 32];
    storage
        .create_transaction_intent_v2(v2_intent(intent_id, [0x90; 32], 10), material(intent_id))
        .unwrap();
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: ceremony_id,
            intent_id,
            credential_id: "cred-1".to_owned(),
            binding_digest: binding,
            started_at: 11,
            expires_at: 100,
        })
        .unwrap();
    (intent_id, ceremony_id, authorization_id, binding)
}

fn completion(
    intent_id: Uuid,
    ceremony_id: Uuid,
    authorization_id: Uuid,
    binding: [u8; 32],
) -> PasskeyApprovalCompletion {
    PasskeyApprovalCompletion {
        ceremony_id,
        intent_id,
        credential_id: "cred-1".to_owned(),
        expected_credential_record_version: 1,
        updated_passkey_json: r#"{"counter":1}"#.to_owned(),
        binding_digest: binding,
        authorization_id,
        authorization_expires_at: 90,
        rp_id: "wallet.example".to_owned(),
        rp_origin: "https://wallet.example".to_owned(),
        approved_at: 12,
    }
}

#[test]
fn complete_passkey_approval_updates_all_security_state_atomically() {
    let (_dir, _path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    let authorization = storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();
    assert_eq!(authorization.id, authorization_id);
    assert_eq!(authorization.intent_id, intent_id);
    assert_eq!(authorization.binding_digest, binding);
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Approved
    );
    assert_eq!(
        storage
            .passkey_record("cred-1")
            .unwrap()
            .unwrap()
            .record_version,
        2
    );
    assert_eq!(
        storage
            .available_authorization(intent_id, 13)
            .unwrap()
            .unwrap()
            .id,
        authorization_id
    );
}

#[test]
fn approval_audit_failure_rolls_back_credential_intent_and_authorization() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    drop(storage);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_v2_approval_audit BEFORE INSERT ON audit_events
         WHEN NEW.event_type = 'approval.passkey_completed'
         BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END;",
    )
    .unwrap();
    drop(raw);
    let mut storage = WalletStorage::open(path).unwrap();
    assert!(
        storage
            .complete_passkey_approval_atomic(completion(
                intent_id,
                ceremony_id,
                authorization_id,
                binding,
            ))
            .is_err()
    );
    assert_eq!(
        storage
            .passkey_record("cred-1")
            .unwrap()
            .unwrap()
            .record_version,
        1
    );
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Pending
    );
    assert!(
        storage
            .available_authorization(intent_id, 13)
            .unwrap()
            .is_none()
    );
}

#[test]
fn authorization_consumption_and_frost_nonce_claim_are_atomic_and_durable() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();
    let claim = FrostNonceAuthorizationClaim {
        authorization_id,
        intent_id,
        signer_id: "frost:participant-1".to_owned(),
        session_id: [0x33; 32],
        fingerprint: [0xaa; 32],
        claimed_at: 14,
    };
    storage
        .consume_authorization_and_claim_frost_nonce(claim.clone())
        .unwrap();
    drop(storage);
    let mut storage = WalletStorage::open(path).unwrap();
    assert_eq!(storage.list_nonce_claims().unwrap().len(), 1);
    assert_eq!(
        storage.list_nonce_claims().unwrap()[0].fingerprint,
        [0xaa; 32]
    );
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Signing
    );
    assert!(matches!(
        storage.consume_authorization_and_claim_frost_nonce(claim),
        Err(StorageError::AuthorizationUnavailable)
            | Err(StorageError::NonceAlreadyClaimed)
            | Err(StorageError::IntentTransitionConflict)
    ));
    storage
        .transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Signing,
            TransactionIntentStatus::Signed,
            15,
        )
        .unwrap();
}

#[test]
fn legacy_authorization_consume_cannot_bypass_v2_nonce_claim() {
    let (_dir, _path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();

    assert!(matches!(
        storage.consume_authorization(authorization_id, 1, 14),
        Err(StorageError::LegacyApiRejectedForV2)
    ));
    assert!(
        storage
            .available_authorization(intent_id, 15)
            .unwrap()
            .is_some()
    );
}

#[test]
fn direct_transition_cannot_bypass_v2_atomic_consume_path() {
    let (_dir, _path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();

    assert!(matches!(
        storage.transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Approved,
            TransactionIntentStatus::Signing,
            14,
        ),
        Err(StorageError::LegacyApiRejectedForV2)
    ));
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Approved
    );
}

#[test]
fn duplicate_nonce_rolls_back_authorization_consumption_and_intent_transition() {
    let (_dir, _path, mut storage, wallet_id) = initialized();
    let duplicate = [0xbb; 32];
    storage
        .claim_nonce(catomicals_wallet_storage::NewNonceClaim {
            fingerprint: duplicate,
            session_id: [0xcc; 32],
            claimed_at: 5,
        })
        .unwrap();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();
    assert!(
        storage
            .consume_authorization_and_claim_frost_nonce(FrostNonceAuthorizationClaim {
                authorization_id,
                intent_id,
                signer_id: "frost:participant-1".to_owned(),
                session_id: [0x33; 32],
                fingerprint: duplicate,
                claimed_at: 14,
            })
            .is_err()
    );
    assert!(
        storage
            .available_authorization(intent_id, 15)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Approved
    );
}

#[test]
fn consume_audit_failure_rolls_back_authorization_nonce_and_intent() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();
    drop(storage);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_v2_consume_audit BEFORE INSERT ON audit_events
         WHEN NEW.event_type = 'authorization.consumed_nonce_claimed'
         BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END;",
    )
    .unwrap();
    drop(raw);
    let mut storage = WalletStorage::open(path).unwrap();
    let fingerprint = [0xbc; 32];
    assert!(
        storage
            .consume_authorization_and_claim_frost_nonce(FrostNonceAuthorizationClaim {
                authorization_id,
                intent_id,
                signer_id: "frost:participant-1".to_owned(),
                session_id: [0x33; 32],
                fingerprint,
                claimed_at: 14,
            })
            .is_err()
    );
    assert!(
        storage
            .available_authorization(intent_id, 15)
            .unwrap()
            .is_some()
    );
    assert!(storage.nonce_claim(fingerprint).unwrap().is_none());
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Approved
    );
}

#[test]
fn startup_invalidates_unfinished_ceremonies_and_completed_authorization_survives_reopen() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, ceremony_id, authorization_id, binding) =
        setup_approval(&mut storage, wallet_id);
    storage
        .complete_passkey_approval_atomic(completion(
            intent_id,
            ceremony_id,
            authorization_id,
            binding,
        ))
        .unwrap();
    let unfinished_intent = Uuid::new_v4();
    storage
        .create_transaction_intent_v2(
            v2_intent(unfinished_intent, [0x91; 32], 20),
            material(unfinished_intent),
        )
        .unwrap();
    let unfinished = Uuid::new_v4();
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: unfinished,
            intent_id: unfinished_intent,
            credential_id: "cred-1".to_owned(),
            binding_digest: [0x92; 32],
            started_at: 21,
            expires_at: 100,
        })
        .unwrap();
    drop(storage);
    let mut storage = WalletStorage::open(path).unwrap();
    assert_eq!(
        storage
            .invalidate_unfinished_ceremonies_on_startup(22)
            .unwrap(),
        0,
        "open already performs startup invalidation"
    );
    assert!(
        storage
            .approval_ceremony(unfinished)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert!(
        storage
            .available_authorization(intent_id, 23)
            .unwrap()
            .is_some()
    );
}

#[test]
fn open_automatically_invalidates_unfinished_passkey_ceremonies() {
    let (_dir, path, mut storage, wallet_id) = initialized();
    let (intent_id, _completed_ceremony, _authorization_id, _binding) =
        setup_approval(&mut storage, wallet_id);
    let unfinished = Uuid::new_v4();
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: unfinished,
            intent_id,
            credential_id: "cred-1".to_owned(),
            binding_digest: [0x93; 32],
            started_at: 20,
            expires_at: 100,
        })
        .unwrap();
    drop(storage);

    let storage = WalletStorage::open(path).unwrap();
    assert!(
        storage
            .approval_ceremony(unfinished)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert!(
        storage
            .audit_events(100)
            .unwrap()
            .iter()
            .any(|event| event.event_type == "approval.startup_invalidated")
    );
}

#[test]
fn v2_status_pagination_uses_index_and_does_not_join_material_payloads() {
    let (_dir, path, storage, wallet_id) = initialized();
    drop(storage);
    let mut raw = Connection::open(&path).unwrap();
    let tx = raw.transaction().unwrap();
    for i in 0..10_000_i64 {
        let id = Uuid::new_v4();
        let nonce = Sha256::digest(i.to_le_bytes());
        tx.execute(
            "INSERT INTO transaction_intents
             (id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
              expires_at, created_at, updated_at, network, protocol_version, action,
              signer_id, approval_nonce, intent_schema_version)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, 'pending', 999999, ?6, ?6,
                     'signet', 1, 'transfer', 'frost:participant-1', ?7, 2)",
            params![
                id.to_string(),
                wallet_id.to_string(),
                [1_u8; 32].as_slice(),
                [2_u8; 32].as_slice(),
                [3_u8; 32].as_slice(),
                i,
                &nonce[..],
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let plan: String = raw
        .query_row(
            "EXPLAIN QUERY PLAN
             SELECT id, wallet_id, epoch, tx_digest, policy_hash, session_id, status,
                    expires_at, created_at, updated_at, network, protocol_version, action,
                    signer_id, approval_nonce, intent_schema_version
             FROM transaction_intents
             WHERE wallet_id = ?1 AND epoch = 1 AND status = 'pending'
               AND intent_schema_version = 2
             ORDER BY created_at ASC, id ASC LIMIT 50",
            [wallet_id.to_string()],
            |row| row.get(3),
        )
        .unwrap();
    assert!(
        plan.contains("transaction_intents_v2_status_page"),
        "{plan}"
    );
    drop(raw);

    let storage = WalletStorage::open(path).unwrap();
    let first = storage
        .transaction_intents_v2_page(TransactionIntentStatus::Pending, None, 50)
        .unwrap();
    assert_eq!(first.len(), 50);
    let cursor = first.last().unwrap().cursor();
    let second = storage
        .transaction_intents_v2_page(TransactionIntentStatus::Pending, Some(cursor), 50)
        .unwrap();
    assert_eq!(second.len(), 50);
    assert!(first.iter().all(|intent| intent.material.is_none()));
    assert!(second.first().unwrap().created_at >= first.last().unwrap().created_at);
}
