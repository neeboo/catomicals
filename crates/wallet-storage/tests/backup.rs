use std::fs;

use catomicals_secret_store::{FileSecretBackend, RuntimeProfile};
use catomicals_wallet_storage::{
    ApprovalDecision, AuditContext, BackupError, NewApprovalCeremony, NewNonceClaim,
    NewTransactionIntent, RestoreState, StorageError, TransactionIntentStatus, WalletStorage,
};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn export_is_an_encrypted_consistent_snapshot_with_a_verifiable_manifest() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let bundle = directory.path().join("backup");
    let backend = file_backend(directory.path());
    let wallet_id = Uuid::from_bytes([0x31; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let intent_id = Uuid::from_bytes([0x32; 16]);
    storage
        .create_transaction_intent(intent(intent_id, 1_800_000_001))
        .unwrap();

    let manifest = storage
        .export_encrypted_backup(&bundle, Some(&backend), 1_800_000_010)
        .unwrap();

    assert_eq!(manifest.wallet_id, wallet_id);
    assert_eq!(manifest.recovery_epoch, 1);
    assert_eq!(manifest.schema_version, storage.schema_version().unwrap());
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Normal
    );
    let artifact = fs::read(bundle.join(&manifest.database_file)).unwrap();
    assert!(
        !artifact
            .windows(b"SQLite format 3".len())
            .any(|part| part == b"SQLite format 3")
    );
    let manifest_text = fs::read_to_string(bundle.join("manifest.json")).unwrap();
    assert!(!manifest_text.contains("wrapped_dek"));
    assert!(!manifest_text.contains("ciphertext"));
    let mut bundle_files = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    bundle_files.sort();
    assert_eq!(bundle_files.len(), 2);

    let verified = WalletStorage::verify_encrypted_backup(&bundle, Some(&backend)).unwrap();
    assert_eq!(verified, manifest);
}

#[test]
fn export_and_verify_fail_closed_without_a_secret_backend() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x41; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();

    assert!(matches!(
        storage.export_encrypted_backup(directory.path().join("backup"), None, 1_800_000_001),
        Err(StorageError::Backup(BackupError::SecretBackendUnavailable))
    ));
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Normal
    );
}

#[test]
fn ciphertext_tampering_is_rejected_before_decryption() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let bundle = directory.path().join("backup");
    let backend = file_backend(directory.path());
    let wallet_id = Uuid::from_bytes([0x51; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let manifest = storage
        .export_encrypted_backup(&bundle, Some(&backend), 1_800_000_001)
        .unwrap();
    let artifact_path = bundle.join(manifest.database_file);
    let mut artifact = fs::read(&artifact_path).unwrap();
    let last = artifact.len() - 1;
    artifact[last] ^= 1;
    fs::write(artifact_path, artifact).unwrap();

    assert!(matches!(
        WalletStorage::verify_encrypted_backup(&bundle, Some(&backend)),
        Err(StorageError::Backup(BackupError::ArtifactChecksumMismatch))
    ));
}

#[test]
fn restore_enters_recovering_with_a_new_epoch_and_invalidates_ephemeral_state() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let bundle = directory.path().join("backup");
    let backend = file_backend(directory.path());
    let wallet_id = Uuid::from_bytes([0x61; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let approved_intent = Uuid::from_bytes([0x62; 16]);
    storage
        .create_transaction_intent(intent(approved_intent, 1_800_000_001))
        .unwrap();
    let completed_ceremony = Uuid::from_bytes([0x63; 16]);
    storage
        .begin_approval_ceremony_atomic(ceremony(
            completed_ceremony,
            approved_intent,
            1_800_000_002,
        ))
        .unwrap();
    let authorization_id = Uuid::from_bytes([0x64; 16]);
    storage
        .approve_and_issue_authorization(
            ApprovalDecision {
                ceremony_id: completed_ceremony,
                authorization_id,
                binding_digest: [0x65; 32],
                authorization_expires_at: 1_900_000_000,
                approved_at: 1_800_000_003,
            },
            &AuditContext::default(),
        )
        .unwrap();
    storage
        .claim_nonce(NewNonceClaim {
            fingerprint: [0x66; 32],
            session_id: [0x67; 32],
            claimed_at: 1_800_000_004,
        })
        .unwrap();
    let pending_intent = Uuid::from_bytes([0x68; 16]);
    let unfinished_ceremony = Uuid::from_bytes([0x69; 16]);
    storage
        .create_transaction_intent(intent(pending_intent, 1_800_000_005))
        .unwrap();
    storage
        .begin_approval_ceremony_atomic(ceremony(
            unfinished_ceremony,
            pending_intent,
            1_800_000_006,
        ))
        .unwrap();
    storage
        .export_encrypted_backup(&bundle, Some(&backend), 1_800_000_010)
        .unwrap();
    drop(storage);

    let mut restored = WalletStorage::restore_encrypted_backup(
        &database,
        &bundle,
        Some(&backend),
        wallet_id,
        1_800_000_020,
    )
    .unwrap();

    let metadata = restored.wallet_metadata().unwrap();
    assert_eq!(metadata.epoch, 2);
    assert_eq!(metadata.restore_state, RestoreState::Recovering);
    assert!(
        restored
            .available_authorization(approved_intent, 1_800_000_021)
            .unwrap()
            .is_none()
    );
    assert!(
        restored
            .nonce_claim([0x66; 32])
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert!(
        restored
            .approval_ceremony(unfinished_ceremony)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert_eq!(
        restored
            .transaction_intent(pending_intent)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Invalidated
    );
    assert!(matches!(
        restored.create_transaction_intent(intent(Uuid::new_v4(), 1_800_000_021)),
        Err(StorageError::MutationBlocked { .. })
    ));
    restored.finish_recovery(1_800_000_022).unwrap();
    assert_eq!(
        restored.wallet_metadata().unwrap().restore_state,
        RestoreState::Normal
    );
}

#[test]
fn restore_rejects_a_backup_from_an_older_recovery_epoch() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let bundle = directory.path().join("backup");
    let backend = file_backend(directory.path());
    let wallet_id = Uuid::from_bytes([0x71; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    storage
        .export_encrypted_backup(&bundle, Some(&backend), 1_800_000_001)
        .unwrap();
    drop(storage);
    let mut restored = WalletStorage::restore_encrypted_backup(
        &database,
        &bundle,
        Some(&backend),
        wallet_id,
        1_800_000_002,
    )
    .unwrap();
    restored.finish_recovery(1_800_000_003).unwrap();
    drop(restored);

    assert!(matches!(
        WalletStorage::restore_encrypted_backup(
            &database,
            &bundle,
            Some(&backend),
            wallet_id,
            1_800_000_004,
        ),
        Err(StorageError::Backup(BackupError::StaleRecoveryEpoch {
            current: 2,
            backup: 1
        }))
    ));
}

#[test]
fn wallet_mismatch_is_rejected_before_the_live_wallet_enters_restore_precheck() {
    let directory = tempdir().unwrap();
    let source_database = directory.path().join("source.sqlite3");
    let live_database = directory.path().join("live.sqlite3");
    let bundle = directory.path().join("backup");
    let backend = file_backend(directory.path());
    let source_wallet = Uuid::from_bytes([0xa1; 16]);
    let live_wallet = Uuid::from_bytes([0xa2; 16]);
    let mut source =
        WalletStorage::initialize(&source_database, source_wallet, 1_800_000_000).unwrap();
    source
        .export_encrypted_backup(&bundle, Some(&backend), 1_800_000_001)
        .unwrap();
    drop(source);
    let live = WalletStorage::initialize(&live_database, live_wallet, 1_800_000_002).unwrap();
    drop(live);

    assert!(matches!(
        WalletStorage::restore_encrypted_backup(
            &live_database,
            &bundle,
            Some(&backend),
            live_wallet,
            1_800_000_003,
        ),
        Err(StorageError::Backup(BackupError::WalletMismatch))
    ));
    let live = WalletStorage::open(&live_database).unwrap();
    let metadata = live.wallet_metadata().unwrap();
    assert_eq!(metadata.wallet_id, live_wallet);
    assert_eq!(metadata.epoch, 1);
    assert_eq!(metadata.restore_state, RestoreState::Normal);
}

fn file_backend(root: &std::path::Path) -> FileSecretBackend {
    FileSecretBackend::open(root.join("secret-store"), RuntimeProfile::Development).unwrap()
}

fn intent(id: Uuid, created_at: i64) -> NewTransactionIntent {
    NewTransactionIntent {
        id,
        tx_digest: [0x11; 32],
        policy_hash: [0x12; 32],
        session_id: [0x13; 32],
        expires_at: 1_900_000_000,
        created_at,
    }
}

fn ceremony(id: Uuid, intent_id: Uuid, started_at: i64) -> NewApprovalCeremony {
    NewApprovalCeremony {
        id,
        intent_id,
        expires_at: started_at + 10_000,
        started_at,
    }
}
