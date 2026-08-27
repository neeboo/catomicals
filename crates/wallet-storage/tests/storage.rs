use std::{
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

use catomicals_wallet_storage::{
    ApprovalDecision, AuditActor, AuditContext, CURRENT_SCHEMA_VERSION, CredentialMetadata,
    NewApprovalCeremony, NewNonceClaim, NewTransactionIntent, RestoreState, SecretBackend,
    SecretRef, StorageError, TransactionIntentStatus, WalletStorage,
};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn initialization_sets_required_sqlite_safety_pragmas_and_schema_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let storage = WalletStorage::initialize(&path, Uuid::new_v4(), 1_700_000_000).unwrap();

    let settings = storage.settings().unwrap();
    assert!(settings.foreign_keys);
    assert_eq!(settings.journal_mode, "wal");
    assert_eq!(settings.synchronous, "full");
    assert_eq!(settings.busy_timeout, Duration::from_secs(5));
    assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
}

#[test]
fn database_reopens_with_the_same_wallet_identity_and_epoch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    WalletStorage::initialize(&path, wallet_id, 1_700_000_000).unwrap();

    let storage = WalletStorage::open(&path).unwrap();
    let metadata = storage.wallet_metadata().unwrap();
    assert_eq!(metadata.wallet_id, wallet_id);
    assert_eq!(metadata.epoch, 1);
}

#[test]
fn wallet_initialization_creates_the_root_audit_event() {
    let (_dir, _path, storage, wallet_id) = initialized_storage();
    let events = storage.audit_events(10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].wallet_id, wallet_id);
    assert_eq!(events[0].epoch, 1);
    assert_eq!(events[0].event_type, "wallet.initialized");
}

fn initialized_storage() -> (tempfile::TempDir, std::path::PathBuf, WalletStorage, Uuid) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    let storage = WalletStorage::initialize(&path, wallet_id, 1_700_000_000).unwrap();
    (dir, path, storage, wallet_id)
}

fn transaction_intent(id: Uuid) -> NewTransactionIntent {
    NewTransactionIntent {
        id,
        tx_digest: [0x11; 32],
        policy_hash: [0x22; 32],
        session_id: [0x33; 32],
        expires_at: 1_800_000_000,
        created_at: 1_700_000_010,
    }
}

fn approval_ceremony(id: Uuid, intent_id: Uuid, started_at: i64) -> NewApprovalCeremony {
    NewApprovalCeremony {
        id,
        intent_id,
        expires_at: started_at + 100,
        started_at,
    }
}

fn approval_decision(
    ceremony_id: Uuid,
    authorization_id: Uuid,
    approved_at: i64,
) -> ApprovalDecision {
    ApprovalDecision {
        ceremony_id,
        authorization_id,
        binding_digest: [0x44; 32],
        authorization_expires_at: approved_at + 100,
        approved_at,
    }
}

#[test]
fn intent_and_credential_writes_are_audited_in_the_same_wallet_epoch() {
    let (_dir, _path, mut storage, wallet_id) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    storage
        .upsert_credential(CredentialMetadata {
            credential_id: "credential-public-id".to_owned(),
            label: "Mac passkey".to_owned(),
            cose_public_key: "public-cose-key".to_owned(),
            sign_count: 0,
            enrolled_at: 1_700_000_020,
            updated_at: 1_700_000_020,
        })
        .unwrap();

    let intent = storage.transaction_intent(intent_id).unwrap().unwrap();
    assert_eq!(intent.wallet_id, wallet_id);
    assert_eq!(intent.epoch, 1);
    assert_eq!(intent.status, TransactionIntentStatus::Pending);
    let events = storage.audit_events(10).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[1].event_type, "transaction_intent.created");
    assert_eq!(events[2].event_type, "credential.upserted");
    assert!(events.iter().all(|event| event.epoch == 1));
}

#[test]
fn secret_storage_accepts_only_typed_opaque_handles() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let secret_id = Uuid::new_v4();
    storage
        .put_secret_ref(
            SecretRef::new(
                secret_id,
                SecretBackend::OsKeychain,
                "keychain://catomicals/frost-participant-1",
                1_700_000_030,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        storage.secret_ref(secret_id).unwrap().unwrap().handle,
        "keychain://catomicals/frost-participant-1"
    );

    let error = SecretRef::new(
        Uuid::new_v4(),
        SecretBackend::OsKeychain,
        "plaintext-frost-share",
        1_700_000_031,
    )
    .unwrap_err();
    assert!(matches!(error, StorageError::InvalidSecretHandle { .. }));
    assert!(!error.to_string().contains("plaintext-frost-share"));
}

#[test]
fn schema_rejects_plaintext_secret_values_even_outside_the_typed_api() {
    let (_dir, path, storage, wallet_id) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(path).unwrap();
    let result = raw.execute(
        "INSERT INTO secret_refs
         (id, wallet_id, backend, handle, created_at, updated_at)
         VALUES (?1, ?2, 'os_keychain', 'plaintext-private-key', 1, 1)",
        [Uuid::new_v4().to_string(), wallet_id.to_string()],
    );
    assert!(result.is_err());
}

#[test]
fn authorization_is_exact_epoch_bound_and_consumable_once() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let authorization_id = Uuid::new_v4();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(ceremony_id, intent_id, 1_700_000_039))
        .unwrap();
    storage
        .approve_and_issue_authorization(
            approval_decision(ceremony_id, authorization_id, 1_700_000_040),
            &AuditContext::default(),
        )
        .unwrap();

    storage
        .consume_authorization(authorization_id, 1, 1_700_000_041)
        .unwrap();
    let second = storage.consume_authorization(authorization_id, 1, 1_700_000_042);
    assert!(matches!(
        second,
        Err(StorageError::AuthorizationUnavailable)
    ));
}

#[test]
fn nonce_fingerprint_is_globally_unique_even_across_sessions_and_reopens() {
    let (_dir, path, mut storage, _) = initialized_storage();
    let claim = NewNonceClaim {
        fingerprint: [0x55; 32],
        session_id: [0x66; 32],
        claimed_at: 1_700_000_050,
    };
    storage.claim_nonce(claim.clone()).unwrap();
    drop(storage);

    let mut reopened = WalletStorage::open(&path).unwrap();
    let duplicate = reopened.claim_nonce(NewNonceClaim {
        session_id: [0x77; 32],
        ..claim
    });
    assert!(matches!(duplicate, Err(StorageError::NonceAlreadyClaimed)));
}

#[test]
fn failed_audit_append_rolls_back_the_security_state_write() {
    let (_dir, path, mut storage, _) = initialized_storage();
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER reject_intent_audit BEFORE INSERT ON audit_events
         WHEN NEW.event_type = 'transaction_intent.created'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    )
    .unwrap();
    let intent_id = Uuid::new_v4();

    assert!(
        storage
            .create_transaction_intent(transaction_intent(intent_id))
            .is_err()
    );
    assert!(storage.transaction_intent(intent_id).unwrap().is_none());
}

#[test]
fn restore_cutover_rotates_epoch_and_invalidates_ephemeral_security_state() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(ceremony_id, intent_id, 1_700_000_060))
        .unwrap();
    let authorization_id = Uuid::new_v4();
    storage
        .approve_and_issue_authorization(
            approval_decision(ceremony_id, authorization_id, 1_700_000_061),
            &AuditContext::default(),
        )
        .unwrap();
    let unfinished_intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(unfinished_intent_id))
        .unwrap();
    let unfinished_ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(
            unfinished_ceremony_id,
            unfinished_intent_id,
            1_700_000_061,
        ))
        .unwrap();
    storage
        .claim_nonce(NewNonceClaim {
            fingerprint: [0x99; 32],
            session_id: [0xaa; 32],
            claimed_at: 1_700_000_062,
        })
        .unwrap();

    storage.begin_restore_precheck(1_700_000_070).unwrap();
    storage.cutover_restore(1_700_000_071).unwrap();
    let metadata = storage.wallet_metadata().unwrap();
    assert_eq!(metadata.epoch, 2);
    assert_eq!(metadata.restore_state, RestoreState::Cutover);
    assert!(matches!(
        storage.consume_authorization(authorization_id, 1, 1_700_000_072),
        Err(StorageError::MutationBlocked { .. })
    ));
    assert!(
        storage
            .approval_ceremony(unfinished_ceremony_id)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert!(
        storage
            .nonce_claim([0x99; 32])
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );

    storage.begin_recovering(1_700_000_073).unwrap();
    storage.finish_recovery(1_700_000_074).unwrap();
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Normal
    );
    assert!(matches!(
        storage.consume_authorization(authorization_id, 1, 1_700_000_075),
        Err(StorageError::StaleEpoch {
            current: 2,
            provided: 1
        })
    ));
}

#[test]
fn unsupported_future_schema_is_rejected_without_migration() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("future.sqlite3");
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
        .unwrap();
    drop(raw);

    let error = WalletStorage::open(&path).unwrap_err();
    assert!(matches!(
        error,
        StorageError::SchemaTooNew {
            found,
            supported
        } if found == CURRENT_SCHEMA_VERSION + 1 && supported == CURRENT_SCHEMA_VERSION
    ));
}

#[test]
fn snapshot_state_allows_only_the_explicit_round_trip() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    storage.begin_snapshot(1_700_000_080).unwrap();
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Snapshotting
    );
    assert!(matches!(
        storage.begin_restore_precheck(1_700_000_081),
        Err(StorageError::InvalidRestoreTransition { .. })
    ));
    storage.finish_snapshot(1_700_000_082).unwrap();
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Normal
    );
}

#[test]
fn completed_ceremony_survives_cutover_while_unfinished_one_is_invalidated() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let completed = Uuid::new_v4();
    let unfinished = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(completed, intent_id, 1_700_000_090))
        .unwrap();
    storage
        .approve_and_issue_authorization(
            approval_decision(completed, Uuid::new_v4(), 1_700_000_091),
            &AuditContext::default(),
        )
        .unwrap();
    let unfinished_intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(unfinished_intent_id))
        .unwrap();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(
            unfinished,
            unfinished_intent_id,
            1_700_000_092,
        ))
        .unwrap();

    storage.begin_restore_precheck(1_700_000_093).unwrap();
    storage.cutover_restore(1_700_000_094).unwrap();
    assert!(
        storage
            .approval_ceremony(completed)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_none()
    );
    assert!(
        storage
            .approval_ceremony(unfinished)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
}

#[test]
fn concurrent_nonce_claims_have_exactly_one_winner() {
    let (_dir, path, storage, wallet_id) = initialized_storage();
    drop(storage);
    let connection_a = rusqlite::Connection::open(&path).unwrap();
    let connection_b = rusqlite::Connection::open(&path).unwrap();
    connection_a.busy_timeout(Duration::from_secs(5)).unwrap();
    connection_b.busy_timeout(Duration::from_secs(5)).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let run = |connection: rusqlite::Connection, barrier: Arc<Barrier>, session_id: [u8; 32]| {
        let wallet_id = wallet_id.to_string();
        thread::spawn(move || {
            barrier.wait();
            connection.execute(
                "INSERT INTO nonce_claims
                 (fingerprint, wallet_id, epoch, session_id, claimed_at)
                 VALUES (?1, ?2, 1, ?3, ?4)",
                rusqlite::params![
                    [0xbbu8; 32].as_slice(),
                    wallet_id,
                    session_id.as_slice(),
                    1_700_000_100,
                ],
            )
        })
    };
    let first = run(connection_a, Arc::clone(&barrier), [0xcc; 32]);
    let second = run(connection_b, barrier, [0xdd; 32]);
    let results = [first.join().unwrap(), second.join().unwrap()];

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}

#[test]
fn audit_rows_cannot_be_updated_or_deleted() {
    let (_dir, path, mut storage, _) = initialized_storage();
    storage
        .create_transaction_intent(transaction_intent(Uuid::new_v4()))
        .unwrap();
    drop(storage);
    let raw = rusqlite::Connection::open(path).unwrap();

    assert!(
        raw.execute("UPDATE audit_events SET event_type = 'tampered'", [])
            .is_err()
    );
    assert!(raw.execute("DELETE FROM audit_events", []).is_err());
}

#[test]
fn wallet_records_have_typed_read_and_intent_transition_paths() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    storage
        .upsert_credential(CredentialMetadata {
            credential_id: "typed-read-credential".to_owned(),
            label: "YubiKey public credential".to_owned(),
            cose_public_key: "public-cose-key".to_owned(),
            sign_count: 7,
            enrolled_at: 1_700_000_110,
            updated_at: 1_700_000_110,
        })
        .unwrap();

    assert!(matches!(
        storage.transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Pending,
            TransactionIntentStatus::Signed,
            1_700_000_110,
        ),
        Err(StorageError::InvalidIntentTransition { .. })
    ));

    storage
        .transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Pending,
            TransactionIntentStatus::Cancelled,
            1_700_000_111,
        )
        .unwrap();
    assert_eq!(storage.list_transaction_intents().unwrap().len(), 1);
    assert_eq!(
        storage
            .transaction_intent(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Cancelled
    );
    assert_eq!(
        storage
            .credential("typed-read-credential")
            .unwrap()
            .unwrap()
            .sign_count,
        7
    );
    assert!(matches!(
        storage.transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Pending,
            TransactionIntentStatus::Cancelled,
            1_700_000_112,
        ),
        Err(StorageError::IntentTransitionConflict)
    ));
}

#[test]
fn restore_precheck_invalidates_unfinished_ceremonies_and_blocks_mutations() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(ceremony_id, intent_id, 1_700_000_200))
        .unwrap();

    storage.begin_restore_precheck(1_700_000_201).unwrap();

    assert!(
        storage
            .approval_ceremony(ceremony_id)
            .unwrap()
            .unwrap()
            .invalidated_at
            .is_some()
    );
    assert!(
        storage
            .create_transaction_intent(transaction_intent(Uuid::new_v4()))
            .is_err()
    );
}

#[test]
fn cutover_and_recovering_block_regular_mutations() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    storage.begin_restore_precheck(1_700_000_210).unwrap();
    storage.cutover_restore(1_700_000_211).unwrap();
    assert!(
        storage
            .upsert_credential(CredentialMetadata {
                credential_id: "blocked-credential".to_owned(),
                label: "blocked".to_owned(),
                cose_public_key: "public".to_owned(),
                sign_count: 0,
                enrolled_at: 1_700_000_212,
                updated_at: 1_700_000_212,
            })
            .is_err()
    );

    storage.begin_recovering(1_700_000_213).unwrap();
    assert!(
        storage
            .claim_nonce(NewNonceClaim {
                fingerprint: [0xde; 32],
                session_id: [0xad; 32],
                claimed_at: 1_700_000_214,
            })
            .is_err()
    );
}

#[test]
fn snapshotting_allows_creating_a_transaction_intent() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    storage.begin_snapshot(1_700_000_220).unwrap();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    assert!(storage.transaction_intent(intent_id).unwrap().is_some());
}

#[test]
fn approval_and_authorization_roll_back_together_when_audit_fails() {
    let (_dir, path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: ceremony_id,
            intent_id,
            expires_at: 1_800_000_000,
            started_at: 1_700_000_230,
        })
        .unwrap();
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER reject_approval_audit BEFORE INSERT ON audit_events
         WHEN NEW.event_type = 'approval.completed'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    )
    .unwrap();
    let authorization_id = Uuid::new_v4();

    assert!(
        storage
            .approve_and_issue_authorization(
                ApprovalDecision {
                    ceremony_id,
                    authorization_id,
                    binding_digest: [0xee; 32],
                    authorization_expires_at: 1_800_000_000,
                    approved_at: 1_700_000_231,
                },
                &AuditContext::default(),
            )
            .is_err()
    );
    assert_eq!(
        storage
            .transaction_intent(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Pending
    );
    assert!(
        storage
            .approval_ceremony(ceremony_id)
            .unwrap()
            .unwrap()
            .completed_at
            .is_none()
    );
    let authorization_count: u64 = raw
        .query_row(
            "SELECT count(*) FROM one_time_authorizations WHERE id = ?1",
            [authorization_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorization_count, 0);
}

#[test]
fn credential_signature_counter_cannot_move_backwards() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let credential = CredentialMetadata {
        credential_id: "monotonic-credential".to_owned(),
        label: "Passkey".to_owned(),
        cose_public_key: "public-cose-key".to_owned(),
        sign_count: 8,
        enrolled_at: 1_700_000_240,
        updated_at: 1_700_000_240,
    };
    storage.upsert_credential(credential.clone()).unwrap();
    let error = storage
        .upsert_credential(CredentialMetadata {
            sign_count: 7,
            enrolled_at: 1_800_000_000,
            updated_at: 1_700_000_241,
            ..credential
        })
        .unwrap_err();

    assert!(matches!(error, StorageError::CredentialCounterRollback));
    let stored = storage.credential("monotonic-credential").unwrap().unwrap();
    assert_eq!(stored.sign_count, 8);
    assert_eq!(stored.enrolled_at, 1_700_000_240);
}

#[test]
fn expired_approval_ceremony_is_rejected_without_state_changes() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: ceremony_id,
            intent_id,
            expires_at: 1_700_000_251,
            started_at: 1_700_000_250,
        })
        .unwrap();

    let error = storage
        .approve_and_issue_authorization(
            approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_252),
            &AuditContext::default(),
        )
        .unwrap_err();
    assert!(matches!(error, StorageError::ApprovalCeremonyExpired));
    assert_eq!(
        storage
            .transaction_intent(intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Pending
    );
    assert!(
        storage
            .approval_ceremony(ceremony_id)
            .unwrap()
            .unwrap()
            .completed_at
            .is_none()
    );
}

#[test]
fn cancelled_intent_cannot_start_an_approval_or_receive_authorization() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    storage
        .transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Pending,
            TransactionIntentStatus::Cancelled,
            1_700_000_260,
        )
        .unwrap();

    let error = storage
        .begin_approval_ceremony_atomic(approval_ceremony(Uuid::new_v4(), intent_id, 1_700_000_261))
        .unwrap_err();
    assert!(matches!(error, StorageError::IntentNotApprovable));
}

#[test]
fn one_intent_cannot_receive_a_second_authorization() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(ceremony_id, intent_id, 1_700_000_270))
        .unwrap();
    storage
        .approve_and_issue_authorization(
            approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_271),
            &AuditContext::default(),
        )
        .unwrap();

    let error = storage
        .approve_and_issue_authorization(
            approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_272),
            &AuditContext::default(),
        )
        .unwrap_err();
    assert!(matches!(error, StorageError::AuthorizationAlreadyExists));
}

#[test]
fn audit_payload_contains_minimal_restore_fields_and_redacted_actor() {
    let (_dir, _path, mut storage, wallet_id) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let context = AuditContext {
        component_version: "walletd-test".to_owned(),
        node_snapshot_id: Some("snapshot-42".to_owned()),
        actor: AuditActor::PasskeyFingerprint([0x12; 32]),
    };
    storage
        .create_transaction_intent_with_audit(transaction_intent(intent_id), &context)
        .unwrap();

    let event = storage.audit_events(10).unwrap().pop().unwrap();
    assert_eq!(event.payload["component_version"], "walletd-test");
    assert_eq!(event.payload["schema_version"], CURRENT_SCHEMA_VERSION);
    assert_eq!(event.payload["wallet_id"], wallet_id.to_string());
    assert_eq!(event.payload["intent_id"], intent_id.to_string());
    assert_eq!(event.payload["policy_hash"], hex::encode([0x22; 32]));
    assert_eq!(event.payload["node_snapshot_id"], "snapshot-42");
    assert_eq!(
        event.payload["actor_ref"],
        format!("passkey_sha256:{}", hex::encode([0x12; 32]))
    );
}

#[test]
fn owner_lock_allows_only_one_wallet_writer_process() {
    let (_dir, path, first, _) = initialized_storage();
    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::WriterAlreadyActive)
    ));
    assert!(path.with_file_name("wallet.sqlite3.owner.lock").exists());
    drop(first);
    assert!(WalletStorage::open(&path).is_ok());
}

#[test]
fn schema_has_indexes_for_restore_and_authorization_paths() {
    let (_dir, path, storage, _) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(path).unwrap();
    let expected = [
        "transaction_intents_epoch_status",
        "approval_ceremonies_intent_epoch",
        "approval_ceremonies_epoch_completion",
        "one_authorization_per_intent",
        "authorizations_intent_epoch",
        "authorizations_epoch_availability",
        "nonce_claims_epoch_invalidation",
    ];
    for index_name in expected {
        let exists: bool = raw
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
                [index_name],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing index {index_name}");
    }
}

#[test]
fn restore_gate_covers_every_security_mutation_entrypoint() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let pending_intent = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(pending_intent))
        .unwrap();
    let pending_ceremony = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(
            pending_ceremony,
            pending_intent,
            1_700_000_280,
        ))
        .unwrap();
    let approved_intent = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(approved_intent))
        .unwrap();
    let approved_ceremony = Uuid::new_v4();
    let authorization_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(approval_ceremony(
            approved_ceremony,
            approved_intent,
            1_700_000_281,
        ))
        .unwrap();
    storage
        .approve_and_issue_authorization(
            approval_decision(approved_ceremony, authorization_id, 1_700_000_282),
            &AuditContext::default(),
        )
        .unwrap();
    storage.begin_restore_precheck(1_700_000_283).unwrap();

    let is_blocked = |result: Result<(), StorageError>| {
        assert!(matches!(result, Err(StorageError::MutationBlocked { .. })))
    };
    is_blocked(storage.create_transaction_intent(transaction_intent(Uuid::new_v4())));
    is_blocked(storage.transition_transaction_intent(
        pending_intent,
        TransactionIntentStatus::Pending,
        TransactionIntentStatus::Cancelled,
        1_700_000_284,
    ));
    is_blocked(storage.upsert_credential(CredentialMetadata {
        credential_id: "blocked".to_owned(),
        label: "blocked".to_owned(),
        cose_public_key: "public".to_owned(),
        sign_count: 0,
        enrolled_at: 1_700_000_284,
        updated_at: 1_700_000_284,
    }));
    is_blocked(
        storage.put_secret_ref(
            SecretRef::new(
                Uuid::new_v4(),
                SecretBackend::Hsm,
                "hsm://slot/1",
                1_700_000_284,
            )
            .unwrap(),
        ),
    );
    is_blocked(storage.consume_authorization(authorization_id, 1, 1_700_000_284));
    is_blocked(storage.claim_nonce(NewNonceClaim {
        fingerprint: [0xf1; 32],
        session_id: [0xf2; 32],
        claimed_at: 1_700_000_284,
    }));
    is_blocked(storage.begin_approval_ceremony_atomic(approval_ceremony(
        Uuid::new_v4(),
        pending_intent,
        1_700_000_284,
    )));
    is_blocked(storage.approve_and_issue_authorization(
        approval_decision(pending_ceremony, Uuid::new_v4(), 1_700_000_284),
        &AuditContext::default(),
    ));
}

#[test]
fn direct_intent_transition_cannot_bypass_atomic_approval() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    storage
        .create_transaction_intent(transaction_intent(intent_id))
        .unwrap();

    let error = storage
        .transition_transaction_intent(
            intent_id,
            TransactionIntentStatus::Pending,
            TransactionIntentStatus::Approved,
            1_700_000_290,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StorageError::InvalidIntentTransition { .. }
    ));
}

#[test]
fn expired_intent_cannot_begin_approval() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let mut intent = transaction_intent(intent_id);
    intent.expires_at = 1_700_000_300;
    storage.create_transaction_intent(intent).unwrap();

    let error = storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: Uuid::new_v4(),
            intent_id,
            started_at: 1_700_000_301,
            expires_at: 1_700_000_302,
        })
        .unwrap_err();
    assert!(matches!(error, StorageError::IntentExpired));
}

#[test]
fn ceremony_expiry_cannot_exceed_intent_expiry() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let mut intent = transaction_intent(intent_id);
    intent.expires_at = 1_700_000_310;
    storage.create_transaction_intent(intent).unwrap();

    let error = storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: Uuid::new_v4(),
            intent_id,
            started_at: 1_700_000_309,
            expires_at: 1_700_000_311,
        })
        .unwrap_err();
    assert!(matches!(
        error,
        StorageError::ApprovalCeremonyExceedsIntentExpiry
    ));
}

#[test]
fn intent_expiring_after_ceremony_start_prevents_finish() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let mut intent = transaction_intent(intent_id);
    intent.expires_at = 1_700_000_320;
    storage.create_transaction_intent(intent).unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: ceremony_id,
            intent_id,
            started_at: 1_700_000_319,
            expires_at: 1_700_000_320,
        })
        .unwrap();

    let error = storage
        .approve_and_issue_authorization(
            ApprovalDecision {
                authorization_expires_at: 1_700_000_320,
                ..approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_321)
            },
            &AuditContext::default(),
        )
        .unwrap_err();
    assert!(matches!(error, StorageError::IntentExpired));
}

#[test]
fn authorization_cannot_expire_before_it_is_approved() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let mut intent = transaction_intent(intent_id);
    intent.expires_at = 1_700_000_500;
    storage.create_transaction_intent(intent).unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: ceremony_id,
            intent_id,
            started_at: 1_700_000_330,
            expires_at: 1_700_000_400,
        })
        .unwrap();

    let error = storage
        .approve_and_issue_authorization(
            ApprovalDecision {
                authorization_expires_at: 1_700_000_349,
                ..approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_350)
            },
            &AuditContext::default(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StorageError::AuthorizationExpiresBeforeApproval
    ));
}

#[test]
fn authorization_expiry_cannot_exceed_intent_expiry() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    let intent_id = Uuid::new_v4();
    let mut intent = transaction_intent(intent_id);
    intent.expires_at = 1_700_000_500;
    storage.create_transaction_intent(intent).unwrap();
    let ceremony_id = Uuid::new_v4();
    storage
        .begin_approval_ceremony_atomic(NewApprovalCeremony {
            id: ceremony_id,
            intent_id,
            started_at: 1_700_000_330,
            expires_at: 1_700_000_400,
        })
        .unwrap();

    let error = storage
        .approve_and_issue_authorization(
            ApprovalDecision {
                authorization_expires_at: 1_700_000_501,
                ..approval_decision(ceremony_id, Uuid::new_v4(), 1_700_000_350)
            },
            &AuditContext::default(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StorageError::AuthorizationExceedsIntentExpiry
    ));
}

#[test]
fn reopen_rejects_missing_append_only_audit_trigger() {
    let (_dir, path, storage, _) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute("DROP TRIGGER audit_events_no_update", [])
        .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn reopen_rejects_missing_unique_authorization_index() {
    let (_dir, path, storage, _) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute("DROP INDEX one_authorization_per_intent", [])
        .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn reopen_rejects_tampered_migration_checksum() {
    let (_dir, path, storage, _) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            checksum TEXT NOT NULL
         ) STRICT;
         INSERT OR REPLACE INTO schema_migrations(version, checksum)
         VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000');",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}

#[test]
fn recent_audit_events_returns_latest_window_in_sequence_order() {
    let (_dir, _path, mut storage, _) = initialized_storage();
    for _ in 0..4 {
        storage
            .create_transaction_intent(transaction_intent(Uuid::new_v4()))
            .unwrap();
    }

    let events = storage.recent_audit_events(3).unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert!(
        events
            .iter()
            .all(|event| event.event_type == "transaction_intent.created")
    );
}

#[test]
fn reopen_rejects_secret_ref_table_without_handle_check() {
    let (_dir, path, storage, _) = initialized_storage();
    drop(storage);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch(
        "PRAGMA foreign_keys = OFF;
         BEGIN IMMEDIATE;
         DROP INDEX secret_refs_wallet;
         ALTER TABLE secret_refs RENAME TO secret_refs_old;
         CREATE TABLE secret_refs (
             id TEXT PRIMARY KEY,
             wallet_id TEXT NOT NULL REFERENCES wallet_metadata(wallet_id),
             backend TEXT NOT NULL,
             handle TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         ) STRICT;
         DROP TABLE secret_refs_old;
         CREATE INDEX secret_refs_wallet ON secret_refs(wallet_id);
         COMMIT;",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        WalletStorage::open(&path),
        Err(StorageError::SchemaIntegrity { .. })
    ));
}
