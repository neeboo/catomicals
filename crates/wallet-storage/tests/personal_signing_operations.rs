use catomicals_wallet_storage::{
    NewPersonalSigningOperation, PersonalSigningOperationStatus, PersonalSigningReceipt,
    PersonalSigningRound, WalletStorage,
};
use tempfile::tempdir;
use uuid::Uuid;

fn operation(wallet_id: Uuid) -> NewPersonalSigningOperation {
    NewPersonalSigningOperation {
        operation_id: Uuid::from_bytes([2; 16]),
        wallet_id,
        profile_id: Uuid::from_bytes([3; 16]),
        signer_set_id: Uuid::from_bytes([4; 16]),
        signer_epoch: 1,
        intent_id: Uuid::from_bytes([5; 16]),
        session_id: [6; 32],
        taproot_sighash: [7; 32],
        policy_digest: [8; 32],
        chain_snapshot_digest: [9; 32],
        group_pubkey_xonly: [10; 32],
        profile_binding_digest: [11; 32],
        operation_binding_digest: [12; 32],
        allowed_participants: [1, 2, 3],
        selected_participants: [1, 2],
        threshold: 2,
        max_signers: 3,
        expires_at: 200,
        created_at: 100,
    }
}

#[test]
fn create_is_idempotent_for_one_binding_and_rejects_operation_id_drift() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([1; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    let original = operation(wallet_id);

    let first = storage
        .create_personal_signing_operation(original.clone())
        .unwrap();
    let repeated = storage
        .create_personal_signing_operation(original.clone())
        .unwrap();
    assert_eq!(first, repeated);

    let mut drifted = original;
    drifted.policy_digest = [99; 32];
    drifted.operation_binding_digest = [98; 32];
    assert!(storage.create_personal_signing_operation(drifted).is_err());
}

#[test]
fn public_round_state_and_final_signature_survive_restart() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([20; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    let request = operation(wallet_id);
    storage
        .create_personal_signing_operation(request.clone())
        .unwrap();

    for signer_id in request.selected_participants {
        storage
            .record_personal_signing_receipt(PersonalSigningReceipt {
                operation_id: request.operation_id,
                signer_id,
                round: PersonalSigningRound::Commitment,
                device_id: Uuid::from_bytes([signer_id as u8; 16]),
                device_generation: 1,
                request_binding_digest: [signer_id as u8; 32],
                payload: vec![signer_id as u8; 64],
                received_at: 110,
            })
            .unwrap();
    }
    storage
        .freeze_personal_signing_operation(
            request.operation_id,
            request.operation_binding_digest,
            vec![42; 96],
            120,
        )
        .unwrap();
    for signer_id in request.selected_participants {
        storage
            .record_personal_signing_receipt(PersonalSigningReceipt {
                operation_id: request.operation_id,
                signer_id,
                round: PersonalSigningRound::SignatureShare,
                device_id: Uuid::from_bytes([signer_id as u8; 16]),
                device_generation: 1,
                request_binding_digest: [signer_id as u8 + 10; 32],
                payload: vec![signer_id as u8 + 10; 32],
                received_at: 130,
            })
            .unwrap();
    }
    storage
        .complete_personal_signing_operation(
            request.operation_id,
            request.operation_binding_digest,
            [55; 64],
            140,
        )
        .unwrap();
    drop(storage);

    let reopened = WalletStorage::open(&database).unwrap();
    let recovered = reopened
        .personal_signing_operation(request.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.status, PersonalSigningOperationStatus::Finalized);
    assert_eq!(
        recovered.signing_package.as_deref(),
        Some(&vec![42; 96][..])
    );
    assert_eq!(recovered.final_signature, Some([55; 64]));
    assert_eq!(
        reopened
            .personal_signing_receipts(request.operation_id)
            .unwrap()
            .len(),
        4
    );

    drop(reopened);
    let connection = rusqlite::Connection::open(&database).unwrap();
    let mut statement = connection
        .prepare("SELECT name FROM pragma_table_info('personal_signing_operations')")
        .unwrap();
    let columns: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for forbidden in ["share_secret", "key_package", "dek", "nonce_secret"] {
        assert!(!columns.iter().any(|column| column == forbidden));
    }
}

#[test]
fn non_selected_participant_and_receipt_drift_are_rejected() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([30; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    let request = operation(wallet_id);
    storage
        .create_personal_signing_operation(request.clone())
        .unwrap();
    let receipt = PersonalSigningReceipt {
        operation_id: request.operation_id,
        signer_id: 3,
        round: PersonalSigningRound::Commitment,
        device_id: Uuid::from_bytes([31; 16]),
        device_generation: 1,
        request_binding_digest: [32; 32],
        payload: vec![33; 64],
        received_at: 110,
    };
    assert!(storage.record_personal_signing_receipt(receipt).is_err());

    let mut accepted = PersonalSigningReceipt {
        signer_id: 1,
        ..PersonalSigningReceipt {
            operation_id: request.operation_id,
            signer_id: 1,
            round: PersonalSigningRound::Commitment,
            device_id: Uuid::from_bytes([34; 16]),
            device_generation: 1,
            request_binding_digest: [35; 32],
            payload: vec![36; 64],
            received_at: 111,
        }
    };
    storage
        .record_personal_signing_receipt(accepted.clone())
        .unwrap();
    storage
        .record_personal_signing_receipt(accepted.clone())
        .unwrap();
    accepted.payload[0] ^= 1;
    assert!(storage.record_personal_signing_receipt(accepted).is_err());
}

#[test]
fn identical_public_receipt_retry_ignores_local_receive_time() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([40; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    let request = operation(wallet_id);
    storage
        .create_personal_signing_operation(request.clone())
        .unwrap();
    let mut receipt = PersonalSigningReceipt {
        operation_id: request.operation_id,
        signer_id: 1,
        round: PersonalSigningRound::Commitment,
        device_id: Uuid::from_bytes([41; 16]),
        device_generation: 1,
        request_binding_digest: [42; 32],
        payload: vec![43; 64],
        received_at: 110,
    };
    storage
        .record_personal_signing_receipt(receipt.clone())
        .unwrap();
    receipt.received_at = 111;

    storage.record_personal_signing_receipt(receipt).unwrap();
    assert_eq!(
        storage
            .personal_signing_receipts(request.operation_id)
            .unwrap()
            .len(),
        1
    );
}
