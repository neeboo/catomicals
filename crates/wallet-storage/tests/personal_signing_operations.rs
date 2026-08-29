use catomicals_wallet_storage::{
    ApprovalNonce, CredentialState, IntentAction, IntentMaterial, IntentMaterialKind,
    IntentNetwork, NewPasskeyApprovalCeremony, NewPasskeyRecord, NewPersonalSigningOperation,
    NewTransactionIntentV2, PasskeyApprovalCompletion, PersonalSigningOperationStatus,
    PersonalSigningReceipt, PersonalSigningRound, TransactionIntentStatus, WalletStorage,
    WebauthnProfile,
};
use sha2::{Digest, Sha256};
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

fn approved_authorization(
    storage: &mut WalletStorage,
    wallet_id: Uuid,
    request: &NewPersonalSigningOperation,
) -> Uuid {
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
    let payload_json = serde_json::json!({
        "personal_signing_policy": {
            "profile_id": request.profile_id,
            "signer_set_id": request.signer_set_id,
            "signer_epoch": request.signer_epoch,
            "group_pubkey_xonly": hex::encode(request.group_pubkey_xonly),
            "allowed_participants": request.allowed_participants,
            "threshold": request.threshold,
            "policy_digest": hex::encode(request.policy_digest),
            "chain_snapshot_digest": hex::encode(request.chain_snapshot_digest),
        }
    });
    let payload_hash = Sha256::digest(serde_json::to_vec(&payload_json).unwrap()).into();
    storage
        .create_transaction_intent_v2(
            NewTransactionIntentV2 {
                id: request.intent_id,
                tx_digest: request.taproot_sighash,
                policy_hash: request.policy_digest,
                session_id: request.session_id,
                network: IntentNetwork::Signet,
                protocol_version: 1,
                action: IntentAction::Spend,
                signer_id: "frost:participant-0".to_owned(),
                approval_nonce: ApprovalNonce([44; 32]),
                intent_schema_version: 2,
                expires_at: request.expires_at,
                created_at: 10,
            },
            IntentMaterial {
                intent_id: request.intent_id,
                kind: IntentMaterialKind::PolicyInput,
                payload_json,
                payload_hash,
                node_snapshot_id: "snapshot-personal".to_owned(),
            },
        )
        .unwrap();
    let ceremony_id = Uuid::from_bytes([46; 16]);
    let authorization_id = Uuid::from_bytes([47; 16]);
    let binding_digest = [48; 32];
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: ceremony_id,
            intent_id: request.intent_id,
            credential_id: "cred-1".to_owned(),
            binding_digest,
            started_at: 20,
            expires_at: 80,
        })
        .unwrap();
    storage
        .complete_passkey_approval_atomic(PasskeyApprovalCompletion {
            ceremony_id,
            intent_id: request.intent_id,
            credential_id: "cred-1".to_owned(),
            expected_credential_record_version: 1,
            updated_passkey_json: r#"{"counter":1}"#.to_owned(),
            binding_digest,
            authorization_id,
            authorization_expires_at: 190,
            rp_id: "wallet.example".to_owned(),
            rp_origin: "https://wallet.example".to_owned(),
            approved_at: 30,
        })
        .unwrap();
    authorization_id
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

#[test]
fn deterministic_failure_does_not_consume_personal_authorization() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([50; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
    let mut request = operation(wallet_id);
    let authorization_id = approved_authorization(&mut storage, wallet_id, &request);
    request.selected_participants = [2, 1];

    assert!(
        storage
            .consume_authorization_and_create_personal_signing_operation(
                authorization_id,
                request.clone(),
                100,
            )
            .is_err()
    );
    assert!(
        storage
            .available_authorization(request.intent_id, 101)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .nonce_claim(request.operation_binding_digest)
            .unwrap()
            .is_none()
    );
}

#[test]
fn approved_chain_snapshot_cannot_be_replaced_or_consume_authorization() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([53; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
    let original = operation(wallet_id);
    let authorization_id = approved_authorization(&mut storage, wallet_id, &original);
    let mut drifted = original.clone();
    drifted.chain_snapshot_digest = [97; 32];
    drifted.operation_binding_digest = [96; 32];

    assert!(
        storage
            .consume_authorization_and_create_personal_signing_operation(
                authorization_id,
                drifted,
                100,
            )
            .is_err()
    );
    assert!(
        storage
            .available_authorization(original.intent_id, 101)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .personal_signing_operation(original.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .nonce_claim(original.operation_binding_digest)
            .unwrap()
            .is_none()
    );
}

#[test]
fn duplicate_operation_id_failure_does_not_consume_personal_authorization() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([52; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
    let request = operation(wallet_id);
    let authorization_id = approved_authorization(&mut storage, wallet_id, &request);
    storage
        .create_personal_signing_operation(request.clone())
        .unwrap();
    let mut drifted = request.clone();
    drifted.policy_digest = [99; 32];
    drifted.operation_binding_digest = [98; 32];

    assert!(
        storage
            .consume_authorization_and_create_personal_signing_operation(
                authorization_id,
                drifted,
                100,
            )
            .is_err()
    );
    assert!(
        storage
            .available_authorization(request.intent_id, 101)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .nonce_claim(request.operation_binding_digest)
            .unwrap()
            .is_none()
    );
}

#[test]
fn atomic_authorization_and_operation_survive_restart_without_a_gap() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([51; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
    let request = operation(wallet_id);
    let authorization_id = approved_authorization(&mut storage, wallet_id, &request);
    storage
        .consume_authorization_and_create_personal_signing_operation(
            authorization_id,
            request.clone(),
            100,
        )
        .unwrap();
    drop(storage);

    let storage = WalletStorage::open(&database).unwrap();
    assert_eq!(
        storage
            .personal_signing_operation(request.operation_id)
            .unwrap()
            .unwrap()
            .status,
        PersonalSigningOperationStatus::CollectingCommitments
    );
    assert!(
        storage
            .available_authorization(request.intent_id, 101)
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .nonce_claim(request.operation_binding_digest)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        storage
            .transaction_intent_v2(request.intent_id)
            .unwrap()
            .unwrap()
            .status,
        TransactionIntentStatus::Signing
    );
}
