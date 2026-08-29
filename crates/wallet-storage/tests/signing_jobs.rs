use catomicals_chain_domain::{BitcoinCashNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet_storage::{
    ApprovalNonce, CredentialState, IntentAction, IntentMaterial, IntentMaterialKind,
    IntentNetwork, NewAddressBinding, NewPasskeyApprovalCeremony, NewPasskeyRecord,
    NewSignerProfile, NewSigningJob, NewTransactionIntentV2, PasskeyApprovalCompletion,
    SecretBackend, SecretRef, SigningJobStatus, WalletStorage, WebauthnProfile,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

fn scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet))
}

fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    WalletStorage,
    Uuid,
    Uuid,
    Uuid,
) {
    let root = tempdir().unwrap();
    let path = root.path().join("wallet.sqlite3");
    let wallet_id = Uuid::new_v4();
    let profile_id = Uuid::new_v4();
    let secret_ref_id = Uuid::new_v4();
    let mut storage = WalletStorage::initialize(&path, wallet_id, NOW).unwrap();
    storage
        .put_secret_ref(
            SecretRef::new(
                secret_ref_id,
                SecretBackend::EncryptedFile,
                "encrypted-file://cb-mpc/share-1".to_owned(),
                NOW,
            )
            .unwrap(),
        )
        .unwrap();
    (root, path, storage, wallet_id, profile_id, secret_ref_id)
}

fn profile(wallet_id: Uuid, profile_id: Uuid, secret_ref_id: Uuid) -> NewSignerProfile {
    NewSignerProfile {
        profile_id,
        wallet_id,
        chain_scope: scope(),
        signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
        signer_set_id: "personal-wallet".to_owned(),
        authorization_signer_id: "frost:participant-1".to_owned(),
        signer_epoch: 7,
        threshold: 2,
        max_signers: 3,
        verification_key: vec![2; 33],
        secret_ref_id,
        created_at: NOW,
    }
}

fn approve_job(storage: &mut WalletStorage, job: &NewSigningJob) -> Uuid {
    let authorization_id = Uuid::new_v4();
    let ceremony_id = Uuid::new_v4();
    storage
        .set_webauthn_profile(WebauthnProfile {
            wallet_id: job.wallet_id,
            user_id: "chain-user".to_owned(),
            rp_id: "wallet.example".to_owned(),
            rp_origin: "https://wallet.example".to_owned(),
            record_version: 1,
            updated_at: NOW - 20,
        })
        .unwrap();
    storage
        .insert_passkey_record(NewPasskeyRecord {
            credential_id: "chain-cred".to_owned(),
            label: "Mac".to_owned(),
            passkey_json: r#"{"counter":0}"#.to_owned(),
            format: "webauthn-rs-passkey-json".to_owned(),
            credential_state: CredentialState::Active,
            enrolled_at: NOW - 19,
        })
        .unwrap();
    let credential = storage.passkey_record("chain-cred").unwrap().unwrap();
    let payload_json = serde_json::json!({"chain_signing_job": job.job_id});
    let payload_hash = Sha256::digest(serde_json::to_vec(&payload_json).unwrap());
    storage
        .create_transaction_intent_v2(
            NewTransactionIntentV2 {
                id: job.intent_id,
                tx_digest: job.signing_message_digest,
                policy_hash: job.policy_snapshot_digest,
                session_id: job.session_id,
                network: IntentNetwork::Testnet,
                protocol_version: 1,
                action: IntentAction::Spend,
                signer_id: "frost:participant-1".to_owned(),
                approval_nonce: ApprovalNonce([13; 32]),
                intent_schema_version: 2,
                expires_at: job.expires_at,
                created_at: NOW - 10,
            },
            IntentMaterial {
                intent_id: job.intent_id,
                kind: IntentMaterialKind::PolicyInput,
                payload_json,
                payload_hash: payload_hash.into(),
                node_snapshot_id: "snapshot-chain-job".to_owned(),
            },
        )
        .unwrap();
    storage
        .begin_passkey_approval(NewPasskeyApprovalCeremony {
            id: ceremony_id,
            intent_id: job.intent_id,
            credential_id: "chain-cred".to_owned(),
            binding_digest: [8; 32],
            started_at: NOW - 9,
            expires_at: NOW + 30,
        })
        .unwrap();
    storage
        .complete_passkey_approval_atomic(PasskeyApprovalCompletion {
            ceremony_id,
            intent_id: job.intent_id,
            credential_id: "chain-cred".to_owned(),
            expected_credential_record_version: credential.record_version,
            updated_passkey_json: r#"{"counter":1}"#.to_owned(),
            binding_digest: [8; 32],
            authorization_expires_at: job.expires_at,
            rp_id: "wallet.example".to_owned(),
            rp_origin: "https://wallet.example".to_owned(),
            authorization_id,
            approved_at: NOW - 1,
        })
        .unwrap();
    authorization_id
}

#[test]
fn signer_profile_and_address_binding_survive_restart_without_secret_material() {
    let (_root, path, mut storage, wallet_id, profile_id, secret_ref_id) = fixture();
    storage
        .register_signer_profile(profile(wallet_id, profile_id, secret_ref_id))
        .unwrap();
    let binding_id = Uuid::new_v4();
    storage
        .bind_signer_address(NewAddressBinding {
            binding_id,
            profile_id,
            chain_scope: scope(),
            address: "bchtest:qexample".to_owned(),
            verification_key_digest: [9; 32],
            created_at: NOW + 1,
        })
        .unwrap();
    drop(storage);

    let reopened = WalletStorage::open(&path).unwrap();
    let stored = reopened.signer_profile(profile_id).unwrap().unwrap();
    assert_eq!(
        stored.signing_suite_id,
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1
    );
    assert_eq!(stored.secret_ref_id, secret_ref_id);
    assert!(!format!("{stored:?}").contains("share-1"));
    assert_eq!(
        reopened.address_bindings(profile_id).unwrap()[0].binding_id,
        binding_id
    );
}

#[test]
fn signer_profile_inventory_is_wallet_scoped_stable_and_keeps_only_opaque_secret_refs() {
    let (_root, path, mut storage, wallet_id, first_profile_id, first_secret_ref_id) = fixture();
    let second_profile_id = Uuid::from_bytes([0x22; 16]);
    let second_secret_ref_id = Uuid::from_bytes([0x33; 16]);
    storage
        .put_secret_ref(
            SecretRef::new(
                second_secret_ref_id,
                SecretBackend::EncryptedFile,
                "encrypted-file://cb-mpc/profile-secondary".to_owned(),
                NOW,
            )
            .unwrap(),
        )
        .unwrap();

    let mut second = profile(wallet_id, second_profile_id, second_secret_ref_id);
    second.created_at = NOW - 1;
    second.signer_set_id = "personal-wallet-secondary".to_owned();
    storage.register_signer_profile(second).unwrap();
    storage
        .register_signer_profile(profile(wallet_id, first_profile_id, first_secret_ref_id))
        .unwrap();

    let later_binding_id = Uuid::from_bytes([0x55; 16]);
    let earlier_binding_id = Uuid::from_bytes([0x44; 16]);
    storage
        .bind_signer_address(NewAddressBinding {
            binding_id: later_binding_id,
            profile_id: second_profile_id,
            chain_scope: scope(),
            address: "bchtest:qlater".to_owned(),
            verification_key_digest: [0x55; 32],
            created_at: NOW + 2,
        })
        .unwrap();
    storage
        .bind_signer_address(NewAddressBinding {
            binding_id: earlier_binding_id,
            profile_id: second_profile_id,
            chain_scope: scope(),
            address: "bchtest:qearlier".to_owned(),
            verification_key_digest: [0x44; 32],
            created_at: NOW + 1,
        })
        .unwrap();
    drop(storage);

    let reopened = WalletStorage::open(&path).unwrap();
    let inventory = reopened.signer_profile_inventory(wallet_id).unwrap();
    assert_eq!(inventory.len(), 2);
    assert_eq!(inventory[0].profile.profile_id, second_profile_id);
    assert_eq!(inventory[1].profile.profile_id, first_profile_id);
    assert_eq!(
        inventory[0]
            .address_bindings
            .iter()
            .map(|binding| binding.binding_id)
            .collect::<Vec<_>>(),
        vec![earlier_binding_id, later_binding_id]
    );
    assert_eq!(
        inventory[0].secret_ref,
        "encrypted-file://cb-mpc/profile-secondary"
    );
    assert!(!format!("{inventory:?}").contains("private_key"));
    assert!(!format!("{inventory:?}").contains("secret_share"));

    let second_read = reopened.signer_profile_inventory(wallet_id).unwrap();
    assert_eq!(inventory, second_read);
}

#[test]
fn signer_profile_inventory_rejects_a_different_wallet() {
    let (_root, _path, mut storage, wallet_id, profile_id, secret_ref_id) = fixture();
    storage
        .register_signer_profile(profile(wallet_id, profile_id, secret_ref_id))
        .unwrap();

    let error = storage
        .signer_profile_inventory(Uuid::from_bytes([0x99; 16]))
        .unwrap_err();
    assert!(matches!(
        error,
        catomicals_wallet_storage::StorageError::InvalidSignerProfile
    ));
}

#[test]
fn signing_job_session_is_durable_immutable_and_terminal_after_restart() {
    let (_root, path, mut storage, wallet_id, profile_id, secret_ref_id) = fixture();
    storage
        .register_signer_profile(profile(wallet_id, profile_id, secret_ref_id))
        .unwrap();
    let job_id = Uuid::new_v4();
    let job = NewSigningJob {
        job_id,
        wallet_id,
        profile_id,
        intent_id: Uuid::new_v4(),
        chain_scope: scope(),
        signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
        review_schema_version: catomicals_chain_domain::REVIEW_ARTIFACT_SCHEMA_VERSION,
        review_artifact: catomicals_chain_domain::ReviewArtifact::new(
            scope(),
            [3; 32],
            [4; 32],
            "BCH test spend".to_owned(),
            vec![0xaa],
        )
        .unwrap(),
        review_digest: [3; 32],
        signing_message_digest: [4; 32],
        policy_snapshot_digest: [5; 32],
        chain_snapshot_digest: [6; 32],
        session_id: [7; 32],
        selected_parties: ["desktop".to_owned(), "mobile".to_owned()],
        receiver: "desktop".to_owned(),
        expires_at: NOW + 120,
        created_at: NOW,
    };
    let authorization_id = approve_job(&mut storage, &job);
    storage
        .create_signing_job(authorization_id, job.clone(), [8; 32], NOW)
        .unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(
        raw.execute(
            "UPDATE signing_jobs SET operation_binding_digest = ?1 WHERE job_id = ?2",
            rusqlite::params![[9_u8; 32].as_slice(), job_id.to_string()],
        )
        .is_err(),
        "the database must reject operation binding replacement"
    );
    drop(raw);
    assert_eq!(
        storage
            .signing_job(job_id)
            .unwrap()
            .unwrap()
            .operation_binding_digest,
        Some([8; 32])
    );
    assert!(
        storage
            .create_signing_job(authorization_id, job, [8; 32], NOW)
            .is_err()
    );
    storage
        .complete_signing_job(job_id, [8; 32], vec![0x30, 1, 2], NOW + 2)
        .unwrap();
    drop(storage);

    let mut reopened = WalletStorage::open(&path).unwrap();
    let stored = reopened.signing_job(job_id).unwrap().unwrap();
    assert_eq!(stored.status, SigningJobStatus::Finalized);
    assert_eq!(stored.final_signature, Some(vec![0x30, 1, 2]));
    assert!(
        reopened
            .complete_signing_job(job_id, [8; 32], vec![1], NOW + 3)
            .is_err()
    );
}
