use catomicals_chain_bitcoin::derive_p2tr_output_key_address;
use catomicals_chain_domain::{BitcoinNetwork as ChainBitcoinNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    FrostSession, LocalFrostParticipant, NonceGuard, PersonalSignerProfile, SignatureShare,
    SigningAuthorization, SigningCommitments, SigningError, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    BitcoinNetwork, DurableWalletStore, IntentStatus, NodeSnapshot, PersonalSigningPolicy,
    RelyingPartyConfig, SigningAction, SigningIntent, StorageMode, ThresholdSigner, WalletApi,
    WalletNodeService, WalletStore,
};
use catomicals_wallet_storage::{
    CURRENT_SCHEMA_VERSION, NewAddressBinding, NewSignerProfile, RestoreState, SecretBackend,
    SecretRef, WalletStorage,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

fn bitcoin_x_only_key(seed: u8) -> [u8; 32] {
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &secret,
    );
    bitcoin::XOnlyPublicKey::from_keypair(&keypair)
        .0
        .serialize()
}

fn intent(wallet_id: Uuid, id: Uuid) -> SigningIntent {
    SigningIntent {
        id,
        network: BitcoinNetwork::Signet,
        protocol_version: 1,
        action: SigningAction::SignTaprootTransaction,
        wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: [0x11; 32],
        session_id: [0x22; 32],
        expiry: 1_800_000_300,
        nonce: [0x33; 32],
        status: IntentStatus::Pending,
        created_at: 1_800_000_000,
    }
}

#[test]
fn durable_store_restores_intents_and_reports_recovery_identity() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x44; 16]);
    let intent_id = Uuid::from_bytes([0x55; 16]);

    let mut store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    store.insert_intent(intent(wallet_id, intent_id)).unwrap();
    let descriptor = store.descriptor();
    assert_eq!(descriptor.mode, StorageMode::Durable);
    assert_eq!(descriptor.schema_version, Some(CURRENT_SCHEMA_VERSION));
    assert_eq!(descriptor.recovery_epoch, Some(1));
    drop(store);

    let reopened = DurableWalletStore::open(&database).unwrap();
    assert_eq!(
        reopened.get_intent(&intent_id).unwrap(),
        intent(wallet_id, intent_id)
    );
    assert_eq!(reopened.list_intents(), vec![intent(wallet_id, intent_id)]);
    assert_eq!(reopened.descriptor().recovery_epoch, Some(1));
}

#[test]
fn durable_wallet_exposes_a_restart_stable_public_signer_startup_snapshot() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x8a; 16]);
    let profile_id = Uuid::from_bytes([0x8b; 16]);
    let secret_ref_id = Uuid::from_bytes([0x8c; 16]);
    let binding_id = Uuid::from_bytes([0x8d; 16]);
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(ChainBitcoinNetwork::Signet));
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    storage
        .put_secret_ref(
            SecretRef::new(
                secret_ref_id,
                SecretBackend::EncryptedFile,
                "encrypted-file://frost/personal-primary",
                1_800_000_000,
            )
            .unwrap(),
        )
        .unwrap();
    let verification_key =
        hex::decode("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115").unwrap();
    let verification_key_digest = Sha256::digest(&verification_key).into();
    let address = derive_p2tr_output_key_address(
        scope,
        bitcoin::XOnlyPublicKey::from_slice(&verification_key).unwrap(),
    )
    .unwrap()
    .to_string();
    storage
        .register_signer_profile(NewSignerProfile {
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            signer_set_id: "personal-wallet".to_owned(),
            authorization_signer_id: "frost:participant-1".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key,
            secret_ref_id,
            created_at: 1_800_000_001,
        })
        .unwrap();
    storage
        .bind_signer_address(NewAddressBinding {
            binding_id,
            profile_id,
            chain_scope: scope,
            address: address.clone(),
            verification_key_digest,
            created_at: 1_800_000_002,
        })
        .unwrap();
    drop(storage);

    let api = WalletApi::with_store(Box::new(DurableWalletStore::open(&database).unwrap()));
    let snapshot = api.signer_profiles_snapshot().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].profile_id, profile_id);
    assert_eq!(snapshot[0].wallet_id, wallet_id);
    assert_eq!(
        snapshot[0].secret_ref,
        "encrypted-file://frost/personal-primary"
    );
    assert_eq!(snapshot[0].address_bindings[0].binding_id, binding_id);
    assert_eq!(snapshot[0].address_bindings[0].address, address);

    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(encoded.contains("personal-primary"));
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("secret_share"));
    drop(api);

    let service = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(DurableWalletStore::open(&database).unwrap()),
        1_800_000_010,
    )
    .unwrap();
    assert_eq!(
        service.signer_profiles_snapshot().unwrap()[0].profile_id,
        profile_id
    );
}

#[test]
fn durable_wallet_rejects_a_stored_address_from_another_verification_key() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x9a; 16]);
    let profile_id = Uuid::from_bytes([0x9b; 16]);
    let secret_ref_id = Uuid::from_bytes([0x9c; 16]);
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(ChainBitcoinNetwork::Signet));
    let verification_key = bitcoin_x_only_key(1).to_vec();
    let verification_key_digest = Sha256::digest(&verification_key).into();
    let another_key_address = derive_p2tr_output_key_address(
        scope,
        bitcoin::XOnlyPublicKey::from_slice(&bitcoin_x_only_key(2)).unwrap(),
    )
    .unwrap()
    .to_string();

    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    storage
        .put_secret_ref(
            SecretRef::new(
                secret_ref_id,
                SecretBackend::EncryptedFile,
                "encrypted-file://frost/tampered-binding",
                1_800_000_000,
            )
            .unwrap(),
        )
        .unwrap();
    storage
        .register_signer_profile(NewSignerProfile {
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            signer_set_id: "tampered-wallet".to_owned(),
            authorization_signer_id: "frost:participant-1".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key,
            secret_ref_id,
            created_at: 1_800_000_001,
        })
        .unwrap();
    // Storage guarantees scope and key digest consistency. Wallet-core must
    // additionally prove that the persisted address came from that exact key.
    storage
        .bind_signer_address(NewAddressBinding {
            binding_id: Uuid::from_bytes([0x9d; 16]),
            profile_id,
            chain_scope: scope,
            address: another_key_address,
            verification_key_digest,
            created_at: 1_800_000_002,
        })
        .unwrap();
    drop(storage);

    let api = WalletApi::with_store(Box::new(DurableWalletStore::open(&database).unwrap()));
    let error = api.signer_profiles_snapshot().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("stored signer address is not key-bound")
    );
}

#[test]
fn durable_store_restores_personal_intent_with_its_approved_policy_digest() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x46; 16]);
    let profile = PersonalSignerProfile::bootstrap(
        Uuid::from_bytes([0x47; 16]),
        wallet_id,
        Uuid::from_bytes([0x48; 16]),
        1,
        run_local_dkg(3, 2).unwrap(),
    )
    .unwrap()
    .profile;
    let mut personal = intent(wallet_id, Uuid::from_bytes([0x49; 16]));
    personal.signer_id = 0;
    personal.personal_signing_policy = Some(PersonalSigningPolicy::from_profile(
        &profile, [0x4a; 32], [0x4b; 32],
    ));

    let mut store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    store.insert_intent(personal.clone()).unwrap();
    drop(store);

    let reopened = DurableWalletStore::open(&database).unwrap();
    assert_eq!(reopened.get_intent(&personal.id), Some(personal.clone()));
    drop(reopened);
    assert_eq!(
        WalletStorage::open(&database)
            .unwrap()
            .transaction_intent_v2(personal.id)
            .unwrap()
            .unwrap()
            .policy_hash,
        [0x4a; 32]
    );
}

#[test]
fn durable_store_rejects_an_intent_for_another_wallet() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x66; 16]);
    let mut store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();

    let error = store
        .insert_intent(intent(Uuid::from_bytes([0x77; 16]), Uuid::new_v4()))
        .unwrap_err();
    assert!(error.to_string().contains("wallet id"));
    assert!(store.list_intents().is_empty());
}

#[test]
fn durable_runtime_without_secret_backend_does_not_invent_a_signer() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x68; 16]);
    let store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let service = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        1_800_000_000,
    )
    .unwrap();
    assert!(!service.signer_status().configured);
    assert!(service.signer_status().group_pubkey_xonly.is_none());
    assert!(!service.wallet_status().threshold.configured);
    assert!(!service.node_status().durable_signer);
}

#[test]
fn durable_store_exposes_the_authoritative_restore_state() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x45; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    storage.begin_restore_precheck(1_800_000_001).unwrap();
    drop(storage);

    let store = DurableWalletStore::open(&database).unwrap();

    assert_eq!(
        store.restore_state().unwrap(),
        RestoreState::RestorePrecheck
    );
}

#[test]
fn explicitly_recovered_signer_reports_durable_without_inventing_remote_participants() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x78; 16]);
    let mut generated = run_local_dkg(3, 2).unwrap();
    let key = generated
        .key_packages
        .remove(&participant_identifier(1).unwrap())
        .unwrap();
    let participant = LocalFrostParticipant::new(1, key, NonceGuard::new()).unwrap();
    let mut service = WalletNodeService::new_with_recovered_signer_store(
        RelyingPartyConfig::default(),
        participant,
        generated.public_key_package,
        2,
        Box::new(DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap()),
        1_800_000_000,
    )
    .unwrap();

    let node_status = service.node_status();
    assert!(node_status.durable_signer);
    assert!(
        node_status
            .persistence
            .contains("restart-recoverable signer")
    );
    assert!(node_status.secret_storage.contains("absent from SQLite"));
    assert!(service.signer_status().configured);
    assert!(service.signer_status().signet_address.is_none());
    assert_eq!(service.node_status().network, "unconfigured");
    service.set_node_snapshot(Some(NodeSnapshot {
        chain: "bitcoin-cash-chipnet".to_owned(),
        blocks: 42,
        headers: 42,
        subversion: "/fixture/".to_owned(),
        op_cat_active: false,
    }));
    assert_eq!(service.node_status().network, "bitcoin-cash-chipnet");
    assert_eq!(service.wallet_status().signers.len(), 1);
    assert!(service.wallet_status().signers[0].online);
    assert_eq!(service.wallet_status().threshold.max_signers, 3);
}

struct OfflineRemoteSigner(u16);

impl ThresholdSigner for OfflineRemoteSigner {
    fn signer_id(&self) -> u16 {
        self.0
    }

    fn round1(
        &mut self,
        _session_id: [u8; 32],
        _message: [u8; 32],
    ) -> Result<SigningCommitments, SigningError> {
        Err(SigningError::RoundOneNotFound)
    }

    fn pending_nonce_fingerprint(
        &self,
        _session_id: &[u8; 32],
        _message: &[u8; 32],
    ) -> Result<[u8; 32], SigningError> {
        Err(SigningError::RoundOneNotFound)
    }

    fn round2(
        &mut self,
        _session: &FrostSession,
        _authorization: &mut dyn SigningAuthorization,
        _now: i64,
    ) -> Result<SignatureShare, SigningError> {
        Err(SigningError::RoundOneNotFound)
    }
}

#[test]
fn an_hsm_or_remote_signer_can_implement_the_narrow_signer_provider_interface() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x79; 16]);
    let generated = run_local_dkg(3, 2).unwrap();
    let service = WalletNodeService::new_with_signer_provider_store(
        RelyingPartyConfig::default(),
        Box::new(OfflineRemoteSigner(1)),
        generated.public_key_package,
        2,
        Box::new(DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap()),
        1_800_000_000,
        true,
    )
    .unwrap();

    assert_eq!(service.signer_status().signer_id, Some(1));
    assert!(service.node_status().durable_signer);
    assert_eq!(service.wallet_status().signers.len(), 1);
}

#[test]
fn durable_intent_transition_records_the_transition_time() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x69; 16]);
    let intent_id = Uuid::from_bytes([0x6a; 16]);
    let mut store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    let mut record = intent(wallet_id, intent_id);
    store.insert_intent(record.clone()).unwrap();
    record.status = IntentStatus::Cancelled;
    store.update_intent(record, 1_800_000_123).unwrap();
    drop(store);

    let storage = catomicals_wallet_storage::WalletStorage::open(&database).unwrap();
    assert_eq!(
        storage
            .transaction_intent_v2(intent_id)
            .unwrap()
            .unwrap()
            .updated_at,
        1_800_000_123
    );
}

#[test]
fn durable_store_rejects_tampered_intent_material() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x6b; 16]);
    let intent_id = Uuid::from_bytes([0x6c; 16]);
    let mut store = DurableWalletStore::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    store.insert_intent(intent(wallet_id, intent_id)).unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE intent_materials SET payload_hash = zeroblob(32) WHERE intent_id = ?1",
            [intent_id.to_string()],
        )
        .unwrap();
    drop(connection);

    let error = DurableWalletStore::open(&database).unwrap_err();
    assert!(error.to_string().contains("material hash"));
}
