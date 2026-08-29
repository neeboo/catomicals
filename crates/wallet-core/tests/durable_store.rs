use catomicals_threshold::{
    FrostSession, LocalFrostParticipant, NonceGuard, SignatureShare, SigningAuthorization,
    SigningCommitments, SigningError, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    BitcoinNetwork, DurableWalletStore, IntentStatus, RelyingPartyConfig, SigningAction,
    SigningIntent, StorageMode, ThresholdSigner, WalletNodeService, WalletStore,
};
use catomicals_wallet_storage::{RestoreState, WalletStorage};
use tempfile::tempdir;
use uuid::Uuid;

fn intent(wallet_id: Uuid, id: Uuid) -> SigningIntent {
    SigningIntent {
        id,
        network: BitcoinNetwork::Signet,
        protocol_version: 1,
        action: SigningAction::SignTaprootTransaction,
        wallet_id,
        signer_id: 1,
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
    assert_eq!(descriptor.schema_version, Some(4));
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
    let service = WalletNodeService::new_with_recovered_signer_store(
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
    assert!(
        service
            .signer_status()
            .signet_address
            .as_deref()
            .is_some_and(|address| address.starts_with("tb1p"))
    );
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
