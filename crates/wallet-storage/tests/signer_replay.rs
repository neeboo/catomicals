use catomicals_threshold::{
    DeviceHealth, DeviceStatus, ProviderError, ProviderIdentity, ProviderReplayStore,
    SIGNER_PROVIDER_PROTOCOL_VERSION, SignerDeviceRecord, SignerDeviceRegistry, SignerProviderKind,
    SignerRequestContext,
};
use catomicals_wallet_storage::WalletStorage;
use tempfile::tempdir;
use uuid::Uuid;

fn identity(wallet_id: Uuid) -> ProviderIdentity {
    ProviderIdentity {
        wallet_id,
        signer_set_id: Uuid::from_bytes([2; 16]),
        signer_epoch: 1,
        signer_id: 2,
        device_id: Uuid::from_bytes([3; 16]),
        device_generation: 1,
        group_pubkey_xonly: [4; 32],
        verifying_share_digest: [5; 32],
    }
}

fn context(identity: &ProviderIdentity, nonce: [u8; 32]) -> SignerRequestContext {
    SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: identity.wallet_id,
        signer_set_id: identity.signer_set_id,
        signer_epoch: identity.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id: Uuid::from_bytes([6; 16]),
        intent_id: Uuid::from_bytes([7; 16]),
        session_id: [8; 32],
        taproot_sighash: [9; 32],
        policy_digest: [10; 32],
        group_pubkey_xonly: identity.group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: 2,
        max_signers: 3,
        chain_snapshot_digest: [11; 32],
        request_nonce: nonce,
        expires_at: 200,
    }
}

#[test]
fn provider_request_nonce_replay_is_rejected_after_database_restart() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([1; 16]);
    let signer = identity(wallet_id);
    let request = context(&signer, [12; 32]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    ProviderReplayStore::claim_request_nonce(&mut storage, &signer, &request, 101).unwrap();
    assert_eq!(
        storage.audit_events(10).unwrap().last().unwrap().event_type,
        "signer.request_nonce_claimed"
    );
    drop(storage);

    let mut restarted = WalletStorage::open(&database).unwrap();
    assert_eq!(
        ProviderReplayStore::claim_request_nonce(&mut restarted, &signer, &request, 102),
        Err(ProviderError::Replay)
    );
    let next_request = context(&signer, [13; 32]);
    ProviderReplayStore::claim_request_nonce(&mut restarted, &signer, &next_request, 103).unwrap();
}

#[test]
fn identity_drift_never_creates_a_replay_claim() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([20; 16]);
    let signer = identity(wallet_id);
    let mut request = context(&signer, [21; 32]);
    request.device_generation = 2;
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();

    assert_eq!(
        ProviderReplayStore::claim_request_nonce(&mut storage, &signer, &request, 101),
        Err(ProviderError::BackendUnavailable)
    );
    assert_eq!(storage.audit_events(10).unwrap().len(), 1);
}

#[test]
fn one_operation_cannot_change_its_policy_or_chain_snapshot_between_requests() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([22; 16]);
    let signer = identity(wallet_id);
    let first = context(&signer, [23; 32]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    ProviderReplayStore::claim_request_nonce(&mut storage, &signer, &first, 101).unwrap();

    let mut drifted = context(&signer, [24; 32]);
    drifted.chain_snapshot_digest = [25; 32];
    assert_eq!(
        ProviderReplayStore::claim_request_nonce(&mut storage, &signer, &drifted, 102),
        Err(ProviderError::RoundBindingMismatch)
    );
    assert_eq!(
        storage
            .audit_events(10)
            .unwrap()
            .iter()
            .filter(|event| event.event_type == "signer.request_nonce_claimed")
            .count(),
        1
    );
}

fn remote_record(signer_id: u16, device_byte: u8, generation: u64) -> SignerDeviceRecord {
    SignerDeviceRecord {
        signer_id,
        device_id: Some(Uuid::from_bytes([device_byte; 16])),
        generation,
        provider: Some(SignerProviderKind::RemoteMtls),
        identity_public_key_hex: Some(hex::encode([device_byte + 1; 32])),
        mtls_spki_sha256_hex: Some(hex::encode([device_byte + 2; 32])),
        status: DeviceStatus::Active,
        registered_at: Some(100),
        rotated_at: (generation > 1).then_some(110),
        revoked_at: None,
        health: DeviceHealth {
            online: true,
            checked_at: Some(111),
            last_success_at: Some(111),
            last_error_code: None,
        },
    }
}

#[test]
fn device_rotation_and_revocation_survive_restart_but_health_does_not() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([30; 16]);
    let signer_set_id = Uuid::from_bytes([31; 16]);
    let mut storage = WalletStorage::initialize(&database, wallet_id, 100).unwrap();
    let first = remote_record(2, 32, 1);
    storage
        .persist_signer_device_transition(wallet_id, signer_set_id, 1, 0, &first, 101)
        .unwrap();
    let rotated = remote_record(2, 33, 2);
    storage
        .persist_signer_device_transition(wallet_id, signer_set_id, 1, 1, &rotated, 102)
        .unwrap();
    drop(storage);

    let mut restarted = WalletStorage::open(&database).unwrap();
    let restored = restarted
        .signer_device_records(wallet_id, signer_set_id, 1)
        .unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].device_id, rotated.device_id);
    assert_eq!(restored[0].generation, 2);
    assert!(!restored[0].health.online);
    let mut registry = SignerDeviceRegistry::new(signer_set_id, 1, 3);
    registry.restore_device_records(restored).unwrap();
    let recovered = registry
        .devices()
        .into_iter()
        .find(|device| device.signer_id == 2)
        .unwrap();
    assert_eq!(recovered.status, DeviceStatus::Active);
    assert!(!recovered.health.online);

    let mut revoked = rotated.clone();
    revoked.status = DeviceStatus::Revoked;
    revoked.revoked_at = Some(103);
    restarted
        .persist_signer_device_transition(wallet_id, signer_set_id, 1, 2, &revoked, 103)
        .unwrap();
    let replacement = remote_record(2, 34, 3);
    assert!(
        restarted
            .persist_signer_device_transition(wallet_id, signer_set_id, 1, 2, &replacement, 104)
            .is_err()
    );
    drop(restarted);

    let reopened = WalletStorage::open(&database).unwrap();
    let records = reopened
        .signer_device_records(wallet_id, signer_set_id, 1)
        .unwrap();
    assert_eq!(records[0].status, DeviceStatus::Revoked);
    assert_eq!(records[0].generation, 2);
    assert!(!records[0].health.online);
}
