use catomicals_chain_domain::{BitcoinCashNetwork, BsvNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet_storage::{
    NewAddressBinding, NewSignerCatalogEntry, NewSignerProfile, SecretBackend, SecretRef,
    SignerCatalogInstallOutcome, StorageError, WalletStorage,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

fn entry(
    wallet_id: Uuid,
    seed: u8,
    scope: ChainScope,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
) -> NewSignerCatalogEntry {
    let secret_ref_id = Uuid::from_bytes([seed; 16]);
    let profile_id = Uuid::from_bytes([seed.wrapping_add(1); 16]);
    let verification_key = vec![seed; 33];
    NewSignerCatalogEntry {
        secret_ref: SecretRef::new(
            secret_ref_id,
            SecretBackend::EncryptedFile,
            format!("encrypted-file://catalog/{seed}"),
            NOW,
        )
        .unwrap(),
        profile: NewSignerProfile {
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: suite,
            backend_requirement: backend,
            signer_set_id: format!("set-{seed}"),
            authorization_signer_id: "local-participant-1".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key: verification_key.clone(),
            secret_ref_id,
            created_at: NOW,
        },
        address_bindings: vec![NewAddressBinding {
            binding_id: Uuid::from_bytes([seed.wrapping_add(2); 16]),
            profile_id,
            chain_scope: scope,
            address: format!("test-address-{seed}"),
            verification_key_digest: Sha256::digest(&verification_key).into(),
            created_at: NOW,
        }],
    }
}

fn catalog(wallet_id: Uuid) -> Vec<NewSignerCatalogEntry> {
    vec![
        entry(
            wallet_id,
            0x11,
            ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet)),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        ),
        entry(
            wallet_id,
            0x22,
            ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet)),
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        ),
    ]
}

fn assert_invalid_catalog_is_atomic(
    mut catalog: Vec<NewSignerCatalogEntry>,
    mutate: impl FnOnce(&mut Vec<NewSignerCatalogEntry>),
) {
    mutate(&mut catalog);
    let root = tempdir().unwrap();
    let wallet_id = catalog[0].profile.wallet_id;
    let path = root.path().join("wallet.sqlite3");
    let mut storage = WalletStorage::initialize(&path, wallet_id, NOW).unwrap();

    assert!(matches!(
        storage.install_signer_catalog(&catalog),
        Err(StorageError::InvalidSignerProfile)
    ));

    let raw = rusqlite::Connection::open(path).unwrap();
    for table in ["secret_refs", "signer_profiles", "signer_address_bindings"] {
        let count: u64 = raw
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must remain empty");
    }
}

#[test]
fn catalog_rejects_duplicate_secret_handles_before_writing() {
    let wallet_id = Uuid::new_v4();
    assert_invalid_catalog_is_atomic(catalog(wallet_id), |catalog| {
        catalog[1].secret_ref.handle = catalog[0].secret_ref.handle.clone();
    });
}

#[test]
fn catalog_rejects_duplicate_signer_set_ids_before_writing() {
    let wallet_id = Uuid::new_v4();
    assert_invalid_catalog_is_atomic(catalog(wallet_id), |catalog| {
        catalog[1].profile.signer_set_id = catalog[0].profile.signer_set_id.clone();
    });
}

#[test]
fn catalog_rejects_duplicate_verification_keys_before_writing() {
    let wallet_id = Uuid::new_v4();
    assert_invalid_catalog_is_atomic(catalog(wallet_id), |catalog| {
        catalog[1].profile.verification_key = catalog[0].profile.verification_key.clone();
        catalog[1].address_bindings[0].verification_key_digest =
            Sha256::digest(&catalog[1].profile.verification_key).into();
    });
}

#[test]
fn catalog_install_is_atomic_and_exactly_idempotent() {
    let root = tempdir().unwrap();
    let wallet_id = Uuid::new_v4();
    let mut storage =
        WalletStorage::initialize(root.path().join("wallet.sqlite3"), wallet_id, NOW).unwrap();
    let catalog = catalog(wallet_id);

    assert_eq!(
        storage.install_signer_catalog(&catalog).unwrap(),
        SignerCatalogInstallOutcome::Installed
    );
    assert_eq!(
        storage.install_signer_catalog(&catalog).unwrap(),
        SignerCatalogInstallOutcome::AlreadyPresent
    );

    let inventory = storage.signer_profile_inventory(wallet_id).unwrap();
    assert_eq!(inventory.len(), 2);
    assert_eq!(
        inventory[0].profile.profile_id,
        catalog[0].profile.profile_id
    );
    assert_eq!(
        inventory[1].profile.profile_id,
        catalog[1].profile.profile_id
    );
    assert_eq!(inventory[0].address_bindings.len(), 1);
    assert_eq!(inventory[1].address_bindings.len(), 1);
}

#[test]
fn different_catalog_is_rejected_without_changing_the_installed_catalog() {
    let root = tempdir().unwrap();
    let wallet_id = Uuid::new_v4();
    let mut storage =
        WalletStorage::initialize(root.path().join("wallet.sqlite3"), wallet_id, NOW).unwrap();
    let catalog = catalog(wallet_id);
    storage.install_signer_catalog(&catalog).unwrap();
    let before = storage.signer_profile_inventory(wallet_id).unwrap();

    let mut changed = catalog.clone();
    changed[1].profile.signer_epoch = 2;
    let error = storage.install_signer_catalog(&changed).unwrap_err();

    assert!(matches!(
        error,
        StorageError::ImmutableConflict("signer_catalog")
    ));
    assert_eq!(storage.signer_profile_inventory(wallet_id).unwrap(), before);
}

#[test]
fn invalid_later_entry_leaves_all_catalog_tables_empty() {
    let root = tempdir().unwrap();
    let wallet_id = Uuid::new_v4();
    let path = root.path().join("wallet.sqlite3");
    let mut storage = WalletStorage::initialize(&path, wallet_id, NOW).unwrap();
    let mut catalog = catalog(wallet_id);
    catalog[1].address_bindings[0].verification_key_digest = [0x55; 32];

    assert!(matches!(
        storage.install_signer_catalog(&catalog),
        Err(StorageError::InvalidSignerProfile)
    ));

    assert!(
        storage
            .signer_profile_inventory(wallet_id)
            .unwrap()
            .is_empty()
    );
    let raw = rusqlite::Connection::open(path).unwrap();
    for table in ["secret_refs", "signer_profiles", "signer_address_bindings"] {
        let count: u64 = raw
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must remain empty");
    }
}

#[test]
fn partial_existing_catalog_is_rejected() {
    let root = tempdir().unwrap();
    let wallet_id = Uuid::new_v4();
    let mut storage =
        WalletStorage::initialize(root.path().join("wallet.sqlite3"), wallet_id, NOW).unwrap();
    let catalog = catalog(wallet_id);
    storage
        .put_secret_ref(catalog[0].secret_ref.clone())
        .unwrap();
    storage
        .register_signer_profile(catalog[0].profile.clone())
        .unwrap();
    storage
        .bind_signer_address(catalog[0].address_bindings[0].clone())
        .unwrap();

    let error = storage.install_signer_catalog(&catalog).unwrap_err();
    assert!(matches!(
        error,
        StorageError::ImmutableConflict("signer_catalog")
    ));
    assert_eq!(
        storage.signer_profile_inventory(wallet_id).unwrap().len(),
        1
    );
}

#[test]
fn orphan_secret_reference_is_rejected_as_partial_catalog_state() {
    let root = tempdir().unwrap();
    let wallet_id = Uuid::new_v4();
    let mut storage =
        WalletStorage::initialize(root.path().join("wallet.sqlite3"), wallet_id, NOW).unwrap();
    let catalog = catalog(wallet_id);
    storage
        .put_secret_ref(
            SecretRef::new(
                Uuid::new_v4(),
                SecretBackend::EncryptedFile,
                "encrypted-file://orphan/share",
                NOW,
            )
            .unwrap(),
        )
        .unwrap();

    let error = storage.install_signer_catalog(&catalog).unwrap_err();
    assert!(matches!(
        error,
        StorageError::ImmutableConflict("signer_catalog")
    ));
    assert!(
        storage
            .signer_profile_inventory(wallet_id)
            .unwrap()
            .is_empty()
    );
}
