#![cfg(unix)]

use std::{collections::HashSet, fs, path::Path, process::Command};

use catomicals_chain_domain::{BitcoinNetwork, ChainNetwork, ChainScope};
use catomicals_secret_store::{FileSecretBackend, RuntimeProfile, SecretBackend as _};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet_storage::{NewSignerProfile, SecretBackend, SecretRef, WalletStorage};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn seven_chain_provisioning_is_exposed_under_wallet_signer_chains() {
    let output = cli()
        .args(["wallet", "signer", "chains", "provision", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--data-dir"));
    assert!(stdout.contains("--network-profile"));
    assert!(stdout.contains("--custody"));
}

#[test]
fn development_custody_must_be_selected_explicitly() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    let output = cli()
        .args([
            "wallet",
            "signer",
            "chains",
            "provision",
            "--data-dir",
            path(&data_dir),
            "--network-profile",
            "default-testnets",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!data_dir.exists());
}

#[test]
fn provision_installs_seven_real_profiles_and_is_idempotent() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    let init = cli()
        .args(["wallet", "signer", "init", "--data-dir", path(&data_dir)])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let signer_before = fs::read(data_dir.join("signer.json")).unwrap();

    let first = provision(&data_dir);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_summary["status"], "installed");
    let profiles = first_summary["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 7);
    assert_eq!(
        profiles
            .iter()
            .map(|profile| profile["chain"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "bitcoin",
            "bitcoin-cash",
            "bsv",
            "fractal-bitcoin",
            "kaspa",
            "chia",
            "ergo",
        ]
    );
    assert!(profiles.iter().all(|profile| {
        profile["profile_id"].as_str().is_some()
            && profile["address"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && profile["verification_key_hex"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && profile.get("secret_ref").is_none()
    }));
    assert_eq!(
        fs::read(data_dir.join("signer.json")).unwrap(),
        signer_before
    );

    let storage = WalletStorage::open(data_dir.join("wallet.sqlite3")).unwrap();
    let wallet_id = storage.wallet_metadata().unwrap().wallet_id;
    let inventory = storage.signer_profile_inventory(wallet_id).unwrap();
    assert_eq!(inventory.len(), 7);
    assert!(inventory.iter().all(|entry| {
        entry.profile.threshold == 2
            && entry.profile.max_signers == 3
            && entry.address_bindings.len() == 1
    }));
    assert_eq!(
        inventory
            .iter()
            .map(|entry| entry.profile.signer_set_id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        7
    );
    assert_eq!(
        inventory
            .iter()
            .map(|entry| entry.profile.verification_key.as_slice())
            .collect::<HashSet<_>>()
            .len(),
        7
    );
    drop(storage);

    let second = provision(&data_dir);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_summary["status"], "already_present");
}

#[test]
fn reopening_an_existing_catalog_requires_its_recovery_material() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    assert!(
        cli()
            .args(["wallet", "signer", "init", "--data-dir", path(&data_dir)])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(provision(&data_dir).status.success());

    let frost_manifest_path = fs::read_dir(data_dir.join("executor-manifests"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(frost_manifest_path).unwrap()).unwrap();
    let recovery_ref = manifest["recovery_signer"]["provider_ref"]
        .as_str()
        .unwrap();
    let backend = FileSecretBackend::open(
        data_dir.join("executor-secrets"),
        RuntimeProfile::Development,
    )
    .unwrap();
    backend.delete_raw(recovery_ref).unwrap();

    let reopened = provision(&data_dir);
    assert!(!reopened.status.success());
}

#[test]
fn partial_catalog_is_rejected_without_generating_executor_material() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    let init = cli()
        .args(["wallet", "signer", "init", "--data-dir", path(&data_dir)])
        .output()
        .unwrap();
    assert!(init.status.success());
    let database = data_dir.join("wallet.sqlite3");
    let mut storage = WalletStorage::open(&database).unwrap();
    let wallet_id = storage.wallet_metadata().unwrap().wallet_id;
    let secret_ref_id = Uuid::new_v4();
    storage
        .put_secret_ref(
            SecretRef::new(
                secret_ref_id,
                SecretBackend::EncryptedFile,
                "encrypted-file://preexisting-partial",
                1_800_000_000,
            )
            .unwrap(),
        )
        .unwrap();
    storage
        .register_signer_profile(NewSignerProfile {
            profile_id: Uuid::new_v4(),
            wallet_id,
            chain_scope: ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet)),
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            signer_set_id: Uuid::new_v4().to_string(),
            authorization_signer_id: "passkey:owner".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key: vec![0x31; 32],
            secret_ref_id,
            created_at: 1_800_000_000,
        })
        .unwrap();
    drop(storage);

    let output = provision(&data_dir);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("catalog is partial"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!data_dir.join("executor-secrets").exists());
    assert!(!data_dir.join("executor-manifests").exists());
}

fn provision(data_dir: &Path) -> std::process::Output {
    cli()
        .args([
            "wallet",
            "signer",
            "chains",
            "provision",
            "--data-dir",
            path(data_dir),
            "--network-profile",
            "default-testnets",
            "--custody",
            "self-hosted-development",
        ])
        .output()
        .unwrap()
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_catomicals"))
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
