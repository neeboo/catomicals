use std::{fs, path::Path, process::Command};

use catomicals_policy_registry::{MAX_BUNDLE_BYTES, compile_policy_json, inspect_bundle};
use catomicals_wallet_storage::{ActivationStatus, WalletStorage};
use tempfile::tempdir;
use uuid::Uuid;

const POLICY: &str = r#"{
  "schema_version":1,
  "canonicalization":"catomicals-policy-jcs-v1",
  "digest_algorithm":"sha256",
  "network":{"bitcoin_network":"signet","deployment_profile":"bitcoin-inquisition-signet-v29.4-op-cat","op_cat":"required"},
  "policy_kind":"catomicals-issuance-v1",
  "name":"cli issuance",
  "input":{"item_id":"4242424242424242424242424242424242424242424242424242424242424242","target_prefix":1,"total_supply":4,"successor_rule":"recursive_issuer","lane_count":1,"salt":"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","metadata_base64":"Y2F0b21pY2FscyBkZW1vIGl0ZW0="}
}"#;

#[test]
fn compile_is_deterministic_and_inspect_detects_tampering_without_a_wallet() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("policy.json");
    fs::write(&source, POLICY).unwrap();

    let first = cli()
        .args(["policy", "compile", path(&source)])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = cli()
        .args(["policy", "compile", path(&source)])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    inspect_bundle(&first.stdout).unwrap();

    let bundle = directory.path().join("policy.bundle.json");
    fs::write(&bundle, &first.stdout).unwrap();
    let inspected = cli()
        .args(["policy", "inspect", path(&bundle)])
        .output()
        .unwrap();
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("all vectors passed"));

    let mut tampered = first.stdout;
    let index = tampered.len() - 2;
    tampered[index] ^= 1;
    let tampered_path = directory.path().join("tampered.bundle.json");
    fs::write(&tampered_path, tampered).unwrap();
    assert!(
        !cli()
            .args(["policy", "inspect", path(&tampered_path)])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn compile_storage_and_pending_activation_respect_the_wallet_lock() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    fs::create_dir(&data_dir).unwrap();
    let database = data_dir.join("wallet.sqlite3");
    let source = directory.path().join("policy.json");
    fs::write(&source, POLICY).unwrap();
    let wallet_id = Uuid::from_bytes([0x51; 16]);
    let locked = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();

    let conflict = cli()
        .args([
            "policy",
            "compile",
            path(&source),
            "--data-dir",
            path(&data_dir),
        ])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("active writer"));
    drop(locked);

    let stored = cli()
        .args([
            "policy",
            "compile",
            path(&source),
            "--data-dir",
            path(&data_dir),
        ])
        .output()
        .unwrap();
    assert!(
        stored.status.success(),
        "{}",
        String::from_utf8_lossy(&stored.stderr)
    );
    let bundle = inspect_bundle(&stored.stdout).unwrap();

    let activation_id = Uuid::from_bytes([0x52; 16]);
    let binding_id = Uuid::from_bytes([0x53; 16]);
    let signer_set_id = Uuid::from_bytes([0x54; 16]);
    let locked = WalletStorage::open(&database).unwrap();
    let activation_conflict = cli()
        .args([
            "policy",
            "activate",
            "--data-dir",
            path(&data_dir),
            "--policy-hash",
            &bundle.policy_hash,
            "--signer-set-id",
            &signer_set_id.to_string(),
            "--signer-epoch",
            "7",
            "--expires-at",
            "1900000000",
            "--activation-id",
            &activation_id.to_string(),
            "--binding-id",
            &binding_id.to_string(),
        ])
        .output()
        .unwrap();
    assert!(!activation_conflict.status.success());
    assert!(String::from_utf8_lossy(&activation_conflict.stderr).contains("active writer"));
    drop(locked);

    let activated = cli()
        .args([
            "policy",
            "activate",
            "--data-dir",
            path(&data_dir),
            "--policy-hash",
            &bundle.policy_hash,
            "--signer-set-id",
            &signer_set_id.to_string(),
            "--signer-epoch",
            "7",
            "--expires-at",
            "1900000000",
            "--activation-id",
            &activation_id.to_string(),
            "--binding-id",
            &binding_id.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        activated.status.success(),
        "{}",
        String::from_utf8_lossy(&activated.stderr)
    );
    let output = String::from_utf8(activated.stdout).unwrap();
    assert!(output.contains("\"state\":\"pending\""));
    assert!(output.contains("approval_digest"));
    assert!(output.contains("AuthorityIntent + Passkey"));
    assert!(!output.contains("\"state\":\"active\""));

    let storage = WalletStorage::open(&database).unwrap();
    assert_eq!(
        storage
            .policy_activation_status_at(activation_id, 1_800_000_100)
            .unwrap(),
        Some(ActivationStatus::Pending)
    );
    assert!(
        !storage
            .policy_binding_usable_for_signing(binding_id)
            .unwrap()
    );
}

#[test]
fn activate_rejects_a_policy_that_was_not_stored_and_validated() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    fs::create_dir(&data_dir).unwrap();
    let database = data_dir.join("wallet.sqlite3");
    let wallet_id = Uuid::from_bytes([0x61; 16]);
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let bundle = compile_policy_json(POLICY.as_bytes()).unwrap();

    let rejected = cli()
        .args([
            "policy",
            "activate",
            "--data-dir",
            path(&data_dir),
            "--policy-hash",
            &bundle.policy_hash,
            "--signer-set-id",
            "62626262-6262-6262-6262-626262626262",
            "--signer-epoch",
            "1",
            "--expires-at",
            "1900000000",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not completed exact"));
}

#[test]
fn inspect_rejects_a_bundle_over_the_shared_size_limit() {
    let directory = tempdir().unwrap();
    let bundle = directory.path().join("oversized.bundle.json");
    fs::write(&bundle, vec![b' '; MAX_BUNDLE_BYTES + 1]).unwrap();

    let rejected = cli()
        .args(["policy", "inspect", path(&bundle)])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains(&format!("{MAX_BUNDLE_BYTES} byte input limit"))
    );
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_catomicals"))
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
