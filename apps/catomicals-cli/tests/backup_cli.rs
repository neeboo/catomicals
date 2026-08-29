use std::{path::Path, process::Command};

use catomicals_wallet_storage::{
    CredentialState, NewPasskeyRecord, RestoreState, WalletStorage, WebauthnProfile,
};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn backup_export_and_verify_require_and_use_an_explicit_development_secret_backend() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    std::fs::create_dir(&data_dir).unwrap();
    let wallet_id = Uuid::from_bytes([0x81; 16]);
    let storage =
        WalletStorage::initialize(data_dir.join("wallet.sqlite3"), wallet_id, 1_800_000_000)
            .unwrap();
    drop(storage);
    let bundle = directory.path().join("backup");
    let secret_dir = directory.path().join("secrets");

    let missing_backend = cli()
        .args([
            "backup",
            "export",
            "--data-dir",
            path(&data_dir),
            "--out",
            path(&bundle),
        ])
        .output()
        .unwrap();
    assert!(!missing_backend.status.success());

    let exported = cli()
        .args([
            "backup",
            "export",
            "--data-dir",
            path(&data_dir),
            "--out",
            path(&bundle),
            "--secret-dir",
            path(&secret_dir),
            "--profile",
            "development",
        ])
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(bundle.join("manifest.json").is_file());

    let verified = cli()
        .args([
            "backup",
            "verify",
            path(&bundle),
            "--secret-dir",
            path(&secret_dir),
            "--profile",
            "development",
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn backup_restore_stops_in_recovering_until_operator_completion() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    std::fs::create_dir(&data_dir).unwrap();
    let wallet_id = Uuid::from_bytes([0x91; 16]);
    let database = data_dir.join("wallet.sqlite3");
    let storage = WalletStorage::initialize(&database, wallet_id, 1_800_000_000).unwrap();
    drop(storage);
    let bundle = directory.path().join("backup");
    let secret_dir = directory.path().join("secrets");
    assert!(
        cli()
            .args([
                "backup",
                "export",
                "--data-dir",
                path(&data_dir),
                "--out",
                path(&bundle),
                "--secret-dir",
                path(&secret_dir),
                "--profile",
                "development",
            ])
            .status()
            .unwrap()
            .success()
    );

    let restored = cli()
        .args([
            "backup",
            "restore",
            path(&bundle),
            "--data-dir",
            path(&data_dir),
            "--wallet-id",
            &wallet_id.to_string(),
            "--secret-dir",
            path(&secret_dir),
            "--profile",
            "development",
        ])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let storage = WalletStorage::open(&database).unwrap();
    assert_eq!(
        storage.wallet_metadata().unwrap().restore_state,
        RestoreState::Recovering
    );
}

#[test]
fn signer_audit_and_backup_restore_keep_the_frost_identity_without_printing_secrets() {
    let directory = tempdir().unwrap();
    let data_dir = directory.path().join("wallet");
    let wallet_id = Uuid::from_bytes([0x92; 16]);
    let initialized = cli()
        .args([
            "wallet",
            "signer",
            "init",
            "--data-dir",
            path(&data_dir),
            "--wallet-id",
            &wallet_id.to_string(),
            "--signer-id",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let initial_audit = cli()
        .args(["wallet", "signer", "audit", "--data-dir", path(&data_dir)])
        .output()
        .unwrap();
    assert!(initial_audit.status.success());
    let initial_text = String::from_utf8(initial_audit.stdout).unwrap();
    assert!(!initial_text.contains("secret_handle"));
    assert!(!initial_text.contains("key_package"));
    assert!(!initial_text.contains("signing_share"));
    let initial_json: serde_json::Value = serde_json::from_str(&initial_text).unwrap();

    let database = data_dir.join("wallet.sqlite3");
    let mut authority = WalletStorage::open(&database).unwrap();
    authority
        .set_webauthn_profile(WebauthnProfile {
            wallet_id,
            user_id: "owner-user-id".to_owned(),
            rp_id: "localhost".to_owned(),
            rp_origin: "http://localhost:5173".to_owned(),
            record_version: 1,
            updated_at: 1_800_000_001,
        })
        .unwrap();
    authority
        .insert_passkey_record(NewPasskeyRecord {
            credential_id: "credential-public-id".to_owned(),
            label: "Primary passkey".to_owned(),
            passkey_json: r#"{"counter":7,"public_key":"test-only-public-metadata"}"#.to_owned(),
            format: "webauthn-rs-passkey-json-v1".to_owned(),
            credential_state: CredentialState::Active,
            enrolled_at: 1_800_000_002,
        })
        .unwrap();
    drop(authority);

    let bundle = directory.path().join("backup");
    let secret_dir = directory.path().join("backup-secrets");
    assert!(
        cli()
            .args([
                "backup",
                "export",
                "--data-dir",
                path(&data_dir),
                "--out",
                path(&bundle),
                "--secret-dir",
                path(&secret_dir),
                "--profile",
                "development",
            ])
            .status()
            .unwrap()
            .success()
    );
    std::fs::remove_file(data_dir.join("signer.json")).unwrap();
    std::fs::remove_dir_all(data_dir.join("signer-secrets")).unwrap();
    let restored = cli()
        .args([
            "backup",
            "restore",
            path(&bundle),
            "--data-dir",
            path(&data_dir),
            "--wallet-id",
            &wallet_id.to_string(),
            "--secret-dir",
            path(&secret_dir),
            "--profile",
            "development",
        ])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let restored_audit = cli()
        .args(["wallet", "signer", "audit", "--data-dir", path(&data_dir)])
        .output()
        .unwrap();
    let restored_json: serde_json::Value = serde_json::from_slice(&restored_audit.stdout).unwrap();
    assert_eq!(
        restored_json["group_pubkey_xonly"],
        initial_json["group_pubkey_xonly"]
    );
    assert_eq!(
        restored_json["signer_set_id"],
        initial_json["signer_set_id"]
    );
    let authority = WalletStorage::open(&database).unwrap();
    let profile = authority.webauthn_profile().unwrap().unwrap();
    assert_eq!(profile.rp_id, "localhost");
    assert_eq!(profile.rp_origin, "http://localhost:5173");
    let credential = authority
        .passkey_record("credential-public-id")
        .unwrap()
        .unwrap();
    assert_eq!(credential.label, "Primary passkey");
    assert_eq!(credential.record_version, 1);
    assert_eq!(credential.credential_state, CredentialState::Active);
    assert_eq!(
        authority.wallet_metadata().unwrap().restore_state,
        RestoreState::Recovering
    );
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_catomicals"))
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
