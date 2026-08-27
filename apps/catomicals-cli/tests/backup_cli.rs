use std::{path::Path, process::Command};

use catomicals_wallet_storage::{RestoreState, WalletStorage};
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

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_catomicals"))
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
