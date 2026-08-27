use std::fs;

use catomicals_secret_store::{
    BackupDek, FileSecretBackend, RuntimeProfile, SecretBackendError, SecretRef, SecretValue,
    open_sealed_payload, seal_payload,
};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn development_file_backend_seals_a_typed_secret_without_serializing_material() {
    let directory = tempdir().unwrap();
    let secret_dir = directory.path().join("secrets");
    let backend = FileSecretBackend::open(&secret_dir, RuntimeProfile::Development).unwrap();
    let plaintext = b"backup database key material";

    let reference: SecretRef<BackupDek> =
        backend.put(SecretValue::new(plaintext.to_vec())).unwrap();

    assert!(reference.handle().starts_with("encrypted-file://"));
    assert_eq!(
        serde_json::to_value(&reference).unwrap(),
        json!({ "handle": reference.handle() })
    );
    let debug = format!("{reference:?}");
    assert!(!debug.contains(reference.handle()));
    assert!(!debug.contains("encrypted-file://"));
    assert_eq!(
        backend.get(&reference).unwrap().expose(),
        plaintext.as_slice()
    );

    for entry in walk_files(&secret_dir) {
        let bytes = fs::read(entry).unwrap();
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }
}

#[test]
fn file_backend_is_rejected_outside_the_development_profile() {
    let directory = tempdir().unwrap();
    assert!(matches!(
        FileSecretBackend::open(directory.path().join("secrets"), RuntimeProfile::Production),
        Err(SecretBackendError::DevelopmentBackendForbidden)
    ));
}

#[cfg(unix)]
#[test]
fn file_backend_rejects_an_existing_directory_with_group_or_world_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let secret_dir = directory.path().join("secrets");
    fs::create_dir(&secret_dir).unwrap();
    fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(matches!(
        FileSecretBackend::open(&secret_dir, RuntimeProfile::Development),
        Err(SecretBackendError::InsecurePermissions { .. })
    ));
}

#[cfg(unix)]
#[test]
fn file_backend_rejects_a_kek_with_group_or_world_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let secret_dir = directory.path().join("secrets");
    drop(FileSecretBackend::open(&secret_dir, RuntimeProfile::Development).unwrap());
    fs::set_permissions(
        secret_dir.join("development.kek"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    assert!(matches!(
        FileSecretBackend::open(&secret_dir, RuntimeProfile::Development),
        Err(SecretBackendError::InsecurePermissions { .. })
    ));
}

#[test]
fn tampered_envelope_fails_closed_without_printing_secret_material() {
    let directory = tempdir().unwrap();
    let backend = FileSecretBackend::open(
        directory.path().join("secrets"),
        RuntimeProfile::Development,
    )
    .unwrap();
    let secret = b"never print this token";
    let reference: SecretRef<BackupDek> = backend.put(SecretValue::new(secret.to_vec())).unwrap();
    let record = backend.record_path(reference.handle()).unwrap();
    let mut bytes = fs::read(&record).unwrap();
    let last = bytes.last_mut().unwrap();
    *last ^= 1;
    fs::write(record, bytes).unwrap();

    let error = backend.get(&reference).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("never print this token"));
    assert!(!rendered.contains("wrapped_dek"));
}

#[test]
fn sealed_payload_uses_a_backend_held_dek_and_detects_ciphertext_tampering() {
    let directory = tempdir().unwrap();
    let backend = FileSecretBackend::open(
        directory.path().join("secrets"),
        RuntimeProfile::Development,
    )
    .unwrap();
    let plaintext = b"SQLite format 3 database bytes";
    let sealed = seal_payload::<BackupDek>(&backend, plaintext, b"wallet-backup-v1").unwrap();

    assert!(
        !sealed
            .ciphertext
            .windows(plaintext.len())
            .any(|part| part == plaintext)
    );
    assert_eq!(
        open_sealed_payload(&backend, &sealed, b"wallet-backup-v1").unwrap(),
        plaintext
    );

    let mut tampered = sealed;
    tampered.ciphertext[0] ^= 1;
    assert!(open_sealed_payload(&backend, &tampered, b"wallet-backup-v1").is_err());
}

fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk_files(&path));
        } else {
            files.push(path);
        }
    }
    files
}
