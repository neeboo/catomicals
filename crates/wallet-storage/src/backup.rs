use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::Path,
    time::Duration,
};

use catomicals_secret_store::{
    BackupDek, SealedPayload, SecretBackend, SecretBackendError, SecretRef, open_sealed_payload,
    require_backend, seal_payload,
};
use rusqlite::{Connection, MAIN_DB, OptionalExtension, backup::Backup, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{CURRENT_SCHEMA_VERSION, Result, WalletStorage, migrations};

const FORMAT_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const DATABASE_FILE: &str = "wallet.sqlite3.enc";
const ARTIFACT_MAGIC: &[u8; 8] = b"CATBKP01";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("no secret backend is configured")]
    SecretBackendUnavailable,
    #[error("the configured secret backend rejected the backup operation")]
    SecretBackendFailure,
    #[error("backup bundle already exists")]
    BundleAlreadyExists,
    #[error("backup manifest is missing, malformed, or unsupported")]
    InvalidManifest,
    #[error("backup artifact is missing, malformed, or too large")]
    InvalidArtifact,
    #[error("backup artifact checksum does not match its manifest")]
    ArtifactChecksumMismatch,
    #[error("decrypted wallet database checksum does not match its manifest")]
    DatabaseChecksumMismatch,
    #[error("backup wallet does not match the requested wallet")]
    WalletMismatch,
    #[error("backup recovery epoch {backup} is older than current epoch {current}")]
    StaleRecoveryEpoch { current: u64, backup: u64 },
    #[error("backup database failed SQLite integrity or schema validation")]
    InvalidDatabase,
    #[error("wallet recovery epoch overflow")]
    RecoveryEpochOverflow,
    #[error("backup I/O failed")]
    Io(#[source] std::io::Error),
    #[error("backup cutover failed; wallet remains fail-closed")]
    CutoverFailed,
}

impl From<SecretBackendError> for BackupError {
    fn from(error: SecretBackendError) -> Self {
        match error {
            SecretBackendError::BackendUnavailable => Self::SecretBackendUnavailable,
            _ => Self::SecretBackendFailure,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format_version: u32,
    pub schema_version: i32,
    pub wallet_id: Uuid,
    pub recovery_epoch: u64,
    pub created_at: i64,
    pub secret_backend: String,
    pub dek_ref: SecretRef<BackupDek>,
    pub database_file: String,
    pub database_sha256: String,
    pub artifact_sha256: String,
}

impl WalletStorage {
    pub fn export_encrypted_backup(
        &mut self,
        destination: impl AsRef<Path>,
        backend: Option<&dyn SecretBackend>,
        now: i64,
    ) -> Result<BackupManifest> {
        let backend = require_backend(backend).map_err(BackupError::from)?;
        let destination = destination.as_ref();
        create_private_bundle(destination)?;
        let metadata = self.wallet_metadata()?;
        let schema_version = self.schema_version()?;
        if schema_version != CURRENT_SCHEMA_VERSION {
            cleanup_incomplete_bundle(destination);
            return Err(BackupError::InvalidDatabase.into());
        }

        if let Err(error) = self.begin_snapshot(now) {
            cleanup_incomplete_bundle(destination);
            return Err(error);
        }
        let snapshot_result = consistent_snapshot_bytes(&self.connection);
        let finish_result = self.finish_snapshot(now);
        if let Err(error) = finish_result {
            cleanup_incomplete_bundle(destination);
            return Err(error);
        }
        let plaintext = snapshot_result.inspect_err(|_| {
            cleanup_incomplete_bundle(destination);
        })?;

        let result = (|| {
            let database_sha256 = sha256_hex(&plaintext);
            let provisional = ManifestCore {
                format_version: FORMAT_VERSION,
                schema_version,
                wallet_id: metadata.wallet_id,
                recovery_epoch: metadata.epoch,
                created_at: now,
                secret_backend: backend.backend_name(),
                database_file: DATABASE_FILE,
                database_sha256: &database_sha256,
            };
            let domain =
                serde_json::to_vec(&provisional).map_err(|_| BackupError::InvalidManifest)?;
            let sealed = seal_payload::<BackupDek>(backend, &plaintext, &domain)?;
            let artifact = encode_artifact(sealed.nonce, &sealed.ciphertext);
            let artifact_sha256 = sha256_hex(&artifact);
            let manifest = BackupManifest {
                format_version: FORMAT_VERSION,
                schema_version,
                wallet_id: metadata.wallet_id,
                recovery_epoch: metadata.epoch,
                created_at: now,
                secret_backend: backend.backend_name().to_owned(),
                dek_ref: sealed.key_ref,
                database_file: DATABASE_FILE.to_owned(),
                database_sha256,
                artifact_sha256,
            };
            let write_result = (|| {
                write_private_atomic(&destination.join(DATABASE_FILE), &artifact)?;
                let encoded_manifest = serde_json::to_vec_pretty(&manifest)
                    .map_err(|_| BackupError::InvalidManifest)?;
                write_private_atomic(&destination.join(MANIFEST_FILE), &encoded_manifest)?;
                sync_directory(destination)
            })();
            if let Err(error) = write_result {
                let _ = backend.delete_raw(manifest.dek_ref.handle());
                return Err(error);
            }
            Ok(manifest)
        })();
        if result.is_err() {
            cleanup_incomplete_bundle(destination);
        }
        result.map_err(Into::into)
    }

    pub fn verify_encrypted_backup(
        bundle: impl AsRef<Path>,
        backend: Option<&dyn SecretBackend>,
    ) -> Result<BackupManifest> {
        let backend = require_backend(backend).map_err(BackupError::from)?;
        let bundle = bundle.as_ref();
        let (manifest, plaintext) = decrypt_and_verify_bundle(bundle, backend)?;
        validate_snapshot_database_bytes(&plaintext, &manifest)?;
        Ok(manifest)
    }

    pub fn restore_encrypted_backup(
        database_path: impl AsRef<Path>,
        bundle: impl AsRef<Path>,
        backend: Option<&dyn SecretBackend>,
        expected_wallet_id: Uuid,
        now: i64,
    ) -> Result<Self> {
        let backend = require_backend(backend).map_err(BackupError::from)?;
        let database_path = database_path.as_ref();
        let bundle = bundle.as_ref();
        let (manifest, plaintext) = decrypt_and_verify_bundle(bundle, backend)?;
        if manifest.wallet_id != expected_wallet_id {
            return Err(BackupError::WalletMismatch.into());
        }
        let mut current = Self::open(database_path)?;
        let current_metadata = current.wallet_metadata()?;
        if current_metadata.wallet_id != expected_wallet_id {
            return Err(BackupError::WalletMismatch.into());
        }
        if manifest.recovery_epoch < current_metadata.epoch {
            return Err(BackupError::StaleRecoveryEpoch {
                current: current_metadata.epoch,
                backup: manifest.recovery_epoch,
            }
            .into());
        }
        let next_epoch = current_metadata
            .epoch
            .max(manifest.recovery_epoch)
            .checked_add(1)
            .ok_or(BackupError::RecoveryEpochOverflow)?;
        let parent = database_path.parent().ok_or(BackupError::CutoverFailed)?;
        let prepared = parent.join(format!(".wallet-restore-{}.sqlite3", Uuid::new_v4()));
        write_private_atomic(&prepared, &plaintext)?;
        validate_snapshot_database_bytes(&plaintext, &manifest)?;
        prepare_recovering_database(&prepared, expected_wallet_id, next_epoch, now)?;

        current.begin_restore_precheck(now)?;
        let checkpoint = current
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| BackupError::CutoverFailed)?;
        if checkpoint.0 != 0 || checkpoint.1 != checkpoint.2 {
            return Err(BackupError::CutoverFailed.into());
        }
        drop(current);
        if remove_sqlite_sidecars(database_path).is_err() {
            let _ = fs::remove_file(&prepared);
            return Err(BackupError::CutoverFailed.into());
        }

        let rollback = parent.join(format!(".wallet-pre-restore-{}.sqlite3", Uuid::new_v4()));
        if fs::rename(database_path, &rollback).is_err() {
            let _ = fs::remove_file(&prepared);
            return Err(BackupError::CutoverFailed.into());
        }
        if fs::rename(&prepared, database_path).is_err() {
            let _ = fs::rename(&rollback, database_path);
            return Err(BackupError::CutoverFailed.into());
        }
        sync_directory(parent)?;
        match Self::open(database_path) {
            Ok(storage) => {
                fs::remove_file(&rollback).map_err(BackupError::Io)?;
                sync_directory(parent)?;
                Ok(storage)
            }
            Err(error) => {
                let failed =
                    parent.join(format!(".wallet-failed-restore-{}.sqlite3", Uuid::new_v4()));
                if fs::rename(database_path, &failed).is_ok() {
                    let _ = remove_sqlite_sidecars(database_path);
                    if fs::rename(&rollback, database_path).is_ok() {
                        let _ = fs::remove_file(failed);
                    }
                }
                let _ = sync_directory(parent);
                Err(error)
            }
        }
    }
}

#[derive(Serialize)]
struct ManifestCore<'a> {
    format_version: u32,
    schema_version: i32,
    wallet_id: Uuid,
    recovery_epoch: u64,
    created_at: i64,
    secret_backend: &'a str,
    database_file: &'a str,
    database_sha256: &'a str,
}

fn decrypt_and_verify_bundle(
    bundle: &Path,
    backend: &dyn SecretBackend,
) -> std::result::Result<(BackupManifest, Vec<u8>), BackupError> {
    let encoded_manifest = read_bounded(&bundle.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)
        .map_err(|_| BackupError::InvalidManifest)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&encoded_manifest).map_err(|_| BackupError::InvalidManifest)?;
    validate_manifest(&manifest, backend)?;
    let artifact = read_bounded(&bundle.join(DATABASE_FILE), MAX_BACKUP_BYTES)
        .map_err(|_| BackupError::InvalidArtifact)?;
    if sha256_hex(&artifact) != manifest.artifact_sha256 {
        return Err(BackupError::ArtifactChecksumMismatch);
    }
    let (nonce, ciphertext) = decode_artifact(&artifact)?;
    let core = ManifestCore {
        format_version: manifest.format_version,
        schema_version: manifest.schema_version,
        wallet_id: manifest.wallet_id,
        recovery_epoch: manifest.recovery_epoch,
        created_at: manifest.created_at,
        secret_backend: &manifest.secret_backend,
        database_file: &manifest.database_file,
        database_sha256: &manifest.database_sha256,
    };
    let domain = serde_json::to_vec(&core).map_err(|_| BackupError::InvalidManifest)?;
    let sealed = SealedPayload {
        key_ref: manifest.dek_ref.clone(),
        nonce,
        ciphertext,
    };
    let plaintext = open_sealed_payload(backend, &sealed, &domain)?;
    if sha256_hex(&plaintext) != manifest.database_sha256 {
        return Err(BackupError::DatabaseChecksumMismatch);
    }
    Ok((manifest, plaintext))
}

fn validate_manifest(
    manifest: &BackupManifest,
    backend: &dyn SecretBackend,
) -> std::result::Result<(), BackupError> {
    if manifest.format_version != FORMAT_VERSION
        || manifest.schema_version != CURRENT_SCHEMA_VERSION
        || manifest.database_file != DATABASE_FILE
        || manifest.secret_backend != backend.backend_name()
        || manifest.database_sha256.len() != 64
        || manifest.artifact_sha256.len() != 64
    {
        return Err(BackupError::InvalidManifest);
    }
    Ok(())
}

fn validate_snapshot_database_bytes(
    bytes: &[u8],
    manifest: &BackupManifest,
) -> std::result::Result<(), BackupError> {
    let mut connection = Connection::open_in_memory().map_err(|_| BackupError::InvalidDatabase)?;
    connection
        .deserialize_read_exact(MAIN_DB, Cursor::new(bytes), bytes.len(), false)
        .map_err(|_| BackupError::InvalidDatabase)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| BackupError::InvalidDatabase)?;
    if integrity != "ok" || migrations::validate_existing(&connection).is_err() {
        return Err(BackupError::InvalidDatabase);
    }
    let stored = connection
        .query_row(
            "SELECT wallet_id, epoch FROM wallet_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
        )
        .optional()
        .map_err(|_| BackupError::InvalidDatabase)?
        .ok_or(BackupError::InvalidDatabase)?;
    let wallet_id = Uuid::parse_str(&stored.0).map_err(|_| BackupError::InvalidDatabase)?;
    if wallet_id != manifest.wallet_id || stored.1 != manifest.recovery_epoch {
        return Err(BackupError::InvalidDatabase);
    }
    Ok(())
}

fn prepare_recovering_database(
    path: &Path,
    wallet_id: Uuid,
    recovery_epoch: u64,
    now: i64,
) -> std::result::Result<(), BackupError> {
    let mut connection = Connection::open(path).map_err(|_| BackupError::InvalidDatabase)?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| BackupError::InvalidDatabase)?;
    let transaction = connection
        .transaction()
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "UPDATE wallet_metadata
             SET epoch = ?1, restore_state = 'recovering', updated_at = ?2
             WHERE singleton = 1 AND wallet_id = ?3",
            params![recovery_epoch, now, wallet_id.to_string()],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "UPDATE transaction_intents SET status = 'invalidated', updated_at = ?1
             WHERE status IN ('pending', 'approved', 'signing')",
            [now],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "UPDATE approval_ceremonies SET invalidated_at = ?1
             WHERE completed_at IS NULL AND invalidated_at IS NULL",
            [now],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "UPDATE one_time_authorizations SET invalidated_at = ?1
             WHERE consumed_at IS NULL AND invalidated_at IS NULL",
            [now],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "UPDATE nonce_claims SET invalidated_at = ?1 WHERE invalidated_at IS NULL",
            [now],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .execute(
            "DELETE FROM intent_materials WHERE kind = 'node_snapshot'",
            [],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    let payload = serde_json::json!({
        "actor_ref": "system",
        "component_version": env!("CARGO_PKG_VERSION"),
        "schema_version": CURRENT_SCHEMA_VERSION,
        "wallet_id": wallet_id,
        "recovery_epoch": recovery_epoch,
    });
    transaction
        .execute(
            "INSERT INTO audit_events
             (wallet_id, epoch, event_type, subject_id, payload_json, created_at)
             VALUES (?1, ?2, 'restore.recovering', NULL, ?3, ?4)",
            params![
                wallet_id.to_string(),
                recovery_epoch,
                payload.to_string(),
                now
            ],
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    transaction
        .commit()
        .map_err(|_| BackupError::InvalidDatabase)?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| BackupError::InvalidDatabase)?;
    Ok(())
}

fn encode_artifact(nonce: [u8; 24], ciphertext: &[u8]) -> Vec<u8> {
    let mut artifact = Vec::with_capacity(ARTIFACT_MAGIC.len() + nonce.len() + ciphertext.len());
    artifact.extend_from_slice(ARTIFACT_MAGIC);
    artifact.extend_from_slice(&nonce);
    artifact.extend_from_slice(ciphertext);
    artifact
}

fn decode_artifact(artifact: &[u8]) -> std::result::Result<([u8; 24], Vec<u8>), BackupError> {
    if artifact.len() <= ARTIFACT_MAGIC.len() + 24
        || &artifact[..ARTIFACT_MAGIC.len()] != ARTIFACT_MAGIC
    {
        return Err(BackupError::InvalidArtifact);
    }
    let nonce = artifact[ARTIFACT_MAGIC.len()..ARTIFACT_MAGIC.len() + 24]
        .try_into()
        .map_err(|_| BackupError::InvalidArtifact)?;
    Ok((nonce, artifact[ARTIFACT_MAGIC.len() + 24..].to_vec()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds configured backup limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds configured backup limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn create_private_bundle(path: &Path) -> std::result::Result<(), BackupError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            BackupError::BundleAlreadyExists
        } else {
            BackupError::Io(error)
        }
    })
}

#[cfg(not(unix))]
fn create_private_bundle(path: &Path) -> std::result::Result<(), BackupError> {
    fs::create_dir(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            BackupError::BundleAlreadyExists
        } else {
            BackupError::Io(error)
        }
    })
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::result::Result<File, BackupError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(BackupError::Io)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::result::Result<File, BackupError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(BackupError::Io)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::result::Result<(), BackupError> {
    let parent = path.parent().ok_or(BackupError::CutoverFailed)?;
    let temporary = parent.join(format!(".backup-write-{}.tmp", Uuid::new_v4()));
    let mut file = create_private_file(&temporary)?;
    let result = (|| {
        file.write_all(bytes).map_err(BackupError::Io)?;
        file.sync_all().map_err(BackupError::Io)?;
        fs::rename(&temporary, path).map_err(BackupError::Io)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn cleanup_incomplete_bundle(bundle: &Path) {
    let _ = fs::remove_file(bundle.join(DATABASE_FILE));
    let _ = fs::remove_file(bundle.join(MANIFEST_FILE));
    let _ = fs::remove_dir(bundle);
}

fn consistent_snapshot_bytes(source: &Connection) -> std::result::Result<Vec<u8>, BackupError> {
    let mut snapshot = Connection::open_in_memory().map_err(|_| BackupError::InvalidDatabase)?;
    {
        let backup =
            Backup::new(source, &mut snapshot).map_err(|_| BackupError::InvalidDatabase)?;
        backup
            .run_to_completion(128, Duration::from_millis(1), None)
            .map_err(|_| BackupError::InvalidDatabase)?;
    }
    snapshot
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| BackupError::InvalidDatabase)?;
    let serialized = snapshot
        .serialize(MAIN_DB)
        .map_err(|_| BackupError::InvalidDatabase)?;
    if serialized.len() as u64 > MAX_BACKUP_BYTES || serialized.len() < 100 {
        return Err(BackupError::InvalidDatabase);
    }
    let mut bytes = serialized.to_vec();
    if &bytes[..16] != b"SQLite format 3\0" {
        return Err(BackupError::InvalidDatabase);
    }
    // SQLite's online backup copied a complete page set into an in-memory
    // database, but the source WAL mode flag remains in header bytes 18-19.
    // No WAL file exists or is needed for this snapshot, so normalize the
    // serialized artifact to rollback-journal mode before encrypting it.
    bytes[18] = 1;
    bytes[19] = 1;
    Ok(bytes)
}

fn remove_sqlite_sidecars(database: &Path) -> std::io::Result<()> {
    if let Some(name) = database.file_name().and_then(|name| name.to_str()) {
        for suffix in ["-wal", "-shm"] {
            match fs::remove_file(database.with_file_name(format!("{name}{suffix}"))) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::result::Result<(), BackupError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(BackupError::Io)
}
