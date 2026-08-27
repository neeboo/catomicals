use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::fs::OpenOptions;

use catomicals_secret_store::{
    BackupDek, SecretBackend, SecretBackendError, SecretRef, open_sealed_payload_parts,
    require_backend, seal_payload,
};
use rusqlite::{Connection, MAIN_DB, OptionalExtension, backup::Backup};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{CURRENT_SCHEMA_VERSION, Result, WalletStorage, migrations};

const FORMAT_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const DATABASE_FILE: &str = "wallet.sqlite3.enc";
const ARTIFACT_MAGIC: &[u8; 8] = b"CATBKP01";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
// Snapshot, serialization, and AEAD buffers can briefly coexist. Keep each
// database buffer under this hard ceiling and avoid constructing a third
// full-size artifact buffer when writing or decoding the envelope.
pub(crate) const MAX_BACKUP_DATABASE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BACKUP_ARTIFACT_BYTES: u64 =
    MAX_BACKUP_DATABASE_BYTES + ARTIFACT_MAGIC.len() as u64 + 24 + 16;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("encrypted wallet backup requires Unix permission semantics")]
    UnsupportedPlatform,
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
    #[error("wallet database exceeds the {max} byte backup limit (actual: {size})")]
    DatabaseTooLarge { size: u64, max: u64 },
    #[error("backup I/O failed")]
    Io(#[source] std::io::Error),
    #[error("backup cutover failed; wallet remains fail-closed")]
    CutoverFailed,
}

impl From<SecretBackendError> for BackupError {
    fn from(error: SecretBackendError) -> Self {
        match error {
            SecretBackendError::BackendUnavailable => Self::SecretBackendUnavailable,
            SecretBackendError::UnsupportedPlatform => Self::UnsupportedPlatform,
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
        ensure_supported_platform()?;
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
        let plaintext = Zeroizing::new(snapshot_result.inspect_err(|_| {
            cleanup_incomplete_bundle(destination);
        })?);

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
            let artifact_sha256 = match write_artifact_atomic(
                &destination.join(DATABASE_FILE),
                sealed.nonce,
                &sealed.ciphertext,
            ) {
                Ok(checksum) => checksum,
                Err(error) => {
                    let _ = backend.delete_raw(sealed.key_ref.handle());
                    return Err(error);
                }
            };
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
        ensure_supported_platform()?;
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
        Self::restore_encrypted_backup_with_hook(
            database_path,
            bundle,
            backend,
            expected_wallet_id,
            now,
            |_| Ok(()),
        )
    }

    fn restore_encrypted_backup_with_hook(
        database_path: impl AsRef<Path>,
        bundle: impl AsRef<Path>,
        backend: Option<&dyn SecretBackend>,
        expected_wallet_id: Uuid,
        now: i64,
        mut hook: impl FnMut(RestoreStage) -> std::result::Result<(), BackupError>,
    ) -> Result<Self> {
        ensure_supported_platform()?;
        let backend = require_backend(backend).map_err(BackupError::from)?;
        let database_path = database_path.as_ref();
        let bundle = bundle.as_ref();
        let (manifest, plaintext) = decrypt_and_verify_bundle(bundle, backend)?;
        if manifest.wallet_id != expected_wallet_id {
            return Err(BackupError::WalletMismatch.into());
        }
        validate_snapshot_database_bytes(&plaintext, &manifest)?;

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
        let parent = database_path.parent().ok_or(BackupError::CutoverFailed)?;
        let mut prepared = PreparedDatabaseGuard::new(parent)?;
        prepared.write(&plaintext)?;
        hook(RestoreStage::PreparedWritten)?;

        {
            let mut staged = Self::open(prepared.path())?;
            staged.finish_snapshot(now)?;
            staged.begin_restore_precheck(now)?;
            let next_epoch = staged.cutover_restore(now)?;
            if next_epoch <= current_metadata.epoch {
                return Err(BackupError::StaleRecoveryEpoch {
                    current: current_metadata.epoch,
                    backup: manifest.recovery_epoch,
                }
                .into());
            }
            staged.begin_recovering(now)?;
            checkpoint_and_use_delete_journal(&staged.connection)?;
        }
        prepared.remove_sidecars_and_lock()?;
        hook(RestoreStage::PreparedRecovering)?;

        current.begin_restore_precheck(now)?;
        hook(RestoreStage::LivePrecheck)?;
        checkpoint_wal(&current.connection)?;
        let owner_lock = current.into_owner_lock();
        remove_sqlite_sidecars(database_path).map_err(|_| BackupError::CutoverFailed)?;

        let mut cutover = CutoverGuard::begin(database_path)?;
        hook(RestoreStage::OriginalRenamed)?;
        cutover.install(prepared.path())?;
        prepared.disarm();
        hook(RestoreStage::Installed)?;
        sync_directory(parent)?;
        hook(RestoreStage::BeforeReopen)?;

        let (connection, invalidated) = Self::open_database_connection(database_path)?;
        cutover.commit()?;
        Ok(Self::from_retained_owner_lock(
            connection,
            owner_lock,
            invalidated,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RestoreStage {
    PreparedWritten,
    PreparedRecovering,
    LivePrecheck,
    OriginalRenamed,
    Installed,
    BeforeReopen,
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
) -> std::result::Result<(BackupManifest, Zeroizing<Vec<u8>>), BackupError> {
    let encoded_manifest = read_bounded(&bundle.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)
        .map_err(|_| BackupError::InvalidManifest)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&encoded_manifest).map_err(|_| BackupError::InvalidManifest)?;
    validate_manifest(&manifest, backend)?;
    let artifact = read_bounded(&bundle.join(DATABASE_FILE), MAX_BACKUP_ARTIFACT_BYTES)
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
    let plaintext = Zeroizing::new(open_sealed_payload_parts(
        backend,
        &manifest.dek_ref,
        nonce,
        ciphertext,
        &domain,
    )?);
    validate_database_size(plaintext.len())?;
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

fn decode_artifact(artifact: &[u8]) -> std::result::Result<([u8; 24], &[u8]), BackupError> {
    if artifact.len() <= ARTIFACT_MAGIC.len() + 24
        || &artifact[..ARTIFACT_MAGIC.len()] != ARTIFACT_MAGIC
    {
        return Err(BackupError::InvalidArtifact);
    }
    let nonce = artifact[ARTIFACT_MAGIC.len()..ARTIFACT_MAGIC.len() + 24]
        .try_into()
        .map_err(|_| BackupError::InvalidArtifact)?;
    Ok((nonce, &artifact[ARTIFACT_MAGIC.len() + 24..]))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_database_size(size: usize) -> std::result::Result<(), BackupError> {
    let size = u64::try_from(size).map_err(|_| BackupError::DatabaseTooLarge {
        size: u64::MAX,
        max: MAX_BACKUP_DATABASE_BYTES,
    })?;
    if size > MAX_BACKUP_DATABASE_BYTES {
        return Err(BackupError::DatabaseTooLarge {
            size,
            max: MAX_BACKUP_DATABASE_BYTES,
        });
    }
    Ok(())
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
fn create_private_bundle(_path: &Path) -> std::result::Result<(), BackupError> {
    Err(BackupError::UnsupportedPlatform)
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
fn create_private_file(_path: &Path) -> std::result::Result<File, BackupError> {
    Err(BackupError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_supported_platform() -> std::result::Result<(), BackupError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_supported_platform() -> std::result::Result<(), BackupError> {
    Err(BackupError::UnsupportedPlatform)
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

fn write_artifact_atomic(
    path: &Path,
    nonce: [u8; 24],
    ciphertext: &[u8],
) -> std::result::Result<String, BackupError> {
    let parent = path.parent().ok_or(BackupError::CutoverFailed)?;
    let temporary = parent.join(format!(".backup-write-{}.tmp", Uuid::new_v4()));
    let mut file = create_private_file(&temporary)?;
    let result = (|| {
        let mut digest = Sha256::new();
        for bytes in [ARTIFACT_MAGIC.as_slice(), nonce.as_slice(), ciphertext] {
            file.write_all(bytes).map_err(BackupError::Io)?;
            digest.update(bytes);
        }
        file.sync_all().map_err(BackupError::Io)?;
        fs::rename(&temporary, path).map_err(BackupError::Io)?;
        sync_directory(parent)?;
        Ok(hex::encode(digest.finalize()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct PreparedDatabaseGuard {
    path: PathBuf,
    armed: bool,
}

impl PreparedDatabaseGuard {
    fn new(parent: &Path) -> std::result::Result<Self, BackupError> {
        if !parent.is_dir() {
            return Err(BackupError::CutoverFailed);
        }
        Ok(Self {
            path: parent.join(format!(".wallet-restore-{}.sqlite3", Uuid::new_v4())),
            armed: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, plaintext: &[u8]) -> std::result::Result<(), BackupError> {
        let mut file = create_private_file(&self.path)?;
        file.write_all(plaintext).map_err(BackupError::Io)?;
        file.sync_all().map_err(BackupError::Io)
    }

    fn remove_sidecars_and_lock(&self) -> std::result::Result<(), BackupError> {
        remove_sqlite_sidecars(&self.path).map_err(BackupError::Io)?;
        remove_if_exists(&owner_lock_path(&self.path)).map_err(BackupError::Io)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedDatabaseGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_sqlite_sidecars(&self.path);
            let _ = fs::remove_file(&self.path);
            let _ = remove_if_exists(&owner_lock_path(&self.path));
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

struct CutoverGuard<'a> {
    database: &'a Path,
    rollback: PathBuf,
    parent: &'a Path,
    active: bool,
}

impl<'a> CutoverGuard<'a> {
    fn begin(database: &'a Path) -> std::result::Result<Self, BackupError> {
        let parent = database.parent().ok_or(BackupError::CutoverFailed)?;
        let rollback = parent.join(format!(".wallet-pre-restore-{}.sqlite3", Uuid::new_v4()));
        fs::rename(database, &rollback).map_err(|_| BackupError::CutoverFailed)?;
        Ok(Self {
            database,
            rollback,
            parent,
            active: true,
        })
    }

    fn install(&self, prepared: &Path) -> std::result::Result<(), BackupError> {
        fs::rename(prepared, self.database).map_err(|_| BackupError::CutoverFailed)
    }

    fn commit(&mut self) -> std::result::Result<(), BackupError> {
        fs::remove_file(&self.rollback).map_err(BackupError::Io)?;
        self.active = false;
        sync_directory(self.parent)
    }
}

impl Drop for CutoverGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = remove_sqlite_sidecars(self.database);
        let _ = remove_if_exists(self.database);
        let _ = fs::rename(&self.rollback, self.database);
        let _ = sync_directory(self.parent);
    }
}

fn checkpoint_wal(connection: &Connection) -> std::result::Result<(), BackupError> {
    let checkpoint = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| BackupError::CutoverFailed)?;
    if checkpoint.0 != 0 || checkpoint.1 != checkpoint.2 {
        return Err(BackupError::CutoverFailed);
    }
    Ok(())
}

fn checkpoint_and_use_delete_journal(
    connection: &Connection,
) -> std::result::Result<(), BackupError> {
    checkpoint_wal(connection)?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| BackupError::CutoverFailed)
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn owner_lock_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".owner.lock");
    PathBuf::from(path)
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
    validate_database_size(serialized.len())?;
    if serialized.len() < 100 {
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

#[cfg(all(test, unix))]
mod tests {
    use catomicals_secret_store::{FileSecretBackend, RuntimeProfile};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn every_restore_failure_stage_removes_plaintext_restore_artifacts() {
        for fail_at in [
            RestoreStage::PreparedWritten,
            RestoreStage::PreparedRecovering,
            RestoreStage::LivePrecheck,
            RestoreStage::OriginalRenamed,
            RestoreStage::Installed,
            RestoreStage::BeforeReopen,
        ] {
            let directory = tempdir().unwrap();
            let database = directory.path().join("wallet.sqlite3");
            let bundle = directory.path().join("backup");
            let backend = FileSecretBackend::open(
                directory.path().join("secrets"),
                RuntimeProfile::Development,
            )
            .unwrap();
            let wallet_id = Uuid::from_bytes([fail_at as u8 + 1; 16]);
            let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
            storage
                .export_encrypted_backup(&bundle, Some(&backend), 2)
                .unwrap();
            drop(storage);

            let mut observed = false;
            let result = WalletStorage::restore_encrypted_backup_with_hook(
                &database,
                &bundle,
                Some(&backend),
                wallet_id,
                3,
                |stage| {
                    if stage == fail_at {
                        observed = true;
                        return Err(BackupError::CutoverFailed);
                    }
                    Ok(())
                },
            );
            assert!(observed, "restore stage was not reached: {fail_at:?}");
            assert!(result.is_err());
            assert!(database.is_file());
            let reopened = WalletStorage::open(&database).unwrap();
            assert_eq!(reopened.wallet_metadata().unwrap().wallet_id, wallet_id);
            drop(reopened);
            assert_no_restore_artifacts(directory.path());
        }
    }

    #[test]
    fn live_owner_lock_remains_held_after_install_and_before_reopen() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("wallet.sqlite3");
        let bundle = directory.path().join("backup");
        let backend = FileSecretBackend::open(
            directory.path().join("secrets"),
            RuntimeProfile::Development,
        )
        .unwrap();
        let wallet_id = Uuid::from_bytes([0xb1; 16]);
        let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
        storage
            .export_encrypted_backup(&bundle, Some(&backend), 2)
            .unwrap();
        drop(storage);

        let result = WalletStorage::restore_encrypted_backup_with_hook(
            &database,
            &bundle,
            Some(&backend),
            wallet_id,
            3,
            |stage| {
                if stage == RestoreStage::BeforeReopen {
                    assert!(matches!(
                        WalletStorage::open(&database),
                        Err(crate::StorageError::WriterAlreadyActive)
                    ));
                    return Err(BackupError::CutoverFailed);
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_no_restore_artifacts(directory.path());
    }

    #[test]
    fn failed_reopen_removes_installed_plaintext_and_restores_the_original_database() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("wallet.sqlite3");
        let bundle = directory.path().join("backup");
        let backend = FileSecretBackend::open(
            directory.path().join("secrets"),
            RuntimeProfile::Development,
        )
        .unwrap();
        let wallet_id = Uuid::from_bytes([0xb2; 16]);
        let mut storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
        storage
            .export_encrypted_backup(&bundle, Some(&backend), 2)
            .unwrap();
        drop(storage);

        let result = WalletStorage::restore_encrypted_backup_with_hook(
            &database,
            &bundle,
            Some(&backend),
            wallet_id,
            3,
            |stage| {
                if stage == RestoreStage::BeforeReopen {
                    fs::write(&database, b"corrupt staged database").unwrap();
                }
                Ok(())
            },
        );

        assert!(result.is_err());
        let reopened = WalletStorage::open(&database).unwrap();
        assert_eq!(reopened.wallet_metadata().unwrap().wallet_id, wallet_id);
        drop(reopened);
        assert_no_restore_artifacts(directory.path());
    }

    #[test]
    fn database_size_limit_is_strict_without_allocating_the_limit() {
        assert!(validate_database_size(MAX_BACKUP_DATABASE_BYTES as usize).is_ok());
        assert!(matches!(
            validate_database_size(MAX_BACKUP_DATABASE_BYTES as usize + 1),
            Err(BackupError::DatabaseTooLarge { .. })
        ));
    }

    fn assert_no_restore_artifacts(directory: &Path) {
        for entry in fs::read_dir(directory).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".wallet-restore-")
                    && !name.starts_with(".wallet-pre-restore-")
                    && !name.starts_with(".wallet-failed-restore-"),
                "plaintext restore artifact leaked: {name}"
            );
        }
    }
}
