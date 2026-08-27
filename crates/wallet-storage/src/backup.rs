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
const CUTOVER_JOURNAL_VERSION: u32 = 1;
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
    #[error("interrupted wallet restore journal is invalid or inconsistent")]
    InvalidCutoverJournal,
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
        let recovery_epoch = manifest
            .recovery_epoch
            .checked_add(1)
            .ok_or(BackupError::CutoverFailed)?;
        let parent = database_path.parent().ok_or(BackupError::CutoverFailed)?;
        let prepared_path = parent.join(format!(
            "{}{}.sqlite3",
            restore_artifact_prefix(database_path),
            Uuid::new_v4()
        ));
        let rollback_path = parent.join(format!(
            "{}{}.sqlite3",
            rollback_artifact_prefix(database_path),
            Uuid::new_v4()
        ));
        let mut journal = CutoverJournalGuard::create(
            database_path,
            CutoverJournal {
                version: CUTOVER_JOURNAL_VERSION,
                recovery_id: Uuid::new_v4(),
                wallet_id: expected_wallet_id,
                recovery_epoch,
                occurred_at: now,
                phase: CutoverPhase::Preparing,
                prepared_file: file_name_string(&prepared_path)?,
                rollback_file: file_name_string(&rollback_path)?,
            },
        )?;
        let mut prepared = PreparedDatabaseGuard::new(prepared_path)?;
        prepared.write(&plaintext)?;
        hook(RestoreStage::PreparedWritten)?;

        {
            let mut staged = Self::open_staged_database(prepared.path())?;
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
        journal.advance(CutoverPhase::Ready)?;
        hook(RestoreStage::PreparedRecovering)?;

        current.begin_restore_precheck(now)?;
        hook(RestoreStage::LivePrecheck)?;
        checkpoint_wal(&current.connection)?;
        let owner_lock = current.into_owner_lock();
        remove_sqlite_sidecars(database_path).map_err(|_| BackupError::CutoverFailed)?;

        journal.preserve_for_cutover();
        let mut cutover =
            CutoverGuard::begin(database_path, rollback_path, journal.path().to_path_buf())?;
        journal.advance(CutoverPhase::OriginalMoved)?;
        hook(RestoreStage::OriginalRenamed)?;
        cutover.install(prepared.path())?;
        prepared.disarm();
        sync_directory(parent)?;
        journal.advance(CutoverPhase::Installed)?;
        hook(RestoreStage::Installed)?;
        hook(RestoreStage::BeforeReopen)?;

        let (connection, invalidated) = Self::open_database_connection(database_path)?;
        cutover.commit()?;
        journal.finish()?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CutoverPhase {
    Preparing,
    Ready,
    OriginalMoved,
    Installed,
    RecoveredRolledBack,
    RecoveredContinued,
    RecoveredCleaned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CutoverJournal {
    version: u32,
    recovery_id: Uuid,
    wallet_id: Uuid,
    recovery_epoch: u64,
    occurred_at: i64,
    phase: CutoverPhase,
    prepared_file: String,
    rollback_file: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashRecoveryKind {
    RolledBack,
    Continued,
    CleanedOrphan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CrashRecoveryOutcome {
    kind: CrashRecoveryKind,
    recovery_id: Option<Uuid>,
    occurred_at: i64,
}

impl CrashRecoveryOutcome {
    pub(crate) fn event_type(self) -> &'static str {
        match self.kind {
            CrashRecoveryKind::RolledBack => "restore.crash_rolled_back",
            CrashRecoveryKind::Continued => "restore.crash_continued",
            CrashRecoveryKind::CleanedOrphan => "restore.orphan_cleaned",
        }
    }

    pub(crate) fn occurred_at(self) -> i64 {
        self.occurred_at
    }

    pub(crate) fn recovery_id(self) -> Option<Uuid> {
        self.recovery_id
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
    fn new(path: PathBuf) -> std::result::Result<Self, BackupError> {
        let parent = path.parent().ok_or(BackupError::CutoverFailed)?;
        if !parent.is_dir() {
            return Err(BackupError::CutoverFailed);
        }
        Ok(Self { path, armed: true })
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

struct CutoverJournalGuard {
    path: PathBuf,
    journal: CutoverJournal,
    cleanup_on_drop: bool,
}

impl CutoverJournalGuard {
    fn create(database: &Path, journal: CutoverJournal) -> std::result::Result<Self, BackupError> {
        let path = cutover_journal_path(database);
        if path.exists() {
            return Err(BackupError::InvalidCutoverJournal);
        }
        write_cutover_journal(&path, &journal)?;
        Ok(Self {
            path,
            journal,
            cleanup_on_drop: true,
        })
    }

    fn advance(&mut self, phase: CutoverPhase) -> std::result::Result<(), BackupError> {
        self.journal.phase = phase;
        write_cutover_journal(&self.path, &self.journal)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn preserve_for_cutover(&mut self) {
        self.cleanup_on_drop = false;
    }

    fn finish(&mut self) -> std::result::Result<(), BackupError> {
        remove_if_exists(&self.path).map_err(BackupError::Io)?;
        self.cleanup_on_drop = false;
        sync_directory(self.path.parent().ok_or(BackupError::CutoverFailed)?)
    }
}

impl Drop for CutoverJournalGuard {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = remove_if_exists(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

pub(crate) fn recover_interrupted_cutover(
    database: &Path,
) -> std::result::Result<Option<CrashRecoveryOutcome>, BackupError> {
    ensure_supported_platform()?;
    let journal_path = cutover_journal_path(database);
    if !journal_path.exists() {
        return cleanup_orphan_restore_files(database);
    }
    ensure_private_existing_file(&journal_path)?;
    let encoded = read_bounded(&journal_path, MAX_MANIFEST_BYTES)
        .map_err(|_| BackupError::InvalidCutoverJournal)?;
    let mut journal: CutoverJournal =
        serde_json::from_slice(&encoded).map_err(|_| BackupError::InvalidCutoverJournal)?;
    validate_cutover_journal(&journal)?;

    let parent = database
        .parent()
        .ok_or(BackupError::InvalidCutoverJournal)?;
    let prepared = journal_artifact_path(
        parent,
        &journal.prepared_file,
        &restore_artifact_prefix(database),
    )?;
    let rollback = journal_artifact_path(
        parent,
        &journal.rollback_file,
        &rollback_artifact_prefix(database),
    )?;

    match journal.phase {
        CutoverPhase::RecoveredRolledBack => {
            validate_original_recovery_database(database, &journal)?;
            return Ok(Some(journal_outcome(
                &journal,
                CrashRecoveryKind::RolledBack,
            )));
        }
        CutoverPhase::RecoveredContinued => {
            validate_installed_recovery_database(database, &journal)?;
            return Ok(Some(journal_outcome(
                &journal,
                CrashRecoveryKind::Continued,
            )));
        }
        CutoverPhase::RecoveredCleaned => {
            validate_original_recovery_database(database, &journal)?;
            return Ok(Some(journal_outcome(
                &journal,
                CrashRecoveryKind::CleanedOrphan,
            )));
        }
        _ => {}
    }

    let live_exists = database.is_file();
    let rollback_exists = rollback.is_file();
    if rollback_exists {
        let continue_install = journal.phase == CutoverPhase::Installed
            && live_exists
            && validate_installed_recovery_database(database, &journal).is_ok();
        if continue_install {
            remove_restore_artifact(&prepared)?;
            remove_restore_artifact(&rollback)?;
            sync_directory(parent)?;
            persist_recovery_receipt(
                &journal_path,
                &mut journal,
                CutoverPhase::RecoveredContinued,
            )?;
            return Ok(Some(journal_outcome(
                &journal,
                CrashRecoveryKind::Continued,
            )));
        }

        validate_original_recovery_database(&rollback, &journal)?;
        remove_sqlite_sidecars(&rollback).map_err(BackupError::Io)?;
        remove_database_file(database)?;
        fs::rename(&rollback, database).map_err(|_| BackupError::CutoverFailed)?;
        remove_restore_artifact(&prepared)?;
        sync_directory(parent)?;
        validate_original_recovery_database(database, &journal)?;
        persist_recovery_receipt(
            &journal_path,
            &mut journal,
            CutoverPhase::RecoveredRolledBack,
        )?;
        return Ok(Some(journal_outcome(
            &journal,
            CrashRecoveryKind::RolledBack,
        )));
    }

    if live_exists && validate_original_recovery_database(database, &journal).is_ok() {
        remove_restore_artifact(&prepared)?;
        sync_directory(parent)?;
        let kind = if matches!(journal.phase, CutoverPhase::Preparing | CutoverPhase::Ready) {
            CrashRecoveryKind::CleanedOrphan
        } else {
            CrashRecoveryKind::RolledBack
        };
        let phase = match kind {
            CrashRecoveryKind::CleanedOrphan => CutoverPhase::RecoveredCleaned,
            CrashRecoveryKind::RolledBack => CutoverPhase::RecoveredRolledBack,
            CrashRecoveryKind::Continued => unreachable!(),
        };
        persist_recovery_receipt(&journal_path, &mut journal, phase)?;
        return Ok(Some(journal_outcome(&journal, kind)));
    }

    if journal.phase == CutoverPhase::Installed
        && live_exists
        && validate_installed_recovery_database(database, &journal).is_ok()
    {
        remove_restore_artifact(&prepared)?;
        sync_directory(parent)?;
        persist_recovery_receipt(
            &journal_path,
            &mut journal,
            CutoverPhase::RecoveredContinued,
        )?;
        return Ok(Some(journal_outcome(
            &journal,
            CrashRecoveryKind::Continued,
        )));
    }

    Err(BackupError::InvalidCutoverJournal)
}

fn journal_outcome(journal: &CutoverJournal, kind: CrashRecoveryKind) -> CrashRecoveryOutcome {
    CrashRecoveryOutcome {
        kind,
        recovery_id: Some(journal.recovery_id),
        occurred_at: journal.occurred_at,
    }
}

fn persist_recovery_receipt(
    path: &Path,
    journal: &mut CutoverJournal,
    phase: CutoverPhase,
) -> std::result::Result<(), BackupError> {
    journal.phase = phase;
    write_cutover_journal(path, journal)
}

pub(crate) fn complete_interrupted_cutover(
    database: &Path,
    outcome: CrashRecoveryOutcome,
) -> std::result::Result<(), BackupError> {
    let Some(recovery_id) = outcome.recovery_id else {
        return Ok(());
    };
    let path = cutover_journal_path(database);
    ensure_private_existing_file(&path)?;
    let encoded =
        read_bounded(&path, MAX_MANIFEST_BYTES).map_err(|_| BackupError::InvalidCutoverJournal)?;
    let journal: CutoverJournal =
        serde_json::from_slice(&encoded).map_err(|_| BackupError::InvalidCutoverJournal)?;
    if journal.recovery_id != recovery_id
        || !matches!(
            journal.phase,
            CutoverPhase::RecoveredRolledBack
                | CutoverPhase::RecoveredContinued
                | CutoverPhase::RecoveredCleaned
        )
    {
        return Err(BackupError::InvalidCutoverJournal);
    }
    remove_if_exists(&path).map_err(BackupError::Io)?;
    sync_directory(path.parent().ok_or(BackupError::CutoverFailed)?)
}

fn validate_installed_recovery_database(
    database: &Path,
    journal: &CutoverJournal,
) -> std::result::Result<(), BackupError> {
    ensure_private_existing_file(database)?;
    let connection =
        Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| BackupError::InvalidDatabase)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| BackupError::InvalidDatabase)?;
    if integrity != "ok" || migrations::validate_existing(&connection).is_err() {
        return Err(BackupError::InvalidDatabase);
    }
    let (wallet_id, epoch, state) = connection
        .query_row(
            "SELECT wallet_id, epoch, restore_state FROM wallet_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    if Uuid::parse_str(&wallet_id).ok() != Some(journal.wallet_id)
        || epoch != journal.recovery_epoch
        || state != "recovering"
    {
        return Err(BackupError::InvalidDatabase);
    }
    Ok(())
}

fn validate_original_recovery_database(
    database: &Path,
    journal: &CutoverJournal,
) -> std::result::Result<(), BackupError> {
    let expected_epoch = journal
        .recovery_epoch
        .checked_sub(1)
        .ok_or(BackupError::InvalidDatabase)?;
    let connection =
        Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| BackupError::InvalidDatabase)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| BackupError::InvalidDatabase)?;
    if integrity != "ok" || migrations::validate_existing(&connection).is_err() {
        return Err(BackupError::InvalidDatabase);
    }
    let (wallet_id, epoch, state) = connection
        .query_row(
            "SELECT wallet_id, epoch, restore_state FROM wallet_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|_| BackupError::InvalidDatabase)?;
    if Uuid::parse_str(&wallet_id).ok() != Some(journal.wallet_id)
        || epoch != expected_epoch
        || !matches!(state.as_str(), "normal" | "restore_precheck")
    {
        return Err(BackupError::InvalidDatabase);
    }
    Ok(())
}

fn cleanup_orphan_restore_files(
    database: &Path,
) -> std::result::Result<Option<CrashRecoveryOutcome>, BackupError> {
    if !database.is_file() {
        return Ok(None);
    }
    let parent = database.parent().ok_or(BackupError::CutoverFailed)?;
    let restore_prefix = restore_artifact_prefix(database);
    let rollback_prefix = rollback_artifact_prefix(database);
    let mut removed = false;
    for entry in fs::read_dir(parent).map_err(BackupError::Io)? {
        let entry = entry.map_err(BackupError::Io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.starts_with(&restore_prefix) || name.starts_with(&rollback_prefix))
            && (name.ends_with(".sqlite3")
                || name.ends_with(".sqlite3-wal")
                || name.ends_with(".sqlite3-shm")
                || name.ends_with(".sqlite3.owner.lock"))
        {
            remove_restore_artifact(&entry.path())?;
            removed = true;
        }
    }
    if !removed {
        return Ok(None);
    }
    sync_directory(parent)?;
    let connection =
        Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| BackupError::InvalidDatabase)?;
    let occurred_at = connection
        .query_row("SELECT unixepoch()", [], |row| row.get(0))
        .map_err(|_| BackupError::InvalidDatabase)?;
    Ok(Some(CrashRecoveryOutcome {
        kind: CrashRecoveryKind::CleanedOrphan,
        recovery_id: None,
        occurred_at,
    }))
}

fn validate_cutover_journal(journal: &CutoverJournal) -> std::result::Result<(), BackupError> {
    if journal.version != CUTOVER_JOURNAL_VERSION || journal.recovery_epoch == 0 {
        return Err(BackupError::InvalidCutoverJournal);
    }
    Ok(())
}

fn journal_artifact_path(
    parent: &Path,
    file_name: &str,
    required_prefix: &str,
) -> std::result::Result<PathBuf, BackupError> {
    let candidate = Path::new(file_name);
    if candidate.file_name().and_then(|name| name.to_str()) != Some(file_name)
        || !file_name.starts_with(required_prefix)
        || !file_name.ends_with(".sqlite3")
    {
        return Err(BackupError::InvalidCutoverJournal);
    }
    Ok(parent.join(candidate))
}

fn write_cutover_journal(
    path: &Path,
    journal: &CutoverJournal,
) -> std::result::Result<(), BackupError> {
    let encoded = serde_json::to_vec(journal).map_err(|_| BackupError::InvalidCutoverJournal)?;
    write_private_atomic(path, &encoded)
}

fn cutover_journal_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".restore-cutover.json");
    PathBuf::from(path)
}

fn restore_artifact_prefix(database: &Path) -> String {
    format!(".wallet-restore-{}-", database_path_token(database))
}

fn rollback_artifact_prefix(database: &Path) -> String {
    format!(".wallet-pre-restore-{}-", database_path_token(database))
}

fn database_path_token(database: &Path) -> String {
    let name = database
        .file_name()
        .map(|name| name.as_encoded_bytes())
        .unwrap_or_default();
    hex::encode(&Sha256::digest(name)[..8])
}

fn file_name_string(path: &Path) -> std::result::Result<String, BackupError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or(BackupError::CutoverFailed)
}

#[cfg(unix)]
fn ensure_private_existing_file(path: &Path) -> std::result::Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(BackupError::Io)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(BackupError::InvalidCutoverJournal);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_existing_file(_path: &Path) -> std::result::Result<(), BackupError> {
    Err(BackupError::UnsupportedPlatform)
}

fn remove_restore_artifact(path: &Path) -> std::result::Result<(), BackupError> {
    remove_sqlite_sidecars(path).map_err(BackupError::Io)?;
    remove_if_exists(path).map_err(BackupError::Io)?;
    remove_if_exists(&owner_lock_path(path)).map_err(BackupError::Io)
}

fn remove_database_file(path: &Path) -> std::result::Result<(), BackupError> {
    remove_sqlite_sidecars(path).map_err(BackupError::Io)?;
    remove_if_exists(path).map_err(BackupError::Io)
}

struct CutoverGuard<'a> {
    database: &'a Path,
    rollback: PathBuf,
    parent: &'a Path,
    journal_path: PathBuf,
    active: bool,
}

impl<'a> CutoverGuard<'a> {
    fn begin(
        database: &'a Path,
        rollback: PathBuf,
        journal_path: PathBuf,
    ) -> std::result::Result<Self, BackupError> {
        let parent = database.parent().ok_or(BackupError::CutoverFailed)?;
        fs::rename(database, &rollback).map_err(|_| BackupError::CutoverFailed)?;
        let guard = Self {
            database,
            rollback,
            parent,
            journal_path,
            active: true,
        };
        sync_directory(parent)?;
        Ok(guard)
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
        let removed_live = remove_sqlite_sidecars(self.database).is_ok()
            && remove_if_exists(self.database).is_ok();
        let restored = removed_live && fs::rename(&self.rollback, self.database).is_ok();
        if restored && sync_directory(self.parent).is_ok() {
            let _ = remove_if_exists(&self.journal_path);
            let _ = sync_directory(self.parent);
        }
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
            assert!(
                observed,
                "restore stage was not reached: {fail_at:?}; result={result:?}"
            );
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

    #[test]
    fn opening_a_missing_database_never_creates_an_empty_sqlite_file() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("missing.sqlite3");

        assert!(matches!(
            WalletStorage::open(&database),
            Err(crate::StorageError::NotInitialized)
        ));
        assert!(!database.exists());
    }

    #[test]
    fn persisted_preinstall_stages_restore_the_original_database_on_reopen() {
        for (index, phase, install_before_phase_update) in [
            (0_u8, CutoverPhase::OriginalMoved, false),
            (1, CutoverPhase::Ready, false),
            (2, CutoverPhase::OriginalMoved, true),
        ] {
            let directory = tempdir().unwrap();
            let wallet_id = Uuid::from_bytes([0xc0 + index; 16]);
            let (database, prepared, rollback) = staged_cutover_files(directory.path(), wallet_id);
            fs::rename(&database, &rollback).unwrap();
            if install_before_phase_update {
                fs::rename(&prepared, &database).unwrap();
            }
            write_test_journal(&database, wallet_id, phase, &prepared, &rollback, 50);

            let reopened = WalletStorage::open(&database).unwrap();
            let metadata = reopened.wallet_metadata().unwrap();
            assert_eq!(metadata.wallet_id, wallet_id);
            assert_eq!(metadata.epoch, 1);
            assert_eq!(metadata.restore_state, crate::RestoreState::Normal);
            assert!(
                reopened
                    .audit_events(10_000)
                    .unwrap()
                    .iter()
                    .any(|event| event.event_type == "restore.crash_rolled_back")
            );
            drop(reopened);
            assert_no_restore_artifacts(directory.path());
            assert!(!cutover_journal_path(&database).exists());
        }
    }

    #[test]
    fn persisted_installed_stage_continues_only_a_valid_recovering_database() {
        for (index, corrupt_installed, retain_rollback) in
            [(0_u8, false, true), (1, false, false), (2, true, true)]
        {
            let directory = tempdir().unwrap();
            let wallet_id = Uuid::from_bytes([0xd0 + index; 16]);
            let (database, prepared, rollback) = staged_cutover_files(directory.path(), wallet_id);
            fs::rename(&database, &rollback).unwrap();
            fs::rename(&prepared, &database).unwrap();
            if corrupt_installed {
                fs::write(&database, b"invalid installed database").unwrap();
            }
            if !retain_rollback {
                fs::remove_file(&rollback).unwrap();
            }
            write_test_journal(
                &database,
                wallet_id,
                CutoverPhase::Installed,
                &prepared,
                &rollback,
                60,
            );

            let reopened = WalletStorage::open(&database).unwrap();
            let metadata = reopened.wallet_metadata().unwrap();
            assert_eq!(metadata.wallet_id, wallet_id);
            if corrupt_installed {
                assert_eq!(metadata.epoch, 1);
                assert_eq!(metadata.restore_state, crate::RestoreState::Normal);
                assert!(
                    reopened
                        .audit_events(10_000)
                        .unwrap()
                        .iter()
                        .any(|event| event.event_type == "restore.crash_rolled_back")
                );
            } else {
                assert_eq!(metadata.epoch, 2);
                assert_eq!(metadata.restore_state, crate::RestoreState::Recovering);
                assert!(
                    reopened
                        .audit_events(10_000)
                        .unwrap()
                        .iter()
                        .any(|event| event.event_type == "restore.crash_continued")
                );
            }
            drop(reopened);
            assert_no_restore_artifacts(directory.path());
            assert!(!cutover_journal_path(&database).exists());
        }
    }

    #[test]
    fn orphaned_restore_files_are_removed_and_audited_before_open() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("wallet.sqlite3");
        let wallet_id = Uuid::from_bytes([0xe1; 16]);
        let storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
        drop(storage);
        let orphan = directory.path().join(format!(
            "{}{}.sqlite3",
            restore_artifact_prefix(&database),
            Uuid::new_v4()
        ));
        fs::write(&orphan, b"orphaned plaintext").unwrap();

        let reopened = WalletStorage::open(&database).unwrap();
        assert!(!orphan.exists());
        assert!(
            reopened
                .audit_events(10_000)
                .unwrap()
                .iter()
                .any(|event| event.event_type == "restore.orphan_cleaned")
        );
    }

    #[test]
    fn insecure_or_path_escaping_cutover_journals_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        for insecure_permissions in [true, false] {
            let directory = tempdir().unwrap();
            let database = directory.path().join("wallet.sqlite3");
            let wallet_id = Uuid::from_bytes([0xe2; 16]);
            let storage = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
            drop(storage);
            let marker = cutover_journal_path(&database);
            let prepared = directory.path().join(format!(
                "{}{}.sqlite3",
                restore_artifact_prefix(&database),
                Uuid::new_v4()
            ));
            let rollback = directory.path().join(format!(
                "{}{}.sqlite3",
                rollback_artifact_prefix(&database),
                Uuid::new_v4()
            ));
            write_test_journal(
                &database,
                wallet_id,
                CutoverPhase::Preparing,
                &prepared,
                &rollback,
                70,
            );
            if insecure_permissions {
                fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
            } else {
                let mut journal: CutoverJournal =
                    serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
                journal.prepared_file = "../outside.sqlite3".to_owned();
                write_cutover_journal(&marker, &journal).unwrap();
            }

            assert!(matches!(
                WalletStorage::open(&database),
                Err(crate::StorageError::Backup(
                    BackupError::InvalidCutoverJournal
                ))
            ));
            assert!(database.is_file());
            assert!(marker.is_file());
        }
    }

    #[test]
    fn owner_lock_blocks_startup_recovery_without_mutating_persisted_stage() {
        use fs2::FileExt;

        let directory = tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0xe3; 16]);
        let (database, prepared, rollback) = staged_cutover_files(directory.path(), wallet_id);
        fs::rename(&database, &rollback).unwrap();
        write_test_journal(
            &database,
            wallet_id,
            CutoverPhase::OriginalMoved,
            &prepared,
            &rollback,
            80,
        );
        let lock_path = owner_lock_path(&database);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        lock.try_lock_exclusive().unwrap();

        assert!(matches!(
            WalletStorage::open(&database),
            Err(crate::StorageError::WriterAlreadyActive)
        ));
        assert!(!database.exists());
        assert!(prepared.is_file());
        assert!(rollback.is_file());
        assert!(cutover_journal_path(&database).is_file());

        lock.unlock().unwrap();
        drop(lock);
        let reopened = WalletStorage::open(&database).unwrap();
        assert_eq!(reopened.wallet_metadata().unwrap().wallet_id, wallet_id);
        drop(reopened);
        assert_no_restore_artifacts(directory.path());
    }

    #[test]
    fn mismatched_journal_identity_preserves_all_cutover_evidence() {
        let directory = tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0xe4; 16]);
        let (database, prepared, rollback) = staged_cutover_files(directory.path(), wallet_id);
        fs::rename(&database, &rollback).unwrap();
        fs::rename(&prepared, &database).unwrap();
        write_test_journal(
            &database,
            Uuid::from_bytes([0xef; 16]),
            CutoverPhase::Installed,
            &prepared,
            &rollback,
            90,
        );

        assert!(matches!(
            WalletStorage::open(&database),
            Err(crate::StorageError::Backup(BackupError::InvalidDatabase))
        ));
        assert!(database.is_file());
        assert!(rollback.is_file());
        assert!(cutover_journal_path(&database).is_file());
    }

    #[test]
    fn recovery_receipt_makes_audit_completion_idempotent_across_restarts() {
        let directory = tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0xe5; 16]);
        let (database, prepared, rollback) = staged_cutover_files(directory.path(), wallet_id);
        fs::rename(&database, &rollback).unwrap();
        fs::rename(&prepared, &database).unwrap();
        write_test_journal(
            &database,
            wallet_id,
            CutoverPhase::Installed,
            &prepared,
            &rollback,
            100,
        );

        let first = recover_interrupted_cutover(&database).unwrap().unwrap();
        let second = recover_interrupted_cutover(&database).unwrap().unwrap();
        assert_eq!(first, second);
        assert!(cutover_journal_path(&database).is_file());
        assert!(!rollback.exists());

        let recovery_id = first.recovery_id().unwrap().to_string();
        let connection = Connection::open(&database).unwrap();
        connection
            .execute(
                "INSERT INTO audit_events
                 (wallet_id, epoch, event_type, subject_id, payload_json, created_at)
                 VALUES (?1, 2, 'restore.crash_continued', ?2, '{}', 100)",
                rusqlite::params![wallet_id.to_string(), recovery_id],
            )
            .unwrap();
        drop(connection);

        let reopened = WalletStorage::open(&database).unwrap();
        let matching = reopened
            .audit_events(10_000)
            .unwrap()
            .into_iter()
            .filter(|event| {
                event.event_type == "restore.crash_continued"
                    && event.subject_id.as_deref() == Some(recovery_id.as_str())
            })
            .count();
        assert_eq!(matching, 1);
        assert!(!cutover_journal_path(&database).exists());
    }

    fn staged_cutover_files(directory: &Path, wallet_id: Uuid) -> (PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let database = directory.join("wallet.sqlite3");
        let prepared = directory.join(format!(
            "{}{}.sqlite3",
            restore_artifact_prefix(&database),
            Uuid::new_v4()
        ));
        let rollback = directory.join(format!(
            "{}{}.sqlite3",
            rollback_artifact_prefix(&database),
            Uuid::new_v4()
        ));
        let mut live = WalletStorage::initialize(&database, wallet_id, 1).unwrap();
        live.begin_restore_precheck(2).unwrap();
        checkpoint_wal(&live.connection).unwrap();
        drop(live);
        let _ = remove_if_exists(&owner_lock_path(&database));

        let mut staged = WalletStorage::initialize(&prepared, wallet_id, 10).unwrap();
        staged.begin_restore_precheck(11).unwrap();
        assert_eq!(staged.cutover_restore(12).unwrap(), 2);
        staged.begin_recovering(13).unwrap();
        checkpoint_and_use_delete_journal(&staged.connection).unwrap();
        drop(staged);
        remove_sqlite_sidecars(&prepared).unwrap();
        let _ = remove_if_exists(&owner_lock_path(&prepared));
        fs::set_permissions(&prepared, fs::Permissions::from_mode(0o600)).unwrap();
        (database, prepared, rollback)
    }

    fn write_test_journal(
        database: &Path,
        wallet_id: Uuid,
        phase: CutoverPhase,
        prepared: &Path,
        rollback: &Path,
        occurred_at: i64,
    ) {
        write_cutover_journal(
            &cutover_journal_path(database),
            &CutoverJournal {
                version: CUTOVER_JOURNAL_VERSION,
                recovery_id: Uuid::new_v4(),
                wallet_id,
                recovery_epoch: 2,
                occurred_at,
                phase,
                prepared_file: file_name_string(prepared).unwrap(),
                rollback_file: file_name_string(rollback).unwrap(),
            },
        )
        .unwrap();
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
