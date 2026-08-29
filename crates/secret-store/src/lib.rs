//! Narrow, fail-closed secret backend contracts for Catomicals.
//!
//! The only concrete backend in this crate is an encrypted file backend for
//! development. Production callers must provide a separately reviewed system
//! keychain or HSM implementation.

mod device_wrap;
mod factory;
mod onepassword;
pub mod platform;

pub use device_wrap::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    DeviceWrapBinding, DeviceWrapError, DeviceWrappedPackageV1,
};
pub use factory::{
    ProductionSecretBackendResolver, SecretBackendFactory, SecretBackendMode,
    SecretBackendPublicStatus,
};
#[cfg(target_os = "macos")]
pub use platform::macos_secure_enclave::MacosSecureEnclaveProtector;

pub use onepassword::{
    ONEPASSWORD_MAX_STDOUT_BYTES, OnePasswordLoadError, OnePasswordResult,
    OnePasswordWrappedPackageLoader,
};

use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::fs::OpenOptions;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const FILE_HANDLE_PREFIX: &str = "encrypted-file://";
const FILE_RECORD_VERSION: u32 = 1;
const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    Development,
    Production,
}

#[derive(Debug, Error)]
pub enum SecretBackendError {
    #[error("this secret backend requires Unix permission semantics")]
    UnsupportedPlatform,
    #[error("the encrypted file secret backend is restricted to the development profile")]
    DevelopmentBackendForbidden,
    #[error("no secret backend is configured")]
    BackendUnavailable,
    #[error("no production secret backend is configured")]
    ProductionBackendUnavailable,
    #[error("production secret backend could not be resolved")]
    ProductionBackendResolutionFailed,
    #[error("secret backend path permissions are unsafe: {path}")]
    InsecurePermissions { path: PathBuf },
    #[error("invalid opaque secret handle")]
    InvalidHandle,
    #[error("secret value exceeds the backend size limit")]
    SecretTooLarge,
    #[error("secret record is missing")]
    SecretNotFound,
    #[error("secret record is corrupt or failed authentication")]
    CorruptRecord,
    #[error("secret backend cryptographic operation failed")]
    CryptographicFailure,
    #[error("secret backend I/O failed")]
    Io(#[source] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SecretBackendError>;

pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Marker for a per-backup data-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupDek {}

/// A typed opaque reference. Serialization deliberately contains only the
/// backend handle; it never contains key bytes or wrapped material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SecretRef<T> {
    handle: String,
    #[serde(skip)]
    marker: PhantomData<fn() -> T>,
}

impl<T> SecretRef<T> {
    pub fn from_handle(handle: impl Into<String>) -> Result<Self> {
        let handle = handle.into();
        if handle.is_empty() {
            return Err(SecretBackendError::InvalidHandle);
        }
        Ok(Self {
            handle,
            marker: PhantomData,
        })
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }
}

impl<T> fmt::Debug for SecretRef<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRef")
            .field("handle", &"[REDACTED]")
            .finish()
    }
}

/// Object-safe platform boundary. Backends own secret persistence and return
/// opaque handles; callers never persist returned plaintext outside a
/// zeroizing [`SecretValue`].
pub trait SecretBackend: Send + Sync {
    fn backend_name(&self) -> &'static str;
    /// Declares whether this implementation is allowed to hold production
    /// signing material. The default is deliberately development-only so a
    /// newly added backend cannot enter a production resolver by omission.
    fn security(&self) -> SecretBackendSecurity {
        SecretBackendSecurity::DevelopmentOnly
    }
    fn put_raw(&self, value: SecretValue) -> Result<String>;
    fn get_raw(&self, handle: &str) -> Result<SecretValue>;
    fn delete_raw(&self, handle: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretBackendSecurity {
    DevelopmentOnly,
    Production,
}

pub fn require_backend(backend: Option<&dyn SecretBackend>) -> Result<&dyn SecretBackend> {
    backend.ok_or(SecretBackendError::BackendUnavailable)
}

#[derive(Serialize, Deserialize)]
struct FileRecord {
    version: u32,
    payload_nonce: String,
    ciphertext: String,
    wrapped_dek_nonce: String,
    wrapped_dek: String,
}

pub struct FileSecretBackend {
    root: PathBuf,
    records: PathBuf,
    kek_path: PathBuf,
}

impl fmt::Debug for FileSecretBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSecretBackend")
            .field("profile", &"development")
            .finish_non_exhaustive()
    }
}

impl FileSecretBackend {
    pub fn open(root: impl AsRef<Path>, profile: RuntimeProfile) -> Result<Self> {
        ensure_supported_platform()?;
        if profile != RuntimeProfile::Development {
            return Err(SecretBackendError::DevelopmentBackendForbidden);
        }
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        ensure_private_directory(&root)?;
        let records = root.join("records");
        create_private_directory(&records)?;
        ensure_private_directory(&records)?;
        let kek_path = root.join("development.kek");
        ensure_development_kek(&kek_path)?;
        Ok(Self {
            root,
            records,
            kek_path,
        })
    }

    pub fn put<T>(&self, value: SecretValue) -> Result<SecretRef<T>> {
        SecretRef::from_handle(self.put_raw(value)?)
    }

    pub fn get<T>(&self, reference: &SecretRef<T>) -> Result<SecretValue> {
        self.get_raw(reference.handle())
    }

    pub fn delete<T>(&self, reference: &SecretRef<T>) -> Result<()> {
        self.delete_raw(reference.handle())
    }

    pub fn record_path(&self, handle: &str) -> Result<PathBuf> {
        let id = parse_file_handle(handle)?;
        Ok(self.records.join(format!("{id}.json")))
    }

    fn load_kek(&self) -> Result<Zeroizing<Vec<u8>>> {
        ensure_private_file(&self.kek_path)?;
        let key = Zeroizing::new(fs::read(&self.kek_path).map_err(SecretBackendError::Io)?);
        if key.len() != 32 {
            return Err(SecretBackendError::CorruptRecord);
        }
        Ok(key)
    }

    fn write_record(&self, id: Uuid, bytes: &[u8]) -> Result<()> {
        let final_path = self.records.join(format!("{id}.json"));
        let temporary_path = self.records.join(format!(".{id}.{}.tmp", Uuid::new_v4()));
        let mut file = create_private_file(&temporary_path)?;
        let result = (|| {
            file.write_all(bytes).map_err(SecretBackendError::Io)?;
            file.sync_all().map_err(SecretBackendError::Io)?;
            fs::rename(&temporary_path, &final_path).map_err(SecretBackendError::Io)?;
            sync_directory(&self.records)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }
}

impl SecretBackend for FileSecretBackend {
    fn backend_name(&self) -> &'static str {
        "encrypted_file_development"
    }

    fn put_raw(&self, value: SecretValue) -> Result<String> {
        if value.expose().len() > MAX_SECRET_BYTES {
            return Err(SecretBackendError::SecretTooLarge);
        }
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.records)?;
        let id = Uuid::new_v4();
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(dek.as_mut());
        let mut payload_nonce = [0u8; 24];
        let mut wrapped_dek_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut payload_nonce);
        OsRng.fill_bytes(&mut wrapped_dek_nonce);
        let aad = file_record_aad(id);
        let ciphertext = XChaCha20Poly1305::new_from_slice(dek.as_ref())
            .map_err(|_| SecretBackendError::CryptographicFailure)?
            .encrypt(
                &XNonce::from(payload_nonce),
                Payload {
                    msg: value.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretBackendError::CryptographicFailure)?;
        let kek = self.load_kek()?;
        let wrapped_dek = XChaCha20Poly1305::new_from_slice(kek.as_slice())
            .map_err(|_| SecretBackendError::CryptographicFailure)?
            .encrypt(
                &XNonce::from(wrapped_dek_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretBackendError::CryptographicFailure)?;
        let record = FileRecord {
            version: FILE_RECORD_VERSION,
            payload_nonce: STANDARD_NO_PAD.encode(payload_nonce),
            ciphertext: STANDARD_NO_PAD.encode(ciphertext),
            wrapped_dek_nonce: STANDARD_NO_PAD.encode(wrapped_dek_nonce),
            wrapped_dek: STANDARD_NO_PAD.encode(wrapped_dek),
        };
        let encoded = serde_json::to_vec(&record).map_err(|_| SecretBackendError::CorruptRecord)?;
        self.write_record(id, &encoded)?;
        Ok(format!("{FILE_HANDLE_PREFIX}{id}"))
    }

    fn get_raw(&self, handle: &str) -> Result<SecretValue> {
        let id = parse_file_handle(handle)?;
        let path = self.record_path(handle)?;
        ensure_private_file(&path)?;
        let file = File::open(path).map_err(map_missing)?;
        let mut encoded = Vec::new();
        file.take((MAX_SECRET_BYTES * 2) as u64)
            .read_to_end(&mut encoded)
            .map_err(SecretBackendError::Io)?;
        let record: FileRecord =
            serde_json::from_slice(&encoded).map_err(|_| SecretBackendError::CorruptRecord)?;
        if record.version != FILE_RECORD_VERSION {
            return Err(SecretBackendError::CorruptRecord);
        }
        let payload_nonce = decode_array::<24>(&record.payload_nonce)?;
        let wrapped_dek_nonce = decode_array::<24>(&record.wrapped_dek_nonce)?;
        let ciphertext = STANDARD_NO_PAD
            .decode(record.ciphertext)
            .map_err(|_| SecretBackendError::CorruptRecord)?;
        let wrapped_dek = STANDARD_NO_PAD
            .decode(record.wrapped_dek)
            .map_err(|_| SecretBackendError::CorruptRecord)?;
        let aad = file_record_aad(id);
        let kek = self.load_kek()?;
        let dek = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(kek.as_slice())
                .map_err(|_| SecretBackendError::CryptographicFailure)?
                .decrypt(
                    &XNonce::from(wrapped_dek_nonce),
                    Payload {
                        msg: &wrapped_dek,
                        aad: &aad,
                    },
                )
                .map_err(|_| SecretBackendError::CorruptRecord)?,
        );
        if dek.len() != 32 {
            return Err(SecretBackendError::CorruptRecord);
        }
        let plaintext = XChaCha20Poly1305::new_from_slice(dek.as_slice())
            .map_err(|_| SecretBackendError::CryptographicFailure)?
            .decrypt(
                &XNonce::from(payload_nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecretBackendError::CorruptRecord)?;
        Ok(SecretValue::new(plaintext))
    }

    fn delete_raw(&self, handle: &str) -> Result<()> {
        let path = self.record_path(handle)?;
        fs::remove_file(path).map_err(map_missing)?;
        sync_directory(&self.records)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayload<T> {
    pub key_ref: SecretRef<T>,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn seal_payload<T>(
    backend: &dyn SecretBackend,
    plaintext: &[u8],
    domain: &[u8],
) -> Result<SealedPayload<T>> {
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(dek.as_mut());
    let handle = backend.put_raw(SecretValue::new(dek.to_vec()))?;
    let key_ref = SecretRef::from_handle(handle)?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = sealed_payload_aad(domain, key_ref.handle());
    let ciphertext = match XChaCha20Poly1305::new_from_slice(dek.as_ref())
        .map_err(|_| SecretBackendError::CryptographicFailure)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        ) {
        Ok(ciphertext) => ciphertext,
        Err(_) => {
            let _ = backend.delete_raw(key_ref.handle());
            return Err(SecretBackendError::CryptographicFailure);
        }
    };
    Ok(SealedPayload {
        key_ref,
        nonce,
        ciphertext,
    })
}

pub fn open_sealed_payload<T>(
    backend: &dyn SecretBackend,
    sealed: &SealedPayload<T>,
    domain: &[u8],
) -> Result<Vec<u8>> {
    open_sealed_payload_parts(
        backend,
        &sealed.key_ref,
        sealed.nonce,
        &sealed.ciphertext,
        domain,
    )
}

pub fn open_sealed_payload_parts<T>(
    backend: &dyn SecretBackend,
    key_ref: &SecretRef<T>,
    nonce: [u8; 24],
    ciphertext: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>> {
    let dek = backend.get_raw(key_ref.handle())?;
    if dek.expose().len() != 32 {
        return Err(SecretBackendError::CorruptRecord);
    }
    let aad = sealed_payload_aad(domain, key_ref.handle());
    XChaCha20Poly1305::new_from_slice(dek.expose())
        .map_err(|_| SecretBackendError::CryptographicFailure)?
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretBackendError::CorruptRecord)
}

fn parse_file_handle(handle: &str) -> Result<Uuid> {
    let id = handle
        .strip_prefix(FILE_HANDLE_PREFIX)
        .ok_or(SecretBackendError::InvalidHandle)?;
    Uuid::parse_str(id).map_err(|_| SecretBackendError::InvalidHandle)
}

fn file_record_aad(id: Uuid) -> Vec<u8> {
    format!("catomicals-file-secret-v{FILE_RECORD_VERSION}:{id}").into_bytes()
}

fn sealed_payload_aad(domain: &[u8], handle: &str) -> Vec<u8> {
    let mut aad = b"catomicals-sealed-payload-v1\0".to_vec();
    aad.extend_from_slice(domain);
    aad.push(0);
    aad.extend_from_slice(handle.as_bytes());
    aad
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| SecretBackendError::CorruptRecord)?;
    bytes
        .try_into()
        .map_err(|_| SecretBackendError::CorruptRecord)
}

fn map_missing(error: std::io::Error) -> SecretBackendError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SecretBackendError::SecretNotFound
    } else {
        SecretBackendError::Io(error)
    }
}

#[cfg(unix)]
fn ensure_supported_platform() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_supported_platform() -> Result<()> {
    Err(SecretBackendError::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).map_err(SecretBackendError::Io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<()> {
    Err(SecretBackendError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(SecretBackendError::Io)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(SecretBackendError::InsecurePermissions {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_path: &Path) -> Result<()> {
    Err(SecretBackendError::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(SecretBackendError::Io)
}

#[cfg(not(unix))]
fn create_private_file(_path: &Path) -> Result<File> {
    Err(SecretBackendError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(map_missing)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(SecretBackendError::InsecurePermissions {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_file(_path: &Path) -> Result<()> {
    Err(SecretBackendError::UnsupportedPlatform)
}

fn ensure_development_kek(path: &Path) -> Result<()> {
    if path.exists() {
        return ensure_private_file(path);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    let mut file = create_private_file(path)?;
    file.write_all(key.as_ref())
        .map_err(SecretBackendError::Io)?;
    file.sync_all().map_err(SecretBackendError::Io)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(SecretBackendError::Io)
}
