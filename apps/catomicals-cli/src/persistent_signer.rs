use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[cfg(test)]
use std::path::PathBuf;

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use catomicals_secret_store::{
    FileSecretBackend, RuntimeProfile, SecretBackend, SecretRef, SecretValue,
    open_sealed_payload_parts, seal_payload,
};
use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, PublicKeyPackage, group_pubkey_xonly,
    participant_identifier, run_local_dkg,
};
use frost_secp256k1_tr::keys::KeyPackage;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

const MANIFEST_VERSION: u32 = 1;
const SECRET_PAYLOAD_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "signer.json";
const OWNER_LOCK_FILE: &str = ".signer.owner.lock";
const SECRET_DIRECTORY: &str = "signer-secrets";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SIGNER_PAYLOAD_BYTES: usize = 64 * 1024;
pub const SIGNER_BACKUP_FILE: &str = "signer-recovery.json";
const SIGNER_BACKUP_VERSION: u32 = 1;
const MAX_SIGNER_BACKUP_BYTES: u64 = 256 * 1024;

enum SignerBackupDek {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerProviderKind {
    LocalEncryptedFile,
    Unconfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerParticipantAudit {
    pub signer_id: u16,
    pub provider: SignerProviderKind,
    pub configured: bool,
}

#[derive(Serialize)]
struct SignerBackupDomain<'a> {
    format_version: u32,
    secret_backend: &'a str,
    audit: &'a SignerAuditManifest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerBackupEnvelope {
    format_version: u32,
    secret_backend: String,
    audit: SignerAuditManifest,
    dek_ref: SecretRef<SignerBackupDek>,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerManifest {
    format_version: u32,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    signer_id: u16,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: String,
    signet_address: String,
    participants: Vec<SignerParticipantAudit>,
    public_key_package: String,
    secret_backend: String,
    secret_handle: String,
    created_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerSecretPayload {
    format_version: u32,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    signer_id: u16,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: String,
    signet_address: String,
    participants: Vec<SignerParticipantAudit>,
    public_key_package: String,
    key_package: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerAuditManifest {
    pub format_version: u32,
    pub wallet_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub signer_id: u16,
    pub min_signers: u16,
    pub max_signers: u16,
    pub group_pubkey_xonly: String,
    pub signet_address: String,
    pub participants: Vec<SignerParticipantAudit>,
    pub secret_backend: String,
    pub created_at: i64,
}

/// One locally hosted signer restored from an authenticated encrypted record.
/// The owner lock is retained for the lifetime of the signer so two processes
/// cannot use the same share concurrently.
pub struct PersistentSigner {
    participant: LocalFrostParticipant,
    public_key_package: PublicKeyPackage,
    manifest: SignerManifest,
    #[cfg(test)]
    secret_record_path: PathBuf,
    _owner_lock: File,
}

/// Keeps the exclusive signer ownership lock alive after key material moves
/// into wallet-core. Future HSM/remote implementations can provide the same
/// lifetime lease without exposing a local key package.
pub struct SignerRuntimeLease {
    _owner_lock: File,
}

impl core::fmt::Debug for PersistentSigner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PersistentSigner")
            .field("audit", &self.audit_manifest())
            .field("participant", &"[REDACTED]")
            .finish()
    }
}

impl PersistentSigner {
    pub fn open_or_initialize(
        data_dir: &Path,
        wallet_id: Uuid,
        signer_id: u16,
        now: i64,
    ) -> anyhow::Result<Self> {
        Self::open(data_dir, wallet_id, signer_id, Some(now))
    }

    /// Opens an already provisioned signer without creating a new FROST
    /// identity. Recovery and other fail-closed startup paths use this entry
    /// point so a missing manifest can never rotate the wallet implicitly.
    pub fn open_existing(data_dir: &Path, wallet_id: Uuid, signer_id: u16) -> anyhow::Result<Self> {
        Self::open(data_dir, wallet_id, signer_id, None)
    }

    fn open(
        data_dir: &Path,
        wallet_id: Uuid,
        signer_id: u16,
        initialize_at: Option<i64>,
    ) -> anyhow::Result<Self> {
        let manifest_path = data_dir.join(MANIFEST_FILE);
        if initialize_at.is_none() && !manifest_path.exists() {
            bail!("durable signer is not initialized");
        }
        fs::create_dir_all(data_dir).context("creating durable wallet directory")?;
        let owner_lock = acquire_owner_lock(data_dir)?;
        let backend =
            FileSecretBackend::open(data_dir.join(SECRET_DIRECTORY), RuntimeProfile::Development)
                .context("opening encrypted signer backend")?;
        let manifest = if manifest_path.exists() {
            read_manifest(&manifest_path)?
        } else {
            initialize_manifest(
                &manifest_path,
                &backend,
                wallet_id,
                signer_id,
                initialize_at.expect("initialization time checked before backend creation"),
            )?
        };
        if manifest.wallet_id != wallet_id {
            bail!("durable signer wallet identity does not match the authority database");
        }
        if manifest.signer_id != signer_id {
            bail!("configured signer id does not match the durable signer manifest");
        }
        if manifest.secret_backend != backend.backend_name() {
            bail!("durable signer requires a different secret backend");
        }
        #[cfg(test)]
        let secret_record_path = backend
            .record_path(&manifest.secret_handle)
            .context("resolving signer secret record")?;
        let secret = backend
            .get_raw(&manifest.secret_handle)
            .context("opening durable signer secret: record is missing, corrupt, or unsafe")?;
        if secret.expose().len() > MAX_SIGNER_PAYLOAD_BYTES {
            bail!("durable signer secret payload exceeds its size limit");
        }
        let payload: SignerSecretPayload = serde_json::from_slice(secret.expose())
            .context("durable signer secret payload is corrupt")?;
        validate_binding(&manifest, &payload)?;
        let public_bytes = STANDARD_NO_PAD
            .decode(&manifest.public_key_package)
            .context("durable signer public package is corrupt")?;
        let public_key_package = PublicKeyPackage::deserialize(&public_bytes)
            .map_err(|_| anyhow::anyhow!("durable signer public package is corrupt"))?;
        let key_bytes = STANDARD_NO_PAD
            .decode(&payload.key_package)
            .context("durable signer key package is corrupt")?;
        let key_package = KeyPackage::deserialize(&key_bytes)
            .map_err(|_| anyhow::anyhow!("durable signer key package is corrupt"))?;
        validate_packages(&manifest, &key_package, &public_key_package)?;
        let participant = LocalFrostParticipant::new(signer_id, key_package, NonceGuard::new())?;
        Ok(Self {
            participant,
            public_key_package,
            manifest,
            #[cfg(test)]
            secret_record_path,
            _owner_lock: owner_lock,
        })
    }

    #[cfg(test)]
    pub fn participant(&self) -> &LocalFrostParticipant {
        &self.participant
    }

    pub fn into_runtime_parts(
        self,
    ) -> (
        LocalFrostParticipant,
        PublicKeyPackage,
        SignerAuditManifest,
        SignerRuntimeLease,
    ) {
        let audit = self.audit_manifest();
        let participant = self.participant;
        let public_key_package = self.public_key_package;
        let _owner_lock = self._owner_lock;
        (
            participant,
            public_key_package,
            audit,
            SignerRuntimeLease { _owner_lock },
        )
    }

    #[cfg(test)]
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    pub fn min_signers(&self) -> u16 {
        self.manifest.min_signers
    }

    #[cfg(test)]
    pub fn max_signers(&self) -> u16 {
        self.manifest.max_signers
    }

    pub fn audit_manifest(&self) -> SignerAuditManifest {
        audit_from_manifest(&self.manifest)
    }

    #[cfg(test)]
    fn secret_record_path(&self) -> PathBuf {
        self.secret_record_path.clone()
    }
}

pub fn read_audit_manifest(data_dir: &Path) -> anyhow::Result<SignerAuditManifest> {
    read_manifest(&data_dir.join(MANIFEST_FILE)).map(|manifest| audit_from_manifest(&manifest))
}

/// Export the authenticated signer package into the already-encrypted wallet
/// backup bundle. The visible envelope contains only the public audit list;
/// the FROST share remains inside an AEAD ciphertext.
pub fn export_backup_attachment(
    data_dir: &Path,
    bundle: &Path,
    backup_backend: &dyn SecretBackend,
) -> anyhow::Result<Option<SignerAuditManifest>> {
    let manifest_path = data_dir.join(MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let manifest = read_manifest(&manifest_path)?;
    let signer = PersistentSigner::open_or_initialize(
        data_dir,
        manifest.wallet_id,
        manifest.signer_id,
        manifest.created_at,
    )?;
    let source_backend =
        FileSecretBackend::open(data_dir.join(SECRET_DIRECTORY), RuntimeProfile::Development)
            .context("opening source signer secret backend")?;
    let secret = source_backend
        .get_raw(&manifest.secret_handle)
        .context("reading source signer secret for backup")?;
    let audit = signer.audit_manifest();
    let domain = signer_backup_domain(&audit, backup_backend.backend_name())?;
    let sealed = seal_payload::<SignerBackupDek>(backup_backend, secret.expose(), &domain)
        .context("encrypting signer recovery attachment")?;
    let envelope = SignerBackupEnvelope {
        format_version: SIGNER_BACKUP_VERSION,
        secret_backend: backup_backend.backend_name().to_owned(),
        audit: audit.clone(),
        dek_ref: sealed.key_ref,
        nonce: STANDARD_NO_PAD.encode(sealed.nonce),
        ciphertext: STANDARD_NO_PAD.encode(sealed.ciphertext),
    };
    let path = bundle.join(SIGNER_BACKUP_FILE);
    if path.exists() {
        let _ = backup_backend.delete_raw(envelope.dek_ref.handle());
        bail!("signer recovery attachment already exists");
    }
    let encoded =
        serde_json::to_vec_pretty(&envelope).context("encoding signer recovery attachment")?;
    if let Err(error) = write_private_atomic(&path, &encoded) {
        let _ = backup_backend.delete_raw(envelope.dek_ref.handle());
        return Err(error);
    }
    Ok(Some(audit))
}

pub fn verify_backup_attachment(
    bundle: &Path,
    backup_backend: &dyn SecretBackend,
) -> anyhow::Result<Option<SignerAuditManifest>> {
    let path = bundle.join(SIGNER_BACKUP_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let (envelope, payload) = decrypt_backup_attachment(&path, backup_backend)?;
    validate_recovery_payload(&envelope.audit, &payload, "encrypted-file://recovery")?;
    Ok(Some(envelope.audit))
}

pub fn restore_backup_attachment(
    bundle: &Path,
    data_dir: &Path,
    backup_backend: &dyn SecretBackend,
    expected_wallet_id: Uuid,
) -> anyhow::Result<Option<SignerAuditManifest>> {
    let path = bundle.join(SIGNER_BACKUP_FILE);
    if !path.exists() {
        return Ok(None);
    }
    fs::create_dir_all(data_dir).context("creating signer restore directory")?;
    let _owner_lock = acquire_owner_lock(data_dir)?;
    let (envelope, payload) = decrypt_backup_attachment(&path, backup_backend)?;
    if envelope.audit.wallet_id != expected_wallet_id {
        bail!("signer recovery wallet does not match the requested wallet");
    }
    validate_recovery_payload(&envelope.audit, &payload, "encrypted-file://recovery")?;
    let destination_backend =
        FileSecretBackend::open(data_dir.join(SECRET_DIRECTORY), RuntimeProfile::Development)
            .context("opening destination signer secret backend")?;
    let handle = destination_backend
        .put_raw(SecretValue::new(payload.to_vec()))
        .context("installing restored signer secret")?;
    let manifest = manifest_from_recovery(&envelope.audit, &payload, handle.clone())?;
    if let Err(error) = write_manifest_atomic(&data_dir.join(MANIFEST_FILE), &manifest) {
        let _ = destination_backend.delete_raw(&handle);
        return Err(error);
    }
    Ok(Some(envelope.audit))
}

fn decrypt_backup_attachment(
    path: &Path,
    backend: &dyn SecretBackend,
) -> anyhow::Result<(SignerBackupEnvelope, Zeroizing<Vec<u8>>)> {
    ensure_private_regular_file(path)?;
    let mut encoded = Vec::new();
    File::open(path)
        .context("opening signer recovery attachment")?
        .take(MAX_SIGNER_BACKUP_BYTES + 1)
        .read_to_end(&mut encoded)
        .context("reading signer recovery attachment")?;
    if encoded.len() as u64 > MAX_SIGNER_BACKUP_BYTES {
        bail!("signer recovery attachment exceeds its size limit");
    }
    let envelope: SignerBackupEnvelope =
        serde_json::from_slice(&encoded).context("signer recovery attachment is malformed")?;
    if envelope.format_version != SIGNER_BACKUP_VERSION
        || envelope.secret_backend != backend.backend_name()
    {
        bail!("signer recovery attachment version or backend is unsupported");
    }
    let nonce: [u8; 24] = STANDARD_NO_PAD
        .decode(&envelope.nonce)
        .context("signer recovery nonce is malformed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer recovery nonce is malformed"))?;
    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.ciphertext)
        .context("signer recovery ciphertext is malformed")?;
    if ciphertext.len() > MAX_SIGNER_PAYLOAD_BYTES + 16 {
        bail!("signer recovery ciphertext exceeds its size limit");
    }
    let domain = signer_backup_domain(&envelope.audit, &envelope.secret_backend)?;
    let plaintext =
        open_sealed_payload_parts(backend, &envelope.dek_ref, nonce, &ciphertext, &domain)
            .context("signer recovery attachment failed authentication")?;
    if plaintext.len() > MAX_SIGNER_PAYLOAD_BYTES {
        bail!("signer recovery payload exceeds its size limit");
    }
    Ok((envelope, Zeroizing::new(plaintext)))
}

fn signer_backup_domain(
    audit: &SignerAuditManifest,
    secret_backend: &str,
) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(&SignerBackupDomain {
        format_version: SIGNER_BACKUP_VERSION,
        secret_backend,
        audit,
    })
    .context("encoding signer recovery authentication domain")
}

fn validate_recovery_payload(
    audit: &SignerAuditManifest,
    bytes: &[u8],
    handle: &str,
) -> anyhow::Result<()> {
    let payload: SignerSecretPayload =
        serde_json::from_slice(bytes).context("signer recovery payload is corrupt")?;
    let manifest = manifest_from_payload(audit, &payload, handle.to_owned())?;
    validate_binding(&manifest, &payload)?;
    let public_bytes = STANDARD_NO_PAD
        .decode(&payload.public_key_package)
        .context("recovered signer public package is corrupt")?;
    let public_key_package = PublicKeyPackage::deserialize(&public_bytes)
        .map_err(|_| anyhow::anyhow!("recovered signer public package is corrupt"))?;
    let key_bytes = STANDARD_NO_PAD
        .decode(&payload.key_package)
        .context("recovered signer key package is corrupt")?;
    let key_package = KeyPackage::deserialize(&key_bytes)
        .map_err(|_| anyhow::anyhow!("recovered signer key package is corrupt"))?;
    validate_packages(&manifest, &key_package, &public_key_package)
}

fn manifest_from_recovery(
    audit: &SignerAuditManifest,
    bytes: &[u8],
    handle: String,
) -> anyhow::Result<SignerManifest> {
    let payload: SignerSecretPayload =
        serde_json::from_slice(bytes).context("signer recovery payload is corrupt")?;
    manifest_from_payload(audit, &payload, handle)
}

fn manifest_from_payload(
    audit: &SignerAuditManifest,
    payload: &SignerSecretPayload,
    handle: String,
) -> anyhow::Result<SignerManifest> {
    let manifest = SignerManifest {
        format_version: audit.format_version,
        wallet_id: audit.wallet_id,
        signer_set_id: audit.signer_set_id,
        signer_epoch: audit.signer_epoch,
        signer_id: audit.signer_id,
        min_signers: audit.min_signers,
        max_signers: audit.max_signers,
        group_pubkey_xonly: audit.group_pubkey_xonly.clone(),
        signet_address: audit.signet_address.clone(),
        participants: audit.participants.clone(),
        public_key_package: payload.public_key_package.clone(),
        secret_backend: "encrypted_file_development".to_owned(),
        secret_handle: handle,
        created_at: audit.created_at,
    };
    validate_binding(&manifest, payload)?;
    Ok(manifest)
}

fn initialize_manifest(
    manifest_path: &Path,
    backend: &FileSecretBackend,
    wallet_id: Uuid,
    signer_id: u16,
    now: i64,
) -> anyhow::Result<SignerManifest> {
    let mut dkg = run_local_dkg(3, 2).context("initial durable local DKG")?;
    let key_package = dkg
        .key_packages
        .remove(&participant_identifier(signer_id)?)
        .ok_or_else(|| anyhow::anyhow!("signer id must be in 1..=3"))?;
    let group_key = group_pubkey_xonly(&dkg.public_key_package)?;
    let group_pubkey_xonly = hex::encode(group_key);
    let signet_address = signet_address(group_key)?;
    let public_key_package = STANDARD_NO_PAD.encode(dkg.public_key_package.serialize()?);
    let signer_set_id = Uuid::new_v4();
    let participants = (1..=dkg.max_signers)
        .map(|id| SignerParticipantAudit {
            signer_id: id,
            provider: if id == signer_id {
                SignerProviderKind::LocalEncryptedFile
            } else {
                SignerProviderKind::Unconfigured
            },
            configured: id == signer_id,
        })
        .collect::<Vec<_>>();
    let payload = SignerSecretPayload {
        format_version: SECRET_PAYLOAD_VERSION,
        wallet_id,
        signer_set_id,
        signer_epoch: 1,
        signer_id,
        min_signers: dkg.min_signers,
        max_signers: dkg.max_signers,
        group_pubkey_xonly: group_pubkey_xonly.clone(),
        signet_address: signet_address.clone(),
        participants: participants.clone(),
        public_key_package: public_key_package.clone(),
        key_package: STANDARD_NO_PAD.encode(key_package.serialize()?),
    };
    let encoded = serde_json::to_vec(&payload).context("encoding durable signer secret")?;
    if encoded.len() > MAX_SIGNER_PAYLOAD_BYTES {
        bail!("durable signer secret payload exceeds its size limit");
    }
    let handle = backend
        .put_raw(SecretValue::new(encoded))
        .context("persisting encrypted durable signer secret")?;
    let manifest = SignerManifest {
        format_version: MANIFEST_VERSION,
        wallet_id,
        signer_set_id,
        signer_epoch: 1,
        signer_id,
        min_signers: dkg.min_signers,
        max_signers: dkg.max_signers,
        group_pubkey_xonly,
        signet_address,
        participants,
        public_key_package,
        secret_backend: backend.backend_name().to_owned(),
        secret_handle: handle,
        created_at: now,
    };
    let result = write_manifest_atomic(manifest_path, &manifest);
    if result.is_err() {
        let _ = backend.delete_raw(&manifest.secret_handle);
    }
    result.map(|()| manifest)
}

fn validate_binding(
    manifest: &SignerManifest,
    payload: &SignerSecretPayload,
) -> anyhow::Result<()> {
    if manifest.format_version != MANIFEST_VERSION
        || payload.format_version != SECRET_PAYLOAD_VERSION
        || manifest.wallet_id != payload.wallet_id
        || manifest.signer_set_id != payload.signer_set_id
        || manifest.signer_epoch != payload.signer_epoch
        || manifest.signer_id != payload.signer_id
        || manifest.min_signers != payload.min_signers
        || manifest.max_signers != payload.max_signers
        || manifest.group_pubkey_xonly != payload.group_pubkey_xonly
        || manifest.signet_address != payload.signet_address
        || manifest.participants != payload.participants
        || manifest.public_key_package != payload.public_key_package
        || manifest.signer_epoch == 0
        || manifest.min_signers < 2
        || manifest.min_signers > manifest.max_signers
    {
        bail!("durable signer manifest and authenticated secret do not match");
    }
    validate_participants(manifest)?;
    Ok(())
}

fn validate_packages(
    manifest: &SignerManifest,
    key_package: &KeyPackage,
    public_key_package: &PublicKeyPackage,
) -> anyhow::Result<()> {
    let identifier = participant_identifier(manifest.signer_id)?;
    let max_signers = u16::try_from(public_key_package.verifying_shares().len())
        .context("durable signer set is too large")?;
    let group = hex::encode(group_pubkey_xonly(public_key_package)?);
    let address = signet_address(group_pubkey_xonly(public_key_package)?)?;
    if key_package.identifier() != &identifier
        || *key_package.min_signers() != manifest.min_signers
        || max_signers != manifest.max_signers
        || key_package.verifying_key() != public_key_package.verifying_key()
        || public_key_package.verifying_shares().get(&identifier)
            != Some(key_package.verifying_share())
        || group != manifest.group_pubkey_xonly
        || address != manifest.signet_address
    {
        bail!("durable signer key material does not match its public manifest");
    }
    Ok(())
}

fn validate_participants(manifest: &SignerManifest) -> anyhow::Result<()> {
    if manifest.participants.len() != usize::from(manifest.max_signers) {
        bail!("durable signer participant inventory has the wrong size");
    }
    for (index, participant) in manifest.participants.iter().enumerate() {
        let expected_id = u16::try_from(index + 1).context("participant inventory is too large")?;
        let is_local = participant.signer_id == manifest.signer_id;
        if participant.signer_id != expected_id
            || participant.configured != is_local
            || (is_local && participant.provider != SignerProviderKind::LocalEncryptedFile)
            || (!is_local && participant.provider != SignerProviderKind::Unconfigured)
        {
            bail!("durable signer participant inventory is inconsistent");
        }
    }
    Ok(())
}

fn signet_address(group_key: [u8; 32]) -> anyhow::Result<String> {
    let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&group_key)
        .context("FROST group key is not a valid BIP340 x-only key")?;
    Ok(bitcoin::Address::p2tr(
        &bitcoin::secp256k1::Secp256k1::verification_only(),
        key,
        None,
        bitcoin::Network::Signet,
    )
    .to_string())
}

fn audit_from_manifest(manifest: &SignerManifest) -> SignerAuditManifest {
    SignerAuditManifest {
        format_version: manifest.format_version,
        wallet_id: manifest.wallet_id,
        signer_set_id: manifest.signer_set_id,
        signer_epoch: manifest.signer_epoch,
        signer_id: manifest.signer_id,
        min_signers: manifest.min_signers,
        max_signers: manifest.max_signers,
        group_pubkey_xonly: manifest.group_pubkey_xonly.clone(),
        signet_address: manifest.signet_address.clone(),
        participants: manifest.participants.clone(),
        secret_backend: manifest.secret_backend.clone(),
        created_at: manifest.created_at,
    }
}

fn read_manifest(path: &Path) -> anyhow::Result<SignerManifest> {
    ensure_private_regular_file(path)?;
    let mut encoded = Vec::new();
    File::open(path)
        .context("opening durable signer manifest")?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut encoded)
        .context("reading durable signer manifest")?;
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("durable signer manifest exceeds its size limit");
    }
    serde_json::from_slice(&encoded).context("durable signer manifest is corrupt")
}

fn write_manifest_atomic(path: &Path, manifest: &SignerManifest) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable signer manifest has no parent directory"))?;
    let temporary = parent.join(format!(".signer-{}.tmp", Uuid::new_v4()));
    let encoded = serde_json::to_vec_pretty(manifest).context("encoding signer manifest")?;
    let mut file = create_private_file(&temporary)?;
    let result = (|| {
        file.write_all(&encoded)
            .context("writing durable signer manifest")?;
        file.sync_all().context("syncing durable signer manifest")?;
        fs::rename(&temporary, path).context("installing durable signer manifest")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("syncing durable signer directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_private_atomic(path: &Path, encoded: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("private output has no parent directory"))?;
    let temporary = parent.join(format!(".signer-backup-{}.tmp", Uuid::new_v4()));
    let mut file = create_private_file(&temporary)?;
    let result = (|| {
        file.write_all(encoded)
            .context("writing private signer backup")?;
        file.sync_all().context("syncing private signer backup")?;
        fs::rename(&temporary, path).context("installing private signer backup")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("syncing signer backup directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn acquire_owner_lock(data_dir: &Path) -> anyhow::Result<File> {
    let path = data_dir.join(OWNER_LOCK_FILE);
    let file = open_private_lock_file(&path)?;
    ensure_private_regular_file(&path)?;
    file.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("durable signer is already owned by another process"))?;
    Ok(file)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> anyhow::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("creating private signer file")
}

#[cfg(not(unix))]
fn create_private_file(_path: &Path) -> anyhow::Result<File> {
    bail!("durable signer files require Unix permission semantics")
}

#[cfg(unix)]
fn open_private_lock_file(path: &Path) -> anyhow::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .context("opening durable signer owner lock")
}

#[cfg(not(unix))]
fn open_private_lock_file(_path: &Path) -> anyhow::Result<File> {
    bail!("durable signer files require Unix permission semantics")
}

#[cfg(unix)]
fn ensure_private_regular_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path).context("reading private signer file metadata")?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        bail!(
            "private signer file permissions are unsafe: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_regular_file(_path: &Path) -> anyhow::Result<()> {
    bail!("durable signer files require Unix permission semantics")
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn durable_signer_reopens_with_the_same_group_key_and_address_identity() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x31; 16]);
        let first =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 10).unwrap();
        let first_status = first.audit_manifest();
        let first_group =
            catomicals_threshold::group_pubkey_xonly(first.public_key_package()).unwrap();
        drop(first);

        let second =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 20).unwrap();
        let second_group =
            catomicals_threshold::group_pubkey_xonly(second.public_key_package()).unwrap();

        assert_eq!(first_group, second_group);
        assert_eq!(first_status, second.audit_manifest());
        assert_eq!(second.participant().signer_id(), 1);
        assert_eq!(second.min_signers(), 2);
        assert_eq!(second.max_signers(), 3);
        assert_eq!(
            second
                .audit_manifest()
                .participants
                .iter()
                .filter(|participant| participant.configured)
                .map(|participant| participant.signer_id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let audit_json = serde_json::to_string(&second.audit_manifest()).unwrap();
        assert!(!audit_json.contains("secret_handle"));
        assert!(!audit_json.contains("signing_share"));
        assert!(!audit_json.contains("key_package"));
    }

    #[test]
    fn opening_an_existing_signer_never_initializes_a_missing_identity() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x30; 16]);

        let error = PersistentSigner::open_existing(directory.path(), wallet_id, 1).unwrap_err();

        assert!(error.to_string().contains("not initialized"));
        assert!(!directory.path().join(MANIFEST_FILE).exists());
        assert!(!directory.path().join(SECRET_DIRECTORY).exists());
    }

    #[test]
    fn corrupt_secret_record_fails_closed_instead_of_regenerating_a_wallet() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x32; 16]);
        let signer =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 10).unwrap();
        let group = signer.audit_manifest().group_pubkey_xonly.clone();
        let record = signer.secret_record_path();
        drop(signer);
        fs::write(&record, b"corrupt").unwrap();

        let error =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 20).unwrap_err();
        assert!(error.to_string().contains("corrupt"));
        let manifest = read_audit_manifest(directory.path()).unwrap();
        assert_eq!(manifest.group_pubkey_xonly, group);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_secret_permissions_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x33; 16]);
        let signer =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 10).unwrap();
        let record = signer.secret_record_path();
        drop(signer);
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();

        let error =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 20).unwrap_err();
        assert!(format!("{error:#}").contains("permissions"));
    }

    #[test]
    fn a_second_signer_owner_cannot_open_the_same_runtime_concurrently() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x34; 16]);
        let first =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 10).unwrap();
        let error =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 11).unwrap_err();
        assert!(error.to_string().contains("already owned"));
        drop(first);
        assert!(PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 12).is_ok());
    }

    #[test]
    fn manifest_wallet_or_participant_drift_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x35; 16]);
        let signer =
            PersistentSigner::open_or_initialize(directory.path(), wallet_id, 1, 10).unwrap();
        drop(signer);

        assert!(
            PersistentSigner::open_or_initialize(
                directory.path(),
                Uuid::from_bytes([0x36; 16]),
                1,
                20,
            )
            .is_err()
        );
        assert!(PersistentSigner::open_or_initialize(directory.path(), wallet_id, 2, 20).is_err());
    }

    #[test]
    fn encrypted_signer_backup_restores_the_same_group_without_exposing_key_fields() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("wallet");
        let bundle = directory.path().join("backup");
        fs::create_dir(&bundle).unwrap();
        let wallet_id = Uuid::from_bytes([0x37; 16]);
        let signer = PersistentSigner::open_or_initialize(&data_dir, wallet_id, 1, 10).unwrap();
        let expected = signer.audit_manifest();
        drop(signer);
        let backup_backend = FileSecretBackend::open(
            directory.path().join("backup-secrets"),
            RuntimeProfile::Development,
        )
        .unwrap();

        let exported = export_backup_attachment(&data_dir, &bundle, &backup_backend).unwrap();
        assert_eq!(exported, Some(expected.clone()));
        let envelope = fs::read_to_string(bundle.join(SIGNER_BACKUP_FILE)).unwrap();
        assert!(!envelope.contains("key_package"));
        assert!(!envelope.contains("signing_share"));
        assert!(!envelope.contains("secret_handle"));
        assert_eq!(
            verify_backup_attachment(&bundle, &backup_backend).unwrap(),
            Some(expected.clone())
        );

        fs::remove_file(data_dir.join(MANIFEST_FILE)).unwrap();
        fs::remove_dir_all(data_dir.join(SECRET_DIRECTORY)).unwrap();
        assert_eq!(
            restore_backup_attachment(&bundle, &data_dir, &backup_backend, wallet_id).unwrap(),
            Some(expected.clone())
        );
        let restored = PersistentSigner::open_or_initialize(&data_dir, wallet_id, 1, 20).unwrap();
        assert_eq!(restored.audit_manifest(), expected);
    }

    #[test]
    fn signer_backup_tampering_is_rejected_before_restore() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("wallet");
        let bundle = directory.path().join("backup");
        fs::create_dir(&bundle).unwrap();
        let wallet_id = Uuid::from_bytes([0x38; 16]);
        drop(PersistentSigner::open_or_initialize(&data_dir, wallet_id, 1, 10).unwrap());
        let backup_backend = FileSecretBackend::open(
            directory.path().join("backup-secrets"),
            RuntimeProfile::Development,
        )
        .unwrap();
        export_backup_attachment(&data_dir, &bundle, &backup_backend).unwrap();
        let path = bundle.join(SIGNER_BACKUP_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(verify_backup_attachment(&bundle, &backup_backend).is_err());
    }
}
