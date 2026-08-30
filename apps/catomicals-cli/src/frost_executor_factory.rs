//! Production Bitcoin and Fractal FROST executor construction.
//!
//! The durable wallet snapshot contains only an opaque manifest handle. The
//! manifest contains public signer bindings and provider references; private
//! shares, client keys and bearer credentials remain inside the registered
//! provider implementations.

use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
};

use bitcoin::XOnlyPublicKey;
use catomicals_chain_bitcoin::{
    BitcoinChainSuite, FractalFrostExecutionAdapter, FractalFrostSessionContext,
};
use catomicals_chain_domain::{ChainId, ChainScope};
use catomicals_secret_store::SecretBackend;
use catomicals_signer_transport::{
    MtlsSignerClient, RemoteSignerProvider, TransportError, TransportLimits, WireErrorCode,
    private_ca_client_config,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    BoundParticipant, DeviceHealth, GuardedSignerProvider, LocalEncryptedFrostBackend,
    LocalFrostParticipant, NonceGuard, ProviderError, ProviderIdentity, ProviderRequestAuthorizer,
    ProviderRound, PublicKeyPackage, SIGNER_PROVIDER_PROTOCOL_VERSION, SignatureShare,
    SignerAbortRequest, SignerProvider, SignerProviderKind, SignerRequestContext,
    SignerRoundOneRequest, SignerRoundTwoRequest, SigningCommitments, ThresholdSessionMachine,
    group_pubkey_xonly, participant_identifier, signature_to_bytes,
};
use catomicals_wallet::{
    BitcoinExecutionClaim, BitcoinExecutionClaimStore, BitcoinThresholdChainSigningExecutor,
    BitcoinThresholdCoordinator, ChainSigningExecution, ChainSigningExecutor,
    FractalExecutionClaimStore, FractalThresholdChainSigningExecutor, FractalThresholdCoordinator,
    NativeFractalThresholdFinalizer, SignerProfile, SignerProfileStartupSnapshot,
};
use frost_secp256k1_tr::keys::KeyPackage;
use rand::{RngCore, rngs::OsRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::wallet_executor_bootstrap::{ExecutorFactoryError, StartupExecutorBuilder};

pub const FROST_SIGNER_MANIFEST_VERSION: u16 = 1;
pub const FROST_SIGNER_MANIFEST_MAX_BYTES: usize = 64 * 1024;
pub const FROST_PROVIDER_SECRET_VERSION: u16 = 1;
const FROST_PROVIDER_SECRET_MAX_BYTES: usize = 64 * 1024;
const FROST_TLS_VALUE_MAX_BYTES: usize = 256 * 1024;

pub trait FrostSignerManifestSource: Send + Sync {
    fn load(&self, secret_ref: &str) -> Result<Vec<u8>, String>;
}

/// Loads bounded manifests from one preconfigured directory. Only relative
/// `encrypted-file://` handles are accepted.
#[allow(dead_code)] // Public bootstrap seam; construction lives in wallet_serve wiring.
pub struct FileFrostSignerManifestSource {
    root: PathBuf,
}

impl FileFrostSignerManifestSource {
    #[allow(dead_code)] // Public bootstrap seam; construction lives in wallet_serve wiring.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        if !root.is_dir() {
            return Err("FROST manifest root is not a directory".to_owned());
        }
        Ok(Self { root })
    }
}

impl FrostSignerManifestSource for FileFrostSignerManifestSource {
    fn load(&self, secret_ref: &str) -> Result<Vec<u8>, String> {
        let relative = secret_ref
            .strip_prefix("encrypted-file://")
            .ok_or_else(|| "unsupported FROST manifest reference".to_owned())?;
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err("invalid FROST manifest path".to_owned());
        }
        let path = fs::canonicalize(self.root.join(relative)).map_err(|error| error.to_string())?;
        if !path.starts_with(&self.root) || !path.is_file() {
            return Err("FROST manifest escaped its configured root".to_owned());
        }
        let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
        if metadata.len() == 0 || metadata.len() > FROST_SIGNER_MANIFEST_MAX_BYTES as u64 {
            return Err("FROST manifest size is invalid".to_owned());
        }
        fs::read(path).map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostProviderKindV1 {
    LocalEncrypted,
    RemoteMtls,
}

impl FrostProviderKindV1 {
    fn provider_kind(self) -> SignerProviderKind {
        match self {
            Self::LocalEncrypted => SignerProviderKind::LocalEncrypted,
            Self::RemoteMtls => SignerProviderKind::RemoteMtls,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrostOnlineSignerV1 {
    pub signer_id: u16,
    pub provider_kind: FrostProviderKindV1,
    pub provider_ref: String,
    pub device_id: Uuid,
    pub device_generation: u64,
    pub verifying_share_digest_hex: String,
    pub mtls_spki_sha256_hex: Option<String>,
}

impl core::fmt::Debug for FrostOnlineSignerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FrostOnlineSignerV1")
            .field("signer_id", &self.signer_id)
            .field("provider_kind", &self.provider_kind)
            .field("provider_ref", &"<opaque>")
            .field("device_id", &self.device_id)
            .field("device_generation", &self.device_generation)
            .field(
                "verifying_share_digest_hex",
                &self.verifying_share_digest_hex,
            )
            .field("mtls_spki_sha256_hex", &self.mtls_spki_sha256_hex)
            .finish()
    }
}

impl FrostOnlineSignerV1 {
    pub fn from_identity(
        provider_ref: String,
        provider_kind: FrostProviderKindV1,
        identity: &ProviderIdentity,
        mtls_spki_sha256: Option<[u8; 32]>,
    ) -> Self {
        Self {
            signer_id: identity.signer_id,
            provider_kind,
            provider_ref,
            device_id: identity.device_id,
            device_generation: identity.device_generation,
            verifying_share_digest_hex: hex::encode(identity.verifying_share_digest),
            mtls_spki_sha256_hex: mtls_spki_sha256.map(hex::encode),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrostSignerManifestV1 {
    pub format_version: u16,
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub threshold: u16,
    pub max_signers: u16,
    pub group_pubkey_xonly_hex: String,
    pub public_key_package_hex: String,
    pub online_signers: [FrostOnlineSignerV1; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_signer: Option<FrostOnlineSignerV1>,
}

impl core::fmt::Debug for FrostSignerManifestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FrostSignerManifestV1")
            .field("format_version", &self.format_version)
            .field("profile_id", &self.profile_id)
            .field("wallet_id", &self.wallet_id)
            .field("chain_scope", &self.chain_scope)
            .field("signing_suite_id", &self.signing_suite_id)
            .field("signer_set_id", &self.signer_set_id)
            .field("signer_epoch", &self.signer_epoch)
            .field("online_signers", &self.online_signers)
            .field("recovery_signer", &self.recovery_signer)
            .finish_non_exhaustive()
    }
}

impl FrostSignerManifestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: Uuid,
        wallet_id: Uuid,
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        signer_set_id: Uuid,
        signer_epoch: u64,
        public_key_package: Vec<u8>,
        online_signers: [FrostOnlineSignerV1; 2],
    ) -> Self {
        let group_pubkey_xonly_hex = PublicKeyPackage::deserialize(&public_key_package)
            .and_then(|package| group_pubkey_xonly(&package))
            .map(hex::encode)
            .unwrap_or_default();
        Self {
            format_version: FROST_SIGNER_MANIFEST_VERSION,
            profile_id,
            wallet_id,
            chain_scope,
            signing_suite_id,
            signer_set_id,
            signer_epoch,
            threshold: 2,
            max_signers: 3,
            group_pubkey_xonly_hex,
            public_key_package_hex: hex::encode(public_key_package),
            online_signers,
            recovery_signer: None,
        }
    }

    #[allow(dead_code)] // Provisioning uses this; path-included factory tests build legacy manifests.
    pub fn with_recovery_signer(mut self, recovery_signer: FrostOnlineSignerV1) -> Self {
        self.recovery_signer = Some(recovery_signer);
        self
    }
}

/// Encrypted provider configuration. This value is itself stored behind the
/// descriptor's opaque `provider_ref`; TLS and key material remain behind
/// additional opaque secret handles.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FrostProviderSecretV1 {
    LocalEncrypted {
        format_version: u16,
        key_package_hex: String,
    },
    RemoteMtls {
        format_version: u16,
        address: String,
        server_name: String,
        server_ca_certificate_der_ref: String,
        client_certificate_der_refs: Vec<String>,
        client_private_key_pkcs8_der_ref: String,
    },
}

impl core::fmt::Debug for FrostProviderSecretV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LocalEncrypted { format_version, .. } => formatter
                .debug_struct("LocalEncrypted")
                .field("format_version", format_version)
                .field("key_package", &"<redacted>")
                .finish(),
            Self::RemoteMtls {
                format_version,
                address,
                server_name,
                client_certificate_der_refs,
                ..
            } => formatter
                .debug_struct("RemoteMtls")
                .field("format_version", format_version)
                .field("address", address)
                .field("server_name", server_name)
                .field("certificate_count", &client_certificate_der_refs.len())
                .field("secret_refs", &"<redacted>")
                .finish(),
        }
    }
}

impl FrostProviderSecretV1 {
    pub fn local_encrypted(key_package: Vec<u8>) -> Self {
        Self::LocalEncrypted {
            format_version: FROST_PROVIDER_SECRET_VERSION,
            key_package_hex: hex::encode(key_package),
        }
    }

    pub fn remote_mtls(
        address: String,
        server_name: String,
        server_ca_certificate_der_ref: String,
        client_certificate_der_refs: Vec<String>,
        client_private_key_pkcs8_der_ref: String,
    ) -> Self {
        Self::RemoteMtls {
            format_version: FROST_PROVIDER_SECRET_VERSION,
            address,
            server_name,
            server_ca_certificate_der_ref,
            client_certificate_der_refs,
            client_private_key_pkcs8_der_ref,
        }
    }
}

pub type LoadedFrostSignerProvider = (Box<dyn SignerProvider>, Option<[u8; 32]>);

pub trait FrostSignerProviderLoader: Send + Sync {
    fn load(
        &self,
        descriptor: &FrostOnlineSignerV1,
        expected_identity: ProviderIdentity,
        public_key_package: &PublicKeyPackage,
    ) -> Result<LoadedFrostSignerProvider, String>;
}

/// Resolves encrypted provider descriptors only when a matching profile is
/// bootstrapped. Plaintext secret values are held in zeroizing backend values
/// and are never copied into the signer manifest.
pub struct SecretBackedFrostProviderLoader {
    backend: Arc<dyn SecretBackend>,
}

impl SecretBackedFrostProviderLoader {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self { backend }
    }

    fn resolve_secret(&self, reference: &str, maximum: usize) -> Result<Vec<u8>, String> {
        if !valid_opaque_reference(reference) {
            return Err("invalid FROST secret reference".to_owned());
        }
        let secret = self
            .backend
            .get_raw(reference)
            .map_err(|_| "FROST secret is unavailable".to_owned())?;
        if secret.expose().is_empty() || secret.expose().len() > maximum {
            return Err("FROST secret size is invalid".to_owned());
        }
        Ok(secret.expose().to_vec())
    }
}

impl core::fmt::Debug for SecretBackedFrostProviderLoader {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SecretBackedFrostProviderLoader")
            .field("backend", &self.backend.backend_name())
            .finish_non_exhaustive()
    }
}

impl FrostSignerProviderLoader for SecretBackedFrostProviderLoader {
    fn load(
        &self,
        descriptor: &FrostOnlineSignerV1,
        expected_identity: ProviderIdentity,
        public_key_package: &PublicKeyPackage,
    ) -> Result<LoadedFrostSignerProvider, String> {
        let encoded =
            self.resolve_secret(&descriptor.provider_ref, FROST_PROVIDER_SECRET_MAX_BYTES)?;
        let secret: FrostProviderSecretV1 = serde_json::from_slice(&encoded)
            .map_err(|_| "invalid FROST provider secret".to_owned())?;
        match (descriptor.provider_kind, secret) {
            (
                FrostProviderKindV1::LocalEncrypted,
                FrostProviderSecretV1::LocalEncrypted {
                    format_version,
                    key_package_hex,
                },
            ) => {
                if format_version != FROST_PROVIDER_SECRET_VERSION {
                    return Err("unsupported FROST provider secret version".to_owned());
                }
                let key_bytes = hex::decode(key_package_hex)
                    .map_err(|_| "invalid encrypted FROST key package".to_owned())?;
                let key_package = KeyPackage::deserialize(&key_bytes)
                    .map_err(|_| "invalid encrypted FROST key package".to_owned())?;
                let identifier = participant_identifier(descriptor.signer_id)
                    .map_err(|_| "invalid FROST signer id".to_owned())?;
                if public_key_package.verifying_shares().get(&identifier)
                    != Some(key_package.verifying_share())
                {
                    return Err("encrypted FROST share drifted".to_owned());
                }
                let participant = LocalFrostParticipant::new(
                    descriptor.signer_id,
                    key_package,
                    NonceGuard::new(),
                )
                .map_err(|_| "invalid encrypted FROST share".to_owned())?;
                let backend = LocalEncryptedFrostBackend::new(
                    participant,
                    public_key_package.clone(),
                    WalletExecutionContextAuthorizer,
                );
                Ok((
                    Box::new(GuardedSignerProvider::new(expected_identity, backend)),
                    None,
                ))
            }
            (
                FrostProviderKindV1::RemoteMtls,
                FrostProviderSecretV1::RemoteMtls {
                    format_version,
                    address,
                    server_name,
                    server_ca_certificate_der_ref,
                    client_certificate_der_refs,
                    client_private_key_pkcs8_der_ref,
                },
            ) => {
                if format_version != FROST_PROVIDER_SECRET_VERSION
                    || server_name.is_empty()
                    || server_name.len() > 253
                    || client_certificate_der_refs.is_empty()
                    || client_certificate_der_refs.len() > 4
                {
                    return Err("invalid FROST mTLS provider configuration".to_owned());
                }
                let address = address
                    .parse()
                    .map_err(|_| "invalid FROST signer address".to_owned())?;
                let server_ca = CertificateDer::from(
                    self.resolve_secret(&server_ca_certificate_der_ref, FROST_TLS_VALUE_MAX_BYTES)?,
                );
                let certificate_chain = client_certificate_der_refs
                    .iter()
                    .map(|reference| {
                        self.resolve_secret(reference, FROST_TLS_VALUE_MAX_BYTES)
                            .map(CertificateDer::from)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let private_key =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.resolve_secret(
                        &client_private_key_pkcs8_der_ref,
                        FROST_TLS_VALUE_MAX_BYTES,
                    )?));
                let pin = descriptor
                    .mtls_spki_sha256_hex
                    .as_deref()
                    .ok_or_else(|| "missing FROST signer SPKI pin".to_owned())
                    .and_then(decode32)?;
                let tls = private_ca_client_config(server_ca, certificate_chain, private_key)
                    .map_err(|_| "invalid FROST mTLS client identity".to_owned())?;
                let client =
                    MtlsSignerClient::new(tls, server_name, pin, TransportLimits::default());
                let remote = RemoteSignerProvider::new(expected_identity, address, client);
                Ok((
                    Box::new(RemoteMtlsSignerProviderAdapter::new(remote)?),
                    Some(pin),
                ))
            }
            _ => Err("FROST provider kind does not match its encrypted descriptor".to_owned()),
        }
    }
}

struct WalletExecutionContextAuthorizer;

impl ProviderRequestAuthorizer for WalletExecutionContextAuthorizer {
    fn authorize(
        &mut self,
        context: &SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        if context.operation_id.is_nil()
            || context.intent_id.is_nil()
            || context.session_id == [0; 32]
            || context.policy_digest == [0; 32]
            || context.chain_snapshot_digest == [0; 32]
            || context.min_signers != 2
            || context.max_signers != 3
        {
            return Err(ProviderError::IdentityDrift);
        }
        Ok(())
    }
}

fn valid_opaque_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 1_024
        && reference.starts_with("encrypted-file://")
        && !reference.bytes().any(|byte| byte.is_ascii_whitespace())
}

#[derive(Clone)]
struct RegisteredProvider {
    provider: Arc<Mutex<Box<dyn SignerProvider>>>,
    identity: ProviderIdentity,
    kind: SignerProviderKind,
    mtls_spki_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Default)]
pub struct SharedFrostProviderRegistry {
    providers: Arc<Mutex<BTreeMap<String, RegisteredProvider>>>,
}

impl SharedFrostProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        provider_ref: String,
        provider: Box<dyn SignerProvider>,
        mtls_spki_sha256: Option<[u8; 32]>,
    ) -> Result<(), String> {
        if provider_ref.is_empty() || provider_ref.len() > 512 {
            return Err("invalid FROST provider reference".to_owned());
        }
        let kind = provider.kind();
        if (kind == SignerProviderKind::RemoteMtls) != mtls_spki_sha256.is_some() {
            return Err("remote FROST provider pin binding is invalid".to_owned());
        }
        let registered = RegisteredProvider {
            identity: provider.identity().clone(),
            kind,
            mtls_spki_sha256,
            provider: Arc::new(Mutex::new(provider)),
        };
        let mut providers = self
            .providers
            .lock()
            .map_err(|_| "FROST provider registry lock poisoned".to_owned())?;
        if providers.insert(provider_ref, registered).is_some() {
            return Err("duplicate FROST provider reference".to_owned());
        }
        Ok(())
    }

    fn register_if_absent(
        &self,
        provider_ref: String,
        provider: Box<dyn SignerProvider>,
        mtls_spki_sha256: Option<[u8; 32]>,
    ) -> Result<(), String> {
        if provider_ref.is_empty() || provider_ref.len() > 512 {
            return Err("invalid FROST provider reference".to_owned());
        }
        let kind = provider.kind();
        if (kind == SignerProviderKind::RemoteMtls) != mtls_spki_sha256.is_some() {
            return Err("remote FROST provider pin binding is invalid".to_owned());
        }
        let registered = RegisteredProvider {
            identity: provider.identity().clone(),
            kind,
            mtls_spki_sha256,
            provider: Arc::new(Mutex::new(provider)),
        };
        self.providers
            .lock()
            .map_err(|_| "FROST provider registry lock poisoned".to_owned())?
            .entry(provider_ref)
            .or_insert(registered);
        Ok(())
    }

    fn resolve(&self, descriptor: &FrostOnlineSignerV1) -> Result<RegisteredProvider, String> {
        let registered = self
            .providers
            .lock()
            .map_err(|_| "FROST provider registry lock poisoned".to_owned())?
            .get(&descriptor.provider_ref)
            .cloned()
            .ok_or_else(|| "FROST provider is unavailable".to_owned())?;
        let expected_digest = decode32(&descriptor.verifying_share_digest_hex)?;
        let expected_spki = descriptor
            .mtls_spki_sha256_hex
            .as_deref()
            .map(decode32)
            .transpose()?;
        if registered.kind != descriptor.provider_kind.provider_kind()
            || registered.identity.signer_id != descriptor.signer_id
            || registered.identity.device_id != descriptor.device_id
            || registered.identity.device_generation != descriptor.device_generation
            || registered.identity.verifying_share_digest != expected_digest
            || registered.mtls_spki_sha256 != expected_spki
        {
            return Err("FROST provider identity or certificate pin drifted".to_owned());
        }
        Ok(registered)
    }
}

/// Synchronous provider facade over the async mTLS transport. A dedicated
/// single-worker runtime avoids borrowing the wallet's request runtime.
#[allow(dead_code)] // Public bootstrap seam; construction lives in wallet_serve wiring.
pub struct RemoteMtlsSignerProviderAdapter {
    identity: ProviderIdentity,
    worker: mpsc::Sender<RemoteProviderCommand>,
}

enum RemoteProviderCommand {
    Health(mpsc::SyncSender<Result<DeviceHealth, ProviderError>>),
    RoundOne(
        SignerRoundOneRequest,
        mpsc::SyncSender<Result<catomicals_threshold::SignerRoundOneResponse, ProviderError>>,
    ),
    RoundTwo(
        SignerRoundTwoRequest,
        mpsc::SyncSender<Result<catomicals_threshold::SignerRoundTwoResponse, ProviderError>>,
    ),
    Abort(
        SignerAbortRequest,
        mpsc::SyncSender<Result<(), ProviderError>>,
    ),
}

impl RemoteMtlsSignerProviderAdapter {
    #[allow(dead_code)] // Public bootstrap seam; construction lives in wallet_serve wiring.
    pub fn new(remote: RemoteSignerProvider) -> Result<Self, String> {
        let identity = remote.identity().clone();
        let (worker, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("catomicals-frost-mtls".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };
                while let Ok(command) = receiver.recv() {
                    match command {
                        RemoteProviderCommand::Health(reply) => {
                            let _ = reply.send(
                                runtime
                                    .block_on(remote.health())
                                    .map_err(map_transport_error),
                            );
                        }
                        RemoteProviderCommand::RoundOne(request, reply) => {
                            let _ = reply.send(
                                runtime
                                    .block_on(remote.round_one(request))
                                    .map_err(map_transport_error),
                            );
                        }
                        RemoteProviderCommand::RoundTwo(request, reply) => {
                            let _ = reply.send(
                                runtime
                                    .block_on(remote.round_two(request))
                                    .map_err(map_transport_error),
                            );
                        }
                        RemoteProviderCommand::Abort(request, reply) => {
                            let _ = reply.send(
                                runtime
                                    .block_on(remote.abort(request))
                                    .map_err(map_transport_error),
                            );
                        }
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self { identity, worker })
    }

    fn dispatch<T>(
        &self,
        build: impl FnOnce(mpsc::SyncSender<Result<T, ProviderError>>) -> RemoteProviderCommand,
    ) -> Result<T, ProviderError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.worker
            .send(build(reply))
            .map_err(|_| ProviderError::BackendUnavailable)?;
        response
            .recv()
            .map_err(|_| ProviderError::BackendUnavailable)?
    }
}

impl SignerProvider for RemoteMtlsSignerProviderAdapter {
    fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    fn kind(&self) -> SignerProviderKind {
        SignerProviderKind::RemoteMtls
    }

    fn health(&mut self, now: i64) -> DeviceHealth {
        self.dispatch(RemoteProviderCommand::Health)
            .unwrap_or_else(|error| DeviceHealth {
                online: false,
                checked_at: Some(now),
                last_success_at: None,
                last_error_code: Some(error.to_string()),
            })
    }

    fn round_one(
        &mut self,
        request: SignerRoundOneRequest,
        _now: i64,
    ) -> Result<catomicals_threshold::SignerRoundOneResponse, ProviderError> {
        self.dispatch(|reply| RemoteProviderCommand::RoundOne(request, reply))
    }

    fn round_two(
        &mut self,
        request: SignerRoundTwoRequest,
        _now: i64,
    ) -> Result<catomicals_threshold::SignerRoundTwoResponse, ProviderError> {
        self.dispatch(|reply| RemoteProviderCommand::RoundTwo(request, reply))
    }

    fn abort(&mut self, request: SignerAbortRequest, _now: i64) -> Result<(), ProviderError> {
        self.dispatch(|reply| RemoteProviderCommand::Abort(request, reply))
    }
}

#[allow(dead_code)] // Used by the remote adapter once wallet_serve injects it.
fn map_transport_error(error: TransportError) -> ProviderError {
    match error {
        TransportError::PeerPinMismatch => ProviderError::SpkiMismatch,
        TransportError::Remote(code) => match code {
            WireErrorCode::Unconfigured => ProviderError::Unconfigured,
            WireErrorCode::Revoked => ProviderError::Revoked,
            WireErrorCode::IdentityDrift => ProviderError::IdentityDrift,
            WireErrorCode::Expired => ProviderError::Expired,
            WireErrorCode::Replay => ProviderError::Replay,
            WireErrorCode::InvalidRequest => ProviderError::InvalidEncoding,
            WireErrorCode::RoundBindingMismatch => ProviderError::RoundBindingMismatch,
            WireErrorCode::BackendUnavailable | WireErrorCode::Internal => {
                ProviderError::BackendUnavailable
            }
        },
        _ => ProviderError::BackendUnavailable,
    }
}

#[derive(Clone)]
struct ValidatedManifest {
    public_key_package: PublicKeyPackage,
    group_pubkey_xonly: [u8; 32],
    providers: [RegisteredProvider; 2],
}

pub struct FrostStartupExecutorBuilder {
    source: Box<dyn FrostSignerManifestSource>,
    registry: SharedFrostProviderRegistry,
    loader: Option<Arc<dyn FrostSignerProviderLoader>>,
}

impl FrostStartupExecutorBuilder {
    pub fn new(
        source: Box<dyn FrostSignerManifestSource>,
        registry: SharedFrostProviderRegistry,
    ) -> Self {
        Self {
            source,
            registry,
            loader: None,
        }
    }

    pub fn with_loader(
        source: Box<dyn FrostSignerManifestSource>,
        registry: SharedFrostProviderRegistry,
        loader: Arc<dyn FrostSignerProviderLoader>,
    ) -> Self {
        Self {
            source,
            registry,
            loader: Some(loader),
        }
    }

    fn validate(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<ValidatedManifest, ExecutorFactoryError> {
        let bytes = self
            .source
            .load(&snapshot.secret_ref)
            .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
        if bytes.is_empty() || bytes.len() > FROST_SIGNER_MANIFEST_MAX_BYTES {
            return Err(ExecutorFactoryError::InvalidConfiguration);
        }
        let manifest: FrostSignerManifestV1 = serde_json::from_slice(&bytes)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let signer_set_id = Uuid::parse_str(&snapshot.signer_set_id)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let expected_group_key = decode32(&snapshot.verification_key_hex)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        if manifest.format_version != FROST_SIGNER_MANIFEST_VERSION
            || manifest.profile_id != snapshot.profile_id
            || manifest.wallet_id != snapshot.wallet_id
            || manifest.chain_scope != snapshot.chain_scope
            || manifest.signing_suite_id != snapshot.signing_suite_id
            || manifest.signer_set_id != signer_set_id
            || manifest.signer_epoch != snapshot.signer_epoch
            || manifest.threshold != 2
            || manifest.max_signers != 3
            || snapshot.threshold != 2
            || snapshot.max_signers != 3
            || snapshot.backend_requirement != SignerBackendRequirement::FrostSecp256k1Tr
            || decode32(&manifest.group_pubkey_xonly_hex).ok() != Some(expected_group_key)
        {
            return Err(ExecutorFactoryError::UnsupportedProfile);
        }
        let package_bytes = hex::decode(&manifest.public_key_package_hex)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let public_key_package = PublicKeyPackage::deserialize(&package_bytes)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        if public_key_package.verifying_shares().len() != 3
            || group_pubkey_xonly(&public_key_package).ok() != Some(expected_group_key)
        {
            return Err(ExecutorFactoryError::UnsupportedProfile);
        }
        let mut signer_ids = HashSet::new();
        let mut provider_refs = HashSet::new();
        let mut device_ids = HashSet::new();
        for descriptor in manifest
            .online_signers
            .iter()
            .chain(manifest.recovery_signer.iter())
        {
            let identifier = participant_identifier(descriptor.signer_id)
                .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
            let verifying_share = public_key_package
                .verifying_shares()
                .get(&identifier)
                .ok_or(ExecutorFactoryError::InvalidConfiguration)?;
            let digest: [u8; 32] = Sha256::digest(
                verifying_share
                    .serialize()
                    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?,
            )
            .into();
            if !signer_ids.insert(descriptor.signer_id)
                || !provider_refs.insert(descriptor.provider_ref.as_str())
                || !device_ids.insert(descriptor.device_id)
                || decode32(&descriptor.verifying_share_digest_hex).ok() != Some(digest)
                || (descriptor.provider_kind == FrostProviderKindV1::RemoteMtls)
                    != descriptor.mtls_spki_sha256_hex.is_some()
            {
                return Err(ExecutorFactoryError::InvalidConfiguration);
            }
        }
        if let Some(loader) = &self.loader {
            for descriptor in manifest
                .online_signers
                .iter()
                .chain(manifest.recovery_signer.iter())
            {
                if self.registry.resolve(descriptor).is_ok() {
                    continue;
                }
                let identity = ProviderIdentity {
                    wallet_id: manifest.wallet_id,
                    signer_set_id: manifest.signer_set_id,
                    signer_epoch: manifest.signer_epoch,
                    signer_id: descriptor.signer_id,
                    device_id: descriptor.device_id,
                    device_generation: descriptor.device_generation,
                    group_pubkey_xonly: expected_group_key,
                    verifying_share_digest: decode32(&descriptor.verifying_share_digest_hex)
                        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?,
                };
                let (provider, pin) = loader
                    .load(descriptor, identity, &public_key_package)
                    .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
                self.registry
                    .register_if_absent(descriptor.provider_ref.clone(), provider, pin)
                    .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
            }
        }
        let first = self
            .registry
            .resolve(&manifest.online_signers[0])
            .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
        let second = self
            .registry
            .resolve(&manifest.online_signers[1])
            .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
        for provider in [&first, &second] {
            let identity = &provider.identity;
            if identity.wallet_id != snapshot.wallet_id
                || identity.signer_set_id != signer_set_id
                || identity.signer_epoch != snapshot.signer_epoch
                || identity.group_pubkey_xonly != expected_group_key
            {
                return Err(ExecutorFactoryError::ProviderUnavailable);
            }
        }
        Ok(ValidatedManifest {
            public_key_package,
            group_pubkey_xonly: expected_group_key,
            providers: [first, second],
        })
    }
}

impl StartupExecutorBuilder for FrostStartupExecutorBuilder {
    fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
        let validated = self.validate(snapshot)?;
        let xonly = XOnlyPublicKey::from_slice(&validated.group_pubkey_xonly)
            .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let profile = SignerProfile::new(
            snapshot.profile_id,
            snapshot.wallet_id,
            snapshot.chain_scope,
            snapshot.signing_suite_id,
            snapshot.backend_requirement,
            snapshot.signer_set_id.clone(),
            snapshot.authorization_signer_id.clone(),
            snapshot.signer_epoch,
            snapshot.threshold,
            snapshot.max_signers,
            validated.group_pubkey_xonly.to_vec(),
            snapshot.secret_ref.clone(),
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let coordinator = ProviderThresholdCoordinator::new(&validated);
        match snapshot.chain_scope.chain {
            ChainId::Bitcoin
                if snapshot.signing_suite_id == SigningSuiteId::BITCOIN_BIP340_FROST_V1 =>
            {
                let suite = BitcoinChainSuite::new(snapshot.chain_scope, xonly)
                    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
                BitcoinThresholdChainSigningExecutor::new(
                    profile,
                    suite,
                    Box::new(coordinator),
                    Box::new(ProcessBitcoinClaimStore::default()),
                )
                .map(|executor| Box::new(executor) as Box<dyn ChainSigningExecutor>)
                .map_err(|_| ExecutorFactoryError::InvalidConfiguration)
            }
            ChainId::FractalBitcoin
                if snapshot.signing_suite_id == SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1 =>
            {
                let suite = BitcoinChainSuite::new(snapshot.chain_scope, xonly)
                    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
                let adapter = FractalFrostExecutionAdapter::new(
                    snapshot.chain_scope,
                    xonly,
                    snapshot.signer_set_id.clone(),
                    snapshot.signer_epoch,
                )
                .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
                FractalThresholdChainSigningExecutor::new(
                    profile,
                    Box::new(suite),
                    Box::new(coordinator),
                    Box::new(ProcessFractalClaimStore::default()),
                    Box::new(NativeFractalThresholdFinalizer::new(adapter)),
                )
                .map(|executor| Box::new(executor) as Box<dyn ChainSigningExecutor>)
                .map_err(|_| ExecutorFactoryError::InvalidConfiguration)
            }
            _ => Err(ExecutorFactoryError::UnsupportedProfile),
        }
    }
}

struct ProviderThresholdCoordinator {
    public_key_package: PublicKeyPackage,
    group_pubkey_xonly: [u8; 32],
    providers: [RegisteredProvider; 2],
}

impl ProviderThresholdCoordinator {
    fn new(validated: &ValidatedManifest) -> Self {
        Self {
            public_key_package: validated.public_key_package.clone(),
            group_pubkey_xonly: validated.group_pubkey_xonly,
            providers: validated.providers.clone(),
        }
    }

    fn sign_execution(
        &mut self,
        execution: &ChainSigningExecution,
        signing_message: [u8; 32],
        now: i64,
    ) -> Result<[u8; 64], String> {
        if execution.job.review.signing_message_digest != signing_message {
            return Err("FROST signing message drifted".to_owned());
        }
        let mut participants = Vec::with_capacity(2);
        let mut round_one_contexts = Vec::with_capacity(2);
        for registered in &self.providers {
            let context = request_context(
                execution,
                &registered.identity,
                self.group_pubkey_xonly,
                random_nonce(),
            );
            participants.push(BoundParticipant {
                signer_id: registered.identity.signer_id,
                device_id: registered.identity.device_id,
                device_generation: registered.identity.device_generation,
                request_binding_digest: execution.operation_binding_digest,
            });
            round_one_contexts.push(context);
        }
        let mut machine = ThresholdSessionMachine::new(
            execution.job.session_id,
            signing_message,
            execution.job.policy_snapshot_digest,
            2,
            execution.job.expires_at,
            participants.clone(),
            self.public_key_package.clone(),
            now,
        )
        .map_err(|error| error.to_string())?;
        let result = (|| {
            for ((registered, participant), context) in self
                .providers
                .iter()
                .zip(&participants)
                .zip(&round_one_contexts)
            {
                let response = registered
                    .provider
                    .lock()
                    .map_err(|_| "FROST provider lock poisoned".to_owned())?
                    .round_one(
                        SignerRoundOneRequest {
                            context: context.clone(),
                        },
                        now,
                    )
                    .map_err(|error| error.to_string())?;
                if response.request_binding_digest != context.binding_digest() {
                    return Err("FROST round-one response binding drifted".to_owned());
                }
                let bytes = hex::decode(response.commitment_hex)
                    .map_err(|_| "FROST round-one encoding is invalid".to_owned())?;
                let commitment = SigningCommitments::deserialize(&bytes)
                    .map_err(|_| "FROST round-one encoding is invalid".to_owned())?;
                machine
                    .add_commitment(participant, commitment, now)
                    .map_err(|error| error.to_string())?;
            }
            let signing_package = machine
                .freeze_commitments(now)
                .map_err(|error| error.to_string())?
                .signing_package
                .serialize()
                .map_err(|error| error.to_string())?;
            for (registered, participant) in self.providers.iter().zip(&participants) {
                let context = request_context(
                    execution,
                    &registered.identity,
                    self.group_pubkey_xonly,
                    random_nonce(),
                );
                let response = registered
                    .provider
                    .lock()
                    .map_err(|_| "FROST provider lock poisoned".to_owned())?
                    .round_two(
                        SignerRoundTwoRequest {
                            context: context.clone(),
                            signing_package_hex: hex::encode(&signing_package),
                        },
                        now,
                    )
                    .map_err(|error| error.to_string())?;
                if response.request_binding_digest != context.binding_digest() {
                    return Err("FROST round-two response binding drifted".to_owned());
                }
                let bytes = hex::decode(response.signature_share_hex)
                    .map_err(|_| "FROST signature share encoding is invalid".to_owned())?;
                let share = SignatureShare::deserialize(&bytes)
                    .map_err(|_| "FROST signature share encoding is invalid".to_owned())?;
                machine
                    .add_signature_share(participant, share, now)
                    .map_err(|error| error.to_string())?;
            }
            let signature = machine.finalize(now).map_err(|error| error.to_string())?;
            signature_to_bytes(&signature).map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = machine.abort("coordinator_failed", now);
            for registered in &self.providers {
                let context = request_context(
                    execution,
                    &registered.identity,
                    self.group_pubkey_xonly,
                    random_nonce(),
                );
                if let Ok(mut provider) = registered.provider.lock() {
                    let _ = provider.abort(
                        SignerAbortRequest {
                            context,
                            reason_code: "coordinator_failed".to_owned(),
                        },
                        now,
                    );
                }
            }
        }
        result
    }
}

impl BitcoinThresholdCoordinator for ProviderThresholdCoordinator {
    fn sign(
        &mut self,
        execution: &ChainSigningExecution,
        claim: &BitcoinExecutionClaim,
        now: i64,
    ) -> Result<[u8; 64], String> {
        if claim.session_id != execution.job.session_id
            || claim.signing_message_digest != execution.job.review.signing_message_digest
            || claim.operation_binding_digest != execution.operation_binding_digest
        {
            return Err("Bitcoin FROST execution claim drifted".to_owned());
        }
        self.sign_execution(execution, claim.signing_message_digest, now)
    }
}

impl FractalThresholdCoordinator for ProviderThresholdCoordinator {
    fn sign(
        &mut self,
        execution: &ChainSigningExecution,
        session: &FractalFrostSessionContext<'_>,
        now: i64,
    ) -> Result<[u8; 64], String> {
        if session.signing_session_id() != execution.job.session_id
            || session.review_binding() != &execution.job.review_binding
            || session.signing_message() != execution.job.review.signing_message_digest
        {
            return Err("Fractal FROST session drifted".to_owned());
        }
        self.sign_execution(execution, session.signing_message(), now)
    }
}

fn request_context(
    execution: &ChainSigningExecution,
    identity: &ProviderIdentity,
    group_pubkey_xonly: [u8; 32],
    request_nonce: [u8; 32],
) -> SignerRequestContext {
    SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: execution.job.wallet_id,
        signer_set_id: identity.signer_set_id,
        signer_epoch: identity.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id: execution.job.job_id,
        intent_id: execution.job.intent_id,
        session_id: execution.job.session_id,
        taproot_sighash: execution.job.review.signing_message_digest,
        policy_digest: execution.job.policy_snapshot_digest,
        group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: 2,
        max_signers: 3,
        chain_snapshot_digest: execution.job.chain_snapshot_digest,
        request_nonce,
        expires_at: execution.job.expires_at,
    }
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn decode32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "expected 32-byte hexadecimal value".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "expected 32-byte hexadecimal value".to_owned())
}

#[derive(Default)]
struct ProcessBitcoinClaimStore {
    consumed: HashSet<[u8; 32]>,
}

impl BitcoinExecutionClaimStore for ProcessBitcoinClaimStore {
    fn claim(
        &mut self,
        replay_key: [u8; 32],
        _claim: &BitcoinExecutionClaim,
    ) -> Result<(), String> {
        if self.consumed.insert(replay_key) {
            Ok(())
        } else {
            Err("Bitcoin FROST session was already executed in this process".to_owned())
        }
    }
}

#[derive(Default)]
struct ProcessFractalClaimStore {
    consumed: HashSet<[u8; 32]>,
}

impl FractalExecutionClaimStore for ProcessFractalClaimStore {
    fn claim(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        bip341_digest: [u8; 32],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals/fractal-process-claim/v1\0");
        hasher.update(session_id);
        hasher.update(review_domain_separator);
        hasher.update(bip341_digest);
        hasher.update(operation_binding_digest);
        let replay_key: [u8; 32] = hasher.finalize().into();
        if self.consumed.insert(replay_key) {
            Ok(())
        } else {
            Err("Fractal FROST session was already executed in this process".to_owned())
        }
    }
}
