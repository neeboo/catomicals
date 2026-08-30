//! Production assembly for the wallet's BCH, BSV, and Kaspa CB-MPC executors.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    CB_MPC_ECDSA_SIGN_STAGES, CbMpcCancellation, CbMpcError, CbMpcRuntime, CbMpcRuntimeLimits,
    CbMpcShareProtector, CbMpcSignerSet, DurableSessionClaimStore, LocalCbMpcProvider, PartyId,
    SecretShareMaterial, SessionTransport, TransportFailure,
};
use catomicals_chain_bitcoin_cash::{
    BitcoinCashChainSuite, BitcoinCashSignatureAlgorithm, ForkIdSighashType,
};
use catomicals_chain_bsv::BsvChainSuite;
use catomicals_chain_domain::{ChainId, ChainNetwork, ChainScope, ChainSuite};
use catomicals_chain_kaspa::{KaspaChainSuite, KaspaVerifier};
use catomicals_secret_store::{OnePasswordWrappedPackageLoader, SecretBackend, SecretValue};
use catomicals_signer_transport::{
    certificate_spki_sha256, private_ca_client_config, private_ca_server_config,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{
    BitcoinCashCbMpcSignatureAssembler, BsvCbMpcSignatureAssembler, CbMpcChainSigningExecutor,
    CbMpcConsensusSignatureAssembler, CbMpcWalletCoordinator, ChainSigningExecutor,
    KaspaCbMpcSignatureAssembler, SignerProfile, SignerProfileStartupSnapshot,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use rustls::{
    ClientConnection, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const CB_MPC_MANIFEST_VERSION: u16 = 1;
pub const CB_MPC_RECOVERY_MANIFEST_VERSION: u16 = 2;
pub const CB_MPC_PROTOCOL_STAGES: u8 = CB_MPC_ECDSA_SIGN_STAGES;
pub const CB_MPC_TLS_IDENTITY_VERSION: u16 = 1;
pub const CB_MPC_RECEIVE_TIMEOUT: Duration = Duration::from_secs(15);
pub const CB_MPC_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
pub const CB_MPC_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

const SHARE_ENVELOPE_VERSION: u8 = 1;
const SHARE_NONCE_BYTES: usize = 24;
const SHARE_AAD_DOMAIN: &[u8] = b"catomicals.cb-mpc.share-envelope.v1\0";
const TRANSPORT_BINDING_DOMAIN: &[u8] = b"catomicals.cb-mpc.transport-binding.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"catomicals.cb-mpc.transport-transcript.v1\0";
const FRAME_MAGIC: &[u8; 8] = b"CATCMP01";
const FRAME_HEADER_BYTES: usize = 8 + 1 + 1 + 4 + 32 + 32 + 4;
const MAX_REFERENCE_BYTES: usize = 1_024;
const TLS_SERVER_NAME: &str = "cbmpc.local";
const MAX_TRANSPORT_FRAMES: u32 = 4_096;

type ChainComponents = (
    Box<dyn ChainSuite>,
    Box<dyn CbMpcConsensusSignatureAssembler>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbMpcSignerRefV1 {
    pub party_id: String,
    pub device_ref: String,
    pub sealed_share_ref: String,
    pub protector_key_ref: String,
    pub endpoint_ref: String,
    pub tls_identity_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbMpcRecoverySignerRefV1 {
    pub party_id: String,
    pub device_ref: String,
    pub sealed_share_ref: String,
    pub protector_key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbMpcExecutorManifestV1 {
    pub format_version: u16,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub signer_set_id: String,
    pub signer_epoch: u64,
    pub protocol_stages: u8,
    pub all_parties: [String; 3],
    pub active_signers: [CbMpcSignerRefV1; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_signer: Option<CbMpcRecoverySignerRefV1>,
    pub receiver: String,
}

impl CbMpcExecutorManifestV1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CbMpcFactoryError> {
        if bytes.len() > 64 * 1024 {
            return Err(CbMpcFactoryError::ManifestInvalid);
        }
        serde_json::from_slice(bytes).map_err(|_| CbMpcFactoryError::ManifestInvalid)
    }

    pub fn validate_for(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<(), CbMpcFactoryError> {
        let version_matches = match self.format_version {
            CB_MPC_MANIFEST_VERSION => self.recovery_signer.is_none(),
            CB_MPC_RECOVERY_MANIFEST_VERSION => self.recovery_signer.is_some(),
            _ => false,
        };
        let descriptor_matches = version_matches
            && self.wallet_id == snapshot.wallet_id
            && self.profile_id == snapshot.profile_id
            && self.chain_scope == snapshot.chain_scope
            && self.signing_suite_id == snapshot.signing_suite_id
            && self.signer_set_id == snapshot.signer_set_id
            && self.signer_epoch == snapshot.signer_epoch
            && self.protocol_stages == CB_MPC_PROTOCOL_STAGES
            && snapshot.backend_requirement == SignerBackendRequirement::CbMpcThresholdEcdsa
            && snapshot.threshold == 2
            && snapshot.max_signers == 3
            && suite_matches_chain(self.chain_scope.chain, self.signing_suite_id);
        if !descriptor_matches {
            return Err(CbMpcFactoryError::ManifestBindingMismatch);
        }
        if self.all_parties.windows(2).any(|pair| pair[0] >= pair[1])
            || self.active_signers[0].party_id >= self.active_signers[1].party_id
            || !self.active_signers.iter().all(|active| {
                self.all_parties.contains(&active.party_id)
                    && valid_reference(&active.device_ref)
                    && valid_reference(&active.sealed_share_ref)
                    && valid_reference(&active.protector_key_ref)
                    && valid_reference(&active.endpoint_ref)
                    && valid_reference(&active.tls_identity_ref)
            })
            || !self
                .active_signers
                .iter()
                .any(|active| active.party_id == self.receiver)
        {
            return Err(CbMpcFactoryError::ManifestInvalid);
        }
        let [first, second] = &self.active_signers;
        if first.device_ref == second.device_ref
            || first.sealed_share_ref == second.sealed_share_ref
            || first.endpoint_ref == second.endpoint_ref
            || first.tls_identity_ref == second.tls_identity_ref
        {
            return Err(CbMpcFactoryError::ManifestInvalid);
        }
        if self.recovery_signer.as_ref().is_some_and(|recovery| {
            !self.all_parties.contains(&recovery.party_id)
                || self
                    .active_signers
                    .iter()
                    .any(|active| active.party_id == recovery.party_id)
                || !valid_reference(&recovery.device_ref)
                || !valid_reference(&recovery.sealed_share_ref)
                || !valid_reference(&recovery.protector_key_ref)
                || self.active_signers.iter().any(|active| {
                    active.device_ref == recovery.device_ref
                        || active.sealed_share_ref == recovery.sealed_share_ref
                        || active.protector_key_ref == recovery.protector_key_ref
                })
        }) {
            return Err(CbMpcFactoryError::ManifestInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbMpcTlsIdentityRefsV1 {
    pub format_version: u16,
    pub certificate_der_ref: String,
    pub private_key_pkcs8_der_ref: String,
    pub peer_ca_certificate_der_ref: String,
    pub peer_spki_sha256_ref: String,
}

pub trait OpaqueSecretResolver: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<SecretValue, CbMpcFactoryError>;
}

pub struct SecretBackendResolver {
    backend: Arc<dyn SecretBackend>,
}

impl SecretBackendResolver {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self { backend }
    }
}

impl OpaqueSecretResolver for SecretBackendResolver {
    fn resolve(&self, reference: &str) -> Result<SecretValue, CbMpcFactoryError> {
        self.backend
            .get_raw(reference)
            .map_err(|_| CbMpcFactoryError::SecretUnavailable)
    }
}

pub struct OnePasswordSecretResolver {
    executable: PathBuf,
    timeout: Duration,
}

impl OnePasswordSecretResolver {
    pub fn new(executable: PathBuf, timeout: Duration) -> Result<Self, CbMpcFactoryError> {
        if !executable.is_absolute() || timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(CbMpcFactoryError::ManifestInvalid);
        }
        Ok(Self {
            executable,
            timeout,
        })
    }
}

impl OpaqueSecretResolver for OnePasswordSecretResolver {
    fn resolve(&self, reference: &str) -> Result<SecretValue, CbMpcFactoryError> {
        OnePasswordWrappedPackageLoader::new(
            self.executable.clone(),
            reference.to_owned(),
            self.timeout,
        )
        .and_then(|loader| loader.load())
        .map_err(|_| CbMpcFactoryError::SecretUnavailable)
    }
}

pub struct CbMpcProductionExecutorBuilder {
    resolver: Arc<dyn OpaqueSecretResolver>,
    claim_root: PathBuf,
}

impl CbMpcProductionExecutorBuilder {
    pub fn new(
        resolver: Arc<dyn OpaqueSecretResolver>,
        claim_root: PathBuf,
    ) -> Result<Self, CbMpcFactoryError> {
        validate_private_root(&claim_root)?;
        Ok(Self {
            resolver,
            claim_root,
        })
    }

    pub fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, CbMpcFactoryError> {
        let manifest_bytes = self.resolver.resolve(&snapshot.secret_ref)?;
        let manifest = CbMpcExecutorManifestV1::from_bytes(manifest_bytes.expose())?;
        manifest.validate_for(snapshot)?;
        let group_public_key = decode_group_public_key(&snapshot.verification_key_hex)?;
        let signer_set = CbMpcSignerSet::new(
            manifest.signer_set_id.clone(),
            manifest.signer_epoch,
            2,
            manifest
                .all_parties
                .iter()
                .map(|party| PartyId::new(party.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| CbMpcFactoryError::ManifestInvalid)?,
        )
        .map_err(|_| CbMpcFactoryError::ManifestInvalid)?;

        let providers = self.load_providers(snapshot, &manifest, group_public_key)?;
        if let Some(recovery) = &manifest.recovery_signer {
            self.validate_recovery_provider(snapshot, &manifest, recovery, group_public_key)?;
        }
        let transports = load_mtls_transport_pair(self.resolver.as_ref(), snapshot, &manifest)?;
        let claim_directory =
            private_claim_directory(&self.claim_root, snapshot.wallet_id, snapshot.profile_id)?;
        let claim_store = Arc::new(
            DurableSessionClaimStore::open(&claim_directory)
                .map_err(|_| CbMpcFactoryError::ClaimStoreUnavailable)?,
        );
        let runtime = CbMpcRuntime::new_native(runtime_limits()?, claim_store)
            .map_err(|_| CbMpcFactoryError::RuntimeUnavailable)?;
        let profile = profile_from_snapshot(snapshot)?;
        let coordinator = CbMpcWalletCoordinator::new(profile, signer_set, runtime)
            .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?;
        let (suite, assembler) = chain_components(snapshot.chain_scope, group_public_key)?;
        let executor = CbMpcChainSigningExecutor::new(
            suite,
            coordinator,
            providers,
            transports,
            assembler,
            CbMpcCancellation::new(),
        )
        .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?;
        Ok(Box::new(executor))
    }

    fn load_providers(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
        manifest: &CbMpcExecutorManifestV1,
        group_public_key: [u8; 33],
    ) -> Result<[LocalCbMpcProvider; 2], CbMpcFactoryError> {
        let load = |signer: CbMpcSignerRefV1| {
            let sealed = self.resolver.resolve(&signer.sealed_share_ref)?;
            let protector = ResolverBackedShareProtector {
                resolver: Arc::clone(&self.resolver),
                key_ref: signer.protector_key_ref.clone(),
                aad: share_aad(snapshot, manifest, &signer)?,
            };
            LocalCbMpcProvider::import_sealed(
                PartyId::new(signer.party_id).map_err(|_| CbMpcFactoryError::ManifestInvalid)?,
                group_public_key,
                sealed.expose(),
                &protector,
            )
            .map_err(|_| CbMpcFactoryError::ShareUnavailable)
        };
        let [first, second] = manifest.active_signers.clone();
        Ok([load(first)?, load(second)?])
    }

    fn validate_recovery_provider(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
        manifest: &CbMpcExecutorManifestV1,
        signer: &CbMpcRecoverySignerRefV1,
        group_public_key: [u8; 33],
    ) -> Result<(), CbMpcFactoryError> {
        let sealed = self.resolver.resolve(&signer.sealed_share_ref)?;
        let protector = ResolverBackedShareProtector {
            resolver: Arc::clone(&self.resolver),
            key_ref: signer.protector_key_ref.clone(),
            aad: recovery_share_aad(snapshot, manifest, signer)?,
        };
        LocalCbMpcProvider::import_sealed(
            PartyId::new(signer.party_id.clone())
                .map_err(|_| CbMpcFactoryError::ManifestInvalid)?,
            group_public_key,
            sealed.expose(),
            &protector,
        )
        .map_err(|_| CbMpcFactoryError::ShareUnavailable)?;
        Ok(())
    }
}

pub fn cb_mpc_executor_builder(
    resolver: Arc<dyn OpaqueSecretResolver>,
    claim_root: PathBuf,
) -> Result<CbMpcProductionExecutorBuilder, CbMpcFactoryError> {
    CbMpcProductionExecutorBuilder::new(resolver, claim_root)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CbMpcFactoryError {
    #[error("CB-MPC manifest is invalid")]
    ManifestInvalid,
    #[error("CB-MPC manifest does not match the durable signer profile")]
    ManifestBindingMismatch,
    #[error("CB-MPC secret material is unavailable")]
    SecretUnavailable,
    #[error("CB-MPC share is unavailable or failed authentication")]
    ShareUnavailable,
    #[error("CB-MPC TLS identity is invalid")]
    TlsIdentityInvalid,
    #[error("CB-MPC authenticated transport is unavailable")]
    TransportUnavailable,
    #[error("CB-MPC durable claim store is unavailable")]
    ClaimStoreUnavailable,
    #[error("CB-MPC runtime is unavailable")]
    RuntimeUnavailable,
    #[error("CB-MPC chain suite is unsupported")]
    UnsupportedSuite,
}

pub(crate) struct ResolverBackedShareProtector {
    resolver: Arc<dyn OpaqueSecretResolver>,
    key_ref: String,
    aad: [u8; 32],
}

impl ResolverBackedShareProtector {
    pub(crate) fn new(
        resolver: Arc<dyn OpaqueSecretResolver>,
        key_ref: String,
        aad: [u8; 32],
    ) -> Self {
        Self {
            resolver,
            key_ref,
            aad,
        }
    }
}

impl CbMpcShareProtector for ResolverBackedShareProtector {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, CbMpcError> {
        let key = self
            .resolver
            .resolve(&self.key_ref)
            .map_err(|_| CbMpcError::ShareMismatch)?;
        if key.expose().len() != 32 || secret.is_empty() {
            return Err(CbMpcError::ShareMismatch);
        }
        let mut nonce = [0; SHARE_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| CbMpcError::ShareMismatch)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &share_envelope_aad(self.aad),
                },
            )
            .map_err(|_| CbMpcError::ShareMismatch)?;
        let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        envelope.push(SHARE_ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn open(&self, sealed: &[u8]) -> Result<SecretShareMaterial, CbMpcError> {
        if sealed.len() <= 1 + SHARE_NONCE_BYTES || sealed[0] != SHARE_ENVELOPE_VERSION {
            return Err(CbMpcError::ShareMismatch);
        }
        let key = self
            .resolver
            .resolve(&self.key_ref)
            .map_err(|_| CbMpcError::ShareMismatch)?;
        if key.expose().len() != 32 {
            return Err(CbMpcError::ShareMismatch);
        }
        let plaintext = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| CbMpcError::ShareMismatch)?
            .decrypt(
                XNonce::from_slice(&sealed[1..1 + SHARE_NONCE_BYTES]),
                Payload {
                    msg: &sealed[1 + SHARE_NONCE_BYTES..],
                    aad: &share_envelope_aad(self.aad),
                },
            )
            .map_err(|_| CbMpcError::ShareMismatch)?;
        SecretShareMaterial::new(plaintext)
    }
}

fn share_envelope_aad(binding: [u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARE_AAD_DOMAIN.len() + 32);
    aad.extend_from_slice(SHARE_AAD_DOMAIN);
    aad.extend_from_slice(&binding);
    aad
}

pub(crate) fn share_aad(
    snapshot: &SignerProfileStartupSnapshot,
    manifest: &CbMpcExecutorManifestV1,
    signer: &CbMpcSignerRefV1,
) -> Result<[u8; 32], CbMpcFactoryError> {
    #[derive(Serialize)]
    struct Binding<'a> {
        wallet_id: Uuid,
        profile_id: Uuid,
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        signer_set_id: &'a str,
        signer_epoch: u64,
        party_id: &'a str,
        device_ref: &'a str,
        endpoint_ref: &'a str,
    }
    let encoded = serde_jcs::to_vec(&Binding {
        wallet_id: snapshot.wallet_id,
        profile_id: snapshot.profile_id,
        chain_scope: snapshot.chain_scope,
        signing_suite_id: snapshot.signing_suite_id,
        signer_set_id: &manifest.signer_set_id,
        signer_epoch: manifest.signer_epoch,
        party_id: &signer.party_id,
        device_ref: &signer.device_ref,
        endpoint_ref: &signer.endpoint_ref,
    })
    .map_err(|_| CbMpcFactoryError::ManifestInvalid)?;
    Ok(Sha256::digest(encoded).into())
}

pub(crate) fn recovery_share_aad(
    snapshot: &SignerProfileStartupSnapshot,
    manifest: &CbMpcExecutorManifestV1,
    signer: &CbMpcRecoverySignerRefV1,
) -> Result<[u8; 32], CbMpcFactoryError> {
    #[derive(Serialize)]
    struct Binding<'a> {
        wallet_id: Uuid,
        profile_id: Uuid,
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        signer_set_id: &'a str,
        signer_epoch: u64,
        party_id: &'a str,
        device_ref: &'a str,
        role: &'static str,
    }
    let encoded = serde_jcs::to_vec(&Binding {
        wallet_id: snapshot.wallet_id,
        profile_id: snapshot.profile_id,
        chain_scope: snapshot.chain_scope,
        signing_suite_id: snapshot.signing_suite_id,
        signer_set_id: &manifest.signer_set_id,
        signer_epoch: manifest.signer_epoch,
        party_id: &signer.party_id,
        device_ref: &signer.device_ref,
        role: "offline_recovery",
    })
    .map_err(|_| CbMpcFactoryError::ManifestInvalid)?;
    Ok(Sha256::digest(encoded).into())
}

fn transport_binding(
    snapshot: &SignerProfileStartupSnapshot,
    manifest: &CbMpcExecutorManifestV1,
) -> Result<[u8; 32], CbMpcFactoryError> {
    let mut hasher = Sha256::new();
    hasher.update(TRANSPORT_BINDING_DOMAIN);
    hasher.update(
        serde_jcs::to_vec(&(snapshot.wallet_id, snapshot.profile_id, manifest))
            .map_err(|_| CbMpcFactoryError::ManifestInvalid)?,
    );
    Ok(hasher.finalize().into())
}

fn load_mtls_transport_pair(
    resolver: &dyn OpaqueSecretResolver,
    snapshot: &SignerProfileStartupSnapshot,
    manifest: &CbMpcExecutorManifestV1,
) -> Result<[Box<dyn SessionTransport>; 2], CbMpcFactoryError> {
    let [first_signer, second_signer] = manifest.active_signers.clone();
    let identities = [
        load_tls_identity(resolver, &first_signer.tls_identity_ref)?,
        load_tls_identity(resolver, &second_signer.tls_identity_ref)?,
    ];
    let binding = transport_binding(snapshot, manifest)?;
    let streams = establish_mtls_pair(resolver, identities)?;
    Ok([
        Box::new(AuthenticatedSessionTransport::new(0, 1, binding, streams.0)),
        Box::new(AuthenticatedSessionTransport::new(1, 0, binding, streams.1)),
    ])
}

fn load_tls_identity(
    resolver: &dyn OpaqueSecretResolver,
    reference: &str,
) -> Result<CbMpcTlsIdentityRefsV1, CbMpcFactoryError> {
    let encoded = resolver.resolve(reference)?;
    let identity: CbMpcTlsIdentityRefsV1 = serde_json::from_slice(encoded.expose())
        .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
    if identity.format_version != CB_MPC_TLS_IDENTITY_VERSION
        || !valid_reference(&identity.certificate_der_ref)
        || !valid_reference(&identity.private_key_pkcs8_der_ref)
        || !valid_reference(&identity.peer_ca_certificate_der_ref)
        || !valid_reference(&identity.peer_spki_sha256_ref)
    {
        return Err(CbMpcFactoryError::TlsIdentityInvalid);
    }
    Ok(identity)
}

struct ResolvedTlsIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    peer_ca: CertificateDer<'static>,
    peer_spki: [u8; 32],
}

fn resolve_tls_identity(
    resolver: &dyn OpaqueSecretResolver,
    refs: CbMpcTlsIdentityRefsV1,
) -> Result<ResolvedTlsIdentity, CbMpcFactoryError> {
    let certificate = resolver.resolve(&refs.certificate_der_ref)?;
    let private_key = resolver.resolve(&refs.private_key_pkcs8_der_ref)?;
    let peer_ca = resolver.resolve(&refs.peer_ca_certificate_der_ref)?;
    let peer_spki = resolver.resolve(&refs.peer_spki_sha256_ref)?;
    let peer_spki: [u8; 32] = peer_spki
        .expose()
        .try_into()
        .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
    Ok(ResolvedTlsIdentity {
        certificate: CertificateDer::from(certificate.expose().to_vec()),
        private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.expose().to_vec())),
        peer_ca: CertificateDer::from(peer_ca.expose().to_vec()),
        peer_spki,
    })
}

fn establish_mtls_pair(
    resolver: &dyn OpaqueSecretResolver,
    refs: [CbMpcTlsIdentityRefsV1; 2],
) -> Result<(AuthenticatedTlsStream, AuthenticatedTlsStream), CbMpcFactoryError> {
    let [server_refs, client_refs] = refs;
    let server_identity = resolve_tls_identity(resolver, server_refs)?;
    let client_identity = resolve_tls_identity(resolver, client_refs)?;
    let server_config = private_ca_server_config(
        server_identity.peer_ca,
        vec![server_identity.certificate.clone()],
        server_identity.private_key,
    )
    .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
    let client_config = private_ca_client_config(
        client_identity.peer_ca,
        vec![client_identity.certificate.clone()],
        client_identity.private_key,
    )
    .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
    let (server_socket, client_socket) =
        UnixStream::pair().map_err(|_| CbMpcFactoryError::TransportUnavailable)?;
    set_socket_timeout(&server_socket, CB_MPC_RECEIVE_TIMEOUT)?;
    set_socket_timeout(&client_socket, CB_MPC_RECEIVE_TIMEOUT)?;
    let expected_client_spki = server_identity.peer_spki;
    let expected_server_spki = client_identity.peer_spki;
    let server_thread = std::thread::spawn(move || {
        let mut connection = ServerConnection::new(Arc::new(server_config))
            .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
        let mut socket = server_socket;
        connection
            .complete_io(&mut socket)
            .map_err(|_| CbMpcFactoryError::TransportUnavailable)?;
        verify_peer_pin(connection.peer_certificates(), expected_client_spki)?;
        Ok::<_, CbMpcFactoryError>(AuthenticatedTlsStream::Server(StreamOwned::new(
            connection, socket,
        )))
    });
    let mut connection = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(TLS_SERVER_NAME).map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?,
    )
    .map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?;
    let mut socket = client_socket;
    connection
        .complete_io(&mut socket)
        .map_err(|_| CbMpcFactoryError::TransportUnavailable)?;
    verify_peer_pin(connection.peer_certificates(), expected_server_spki)?;
    let client = AuthenticatedTlsStream::Client(StreamOwned::new(connection, socket));
    let server = server_thread
        .join()
        .map_err(|_| CbMpcFactoryError::TransportUnavailable)??;
    Ok((server, client))
}

fn verify_peer_pin(
    certificates: Option<&[CertificateDer<'static>]>,
    expected: [u8; 32],
) -> Result<(), CbMpcFactoryError> {
    let leaf = certificates
        .and_then(|values| values.first())
        .ok_or(CbMpcFactoryError::TlsIdentityInvalid)?;
    if certificate_spki_sha256(leaf.as_ref()).map_err(|_| CbMpcFactoryError::TlsIdentityInvalid)?
        != expected
    {
        return Err(CbMpcFactoryError::TlsIdentityInvalid);
    }
    Ok(())
}

enum AuthenticatedTlsStream {
    Client(StreamOwned<ClientConnection, UnixStream>),
    Server(StreamOwned<ServerConnection, UnixStream>),
}

impl AuthenticatedTlsStream {
    fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Client(stream) => set_socket_timeout(&stream.sock, timeout),
            Self::Server(stream) => set_socket_timeout(&stream.sock, timeout),
        }
        .map_err(|_| io::Error::other("transport timeout configuration failed"))
    }
}

impl Read for AuthenticatedTlsStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(buffer),
            Self::Server(stream) => stream.read(buffer),
        }
    }
}

impl Write for AuthenticatedTlsStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write(buffer),
            Self::Server(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}

struct AuthenticatedSessionTransport {
    local: u8,
    peer: u8,
    binding: [u8; 32],
    stream: Mutex<AuthenticatedTlsStream>,
    send_state: Mutex<TranscriptState>,
    receive_state: Mutex<TranscriptState>,
}

impl AuthenticatedSessionTransport {
    fn new(local: u8, peer: u8, binding: [u8; 32], stream: AuthenticatedTlsStream) -> Self {
        Self {
            local,
            peer,
            binding,
            stream: Mutex::new(stream),
            send_state: Mutex::new(TranscriptState::new(binding, local, peer)),
            receive_state: Mutex::new(TranscriptState::new(binding, peer, local)),
        }
    }
}

#[derive(Clone, Copy)]
struct TranscriptState {
    sequence: u32,
    digest: [u8; 32],
}

impl TranscriptState {
    fn new(binding: [u8; 32], sender: u8, receiver: u8) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(binding);
        hasher.update([sender, receiver]);
        Self {
            sequence: 0,
            digest: hasher.finalize().into(),
        }
    }

    fn advance(&mut self, payload: &[u8]) -> Result<(), TransportFailure> {
        if self.sequence >= MAX_TRANSPORT_FRAMES {
            return Err(TransportFailure::Terminated);
        }
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(self.digest);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(Sha256::digest(payload));
        self.digest = hasher.finalize().into();
        self.sequence += 1;
        Ok(())
    }
}

impl SessionTransport for AuthenticatedSessionTransport {
    fn send(
        &self,
        receiver: usize,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(), TransportFailure> {
        if receiver != usize::from(self.peer) || frame.len() > CB_MPC_MAX_FRAME_BYTES {
            return Err(if frame.len() > CB_MPC_MAX_FRAME_BYTES {
                TransportFailure::FrameTooLarge
            } else {
                TransportFailure::Failed
            });
        }
        let mut state = self
            .send_state
            .lock()
            .map_err(|_| TransportFailure::Terminated)?;
        let frame_len = u32::try_from(frame.len()).map_err(|_| TransportFailure::FrameTooLarge)?;
        let mut encoded = Vec::with_capacity(FRAME_HEADER_BYTES + frame.len());
        encoded.extend_from_slice(FRAME_MAGIC);
        encoded.push(self.local);
        encoded.push(self.peer);
        encoded.extend_from_slice(&state.sequence.to_be_bytes());
        encoded.extend_from_slice(&self.binding);
        encoded.extend_from_slice(&state.digest);
        encoded.extend_from_slice(&frame_len.to_be_bytes());
        encoded.extend_from_slice(frame);
        let timeout = remaining(deadline)?;
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| TransportFailure::Terminated)?;
        stream.set_timeout(timeout).map_err(map_io)?;
        stream.write_all(&encoded).map_err(map_io)?;
        stream.flush().map_err(map_io)?;
        state.advance(frame)
    }

    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        if sender != usize::from(self.peer) {
            return Err(TransportFailure::Failed);
        }
        let timeout = remaining(deadline)?;
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| TransportFailure::Terminated)?;
        stream.set_timeout(timeout).map_err(map_io)?;
        let mut header = [0; FRAME_HEADER_BYTES];
        stream.read_exact(&mut header).map_err(map_io)?;
        let mut state = self
            .receive_state
            .lock()
            .map_err(|_| TransportFailure::Terminated)?;
        let sequence = u32::from_be_bytes(header[10..14].try_into().expect("fixed header"));
        let binding: [u8; 32] = header[14..46].try_into().expect("fixed header");
        let prior: [u8; 32] = header[46..78].try_into().expect("fixed header");
        let length = u32::from_be_bytes(header[78..82].try_into().expect("fixed header")) as usize;
        if &header[..8] != FRAME_MAGIC
            || header[8] != self.peer
            || header[9] != self.local
            || sequence != state.sequence
            || binding != self.binding
            || prior != state.digest
            || length > CB_MPC_MAX_FRAME_BYTES
        {
            return Err(TransportFailure::Failed);
        }
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).map_err(map_io)?;
        state.advance(&payload)?;
        Ok(payload)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, TransportFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(TransportFailure::Timeout)
}

fn map_io(error: io::Error) -> TransportFailure {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        TransportFailure::Timeout
    } else {
        TransportFailure::Terminated
    }
}

fn set_socket_timeout(socket: &UnixStream, timeout: Duration) -> Result<(), CbMpcFactoryError> {
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|_| CbMpcFactoryError::TransportUnavailable)
}

fn runtime_limits() -> Result<CbMpcRuntimeLimits, CbMpcFactoryError> {
    CbMpcRuntimeLimits::new(
        CB_MPC_RECEIVE_TIMEOUT,
        CB_MPC_SESSION_TIMEOUT,
        CB_MPC_MAX_FRAME_BYTES,
    )
    .map_err(|_| CbMpcFactoryError::RuntimeUnavailable)
}

fn profile_from_snapshot(
    snapshot: &SignerProfileStartupSnapshot,
) -> Result<SignerProfile, CbMpcFactoryError> {
    SignerProfile::new(
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
        hex::decode(&snapshot.verification_key_hex)
            .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?,
        snapshot.secret_ref.clone(),
    )
    .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)
}

fn chain_components(
    scope: ChainScope,
    group_public_key: [u8; 33],
) -> Result<ChainComponents, CbMpcFactoryError> {
    match scope.network {
        ChainNetwork::BitcoinCash(network) => Ok((
            Box::new(
                BitcoinCashChainSuite::new(
                    network,
                    BitcoinCashSignatureAlgorithm::Ecdsa,
                    &group_public_key,
                    ForkIdSighashType::ALL,
                )
                .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?,
            ),
            Box::new(BitcoinCashCbMpcSignatureAssembler),
        )),
        ChainNetwork::Bsv(network) => Ok((
            Box::new(
                BsvChainSuite::new(network, group_public_key)
                    .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?,
            ),
            Box::new(BsvCbMpcSignatureAssembler),
        )),
        ChainNetwork::Kaspa(network) => Ok((
            Box::new(
                KaspaChainSuite::new(network, KaspaVerifier::EcdsaCbMpc(group_public_key))
                    .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?,
            ),
            Box::new(KaspaCbMpcSignatureAssembler),
        )),
        _ => Err(CbMpcFactoryError::UnsupportedSuite),
    }
}

fn suite_matches_chain(chain: ChainId, suite: SigningSuiteId) -> bool {
    matches!(
        (chain, suite),
        (
            ChainId::BitcoinCash,
            SigningSuiteId::BitcoinCashEcdsaCbMpcV1
        ) | (ChainId::Bsv, SigningSuiteId::BsvEcdsaCbMpcV1)
            | (ChainId::Kaspa, SigningSuiteId::KaspaEcdsaCbMpcV1)
    )
}

fn decode_group_public_key(encoded: &str) -> Result<[u8; 33], CbMpcFactoryError> {
    hex::decode(encoded)
        .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)?
        .try_into()
        .map_err(|_| CbMpcFactoryError::ManifestBindingMismatch)
}

fn valid_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REFERENCE_BYTES
        && !value.chars().any(char::is_control)
        && value.contains("://")
}

fn validate_private_root(path: &Path) -> Result<(), CbMpcFactoryError> {
    if !path.is_absolute() {
        return Err(CbMpcFactoryError::ClaimStoreUnavailable);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CbMpcFactoryError::ClaimStoreUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.uid() != current_uid()
    {
        return Err(CbMpcFactoryError::ClaimStoreUnavailable);
    }
    Ok(())
}

fn private_claim_directory(
    root: &Path,
    wallet_id: Uuid,
    profile_id: Uuid,
) -> Result<PathBuf, CbMpcFactoryError> {
    validate_private_root(root)?;
    let wallet = root.join(wallet_id.to_string());
    create_private_directory(&wallet)?;
    Ok(wallet.join(profile_id.to_string()))
}

fn create_private_directory(path: &Path) -> Result<(), CbMpcFactoryError> {
    match fs::create_dir(path) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| CbMpcFactoryError::ClaimStoreUnavailable)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(CbMpcFactoryError::ClaimStoreUnavailable),
    }
    validate_private_root(path)
}

fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use catomicals_secret_store::SecretValue;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    use super::*;

    struct TestResolver(HashMap<String, Vec<u8>>);

    impl OpaqueSecretResolver for TestResolver {
        fn resolve(&self, reference: &str) -> Result<SecretValue, CbMpcFactoryError> {
            self.0
                .get(reference)
                .cloned()
                .map(SecretValue::new)
                .ok_or(CbMpcFactoryError::SecretUnavailable)
        }
    }

    #[test]
    fn encrypted_share_envelope_authenticates_key_and_wallet_binding() {
        let resolver = Arc::new(TestResolver(HashMap::from([(
            "test://protector-key".to_owned(),
            vec![0x41; 32],
        )])));
        let protector = ResolverBackedShareProtector {
            resolver: resolver.clone(),
            key_ref: "test://protector-key".to_owned(),
            aad: [0x52; 32],
        };
        let plaintext = vec![0x63; 96];
        let sealed = protector.seal(&plaintext).expect("seal share");
        assert_eq!(protector.open(&sealed).expect("open share").len(), 96);
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|part| part == plaintext)
        );

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            protector.open(&tampered),
            Err(CbMpcError::ShareMismatch)
        ));
        let drifted = ResolverBackedShareProtector {
            resolver,
            key_ref: "test://protector-key".to_owned(),
            aad: [0x53; 32],
        };
        assert!(matches!(
            drifted.open(&sealed),
            Err(CbMpcError::ShareMismatch)
        ));
    }

    #[test]
    fn mutual_tls_transport_rejects_binding_and_transcript_drift() {
        let (resolver, identities) = test_tls_resolver();
        let (server, client) = establish_mtls_pair(&resolver, identities.clone()).expect("mTLS");
        let server = AuthenticatedSessionTransport::new(0, 1, [0x71; 32], server);
        let client = AuthenticatedSessionTransport::new(1, 0, [0x71; 32], client);
        let deadline = Instant::now() + Duration::from_secs(2);
        server.send(1, b"round-one", deadline).expect("send");
        assert_eq!(client.receive(0, deadline).expect("receive"), b"round-one");
        client.send(0, b"round-two", deadline).expect("send");
        assert_eq!(server.receive(1, deadline).expect("receive"), b"round-two");

        let (server, client) = establish_mtls_pair(&resolver, identities).expect("mTLS");
        let server = AuthenticatedSessionTransport::new(0, 1, [0x71; 32], server);
        let drifted_client = AuthenticatedSessionTransport::new(1, 0, [0x72; 32], client);
        let deadline = Instant::now() + Duration::from_secs(2);
        server.send(1, b"round-one", deadline).expect("send");
        assert_eq!(
            drifted_client.receive(0, deadline),
            Err(TransportFailure::Failed)
        );
    }

    fn test_tls_resolver() -> (TestResolver, [CbMpcTlsIdentityRefsV1; 2]) {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("CA key");
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let (server, server_key) = leaf(
            TLS_SERVER_NAME,
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client, client_key) = leaf(
            "cbmpc-client.local",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        let server_pin = certificate_spki_sha256(server.der().as_ref()).expect("server SPKI");
        let client_pin = certificate_spki_sha256(client.der().as_ref()).expect("client SPKI");
        let mut secrets = HashMap::new();
        secrets.insert("test://ca".to_owned(), ca.der().to_vec());
        secrets.insert("test://server-cert".to_owned(), server.der().to_vec());
        secrets.insert("test://server-key".to_owned(), server_key.serialize_der());
        secrets.insert("test://server-peer-pin".to_owned(), client_pin.to_vec());
        secrets.insert("test://client-cert".to_owned(), client.der().to_vec());
        secrets.insert("test://client-key".to_owned(), client_key.serialize_der());
        secrets.insert("test://client-peer-pin".to_owned(), server_pin.to_vec());
        (
            TestResolver(secrets),
            [
                tls_refs("server", "test://server-peer-pin"),
                tls_refs("client", "test://client-peer-pin"),
            ],
        )
    }

    fn tls_refs(identity: &str, peer_pin: &str) -> CbMpcTlsIdentityRefsV1 {
        CbMpcTlsIdentityRefsV1 {
            format_version: CB_MPC_TLS_IDENTITY_VERSION,
            certificate_der_ref: format!("test://{identity}-cert"),
            private_key_pkcs8_der_ref: format!("test://{identity}-key"),
            peer_ca_certificate_der_ref: "test://ca".to_owned(),
            peer_spki_sha256_ref: peer_pin.to_owned(),
        }
    }

    fn leaf(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().expect("leaf key");
        let certificate = params
            .signed_by(&key, ca, ca_key)
            .expect("leaf certificate");
        (certificate, key)
    }
}
