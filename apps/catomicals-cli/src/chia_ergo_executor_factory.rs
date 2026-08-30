//! Production startup factories for Chia and Ergo threshold signers.
//!
//! A snapshot contains one opaque manifest handle. The manifest binds the
//! complete public profile and points at two independently stored share
//! handles. Plaintext shares only exist while imported into zeroizing signer
//! types in this module.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use catomicals_chain_chia::{
    BlsSignatureShare, ChiaChainSuite, ThresholdBlsCommitment, ThresholdBlsDealerKeyKind,
    ThresholdBlsSecretShare, finalize_reviewed_threshold_spend, sign_reviewed_threshold_share,
    validate_threshold_secret_share as validate_chia_share,
};
use catomicals_chain_domain::{ChainNetwork, ChainScope};
use catomicals_chain_ergo::{
    ErgoAdapterError, ErgoChainSuite, ErgoThresholdCommitment, ErgoThresholdCommitments,
    ErgoThresholdNonceReplayGuard, ErgoThresholdNonceReservation, ErgoThresholdSecretShare,
    ErgoThresholdSignatureShare, ErgoThresholdSigningNonces, ErgoThresholdSigningPackage,
    ErgoThresholdSigningRequest, generate_threshold_nonces_2_of_3, sign_threshold_share_2_of_3,
    validate_threshold_secret_share as validate_ergo_share,
};
use catomicals_secret_store::{SecretBackend, SecretValue};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{
    ChainSigningExecutor, ChiaExecutionClaimStore, ChiaThresholdChainSigningExecutor,
    ChiaThresholdShareProvider, ChiaThresholdSpendFinalizer, ErgoNonceReplayStore,
    ErgoThresholdChainSigningExecutor, ErgoThresholdShareProvider,
    NativeErgoThresholdProofAssembler, SignerProfile, SignerProfileStartupSnapshot, SigningJob,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::wallet_executor_bootstrap::{ExecutorFactoryError, StartupExecutorBuilder};

const MANIFEST_VERSION: u16 = 1;
const RECOVERY_MANIFEST_VERSION: u16 = 2;
#[allow(dead_code)] // Provisioning CLI consumes this through `ThresholdShareReference::new`.
const MAX_SECRET_HANDLE_BYTES: usize = 1_024;
const MAX_MANIFEST_BYTES: usize = 32 * 1_024;

/// Resolves an opaque manifest or share reference. Implementations must not
/// include plaintext in their errors.
pub trait ThresholdSecretResolver: Send + Sync {
    fn resolve(&self, secret_ref: &str) -> Result<SecretValue, String>;
}

pub struct SecretBackendThresholdResolver {
    backend: Arc<dyn SecretBackend>,
}

impl SecretBackendThresholdResolver {
    pub fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self { backend }
    }
}

impl ThresholdSecretResolver for SecretBackendThresholdResolver {
    fn resolve(&self, secret_ref: &str) -> Result<SecretValue, String> {
        self.backend
            .get_raw(secret_ref)
            .map_err(|_| "threshold secret is unavailable".to_owned())
    }
}

/// One independently stored participant share. Debug output hides its handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdShareReference {
    participant_id: u16,
    secret_ref: String,
}

impl core::fmt::Debug for ThresholdShareReference {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ThresholdShareReference")
            .field("participant_id", &self.participant_id)
            .field("secret_ref", &"[REDACTED]")
            .finish()
    }
}

impl ThresholdShareReference {
    #[allow(dead_code)] // Public provisioning seam; runtime only deserializes manifests.
    pub fn new(participant_id: u16, secret_ref: impl Into<String>) -> Result<Self, String> {
        let secret_ref = secret_ref.into();
        if !(1..=3).contains(&participant_id)
            || secret_ref.is_empty()
            || secret_ref.len() > MAX_SECRET_HANDLE_BYTES
            || secret_ref.chars().any(char::is_control)
        {
            return Err("invalid threshold share reference".to_owned());
        }
        Ok(Self {
            participant_id,
            secret_ref,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestProfileBinding {
    profile_id: Uuid,
    wallet_id: Uuid,
    chain_scope: ChainScope,
    signing_suite_id: SigningSuiteId,
    backend_requirement: SignerBackendRequirement,
    signer_set_id: String,
    authorization_signer_id: String,
    signer_epoch: u64,
    threshold: u16,
    max_signers: u16,
    address_bindings_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdManifest {
    format_version: u16,
    binding: ManifestProfileBinding,
    group_public_key_hex: String,
    coefficient_public_key_hex: String,
    shares: [ThresholdShareReference; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_share: Option<ThresholdShareReference>,
}

#[allow(dead_code)] // Public provisioning seam; wallet startup only reads manifests.
pub fn encode_chia_threshold_manifest(
    snapshot: &SignerProfileStartupSnapshot,
    coefficient_public_key: [u8; 48],
    shares: [ThresholdShareReference; 2],
) -> Result<SecretValue, String> {
    encode_manifest(
        MANIFEST_VERSION,
        snapshot,
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        &coefficient_public_key,
        shares,
        None,
    )
}

pub fn encode_chia_threshold_manifest_with_recovery(
    snapshot: &SignerProfileStartupSnapshot,
    coefficient_public_key: [u8; 48],
    shares: [ThresholdShareReference; 2],
    recovery_share: ThresholdShareReference,
) -> Result<SecretValue, String> {
    encode_manifest(
        RECOVERY_MANIFEST_VERSION,
        snapshot,
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        &coefficient_public_key,
        shares,
        Some(recovery_share),
    )
}

#[allow(dead_code)] // Public provisioning seam; wallet startup only reads manifests.
pub fn encode_ergo_threshold_manifest(
    snapshot: &SignerProfileStartupSnapshot,
    coefficient_public_key: [u8; 33],
    shares: [ThresholdShareReference; 2],
) -> Result<SecretValue, String> {
    encode_manifest(
        MANIFEST_VERSION,
        snapshot,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        &coefficient_public_key,
        shares,
        None,
    )
}

pub fn encode_ergo_threshold_manifest_with_recovery(
    snapshot: &SignerProfileStartupSnapshot,
    coefficient_public_key: [u8; 33],
    shares: [ThresholdShareReference; 2],
    recovery_share: ThresholdShareReference,
) -> Result<SecretValue, String> {
    encode_manifest(
        RECOVERY_MANIFEST_VERSION,
        snapshot,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        &coefficient_public_key,
        shares,
        Some(recovery_share),
    )
}

#[allow(dead_code)]
fn encode_manifest(
    format_version: u16,
    snapshot: &SignerProfileStartupSnapshot,
    expected_suite: SigningSuiteId,
    expected_backend: SignerBackendRequirement,
    coefficient_public_key: &[u8],
    shares: [ThresholdShareReference; 2],
    recovery_share: Option<ThresholdShareReference>,
) -> Result<SecretValue, String> {
    validate_share_references(&shares, recovery_share.as_ref())?;
    if snapshot.signing_suite_id != expected_suite
        || snapshot.backend_requirement != expected_backend
        || snapshot.threshold != 2
        || snapshot.max_signers != 3
    {
        return Err("threshold manifest profile is incompatible".to_owned());
    }
    let group_public_key = hex::decode(&snapshot.verification_key_hex)
        .map_err(|_| "invalid group public key".to_owned())?;
    if group_public_key.len() != coefficient_public_key.len() {
        return Err("invalid public commitment length".to_owned());
    }
    let manifest = ThresholdManifest {
        format_version,
        binding: manifest_binding(snapshot)?,
        group_public_key_hex: snapshot.verification_key_hex.to_lowercase(),
        coefficient_public_key_hex: hex::encode(coefficient_public_key),
        shares,
        recovery_share,
    };
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|_| "threshold manifest encoding failed".to_owned())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("threshold manifest is too large".to_owned());
    }
    Ok(SecretValue::new(bytes))
}

fn manifest_binding(
    snapshot: &SignerProfileStartupSnapshot,
) -> Result<ManifestProfileBinding, String> {
    let address_bindings = serde_json::to_vec(&snapshot.address_bindings)
        .map_err(|_| "address binding encoding failed".to_owned())?;
    Ok(ManifestProfileBinding {
        profile_id: snapshot.profile_id,
        wallet_id: snapshot.wallet_id,
        chain_scope: snapshot.chain_scope,
        signing_suite_id: snapshot.signing_suite_id,
        backend_requirement: snapshot.backend_requirement,
        signer_set_id: snapshot.signer_set_id.clone(),
        authorization_signer_id: snapshot.authorization_signer_id.clone(),
        signer_epoch: snapshot.signer_epoch,
        threshold: snapshot.threshold,
        max_signers: snapshot.max_signers,
        address_bindings_digest_hex: hex::encode(Sha256::digest(address_bindings)),
    })
}

fn validate_share_references(
    shares: &[ThresholdShareReference; 2],
    recovery_share: Option<&ThresholdShareReference>,
) -> Result<(), String> {
    if shares[0].participant_id == shares[1].participant_id
        || shares[0].secret_ref == shares[1].secret_ref
    {
        return Err("threshold shares must use distinct participants and handles".to_owned());
    }
    if recovery_share.is_some_and(|recovery| {
        shares.iter().any(|online| {
            online.participant_id == recovery.participant_id
                || online.secret_ref == recovery.secret_ref
        })
    }) {
        return Err(
            "threshold recovery share must use a distinct participant and handle".to_owned(),
        );
    }
    Ok(())
}

fn load_manifest(
    resolver: &dyn ThresholdSecretResolver,
    snapshot: &SignerProfileStartupSnapshot,
) -> Result<ThresholdManifest, ExecutorFactoryError> {
    let encoded = resolver
        .resolve(&snapshot.secret_ref)
        .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
    if encoded.expose().len() > MAX_MANIFEST_BYTES {
        return Err(ExecutorFactoryError::InvalidConfiguration);
    }
    let manifest: ThresholdManifest = serde_json::from_slice(encoded.expose())
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    let expected =
        manifest_binding(snapshot).map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    let valid_manifest_version = match manifest.format_version {
        MANIFEST_VERSION => manifest.recovery_share.is_none(),
        RECOVERY_MANIFEST_VERSION => manifest.recovery_share.is_some(),
        _ => false,
    };
    if !valid_manifest_version
        || manifest.binding != expected
        || manifest.group_public_key_hex != snapshot.verification_key_hex.to_lowercase()
        || validate_share_references(&manifest.shares, manifest.recovery_share.as_ref()).is_err()
    {
        return Err(ExecutorFactoryError::InvalidConfiguration);
    }
    Ok(manifest)
}

fn import_share_bytes(
    resolver: &dyn ThresholdSecretResolver,
    reference: &ThresholdShareReference,
) -> Result<Zeroizing<[u8; 32]>, ExecutorFactoryError> {
    let resolved = resolver
        .resolve(&reference.secret_ref)
        .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
    if resolved.expose().len() != 32 {
        return Err(ExecutorFactoryError::InvalidConfiguration);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(resolved.expose());
    Ok(bytes)
}

fn profile_from_snapshot(
    snapshot: &SignerProfileStartupSnapshot,
) -> Result<SignerProfile, ExecutorFactoryError> {
    let verification_key = hex::decode(&snapshot.verification_key_hex)
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
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
        verification_key,
        snapshot.secret_ref.clone(),
    )
    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)
}

/// Public construction seam for `snapshot_backed_factories`.
pub type StartupBuilderRegistration = (SignerBackendRequirement, Box<dyn StartupExecutorBuilder>);

pub fn chia_ergo_startup_builders(
    resolver: Arc<dyn ThresholdSecretResolver>,
    replay_root: impl AsRef<Path>,
) -> Result<Vec<StartupBuilderRegistration>, ExecutorFactoryError> {
    let replay_root = replay_root.as_ref().to_path_buf();
    create_private_directory(&replay_root)
        .map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
    Ok(vec![
        (
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            Box::new(ChiaStartupBuilder {
                resolver: Arc::clone(&resolver),
                replay_root: replay_root.clone(),
            }),
        ),
        (
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
            Box::new(ErgoStartupBuilder {
                resolver,
                replay_root,
            }),
        ),
    ])
}

struct ChiaStartupBuilder {
    resolver: Arc<dyn ThresholdSecretResolver>,
    replay_root: PathBuf,
}

impl StartupExecutorBuilder for ChiaStartupBuilder {
    fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
        if snapshot.backend_requirement != SignerBackendRequirement::ChiaBlsAugThreshold2of3
            || snapshot.signing_suite_id != SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1
        {
            return Err(ExecutorFactoryError::UnsupportedProfile);
        }
        let manifest = load_manifest(self.resolver.as_ref(), snapshot)?;
        let commitment = ThresholdBlsCommitment::import(
            decode_array::<48>(&manifest.group_public_key_hex)?,
            decode_array::<48>(&manifest.coefficient_public_key_hex)?,
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let first = import_chia_provider(self.resolver.as_ref(), &manifest.shares[0], &commitment)?;
        let second =
            import_chia_provider(self.resolver.as_ref(), &manifest.shares[1], &commitment)?;
        if let Some(recovery) = &manifest.recovery_share {
            drop(import_chia_provider(
                self.resolver.as_ref(),
                recovery,
                &commitment,
            )?);
        }
        let suite = ChiaChainSuite::new_threshold(
            snapshot.chain_scope,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            commitment.clone(),
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let claims = DurableClaimStore::new(
            profile_claim_root(&self.replay_root, "chia", snapshot.profile_id),
            binding_key(snapshot),
        )?;
        let executor = ChiaThresholdChainSigningExecutor::new(
            profile_from_snapshot(snapshot)?,
            Box::new(suite),
            commitment,
            Box::new(first),
            Box::new(second),
            Box::new(ReviewedChiaFinalizer {
                scope: snapshot.chain_scope,
            }),
            Box::new(claims),
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        Ok(Box::new(executor))
    }
}

fn import_chia_provider(
    resolver: &dyn ThresholdSecretResolver,
    reference: &ThresholdShareReference,
    commitment: &ThresholdBlsCommitment,
) -> Result<LocalChiaShareProvider, ExecutorFactoryError> {
    let share = ThresholdBlsSecretShare::import_for_signing(
        reference.participant_id,
        import_share_bytes(resolver, reference)?,
    )
    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    validate_chia_share(commitment, &share)
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    Ok(LocalChiaShareProvider {
        secret_ref: reference.secret_ref.clone(),
        share,
    })
}

struct LocalChiaShareProvider {
    secret_ref: String,
    share: ThresholdBlsSecretShare,
}

impl ChiaThresholdShareProvider for LocalChiaShareProvider {
    fn secret_ref(&self) -> &str {
        &self.secret_ref
    }

    fn sign_reviewed_share(
        &mut self,
        job: &SigningJob,
        commitment: &ThresholdBlsCommitment,
    ) -> Result<BlsSignatureShare, String> {
        sign_reviewed_threshold_share(
            job.chain_scope,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            commitment,
            &job.review.reviewed_material,
            &self.share,
        )
        .map_err(|error| error.to_string())
    }
}

struct ReviewedChiaFinalizer {
    scope: ChainScope,
}

impl ChiaThresholdSpendFinalizer for ReviewedChiaFinalizer {
    fn finalize(
        &mut self,
        job: &SigningJob,
        commitment: &ThresholdBlsCommitment,
        shares: &[BlsSignatureShare; 2],
    ) -> Result<Vec<u8>, String> {
        if job.chain_scope != self.scope {
            return Err("Chia finalizer scope mismatch".to_owned());
        }
        finalize_reviewed_threshold_spend(
            self.scope,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            commitment,
            &job.review.reviewed_material,
            shares,
        )
        .and_then(|bundle| bundle.to_bytes())
        .map_err(|error| error.to_string())
    }
}

struct ErgoStartupBuilder {
    resolver: Arc<dyn ThresholdSecretResolver>,
    replay_root: PathBuf,
}

impl StartupExecutorBuilder for ErgoStartupBuilder {
    fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
        if snapshot.backend_requirement != SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
            || snapshot.signing_suite_id != SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1
        {
            return Err(ExecutorFactoryError::UnsupportedProfile);
        }
        let network = match snapshot.chain_scope.network {
            ChainNetwork::Ergo(network) => network,
            _ => return Err(ExecutorFactoryError::UnsupportedProfile),
        };
        let manifest = load_manifest(self.resolver.as_ref(), snapshot)?;
        let commitment = ErgoThresholdCommitment::import(
            decode_array::<33>(&manifest.group_public_key_hex)?,
            decode_array::<33>(&manifest.coefficient_public_key_hex)?,
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        let profile_root = profile_claim_root(&self.replay_root, "ergo", snapshot.profile_id);
        let first = import_ergo_provider(
            self.resolver.as_ref(),
            &manifest.shares[0],
            &commitment,
            profile_root.join(format!("participant-{}", manifest.shares[0].participant_id)),
        )?;
        let second = import_ergo_provider(
            self.resolver.as_ref(),
            &manifest.shares[1],
            &commitment,
            profile_root.join(format!("participant-{}", manifest.shares[1].participant_id)),
        )?;
        if let Some(recovery) = &manifest.recovery_share {
            drop(import_ergo_provider(
                self.resolver.as_ref(),
                recovery,
                &commitment,
                profile_root.join(format!("participant-{}", recovery.participant_id)),
            )?);
        }
        let replay =
            DurableClaimStore::new(profile_root.join("operations"), binding_key(snapshot))?;
        let executor = ErgoThresholdChainSigningExecutor::new(
            profile_from_snapshot(snapshot)?,
            Box::new(ErgoChainSuite::new(network)),
            commitment,
            Box::new(first),
            Box::new(second),
            Box::new(NativeErgoThresholdProofAssembler),
            Box::new(replay),
        )
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
        Ok(Box::new(executor))
    }
}

fn import_ergo_provider(
    resolver: &dyn ThresholdSecretResolver,
    reference: &ThresholdShareReference,
    commitment: &ErgoThresholdCommitment,
    replay_root: PathBuf,
) -> Result<LocalErgoShareProvider, ExecutorFactoryError> {
    let share = ErgoThresholdSecretShare::import_for_signing(
        reference.participant_id,
        import_share_bytes(resolver, reference)?,
    )
    .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    validate_ergo_share(commitment, &share)
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?;
    Ok(LocalErgoShareProvider {
        secret_ref: reference.secret_ref.clone(),
        commitment: commitment.clone(),
        share,
        pending: HashMap::new(),
        replay: DurableErgoNonceGuard::new(replay_root)?,
    })
}

struct LocalErgoShareProvider {
    secret_ref: String,
    commitment: ErgoThresholdCommitment,
    share: ErgoThresholdSecretShare,
    pending: HashMap<[u8; 32], ErgoThresholdSigningNonces>,
    replay: DurableErgoNonceGuard,
}

impl ErgoThresholdShareProvider for LocalErgoShareProvider {
    fn secret_ref(&self) -> &str {
        &self.secret_ref
    }

    fn reserve(
        &mut self,
        request: &ErgoThresholdSigningRequest,
    ) -> Result<ErgoThresholdCommitments, String> {
        if self.pending.contains_key(&request.session_id()) {
            return Err("Ergo threshold session already has reserved nonces".to_owned());
        }
        let nonces =
            generate_threshold_nonces_2_of_3(&self.share, request.session_id(), &mut self.replay)
                .map_err(|error| error.to_string())?;
        let commitments = nonces.commitments();
        self.pending.insert(request.session_id(), nonces);
        Ok(commitments)
    }

    fn sign(
        &mut self,
        request: &ErgoThresholdSigningRequest,
        package: &ErgoThresholdSigningPackage,
    ) -> Result<ErgoThresholdSignatureShare, String> {
        let nonces = self
            .pending
            .remove(&request.session_id())
            .ok_or_else(|| "Ergo threshold nonces were not reserved".to_owned())?;
        sign_threshold_share_2_of_3(
            &self.commitment,
            &self.share,
            nonces,
            request.review_binding(),
            package,
            &mut self.replay,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
struct DurableClaimStore {
    root: PathBuf,
    binding_key: [u8; 32],
}

impl DurableClaimStore {
    fn new(root: PathBuf, binding_key: [u8; 32]) -> Result<Self, ExecutorFactoryError> {
        create_private_directory(&root).map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
        Ok(Self { root, binding_key })
    }

    fn claim_once(
        &self,
        namespace: &[u8],
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals/durable-threshold-operation/v1\0");
        hasher.update(namespace);
        hasher.update(self.binding_key);
        hasher.update(session_id);
        hasher.update((review_domain_separator.len() as u64).to_be_bytes());
        hasher.update(review_domain_separator);
        hasher.update(operation_binding_digest);
        let digest: [u8; 32] = hasher.finalize().into();
        write_once(
            &self.root.join(format!("{}.claim", hex::encode(digest))),
            &digest,
        )
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => "threshold operation replay rejected".to_owned(),
            _ => "threshold replay store unavailable".to_owned(),
        })
    }
}

impl ChiaExecutionClaimStore for DurableClaimStore {
    fn claim(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        self.claim_once(
            b"chia",
            session_id,
            review_domain_separator,
            operation_binding_digest,
        )
    }
}

impl ErgoNonceReplayStore for DurableClaimStore {
    fn claim_operation(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        self.claim_once(
            b"ergo",
            session_id,
            review_domain_separator,
            operation_binding_digest,
        )
    }
}

struct DurableErgoNonceGuard {
    root: PathBuf,
}

impl DurableErgoNonceGuard {
    fn new(root: PathBuf) -> Result<Self, ExecutorFactoryError> {
        create_private_directory(&root).map_err(|_| ExecutorFactoryError::ProviderUnavailable)?;
        Ok(Self { root })
    }

    fn record_digest(reservation: &ErgoThresholdNonceReservation) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals/ergo-nonce-reservation/v1\0");
        hasher.update(reservation.session_id);
        hasher.update(reservation.participant_id.to_be_bytes());
        hasher.update(reservation.nonce_fingerprint);
        hasher.update(reservation.commitments.hiding);
        hasher.update(reservation.commitments.binding);
        hasher.finalize().into()
    }

    fn record_path(&self, reservation: &ErgoThresholdNonceReservation, state: &str) -> PathBuf {
        self.root.join(format!(
            "{}-{state}.claim",
            hex::encode(reservation.nonce_fingerprint)
        ))
    }
}

impl ErgoThresholdNonceReplayGuard for DurableErgoNonceGuard {
    fn reserve(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
    ) -> Result<(), ErgoAdapterError> {
        let digest = Self::record_digest(reservation);
        write_once(&self.record_path(reservation, "reserved"), &digest).map_err(|error| {
            ErgoAdapterError::ThresholdNonceReplay(match error.kind() {
                std::io::ErrorKind::AlreadyExists => "nonce was already reserved".to_owned(),
                _ => "nonce reservation store unavailable".to_owned(),
            })
        })
    }

    fn consume(
        &mut self,
        reservation: &ErgoThresholdNonceReservation,
        transcript_digest: [u8; 32],
    ) -> Result<(), ErgoAdapterError> {
        let expected = Self::record_digest(reservation);
        let mut actual = Vec::new();
        File::open(self.record_path(reservation, "reserved"))
            .and_then(|mut file| file.read_to_end(&mut actual))
            .map_err(|_| {
                ErgoAdapterError::ThresholdNonceReplay("nonce reservation is missing".to_owned())
            })?;
        if actual.as_slice() != expected {
            return Err(ErgoAdapterError::ThresholdNonceReplay(
                "nonce reservation record is invalid".to_owned(),
            ));
        }
        let mut consumed = Vec::with_capacity(64);
        consumed.extend_from_slice(&expected);
        consumed.extend_from_slice(&transcript_digest);
        write_once(&self.record_path(reservation, "consumed"), &consumed).map_err(|error| {
            ErgoAdapterError::ThresholdNonceReplay(match error.kind() {
                std::io::ErrorKind::AlreadyExists => "nonce was already consumed".to_owned(),
                _ => "nonce consumption store unavailable".to_owned(),
            })
        })
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], ExecutorFactoryError> {
    hex::decode(value)
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)?
        .try_into()
        .map_err(|_| ExecutorFactoryError::InvalidConfiguration)
}

fn profile_claim_root(root: &Path, chain: &str, profile_id: Uuid) -> PathBuf {
    root.join(chain).join(profile_id.to_string())
}

fn binding_key(snapshot: &SignerProfileStartupSnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals/threshold-profile-binding/v1\0");
    hasher.update(snapshot.profile_id.as_bytes());
    hasher.update(snapshot.wallet_id.as_bytes());
    hasher.update(snapshot.chain_scope.network.as_str().as_bytes());
    hasher.update(snapshot.signing_suite_id.as_str().as_bytes());
    hasher.update(snapshot.backend_requirement.as_str().as_bytes());
    hasher.update(snapshot.signer_set_id.as_bytes());
    hasher.update(snapshot.signer_epoch.to_be_bytes());
    hasher.finalize().into()
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_once(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catomicals_chain_chia::{
        ChiaCoin, ChiaSpendOutput, ThresholdChiaSpend,
        dealer_split_threshold_secret_2_of_3 as chia_dealer_split, standard_threshold_puzzle_hash,
    };
    use catomicals_chain_domain::{ChainSuite, ChiaNetwork, ErgoNetwork};
    use catomicals_chain_ergo::dealer_split_threshold_secret_2_of_3 as ergo_dealer_split;
    use catomicals_signing_domain::ReviewBinding;
    use catomicals_wallet::{ChainSigningExecution, SigningJobError};

    struct MapResolver(HashMap<String, Vec<u8>>);

    impl ThresholdSecretResolver for MapResolver {
        fn resolve(&self, secret_ref: &str) -> Result<SecretValue, String> {
            self.0
                .get(secret_ref)
                .cloned()
                .map(SecretValue::new)
                .ok_or_else(|| "missing".to_owned())
        }
    }

    fn snapshot(
        profile_id: Uuid,
        network: ChainNetwork,
        suite: SigningSuiteId,
        backend: SignerBackendRequirement,
        verification_key: &[u8],
        secret_ref: &str,
    ) -> SignerProfileStartupSnapshot {
        SignerProfileStartupSnapshot {
            profile_id,
            wallet_id: Uuid::from_u128(2),
            chain_scope: ChainScope::for_network(network),
            signing_suite_id: suite,
            backend_requirement: backend,
            signer_set_id: "personal-2-of-3".to_owned(),
            authorization_signer_id: "passkey-owner".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key_hex: hex::encode(verification_key),
            secret_ref: secret_ref.to_owned(),
            address_bindings: Vec::new(),
        }
    }

    #[test]
    fn share_references_require_independent_participants_and_handles() {
        let first = ThresholdShareReference::new(1, "opaque://desktop").unwrap();
        let second = ThresholdShareReference::new(3, "opaque://backup").unwrap();
        assert!(validate_share_references(&[first.clone(), second], None).is_ok());
        assert!(validate_share_references(&[first.clone(), first], None).is_err());
        let online = [
            ThresholdShareReference::new(1, "opaque://desktop").unwrap(),
            ThresholdShareReference::new(2, "opaque://onepassword").unwrap(),
        ];
        let recovery = ThresholdShareReference::new(3, "opaque://mobile").unwrap();
        assert!(validate_share_references(&online, Some(&recovery)).is_ok());
        let duplicate = ThresholdShareReference::new(2, "opaque://mobile").unwrap();
        assert!(validate_share_references(&online, Some(&duplicate)).is_err());
    }

    #[test]
    fn strict_threshold_manifests_require_recovery_while_legacy_remains_compatible() {
        let chia = chia_dealer_split(
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            [0x31; 32],
            [0x32; 32],
        )
        .unwrap();
        let chia_snapshot = snapshot(
            Uuid::from_u128(31),
            ChainNetwork::Chia(ChiaNetwork::Testnet11),
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            &chia.commitment().group_public_key(),
            "opaque://manifest/chia-version",
        );
        let chia_online = [
            ThresholdShareReference::new(1, "opaque://chia/1").unwrap(),
            ThresholdShareReference::new(2, "opaque://chia/2").unwrap(),
        ];
        let strict_chia = encode_chia_threshold_manifest_with_recovery(
            &chia_snapshot,
            chia.commitment().coefficient_public_key(),
            chia_online.clone(),
            ThresholdShareReference::new(3, "opaque://chia/3").unwrap(),
        )
        .unwrap();
        let mut strict_chia_json: serde_json::Value =
            serde_json::from_slice(strict_chia.expose()).unwrap();
        strict_chia_json
            .as_object_mut()
            .unwrap()
            .remove("recovery_share");
        let strict_chia_resolver = MapResolver(HashMap::from([(
            chia_snapshot.secret_ref.clone(),
            serde_json::to_vec(&strict_chia_json).unwrap(),
        )]));
        assert!(load_manifest(&strict_chia_resolver, &chia_snapshot).is_err());
        let legacy_chia = encode_chia_threshold_manifest(
            &chia_snapshot,
            chia.commitment().coefficient_public_key(),
            chia_online,
        )
        .unwrap();
        let legacy_chia_resolver = MapResolver(HashMap::from([(
            chia_snapshot.secret_ref.clone(),
            legacy_chia.expose().to_vec(),
        )]));
        assert!(load_manifest(&legacy_chia_resolver, &chia_snapshot).is_ok());

        let mut ergo_first = [0_u8; 32];
        ergo_first[31] = 11;
        let mut ergo_second = [0_u8; 32];
        ergo_second[31] = 13;
        let ergo = ergo_dealer_split(ergo_first, ergo_second).unwrap();
        let ergo_snapshot = snapshot(
            Uuid::from_u128(32),
            ChainNetwork::Ergo(ErgoNetwork::Testnet),
            SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
            &ergo.commitment().group_public_key(),
            "opaque://manifest/ergo-version",
        );
        let ergo_online = [
            ThresholdShareReference::new(1, "opaque://ergo/1").unwrap(),
            ThresholdShareReference::new(2, "opaque://ergo/2").unwrap(),
        ];
        let strict_ergo = encode_ergo_threshold_manifest_with_recovery(
            &ergo_snapshot,
            ergo.commitment().coefficient_public_key(),
            ergo_online.clone(),
            ThresholdShareReference::new(3, "opaque://ergo/3").unwrap(),
        )
        .unwrap();
        let mut strict_ergo_json: serde_json::Value =
            serde_json::from_slice(strict_ergo.expose()).unwrap();
        strict_ergo_json
            .as_object_mut()
            .unwrap()
            .remove("recovery_share");
        let strict_ergo_resolver = MapResolver(HashMap::from([(
            ergo_snapshot.secret_ref.clone(),
            serde_json::to_vec(&strict_ergo_json).unwrap(),
        )]));
        assert!(load_manifest(&strict_ergo_resolver, &ergo_snapshot).is_err());
        let legacy_ergo = encode_ergo_threshold_manifest(
            &ergo_snapshot,
            ergo.commitment().coefficient_public_key(),
            ergo_online,
        )
        .unwrap();
        let legacy_ergo_resolver = MapResolver(HashMap::from([(
            ergo_snapshot.secret_ref.clone(),
            legacy_ergo.expose().to_vec(),
        )]));
        assert!(load_manifest(&legacy_ergo_resolver, &ergo_snapshot).is_ok());
    }

    #[test]
    fn durable_operation_claim_survives_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let mut first = DurableClaimStore::new(temporary.path().to_path_buf(), key).unwrap();
        ChiaExecutionClaimStore::claim(&mut first, [1; 32], b"review", [2; 32]).unwrap();
        drop(first);
        let mut restarted = DurableClaimStore::new(temporary.path().to_path_buf(), key).unwrap();
        assert!(
            ChiaExecutionClaimStore::claim(&mut restarted, [1; 32], b"review", [2; 32]).is_err()
        );
    }

    #[test]
    fn manifest_rejects_network_and_profile_drift() {
        let dealer = chia_dealer_split(
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            [1_u8; 32],
            [2_u8; 32],
        )
        .unwrap();
        let original = snapshot(
            Uuid::from_u128(10),
            ChainNetwork::Chia(ChiaNetwork::Testnet11),
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            &dealer.commitment().group_public_key(),
            "opaque://manifest",
        );
        let encoded = encode_chia_threshold_manifest(
            &original,
            dealer.commitment().coefficient_public_key(),
            [
                ThresholdShareReference::new(1, "opaque://first").unwrap(),
                ThresholdShareReference::new(3, "opaque://third").unwrap(),
            ],
        )
        .unwrap();
        let resolver = MapResolver(HashMap::from([(
            "opaque://manifest".to_owned(),
            encoded.expose().to_vec(),
        )]));
        assert!(load_manifest(&resolver, &original).is_ok());
        let mut drifted = original;
        drifted.chain_scope = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Mainnet));
        assert_eq!(
            load_manifest(&resolver, &drifted).unwrap_err(),
            ExecutorFactoryError::InvalidConfiguration
        );
    }

    #[test]
    fn production_builders_import_two_committed_shares_for_each_chain() {
        let chia = chia_dealer_split(
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            [3_u8; 32],
            [4_u8; 32],
        )
        .unwrap();
        let chia_snapshot = snapshot(
            Uuid::from_u128(20),
            ChainNetwork::Chia(ChiaNetwork::Testnet11),
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            &chia.commitment().group_public_key(),
            "opaque://chia-manifest",
        );
        let chia_manifest = encode_chia_threshold_manifest(
            &chia_snapshot,
            chia.commitment().coefficient_public_key(),
            [
                ThresholdShareReference::new(1, "opaque://chia-1").unwrap(),
                ThresholdShareReference::new(3, "opaque://chia-3").unwrap(),
            ],
        )
        .unwrap();

        let mut one = [0_u8; 32];
        one[31] = 5;
        let mut two = [0_u8; 32];
        two[31] = 7;
        let ergo = ergo_dealer_split(one, two).unwrap();
        let ergo_snapshot = snapshot(
            Uuid::from_u128(21),
            ChainNetwork::Ergo(ErgoNetwork::Testnet),
            SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
            &ergo.commitment().group_public_key(),
            "opaque://ergo-manifest",
        );
        let ergo_manifest = encode_ergo_threshold_manifest(
            &ergo_snapshot,
            ergo.commitment().coefficient_public_key(),
            [
                ThresholdShareReference::new(1, "opaque://ergo-1").unwrap(),
                ThresholdShareReference::new(2, "opaque://ergo-2").unwrap(),
            ],
        )
        .unwrap();

        let resolver: Arc<dyn ThresholdSecretResolver> = Arc::new(MapResolver(HashMap::from([
            (
                "opaque://chia-manifest".to_owned(),
                chia_manifest.expose().to_vec(),
            ),
            (
                "opaque://chia-1".to_owned(),
                chia.shares()[0].export_for_provisioning().to_vec(),
            ),
            (
                "opaque://chia-3".to_owned(),
                chia.shares()[2].export_for_provisioning().to_vec(),
            ),
            (
                "opaque://ergo-manifest".to_owned(),
                ergo_manifest.expose().to_vec(),
            ),
            (
                "opaque://ergo-1".to_owned(),
                ergo.shares()[0].export_for_provisioning().to_vec(),
            ),
            (
                "opaque://ergo-2".to_owned(),
                ergo.shares()[1].export_for_provisioning().to_vec(),
            ),
        ])));
        let temporary = tempfile::tempdir().unwrap();
        let builders = chia_ergo_startup_builders(Arc::clone(&resolver), temporary.path()).unwrap();
        assert!(builders[0].1.build(&chia_snapshot).is_ok());
        assert!(builders[1].1.build(&ergo_snapshot).is_ok());

        let scope = chia_snapshot.chain_scope;
        let puzzle_hash =
            standard_threshold_puzzle_hash(chia.commitment().group_public_key()).unwrap();
        let spend = ThresholdChiaSpend::standard(
            scope,
            ChiaCoin::new([0x44; 32].into(), puzzle_hash.into(), 2_000_000),
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            chia.commitment().clone(),
            vec![ChiaSpendOutput::new([0x55; 32], 1_900_000)],
        )
        .unwrap();
        let suite = ChiaChainSuite::new_threshold(
            scope,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            chia.commitment().clone(),
        )
        .unwrap();
        let review = suite
            .review_transaction(&spend.to_review_bytes().unwrap())
            .unwrap();
        let review_binding = ReviewBinding::new(
            scope,
            chia_snapshot.signing_suite_id,
            chia_snapshot.signer_set_id.clone(),
            chia_snapshot.signer_epoch,
            review.schema_version,
            review.review_digest,
        )
        .unwrap();
        let execution = ChainSigningExecution {
            operation_binding_digest: [0x66; 32],
            job: SigningJob {
                job_id: Uuid::from_u128(30),
                intent_id: Uuid::from_u128(31),
                profile_id: chia_snapshot.profile_id,
                wallet_id: chia_snapshot.wallet_id,
                chain_scope: scope,
                signing_suite_id: chia_snapshot.signing_suite_id,
                backend_requirement: chia_snapshot.backend_requirement,
                review,
                review_binding,
                policy_snapshot_digest: [0x77; 32],
                chain_snapshot_digest: [0x88; 32],
                online_parties: ["desktop".to_owned(), "backup".to_owned()],
                receiver: "receiver".to_owned(),
                session_id: [0x99; 32],
                expires_at: 200,
                created_at: 100,
            },
        };
        let executor = builders[0].1.build(&chia_snapshot).unwrap();
        executor.execute(&execution, 150).unwrap();

        let restarted = chia_ergo_startup_builders(resolver, temporary.path()).unwrap();
        let restarted = restarted[0].1.build(&chia_snapshot).unwrap();
        assert!(matches!(
            restarted.execute(&execution, 151),
            Err(SigningJobError::Backend(_))
        ));
    }

    #[test]
    fn builders_expose_only_the_two_chain_threshold_backends() {
        struct Missing;
        impl ThresholdSecretResolver for Missing {
            fn resolve(&self, _: &str) -> Result<SecretValue, String> {
                Err("missing".to_owned())
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let builders = chia_ergo_startup_builders(Arc::new(Missing), temporary.path()).unwrap();
        assert_eq!(builders.len(), 2);
        assert_eq!(
            builders[0].0,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3
        );
        assert_eq!(
            builders[1].0,
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
        );
    }
}
