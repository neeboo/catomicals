//! Signer-provider identity and request contracts.
//!
//! These types deliberately carry only public identity, an exact Taproot
//! message digest, an approved-policy digest, session binding, and one-time
//! request nonces. Key packages, signing shares, secret nonces, Passkey
//! assertions, and HSM handles are outside the contract.

use std::collections::{BTreeMap, HashSet};

use frost_secp256k1_tr::{
    SigningPackage, keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare,
};
use rand::{RngCore, rngs::OsRng};
use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{AuthorizationError, FrostSession, LocalFrostParticipant, SigningAuthorization};

pub const SIGNER_PROVIDER_PROTOCOL_VERSION: u16 = 1;
const REGISTRATION_DOMAIN: &[u8] = b"catomicals/signer-device-registration/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerProviderKind {
    LocalEncrypted,
    RemoteMtls,
    HsmAdapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Unconfigured,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceHealth {
    pub online: bool,
    pub checked_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerDeviceRecord {
    pub signer_id: u16,
    pub device_id: Option<Uuid>,
    pub generation: u64,
    pub provider: Option<SignerProviderKind>,
    pub identity_public_key_hex: Option<String>,
    pub mtls_spki_sha256_hex: Option<String>,
    pub status: DeviceStatus,
    pub registered_at: Option<i64>,
    pub rotated_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub health: DeviceHealth,
}

impl SignerDeviceRecord {
    fn unconfigured(signer_id: u16) -> Self {
        Self {
            signer_id,
            device_id: None,
            generation: 0,
            provider: None,
            identity_public_key_hex: None,
            mtls_spki_sha256_hex: None,
            status: DeviceStatus::Unconfigured,
            registered_at: None,
            rotated_at: None,
            revoked_at: None,
            health: DeviceHealth::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationChallenge {
    pub challenge_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub signer_id: u16,
    pub next_generation: u64,
    #[serde(with = "hex32")]
    pub nonce: [u8; 32],
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationProof {
    pub challenge_id: Uuid,
    pub device_id: Uuid,
    pub provider: SignerProviderKind,
    pub identity_public_key_hex: String,
    pub mtls_spki_sha256_hex: Option<String>,
    pub signature_hex: String,
    pub previous_device_signature_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRequestContext {
    pub protocol_version: u16,
    pub wallet_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub signer_id: u16,
    pub device_id: Uuid,
    pub device_generation: u64,
    pub operation_id: Uuid,
    pub intent_id: Uuid,
    #[serde(with = "hex32")]
    pub session_id: [u8; 32],
    #[serde(with = "hex32")]
    pub taproot_sighash: [u8; 32],
    #[serde(with = "hex32")]
    pub policy_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub group_pubkey_xonly: [u8; 32],
    #[serde(with = "hex32")]
    pub verifying_share_digest: [u8; 32],
    pub min_signers: u16,
    pub max_signers: u16,
    #[serde(with = "hex32")]
    pub chain_snapshot_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub request_nonce: [u8; 32],
    pub expires_at: i64,
}

impl SignerRequestContext {
    /// Stable digest shared by every request in one signer operation. The
    /// request nonce is intentionally excluded so round one, round two and an
    /// abort can each use an independent replay nonce without changing the
    /// approved transaction, policy, device or signer-set binding.
    pub fn operation_binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals/signer-operation/v1\0");
        self.update_common_binding(&mut hasher);
        hasher.finalize().into()
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals/signer-request/v1\0");
        self.update_common_binding(&mut hasher);
        hasher.update(self.request_nonce);
        hasher.finalize().into()
    }

    fn update_common_binding(&self, hasher: &mut Sha256) {
        hasher.update(self.protocol_version.to_be_bytes());
        hasher.update(self.wallet_id.as_bytes());
        hasher.update(self.signer_set_id.as_bytes());
        hasher.update(self.signer_epoch.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        hasher.update(self.device_id.as_bytes());
        hasher.update(self.device_generation.to_be_bytes());
        hasher.update(self.operation_id.as_bytes());
        hasher.update(self.intent_id.as_bytes());
        hasher.update(self.session_id);
        hasher.update(self.taproot_sighash);
        hasher.update(self.policy_digest);
        hasher.update(self.group_pubkey_xonly);
        hasher.update(self.verifying_share_digest);
        hasher.update(self.min_signers.to_be_bytes());
        hasher.update(self.max_signers.to_be_bytes());
        hasher.update(self.chain_snapshot_digest);
        hasher.update(self.expires_at.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRoundOneRequest {
    pub context: SignerRequestContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRoundOneResponse {
    #[serde(with = "hex32")]
    pub request_binding_digest: [u8; 32],
    pub commitment_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRoundTwoRequest {
    pub context: SignerRequestContext,
    pub signing_package_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRoundTwoResponse {
    #[serde(with = "hex32")]
    pub request_binding_digest: [u8; 32],
    pub signature_share_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerAbortRequest {
    pub context: SignerRequestContext,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub wallet_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub signer_id: u16,
    pub device_id: Uuid,
    pub device_generation: u64,
    pub group_pubkey_xonly: [u8; 32],
    pub verifying_share_digest: [u8; 32],
}

/// Backend boundary implemented by the encrypted local signer process or a
/// concrete HSM integration. Implementations must atomically reserve and burn
/// nonce state before exposing a commitment. No method returns key material,
/// an HSM object handle, or a secret nonce.
pub trait FrostSignerBackend: Send {
    fn provider_kind(&self) -> SignerProviderKind;
    fn health(&mut self, now: i64) -> DeviceHealth;
    fn reserve_nonce_and_commit(
        &mut self,
        context: &SignerRequestContext,
    ) -> Result<SigningCommitments, ProviderError>;
    fn sign_reserved_share(
        &mut self,
        context: &SignerRequestContext,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare, ProviderError>;
    fn burn_reservation(
        &mut self,
        operation_id: Uuid,
        session_id: [u8; 32],
        reason_code: &str,
    ) -> Result<(), ProviderError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRound {
    RoundOne,
    RoundTwo,
}

/// Wallet-owned policy hook. A local signer backend calls this before nonce
/// creation and again before consuming the nonce to produce a share. The
/// implementation is expected to read durable approval and policy state.
pub trait ProviderRequestAuthorizer: Send {
    fn authorize(
        &mut self,
        context: &SignerRequestContext,
        round: ProviderRound,
    ) -> Result<(), ProviderError>;
}

/// Local signer backend for a key package loaded from encrypted storage.
/// Encryption and key loading stay outside this type; once loaded, the key and
/// nonce state remain inside `LocalFrostParticipant` and never cross the
/// provider interface.
pub struct LocalEncryptedFrostBackend<A> {
    participant: LocalFrostParticipant,
    public_key_package: PublicKeyPackage,
    authorizer: A,
    reservations: BTreeMap<Uuid, ReservationBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReservationBinding {
    session_id: [u8; 32],
    taproot_sighash: [u8; 32],
    operation_binding_digest: [u8; 32],
}

impl<A: ProviderRequestAuthorizer> LocalEncryptedFrostBackend<A> {
    pub fn new(
        participant: LocalFrostParticipant,
        public_key_package: PublicKeyPackage,
        authorizer: A,
    ) -> Self {
        Self {
            participant,
            public_key_package,
            authorizer,
            reservations: BTreeMap::new(),
        }
    }
}

impl<A: ProviderRequestAuthorizer> FrostSignerBackend for LocalEncryptedFrostBackend<A> {
    fn provider_kind(&self) -> SignerProviderKind {
        SignerProviderKind::LocalEncrypted
    }

    fn health(&mut self, now: i64) -> DeviceHealth {
        DeviceHealth {
            online: true,
            checked_at: Some(now),
            last_success_at: Some(now),
            last_error_code: None,
        }
    }

    fn reserve_nonce_and_commit(
        &mut self,
        context: &SignerRequestContext,
    ) -> Result<SigningCommitments, ProviderError> {
        self.authorizer
            .authorize(context, ProviderRound::RoundOne)?;
        if self.reservations.contains_key(&context.operation_id) {
            return Err(ProviderError::Replay);
        }
        let commitment = self
            .participant
            .round1(context.session_id, context.taproot_sighash)
            .map_err(|_| ProviderError::RoundBindingMismatch)?;
        self.reservations.insert(
            context.operation_id,
            ReservationBinding {
                session_id: context.session_id,
                taproot_sighash: context.taproot_sighash,
                operation_binding_digest: context.operation_binding_digest(),
            },
        );
        Ok(commitment)
    }

    fn sign_reserved_share(
        &mut self,
        context: &SignerRequestContext,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare, ProviderError> {
        if self.reservations.get(&context.operation_id)
            != Some(&ReservationBinding {
                session_id: context.session_id,
                taproot_sighash: context.taproot_sighash,
                operation_binding_digest: context.operation_binding_digest(),
            })
        {
            return Err(ProviderError::RoundBindingMismatch);
        }
        self.authorizer
            .authorize(context, ProviderRound::RoundTwo)?;
        // Burn the operation before asking the participant to sign. A failure
        // after this point requires a fresh round-one nonce reservation.
        self.reservations.remove(&context.operation_id);
        let session = FrostSession {
            id: context.session_id,
            message: context.taproot_sighash,
            min_signers: context.min_signers,
            signing_package: signing_package.clone(),
            public_key_package: self.public_key_package.clone(),
        };
        let mut authorization = ExactContextAuthorization {
            context,
            used: false,
        };
        self.participant
            .round2(&session, &mut authorization, context.expires_at)
            .map_err(|_| ProviderError::RoundBindingMismatch)
    }

    fn burn_reservation(
        &mut self,
        operation_id: Uuid,
        session_id: [u8; 32],
        _reason_code: &str,
    ) -> Result<(), ProviderError> {
        let Some(reservation) = self.reservations.remove(&operation_id) else {
            return Err(ProviderError::RoundBindingMismatch);
        };
        if reservation.session_id != session_id {
            return Err(ProviderError::RoundBindingMismatch);
        }
        self.participant.abort_round(&session_id);
        Ok(())
    }
}

struct ExactContextAuthorization<'a> {
    context: &'a SignerRequestContext,
    used: bool,
}

impl SigningAuthorization for ExactContextAuthorization<'_> {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        now: i64,
    ) -> Result<(), AuthorizationError> {
        if self.used {
            return Err(AuthorizationError::AlreadyConsumed);
        }
        if session_id != &self.context.session_id {
            return Err(AuthorizationError::WrongSession);
        }
        if message != &self.context.taproot_sighash {
            return Err(AuthorizationError::WrongMessage);
        }
        if signer_id != self.context.signer_id {
            return Err(AuthorizationError::WrongSigner);
        }
        if now > self.context.expires_at {
            return Err(AuthorizationError::Expired);
        }
        self.used = true;
        Ok(())
    }
}

/// Narrow provider interface used by a local wallet or signer transport.
pub trait SignerProvider: Send {
    fn identity(&self) -> &ProviderIdentity;
    fn kind(&self) -> SignerProviderKind;
    fn health(&mut self, now: i64) -> DeviceHealth;
    fn round_one(
        &mut self,
        request: SignerRoundOneRequest,
        now: i64,
    ) -> Result<SignerRoundOneResponse, ProviderError>;
    fn round_two(
        &mut self,
        request: SignerRoundTwoRequest,
        now: i64,
    ) -> Result<SignerRoundTwoResponse, ProviderError>;
    fn abort(&mut self, request: SignerAbortRequest, now: i64) -> Result<(), ProviderError>;
}

/// Durable implementations must atomically insert the claim and return
/// [`ProviderError::Replay`] on a uniqueness conflict. This seam keeps request
/// replay state out of HSM drivers while allowing the signer process to use its
/// encrypted SQLite authority store.
pub trait ProviderReplayStore: Send {
    fn claim_request_nonce(
        &mut self,
        identity: &ProviderIdentity,
        context: &SignerRequestContext,
        claimed_at: i64,
    ) -> Result<(), ProviderError>;
}

#[derive(Default)]
pub struct MemoryProviderReplayStore {
    consumed: HashSet<[u8; 32]>,
}

impl ProviderReplayStore for MemoryProviderReplayStore {
    fn claim_request_nonce(
        &mut self,
        _identity: &ProviderIdentity,
        context: &SignerRequestContext,
        _claimed_at: i64,
    ) -> Result<(), ProviderError> {
        if self.consumed.insert(context.request_nonce) {
            Ok(())
        } else {
            Err(ProviderError::Replay)
        }
    }
}

/// Common fail-closed wrapper for local encrypted and HSM backends. A remote
/// signer hosts one of these behind the authenticated transport; a coordinator
/// never receives the wrapped backend or its key material.
pub struct GuardedSignerProvider<B, R = MemoryProviderReplayStore> {
    identity: ProviderIdentity,
    backend: B,
    replay_store: R,
}

impl<B: FrostSignerBackend> GuardedSignerProvider<B, MemoryProviderReplayStore> {
    pub fn new(identity: ProviderIdentity, backend: B) -> Self {
        Self::with_replay_store(identity, backend, MemoryProviderReplayStore::default())
    }
}

impl<B: FrostSignerBackend, R: ProviderReplayStore> GuardedSignerProvider<B, R> {
    pub fn with_replay_store(identity: ProviderIdentity, backend: B, replay_store: R) -> Self {
        Self {
            identity,
            backend,
            replay_store,
        }
    }

    fn authorize_context(
        &mut self,
        context: &SignerRequestContext,
        now: i64,
    ) -> Result<(), ProviderError> {
        if context.protocol_version != SIGNER_PROVIDER_PROTOCOL_VERSION
            || context.wallet_id != self.identity.wallet_id
            || context.signer_set_id != self.identity.signer_set_id
            || context.signer_epoch != self.identity.signer_epoch
            || context.signer_id != self.identity.signer_id
            || context.device_id != self.identity.device_id
            || context.device_generation != self.identity.device_generation
            || context.group_pubkey_xonly != self.identity.group_pubkey_xonly
            || context.verifying_share_digest != self.identity.verifying_share_digest
            || context.min_signers == 0
            || context.min_signers > context.max_signers
        {
            return Err(ProviderError::IdentityDrift);
        }
        if now > context.expires_at {
            return Err(ProviderError::Expired);
        }
        self.replay_store
            .claim_request_nonce(&self.identity, context, now)
    }
}

impl<B: FrostSignerBackend, R: ProviderReplayStore> SignerProvider for GuardedSignerProvider<B, R> {
    fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    fn kind(&self) -> SignerProviderKind {
        self.backend.provider_kind()
    }

    fn health(&mut self, now: i64) -> DeviceHealth {
        self.backend.health(now)
    }

    fn round_one(
        &mut self,
        request: SignerRoundOneRequest,
        now: i64,
    ) -> Result<SignerRoundOneResponse, ProviderError> {
        self.authorize_context(&request.context, now)?;
        let binding = request.context.binding_digest();
        let commitment = self.backend.reserve_nonce_and_commit(&request.context)?;
        Ok(SignerRoundOneResponse {
            request_binding_digest: binding,
            commitment_hex: hex::encode(
                commitment
                    .serialize()
                    .map_err(|_| ProviderError::InvalidEncoding)?,
            ),
        })
    }

    fn round_two(
        &mut self,
        request: SignerRoundTwoRequest,
        now: i64,
    ) -> Result<SignerRoundTwoResponse, ProviderError> {
        self.authorize_context(&request.context, now)?;
        let bytes = hex::decode(&request.signing_package_hex)
            .map_err(|_| ProviderError::InvalidEncoding)?;
        if bytes.len() > MAX_SIGNING_PACKAGE_BYTES {
            return Err(ProviderError::InvalidEncoding);
        }
        let package =
            SigningPackage::deserialize(&bytes).map_err(|_| ProviderError::InvalidEncoding)?;
        let identifier = frost_secp256k1_tr::Identifier::try_from(request.context.signer_id)
            .map_err(|_| ProviderError::InvalidEncoding)?;
        if package.message().as_slice() != request.context.taproot_sighash
            || !package.signing_commitments().contains_key(&identifier)
        {
            return Err(ProviderError::RoundBindingMismatch);
        }
        let binding = request.context.binding_digest();
        let share = self
            .backend
            .sign_reserved_share(&request.context, &package)?;
        Ok(SignerRoundTwoResponse {
            request_binding_digest: binding,
            signature_share_hex: hex::encode(share.serialize()),
        })
    }

    fn abort(&mut self, request: SignerAbortRequest, now: i64) -> Result<(), ProviderError> {
        self.authorize_context(&request.context, now)?;
        if request.reason_code.is_empty()
            || request.reason_code.len() > MAX_REASON_CODE_BYTES
            || !request
                .reason_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ProviderError::InvalidEncoding);
        }
        self.backend.burn_reservation(
            request.context.operation_id,
            request.context.session_id,
            &request.reason_code,
        )
    }
}

/// Adapter boundary for a concrete FROST-capable HSM driver. Construction
/// rejects ordinary local backends, preventing an in-process signer from being
/// presented as hardware-backed.
pub struct HsmSignerAdapter<B, R = MemoryProviderReplayStore>(GuardedSignerProvider<B, R>);

impl<B: FrostSignerBackend> HsmSignerAdapter<B, MemoryProviderReplayStore> {
    pub fn new(identity: ProviderIdentity, backend: B) -> Result<Self, ProviderError> {
        if backend.provider_kind() != SignerProviderKind::HsmAdapter {
            return Err(ProviderError::InvalidProvider);
        }
        Ok(Self(GuardedSignerProvider::new(identity, backend)))
    }
}

impl<B: FrostSignerBackend, R: ProviderReplayStore> HsmSignerAdapter<B, R> {
    pub fn with_replay_store(
        identity: ProviderIdentity,
        backend: B,
        replay_store: R,
    ) -> Result<Self, ProviderError> {
        if backend.provider_kind() != SignerProviderKind::HsmAdapter {
            return Err(ProviderError::InvalidProvider);
        }
        Ok(Self(GuardedSignerProvider::with_replay_store(
            identity,
            backend,
            replay_store,
        )))
    }
}

impl<B: FrostSignerBackend, R: ProviderReplayStore> SignerProvider for HsmSignerAdapter<B, R> {
    fn identity(&self) -> &ProviderIdentity {
        self.0.identity()
    }

    fn kind(&self) -> SignerProviderKind {
        SignerProviderKind::HsmAdapter
    }

    fn health(&mut self, now: i64) -> DeviceHealth {
        self.0.health(now)
    }

    fn round_one(
        &mut self,
        request: SignerRoundOneRequest,
        now: i64,
    ) -> Result<SignerRoundOneResponse, ProviderError> {
        self.0.round_one(request, now)
    }

    fn round_two(
        &mut self,
        request: SignerRoundTwoRequest,
        now: i64,
    ) -> Result<SignerRoundTwoResponse, ProviderError> {
        self.0.round_two(request, now)
    }

    fn abort(&mut self, request: SignerAbortRequest, now: i64) -> Result<(), ProviderError> {
        self.0.abort(request, now)
    }
}

const MAX_SIGNING_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_REASON_CODE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("signer participant is outside this signer set")]
    UnknownParticipant,
    #[error("signer device is not configured")]
    Unconfigured,
    #[error("signer device is revoked")]
    Revoked,
    #[error("signer registration challenge is missing, expired, or already consumed")]
    InvalidChallenge,
    #[error("signer device proof of possession is invalid")]
    InvalidProof,
    #[error("signer rotation requires authorization from the active device")]
    RotationAuthorizationRequired,
    #[error("signer provider kind is invalid for this registration")]
    InvalidProvider,
    #[error("signer device identity or generation drifted")]
    IdentityDrift,
    #[error("mTLS peer public-key pin does not match the registered device")]
    SpkiMismatch,
    #[error("signer request has expired")]
    Expired,
    #[error("signer request protocol or signer-set binding is invalid")]
    WrongSignerSet,
    #[error("signer request nonce was already consumed")]
    Replay,
    #[error("signer request encoding is invalid")]
    InvalidEncoding,
    #[error("signer round is not bound to the reserved operation and message")]
    RoundBindingMismatch,
    #[error("signer backend is unavailable")]
    BackendUnavailable,
}

/// Authority-side registry. Health is false until a successfully authenticated
/// request or probe is observed; registration alone never claims availability.
pub struct SignerDeviceRegistry {
    signer_set_id: Uuid,
    signer_epoch: u64,
    devices: BTreeMap<u16, SignerDeviceRecord>,
    challenges: BTreeMap<Uuid, DeviceRegistrationChallenge>,
    consumed_request_nonces: HashSet<(Uuid, u64, [u8; 32])>,
}

impl SignerDeviceRegistry {
    pub fn new(signer_set_id: Uuid, signer_epoch: u64, max_signers: u16) -> Self {
        let devices = (1..=max_signers)
            .map(|signer_id| (signer_id, SignerDeviceRecord::unconfigured(signer_id)))
            .collect();
        Self {
            signer_set_id,
            signer_epoch,
            devices,
            challenges: BTreeMap::new(),
            consumed_request_nonces: HashSet::new(),
        }
    }

    pub fn devices(&self) -> Vec<SignerDeviceRecord> {
        self.devices.values().cloned().collect()
    }

    /// Restore configured device metadata from the wallet authority database.
    /// Availability is never restored: every device starts offline until a new
    /// authenticated probe or request succeeds.
    pub fn restore_device_records(
        &mut self,
        records: Vec<SignerDeviceRecord>,
    ) -> Result<(), ProviderError> {
        if self
            .devices
            .values()
            .any(|record| record.status != DeviceStatus::Unconfigured)
        {
            return Err(ProviderError::IdentityDrift);
        }
        let mut restored = self.devices.clone();
        let mut seen = HashSet::new();
        for mut record in records {
            if !seen.insert(record.signer_id)
                || record.generation == 0
                || record.device_id.is_none()
                || !matches!(record.status, DeviceStatus::Active | DeviceStatus::Revoked)
                || !matches!(
                    record.provider,
                    Some(SignerProviderKind::RemoteMtls | SignerProviderKind::HsmAdapter)
                )
            {
                return Err(ProviderError::InvalidEncoding);
            }
            parse_hex32(
                record
                    .identity_public_key_hex
                    .as_deref()
                    .ok_or(ProviderError::InvalidEncoding)?,
            )?;
            let certificate = record
                .mtls_spki_sha256_hex
                .as_deref()
                .map(parse_hex32)
                .transpose()?;
            if record.provider == Some(SignerProviderKind::RemoteMtls) && certificate.is_none() {
                return Err(ProviderError::SpkiMismatch);
            }
            if !restored.contains_key(&record.signer_id) {
                return Err(ProviderError::UnknownParticipant);
            }
            record.health = DeviceHealth::default();
            restored.insert(record.signer_id, record);
        }
        self.devices = restored;
        Ok(())
    }

    pub fn issue_registration_challenge(
        &mut self,
        signer_id: u16,
        now: i64,
        ttl_seconds: i64,
    ) -> Result<DeviceRegistrationChallenge, ProviderError> {
        if ttl_seconds <= 0 {
            return Err(ProviderError::InvalidChallenge);
        }
        let record = self
            .devices
            .get(&signer_id)
            .ok_or(ProviderError::UnknownParticipant)?;
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let challenge = DeviceRegistrationChallenge {
            challenge_id: Uuid::new_v4(),
            signer_set_id: self.signer_set_id,
            signer_epoch: self.signer_epoch,
            signer_id,
            next_generation: record.generation + 1,
            nonce,
            expires_at: now
                .checked_add(ttl_seconds)
                .ok_or(ProviderError::InvalidChallenge)?,
        };
        self.challenges
            .insert(challenge.challenge_id, challenge.clone());
        Ok(challenge)
    }

    pub fn register(
        &mut self,
        proof: DeviceRegistrationProof,
        now: i64,
    ) -> Result<SignerDeviceRecord, ProviderError> {
        let challenge = self
            .challenges
            .remove(&proof.challenge_id)
            .ok_or(ProviderError::InvalidChallenge)?;
        if now > challenge.expires_at
            || challenge.signer_set_id != self.signer_set_id
            || challenge.signer_epoch != self.signer_epoch
        {
            return Err(ProviderError::InvalidChallenge);
        }
        if proof.provider == SignerProviderKind::LocalEncrypted {
            return Err(ProviderError::InvalidProvider);
        }
        let certificate = match proof.provider {
            SignerProviderKind::RemoteMtls => Some(parse_hex32(
                proof
                    .mtls_spki_sha256_hex
                    .as_deref()
                    .ok_or(ProviderError::SpkiMismatch)?,
            )?),
            SignerProviderKind::HsmAdapter => proof
                .mtls_spki_sha256_hex
                .as_deref()
                .map(parse_hex32)
                .transpose()?,
            SignerProviderKind::LocalEncrypted => unreachable!(),
        };
        let current = self
            .devices
            .get(&challenge.signer_id)
            .ok_or(ProviderError::UnknownParticipant)?;
        if challenge.next_generation != current.generation + 1 {
            return Err(ProviderError::IdentityDrift);
        }
        if current.status == DeviceStatus::Revoked {
            return Err(ProviderError::Revoked);
        }
        verify_registration_proof(&challenge, &proof, certificate)?;
        if current.status == DeviceStatus::Active {
            verify_rotation_authorization(current, &challenge, &proof, certificate)?;
        }
        let record = SignerDeviceRecord {
            signer_id: challenge.signer_id,
            device_id: Some(proof.device_id),
            generation: challenge.next_generation,
            provider: Some(proof.provider),
            identity_public_key_hex: Some(proof.identity_public_key_hex.to_ascii_lowercase()),
            mtls_spki_sha256_hex: certificate.map(hex::encode),
            status: DeviceStatus::Active,
            registered_at: current.registered_at.or(Some(now)),
            rotated_at: (current.generation > 0).then_some(now),
            revoked_at: None,
            health: DeviceHealth::default(),
        };
        self.devices.insert(challenge.signer_id, record.clone());
        Ok(record)
    }

    pub fn revoke(
        &mut self,
        signer_id: u16,
        expected_device_id: Uuid,
        expected_generation: u64,
        now: i64,
    ) -> Result<SignerDeviceRecord, ProviderError> {
        let record = self
            .devices
            .get_mut(&signer_id)
            .ok_or(ProviderError::UnknownParticipant)?;
        if record.status == DeviceStatus::Unconfigured {
            return Err(ProviderError::Unconfigured);
        }
        if record.device_id != Some(expected_device_id) || record.generation != expected_generation
        {
            return Err(ProviderError::IdentityDrift);
        }
        record.status = DeviceStatus::Revoked;
        record.revoked_at = Some(now);
        record.health = DeviceHealth {
            online: false,
            checked_at: Some(now),
            last_success_at: record.health.last_success_at,
            last_error_code: Some("revoked".to_owned()),
        };
        Ok(record.clone())
    }

    pub fn authorize_request(
        &mut self,
        context: &SignerRequestContext,
        presented_spki_sha256: Option<[u8; 32]>,
        now: i64,
    ) -> Result<(), ProviderError> {
        if context.protocol_version != SIGNER_PROVIDER_PROTOCOL_VERSION
            || context.signer_set_id != self.signer_set_id
            || context.signer_epoch != self.signer_epoch
            || context.min_signers == 0
            || context.min_signers > context.max_signers
        {
            return Err(ProviderError::WrongSignerSet);
        }
        if now > context.expires_at {
            return Err(ProviderError::Expired);
        }
        let record = self
            .devices
            .get_mut(&context.signer_id)
            .ok_or(ProviderError::UnknownParticipant)?;
        match record.status {
            DeviceStatus::Unconfigured => return Err(ProviderError::Unconfigured),
            DeviceStatus::Revoked => return Err(ProviderError::Revoked),
            DeviceStatus::Active => {}
        }
        if record.device_id != Some(context.device_id)
            || record.generation != context.device_generation
        {
            return Err(ProviderError::IdentityDrift);
        }
        let expected_spki = record
            .mtls_spki_sha256_hex
            .as_deref()
            .map(parse_hex32)
            .transpose()?;
        if expected_spki != presented_spki_sha256 {
            return Err(ProviderError::SpkiMismatch);
        }
        if !self.consumed_request_nonces.insert((
            context.device_id,
            context.device_generation,
            context.request_nonce,
        )) {
            return Err(ProviderError::Replay);
        }
        record.health = DeviceHealth {
            online: true,
            checked_at: Some(now),
            last_success_at: Some(now),
            last_error_code: None,
        };
        Ok(())
    }

    pub fn mark_unavailable(
        &mut self,
        signer_id: u16,
        expected_device_id: Uuid,
        expected_generation: u64,
        error_code: &str,
        now: i64,
    ) -> Result<(), ProviderError> {
        let record = self
            .devices
            .get_mut(&signer_id)
            .ok_or(ProviderError::UnknownParticipant)?;
        if record.device_id != Some(expected_device_id) || record.generation != expected_generation
        {
            return Err(ProviderError::IdentityDrift);
        }
        record.health = DeviceHealth {
            online: false,
            checked_at: Some(now),
            last_success_at: record.health.last_success_at,
            last_error_code: Some(error_code.to_owned()),
        };
        Ok(())
    }
}

pub fn registration_digest(
    challenge: &DeviceRegistrationChallenge,
    proof: &DeviceRegistrationProof,
    spki_sha256: Option<[u8; 32]>,
) -> Result<[u8; 32], ProviderError> {
    let public_key = parse_hex32(&proof.identity_public_key_hex)?;
    let mut hasher = Sha256::new();
    hasher.update(REGISTRATION_DOMAIN);
    hasher.update(challenge.challenge_id.as_bytes());
    hasher.update(challenge.signer_set_id.as_bytes());
    hasher.update(challenge.signer_epoch.to_be_bytes());
    hasher.update(challenge.signer_id.to_be_bytes());
    hasher.update(challenge.next_generation.to_be_bytes());
    hasher.update(challenge.nonce);
    hasher.update(challenge.expires_at.to_be_bytes());
    hasher.update(proof.device_id.as_bytes());
    hasher.update([match proof.provider {
        SignerProviderKind::LocalEncrypted => 1,
        SignerProviderKind::RemoteMtls => 2,
        SignerProviderKind::HsmAdapter => 3,
    }]);
    hasher.update(public_key);
    hasher.update(spki_sha256.unwrap_or([0u8; 32]));
    Ok(hasher.finalize().into())
}

fn verify_registration_proof(
    challenge: &DeviceRegistrationChallenge,
    proof: &DeviceRegistrationProof,
    spki_sha256: Option<[u8; 32]>,
) -> Result<(), ProviderError> {
    let public_key = XOnlyPublicKey::from_slice(&parse_hex32(&proof.identity_public_key_hex)?)
        .map_err(|_| ProviderError::InvalidEncoding)?;
    let signature = Signature::from_slice(&parse_hex64(&proof.signature_hex)?)
        .map_err(|_| ProviderError::InvalidEncoding)?;
    let message = Message::from_digest(registration_digest(challenge, proof, spki_sha256)?);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| ProviderError::InvalidProof)
}

fn verify_rotation_authorization(
    current: &SignerDeviceRecord,
    challenge: &DeviceRegistrationChallenge,
    proof: &DeviceRegistrationProof,
    spki_sha256: Option<[u8; 32]>,
) -> Result<(), ProviderError> {
    let current_key = current
        .identity_public_key_hex
        .as_deref()
        .ok_or(ProviderError::RotationAuthorizationRequired)?;
    let signature_hex = proof
        .previous_device_signature_hex
        .as_deref()
        .ok_or(ProviderError::RotationAuthorizationRequired)?;
    let public_key = XOnlyPublicKey::from_slice(&parse_hex32(current_key)?)
        .map_err(|_| ProviderError::InvalidEncoding)?;
    let signature = Signature::from_slice(&parse_hex64(signature_hex)?)
        .map_err(|_| ProviderError::InvalidEncoding)?;
    let message = Message::from_digest(registration_digest(challenge, proof, spki_sha256)?);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| ProviderError::InvalidProof)
}

fn parse_hex32(value: &str) -> Result<[u8; 32], ProviderError> {
    hex::decode(value)
        .map_err(|_| ProviderError::InvalidEncoding)?
        .try_into()
        .map_err(|_| ProviderError::InvalidEncoding)
}

fn parse_hex64(value: &str) -> Result<[u8; 64], ProviderError> {
    hex::decode(value)
        .map_err(|_| ProviderError::InvalidEncoding)?
        .try_into()
        .map_err(|_| ProviderError::InvalidEncoding)
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(&value)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hexadecimal value"))
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, SecretKey};

    use super::*;

    fn proof(
        challenge: &DeviceRegistrationChallenge,
        secret_byte: u8,
        provider: SignerProviderKind,
        certificate: Option<[u8; 32]>,
    ) -> DeviceRegistrationProof {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let mut proof = DeviceRegistrationProof {
            challenge_id: challenge.challenge_id,
            device_id: Uuid::from_bytes([secret_byte; 16]),
            provider,
            identity_public_key_hex: hex::encode(public_key.serialize()),
            mtls_spki_sha256_hex: certificate.map(hex::encode),
            signature_hex: String::new(),
            previous_device_signature_hex: None,
        };
        let digest = registration_digest(challenge, &proof, certificate).unwrap();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair);
        proof.signature_hex = hex::encode(signature.as_ref() as &[u8; 64]);
        proof
    }

    fn authorize_rotation(
        challenge: &DeviceRegistrationChallenge,
        mut proof: DeviceRegistrationProof,
        prior_secret_byte: u8,
        certificate: Option<[u8; 32]>,
    ) -> DeviceRegistrationProof {
        let secp = Secp256k1::new();
        let prior_secret = SecretKey::from_slice(&[prior_secret_byte; 32]).unwrap();
        let prior_keypair = Keypair::from_secret_key(&secp, &prior_secret);
        let digest = registration_digest(challenge, &proof, certificate).unwrap();
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &prior_keypair);
        proof.previous_device_signature_hex = Some(hex::encode(signature.as_ref() as &[u8; 64]));
        proof
    }

    #[test]
    fn participants_default_to_unconfigured_and_offline() {
        let registry = SignerDeviceRegistry::new(Uuid::from_bytes([1; 16]), 1, 3);
        assert_eq!(registry.devices().len(), 3);
        assert!(registry.devices().iter().all(|device| {
            device.status == DeviceStatus::Unconfigured && !device.health.online
        }));
    }

    #[test]
    fn remote_registration_requires_possession_and_never_claims_health() {
        let mut registry = SignerDeviceRegistry::new(Uuid::from_bytes([2; 16]), 4, 3);
        let challenge = registry.issue_registration_challenge(2, 100, 30).unwrap();
        let record = registry
            .register(
                proof(&challenge, 7, SignerProviderKind::RemoteMtls, Some([9; 32])),
                110,
            )
            .unwrap();
        assert_eq!(record.status, DeviceStatus::Active);
        assert_eq!(record.generation, 1);
        assert!(!record.health.online);
        assert_eq!(
            registry.register(
                proof(&challenge, 7, SignerProviderKind::RemoteMtls, Some([9; 32])),
                111
            ),
            Err(ProviderError::InvalidChallenge)
        );
    }

    #[test]
    fn request_identity_certificate_expiry_and_nonce_are_exactly_bound() {
        let signer_set_id = Uuid::from_bytes([3; 16]);
        let mut registry = SignerDeviceRegistry::new(signer_set_id, 5, 3);
        let challenge = registry.issue_registration_challenge(2, 100, 30).unwrap();
        let record = registry
            .register(
                proof(
                    &challenge,
                    8,
                    SignerProviderKind::RemoteMtls,
                    Some([10; 32]),
                ),
                101,
            )
            .unwrap();
        let context = SignerRequestContext {
            protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
            wallet_id: Uuid::from_bytes([20; 16]),
            signer_set_id,
            signer_epoch: 5,
            signer_id: 2,
            device_id: record.device_id.unwrap(),
            device_generation: 1,
            operation_id: Uuid::from_bytes([21; 16]),
            intent_id: Uuid::from_bytes([22; 16]),
            session_id: [1; 32],
            taproot_sighash: [2; 32],
            policy_digest: [3; 32],
            group_pubkey_xonly: [7; 32],
            verifying_share_digest: [8; 32],
            min_signers: 2,
            max_signers: 3,
            chain_snapshot_digest: [9; 32],
            request_nonce: [4; 32],
            expires_at: 120,
        };
        assert_eq!(
            registry.authorize_request(&context, Some([11; 32]), 102),
            Err(ProviderError::SpkiMismatch)
        );
        registry
            .authorize_request(&context, Some([10; 32]), 102)
            .unwrap();
        assert_eq!(
            registry.authorize_request(&context, Some([10; 32]), 103),
            Err(ProviderError::Replay)
        );
        let mut drifted = context.clone();
        drifted.device_generation = 2;
        drifted.request_nonce = [5; 32];
        assert_eq!(
            registry.authorize_request(&drifted, Some([10; 32]), 103),
            Err(ProviderError::IdentityDrift)
        );
        let mut expired = context;
        expired.request_nonce = [6; 32];
        assert_eq!(
            registry.authorize_request(&expired, Some([10; 32]), 121),
            Err(ProviderError::Expired)
        );
    }

    #[test]
    fn signer_request_context_rejects_unknown_fields() {
        let identity = ProviderIdentity {
            wallet_id: Uuid::from_bytes([30; 16]),
            signer_set_id: Uuid::from_bytes([31; 16]),
            signer_epoch: 1,
            signer_id: 2,
            device_id: Uuid::from_bytes([32; 16]),
            device_generation: 1,
            group_pubkey_xonly: [33; 32],
            verifying_share_digest: [34; 32],
        };
        let context = SignerRequestContext {
            protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
            wallet_id: identity.wallet_id,
            signer_set_id: identity.signer_set_id,
            signer_epoch: identity.signer_epoch,
            signer_id: identity.signer_id,
            device_id: identity.device_id,
            device_generation: identity.device_generation,
            operation_id: Uuid::from_bytes([35; 16]),
            intent_id: Uuid::from_bytes([36; 16]),
            session_id: [37; 32],
            taproot_sighash: [38; 32],
            policy_digest: [39; 32],
            group_pubkey_xonly: identity.group_pubkey_xonly,
            verifying_share_digest: identity.verifying_share_digest,
            min_signers: 2,
            max_signers: 3,
            chain_snapshot_digest: [40; 32],
            request_nonce: [41; 32],
            expires_at: 200,
        };
        let mut encoded = serde_json::to_value(context).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<SignerRequestContext>(encoded).is_err());
    }

    #[test]
    fn rotation_increments_generation_and_revocation_forces_offline() {
        let mut registry = SignerDeviceRegistry::new(Uuid::from_bytes([4; 16]), 2, 3);
        let first_challenge = registry.issue_registration_challenge(3, 10, 30).unwrap();
        let first = registry
            .register(
                proof(&first_challenge, 10, SignerProviderKind::HsmAdapter, None),
                11,
            )
            .unwrap();
        let rotate_challenge = registry.issue_registration_challenge(3, 12, 30).unwrap();
        let rotated_proof = authorize_rotation(
            &rotate_challenge,
            proof(&rotate_challenge, 11, SignerProviderKind::HsmAdapter, None),
            10,
            None,
        );
        let rotated = registry.register(rotated_proof, 13).unwrap();
        assert_eq!(rotated.generation, 2);
        assert_eq!(rotated.rotated_at, Some(13));
        let revoked = registry
            .revoke(3, rotated.device_id.unwrap(), 2, 14)
            .unwrap();
        assert_eq!(revoked.status, DeviceStatus::Revoked);
        assert!(!revoked.health.online);
        assert_eq!(
            registry.revoke(3, first.device_id.unwrap(), 1, 15),
            Err(ProviderError::IdentityDrift)
        );
    }

    #[test]
    fn rotation_requires_the_active_device_to_authorize_the_replacement() {
        let mut registry = SignerDeviceRegistry::new(Uuid::from_bytes([5; 16]), 7, 3);
        let first_challenge = registry.issue_registration_challenge(2, 10, 30).unwrap();
        registry
            .register(
                proof(&first_challenge, 12, SignerProviderKind::HsmAdapter, None),
                11,
            )
            .unwrap();

        let rotate_challenge = registry.issue_registration_challenge(2, 12, 30).unwrap();
        assert_eq!(
            registry.register(
                proof(&rotate_challenge, 13, SignerProviderKind::HsmAdapter, None),
                13,
            ),
            Err(ProviderError::RotationAuthorizationRequired)
        );
    }
}
