//! Bounded, review-bound cb-mpc ECDSA signing for Bitcoin Cash and BSV.

use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

use catomicals_chain_domain::{ChainId, ReviewArtifact};
use catomicals_signing_domain::{ReviewBinding, SigningSuiteId};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

/// cb-mpc ECDSA-MP has nine fixed online communication stages.
pub const CB_MPC_ECDSA_SIGN_STAGES: u8 = 9;
/// In-memory replay protection is fail-closed at this fixed capacity.
///
/// Long-running deployments must replace it with a durable replay store;
/// entries are never evicted because eviction would reopen old session IDs.
pub const MAX_RETAINED_SESSION_IDS: usize = 4_096;
const REQUEST_BINDING_DOMAIN: &[u8] = b"catomicals.cb-mpc.approved-sign-request.v1\0";
const MAX_PARTY_ID_BYTES: usize = 64;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "native-cbmpc")]
mod native;

#[cfg(feature = "native-cbmpc")]
pub use native::{
    CanonicalEcdsaSignature, CbMpcShare, SecretShareMaterial, generate_native_2_of_3,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbMpcProfile {
    BitcoinCashEcdsaV1,
    BsvEcdsaV1,
}

impl CbMpcProfile {
    pub const fn signing_suite_id(self) -> SigningSuiteId {
        match self {
            Self::BitcoinCashEcdsaV1 => SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            Self::BsvEcdsaV1 => SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        }
    }

    const fn chain_id(self) -> ChainId {
        match self {
            Self::BitcoinCashEcdsaV1 => ChainId::BitcoinCash,
            Self::BsvEcdsaV1 => ChainId::Bsv,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinCashEcdsaV1 => "bch.ecdsa.cb-mpc.v1",
            Self::BsvEcdsaV1 => "bsv.ecdsa.cb-mpc.v1",
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(String);

impl PartyId {
    pub fn new(value: impl Into<String>) -> Result<Self, CbMpcError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PARTY_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(CbMpcError::InvalidPartyId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PartyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("PartyId").field(&self.0).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbMpcSignerSet {
    id: String,
    epoch: u64,
    threshold: u8,
    parties: Vec<PartyId>,
}

impl CbMpcSignerSet {
    pub fn new(
        id: impl Into<String>,
        epoch: u64,
        threshold: u8,
        parties: Vec<PartyId>,
    ) -> Result<Self, CbMpcError> {
        let id = id.into();
        if id.is_empty() || id.len() > 128 {
            return Err(CbMpcError::InvalidSignerSet);
        }
        if threshold != 2 || parties.len() != 3 {
            return Err(CbMpcError::InvalidSignerSet);
        }
        if parties.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(CbMpcError::NonCanonicalPartyOrder);
        }
        Ok(Self {
            id,
            epoch,
            threshold,
            parties,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn parties(&self) -> &[PartyId] {
        &self.parties
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCbMpcSignRequestParts {
    pub profile: CbMpcProfile,
    pub review: ReviewArtifact,
    pub review_binding: ReviewBinding,
    pub signer_set: CbMpcSignerSet,
    pub group_public_key: [u8; 33],
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub online_parties: Vec<PartyId>,
    pub receiver: PartyId,
    pub session_id: [u8; 32],
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCbMpcSignRequest {
    parts: ApprovedCbMpcSignRequestParts,
    binding_digest: [u8; 32],
}

impl ApprovedCbMpcSignRequest {
    /// Binds an artifact that a chain coordinator has already reviewed.
    ///
    /// This constructor checks exact cross-object consistency. It does not
    /// parse transaction material or independently enforce chain policy; the
    /// chain suite must do that before creating the review artifact.
    pub fn new(parts: ApprovedCbMpcSignRequestParts, now: i64) -> Result<Self, CbMpcError> {
        validate_request_parts(&parts, now)?;
        let binding_digest = request_binding_digest(&parts);
        Ok(Self {
            parts,
            binding_digest,
        })
    }

    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    pub fn into_parts(self) -> ApprovedCbMpcSignRequestParts {
        self.parts
    }

    pub fn parts(&self) -> &ApprovedCbMpcSignRequestParts {
        &self.parts
    }
}

fn validate_request_parts(
    parts: &ApprovedCbMpcSignRequestParts,
    now: i64,
) -> Result<(), CbMpcError> {
    if parts.expires_at <= now {
        return Err(CbMpcError::Expired);
    }
    if parts.review.scope.chain != parts.profile.chain_id()
        || parts.review_binding.chain_scope.chain != parts.profile.chain_id()
        || parts.review_binding.signing_suite_id != parts.profile.signing_suite_id()
    {
        return Err(CbMpcError::ProfileMismatch);
    }
    if parts.review.scope != parts.review_binding.chain_scope
        || parts.review_binding.schema_version != 1
        || parts.review.schema_version != parts.review_binding.review_schema_version
        || parts.review.review_digest != parts.review_binding.review_digest
    {
        return Err(CbMpcError::ReviewBindingMismatch);
    }
    if parts.signer_set.id != parts.review_binding.signer_set_id
        || parts.signer_set.epoch != parts.review_binding.signer_set_epoch
    {
        return Err(CbMpcError::SignerSetMismatch);
    }
    PublicKey::from_slice(&parts.group_public_key)
        .map_err(|_| CbMpcError::InvalidGroupPublicKey)?;
    if parts.policy_snapshot_digest == [0; 32]
        || parts.chain_snapshot_digest == [0; 32]
        || parts.session_id == [0; 32]
    {
        return Err(CbMpcError::MissingSecurityBinding);
    }
    if parts.online_parties.len() != usize::from(parts.signer_set.threshold) {
        return Err(CbMpcError::InvalidQuorum);
    }
    let mut prior_index = None;
    let mut unique = HashSet::with_capacity(parts.online_parties.len());
    for party in &parts.online_parties {
        let index = parts
            .signer_set
            .parties
            .iter()
            .position(|candidate| candidate == party)
            .ok_or(CbMpcError::InvalidQuorum)?;
        if prior_index.is_some_and(|prior| prior >= index) || !unique.insert(party) {
            return Err(CbMpcError::NonCanonicalPartyOrder);
        }
        prior_index = Some(index);
    }
    if !parts.online_parties.contains(&parts.receiver) {
        return Err(CbMpcError::InvalidReceiver);
    }
    Ok(())
}

fn request_binding_digest(parts: &ApprovedCbMpcSignRequestParts) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_BINDING_DOMAIN);
    append_field(&mut hasher, parts.profile.as_str().as_bytes());
    append_field(&mut hasher, parts.review.scope.chain.as_str().as_bytes());
    append_field(&mut hasher, parts.review.scope.network.as_str().as_bytes());
    hasher.update(parts.review.schema_version.to_be_bytes());
    hasher.update(parts.review.review_digest);
    hasher.update(parts.review.signing_message_digest);
    append_field(&mut hasher, parts.review.summary.as_bytes());
    append_field(&mut hasher, &parts.review.reviewed_material);
    append_field(&mut hasher, &parts.review_binding.domain_separator());
    append_field(&mut hasher, parts.signer_set.id.as_bytes());
    hasher.update(parts.signer_set.epoch.to_be_bytes());
    hasher.update([parts.signer_set.threshold]);
    for party in &parts.signer_set.parties {
        append_field(&mut hasher, party.as_str().as_bytes());
    }
    hasher.update(parts.group_public_key);
    hasher.update(parts.policy_snapshot_digest);
    hasher.update(parts.chain_snapshot_digest);
    for party in &parts.online_parties {
        append_field(&mut hasher, party.as_str().as_bytes());
    }
    append_field(&mut hasher, parts.receiver.as_str().as_bytes());
    hasher.update(parts.session_id);
    hasher.update(parts.expires_at.to_be_bytes());
    hasher.finalize().into()
}

fn append_field(hasher: &mut Sha256, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("bounded request field fits in u32");
    hasher.update(length.to_be_bytes());
    hasher.update(field);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbMpcRuntimeLimits {
    receive_timeout: Duration,
    session_timeout: Duration,
    max_frame_bytes: usize,
}

impl CbMpcRuntimeLimits {
    pub fn new(
        receive_timeout: Duration,
        session_timeout: Duration,
        max_frame_bytes: usize,
    ) -> Result<Self, CbMpcError> {
        if receive_timeout.is_zero()
            || session_timeout < receive_timeout
            || max_frame_bytes == 0
            || max_frame_bytes > MAX_FRAME_BYTES
        {
            return Err(CbMpcError::InvalidRuntimeLimits);
        }
        Ok(Self {
            receive_timeout,
            session_timeout,
            max_frame_bytes,
        })
    }

    pub const fn receive_timeout(&self) -> Duration {
        self.receive_timeout
    }

    pub const fn session_timeout(&self) -> Duration {
        self.session_timeout
    }

    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

pub struct CbMpcRuntime {
    limits: CbMpcRuntimeLimits,
    #[cfg(feature = "native-cbmpc")]
    sessions: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
}

impl CbMpcRuntime {
    #[cfg(feature = "native-cbmpc")]
    pub fn new_native(limits: CbMpcRuntimeLimits) -> Result<Self, CbMpcError> {
        Ok(Self {
            limits,
            sessions: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    #[cfg(not(feature = "native-cbmpc"))]
    pub fn new_native(_limits: CbMpcRuntimeLimits) -> Result<Self, CbMpcError> {
        Err(CbMpcError::BackendUnavailable)
    }

    pub const fn limits(&self) -> CbMpcRuntimeLimits {
        self.limits
    }
}

/// Synchronous transport boundary used by the native backend.
///
/// Implementations receive a hard deadline for each operation. The first
/// implementation is intentionally an in-memory test transport; mTLS is not
/// implied by this contract.
pub trait SessionTransport: Send + Sync {
    fn send(
        &self,
        receiver: usize,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(), TransportFailure>;

    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportFailure {
    #[error("transport receive timed out")]
    Timeout,
    #[error("transport session terminated")]
    Terminated,
    #[error("transport frame exceeds its configured limit")]
    FrameTooLarge,
    #[error("transport failed")]
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CbMpcError {
    #[error("native cb-mpc backend is not compiled in")]
    BackendUnavailable,
    #[error("invalid cb-mpc party id")]
    InvalidPartyId,
    #[error("cb-mpc signer set must be a canonical 2-of-3 set")]
    InvalidSignerSet,
    #[error("cb-mpc parties are not in canonical signer-set order")]
    NonCanonicalPartyOrder,
    #[error("approved review artifact does not match its review binding")]
    ReviewBindingMismatch,
    #[error("cb-mpc profile, chain scope, and signing suite do not match")]
    ProfileMismatch,
    #[error("approved signer set does not match its review binding")]
    SignerSetMismatch,
    #[error("invalid compressed secp256k1 group public key")]
    InvalidGroupPublicKey,
    #[error("required policy, chain, or session binding is missing")]
    MissingSecurityBinding,
    #[error("online parties do not form the approved quorum")]
    InvalidQuorum,
    #[error("signature receiver is not in the approved online quorum")]
    InvalidReceiver,
    #[error("approved signing request is expired")]
    Expired,
    #[error("invalid cb-mpc runtime limits")]
    InvalidRuntimeLimits,
    #[error("a cb-mpc share is already serving another session")]
    ShareBusy,
    #[error("cb-mpc session is already terminal or active")]
    SessionTerminal,
    #[error("cb-mpc replay store is full; durable replay storage is required")]
    ReplayCacheFull,
    #[error("cb-mpc transport timed out")]
    TransportTimeout,
    #[error("cb-mpc transport was terminated")]
    TransportTerminated,
    #[error("cb-mpc frame exceeds the configured limit")]
    FrameTooLarge,
    #[error("cb-mpc transport failed")]
    TransportFailed,
    #[error("cb-mpc native protocol failed with code {0:?}")]
    NativeFailure(Option<i32>),
    #[error("cb-mpc native backend returned an invalid signature")]
    InvalidSignature,
    #[error("cb-mpc share does not match the approved signer request")]
    ShareMismatch,
}
