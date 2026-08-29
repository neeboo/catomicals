#![forbid(unsafe_code)]

//! Chia chain adapter.

use std::fmt;

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use blst::{
    BLST_ERROR, MultiPoint,
    min_pk::{
        AggregatePublicKey as BlstAggregatePublicKey, PublicKey as BlstPublicKey,
        SecretKey as BlstSecretKey, Signature as BlstSignature,
    },
};
use catomicals_chain_domain::{
    ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite, ChiaNetwork, ReviewArtifact,
    ReviewContractError,
};
use catomicals_signing_domain::{
    SigningSuite, SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};
use chia_bls::{
    PublicKey, SecretKey, Signature, aggregate, aggregate_verify, master_to_wallet_hardened,
    master_to_wallet_unhardened, sign, verify,
};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Chia's standard hidden puzzle `(=)` tree hash.
pub const DEFAULT_HIDDEN_PUZZLE_HASH: [u8; 32] = [
    0x71, 0x1d, 0x6c, 0x4e, 0x32, 0xc9, 0x2e, 0x53, 0x17, 0x9b, 0x19, 0x94, 0x84, 0xcf, 0x8c, 0x89,
    0x75, 0x42, 0xbc, 0x57, 0xf2, 0xb2, 0x25, 0x82, 0x79, 0x9f, 0x9d, 0x65, 0x7e, 0xec, 0x46, 0x99,
];

const BLS_GROUP_ORDER: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

const MAINNET_AGG_SIG_ME_ADDITIONAL_DATA: [u8; 32] = [
    0xcc, 0xd5, 0xbb, 0x71, 0x18, 0x35, 0x32, 0xbf, 0xf2, 0x20, 0xba, 0x46, 0xc2, 0x68, 0x99, 0x1a,
    0x3f, 0xf0, 0x7e, 0xb3, 0x58, 0xe8, 0x25, 0x5a, 0x65, 0xc3, 0x0a, 0x2d, 0xce, 0x0e, 0x5f, 0xbb,
];

const TESTNET11_AGG_SIG_ME_ADDITIONAL_DATA: [u8; 32] = [
    0x37, 0xa9, 0x0e, 0xb5, 0x18, 0x5a, 0x9c, 0x44, 0x39, 0xa9, 0x1d, 0xdc, 0x98, 0xbb, 0xad, 0xce,
    0x7b, 0x4f, 0xeb, 0xa0, 0x60, 0xd5, 0x01, 0x16, 0xa0, 0x67, 0xde, 0x66, 0xbf, 0x23, 0x66, 0x15,
];

const CHIA_AUG_SCHEME_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";

/// Errors produced before Chia consensus operations are attempted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChiaAdapterError {
    #[error("network `{network}` belongs to `{actual}`, not `{declared}`")]
    MismatchedChainNetwork {
        declared: ChainId,
        actual: ChainId,
        network: ChainNetwork,
    },
    #[error("chain scope `{0:?}` is not a Chia scope")]
    UnsupportedChainScope(ChainScope),
    #[error("invalid Chia address: {0}")]
    InvalidAddress(String),
    #[error("address prefix `{actual}` does not match expected `{expected}`")]
    WrongAddressPrefix { expected: String, actual: String },
    #[error("Chia address payload must be exactly 32 bytes, got {0}")]
    InvalidPuzzleHashLength(usize),
    #[error("invalid Chia BLS public key: {0}")]
    InvalidPublicKey(String),
    #[error("the zero BLS secret key is not valid for signing")]
    InvalidSecretKey,
    #[error("the BLS identity public key is not valid for verification")]
    IdentityPublicKey,
    #[error("the BLS identity signature is not valid for verification")]
    IdentitySignature,
    #[error("invalid Chia BLS signature: {0}")]
    InvalidSignature(String),
    #[error("at least one BLS signature is required for aggregation")]
    EmptySignatureSet,
    #[error("threshold BLS participant id must be in 1..=3, got {0}")]
    InvalidThresholdParticipant(u16),
    #[error("threshold BLS participant {0} appears more than once")]
    DuplicateThresholdParticipant(u16),
    #[error("2-of-3 threshold BLS requires exactly two shares, got {actual}")]
    InsufficientThresholdShares { actual: usize },
    #[error("invalid threshold BLS commitment: {0}")]
    InvalidThresholdCommitment(String),
    #[error("secret share {participant_id} does not match its Feldman commitment")]
    ThresholdShareCommitmentMismatch { participant_id: u16 },
    #[error("threshold BLS partial from participant {participant_id} is invalid")]
    InvalidThresholdPartial { participant_id: u16 },
    #[error("interpolated threshold BLS signature did not verify under the group key")]
    InvalidThresholdFinalSignature,
    #[error("threshold BLS v1 requires an already derived and synthesized final signing key")]
    ThresholdKeyMustBeFinalSigningKey,
}

#[derive(Debug, Clone, Copy)]
struct ScopeProfile {
    address_hrp: &'static str,
    agg_sig_me_additional_data: [u8; 32],
}

fn scope_profile(scope: ChainScope) -> Result<ScopeProfile, ChiaAdapterError> {
    let actual = scope.network.chain_id();
    if scope.chain != actual {
        return Err(ChiaAdapterError::MismatchedChainNetwork {
            declared: scope.chain,
            actual,
            network: scope.network,
        });
    }

    match scope.network {
        ChainNetwork::Chia(ChiaNetwork::Mainnet) => Ok(ScopeProfile {
            address_hrp: "xch",
            agg_sig_me_additional_data: MAINNET_AGG_SIG_ME_ADDITIONAL_DATA,
        }),
        ChainNetwork::Chia(ChiaNetwork::Testnet11) => Ok(ScopeProfile {
            address_hrp: "txch",
            agg_sig_me_additional_data: TESTNET11_AGG_SIG_ME_ADDITIONAL_DATA,
        }),
        _ => Err(ChiaAdapterError::UnsupportedChainScope(scope)),
    }
}

/// Encodes a 32-byte puzzle hash with the network's `xch` or `txch` Bech32m prefix.
pub fn encode_puzzle_hash(
    scope: ChainScope,
    puzzle_hash: [u8; 32],
) -> Result<String, ChiaAdapterError> {
    let profile = scope_profile(scope)?;
    let hrp = Hrp::parse(profile.address_hrp)
        .expect("the static Chia address prefixes are valid Bech32 HRPs");
    bech32::encode::<Bech32m>(hrp, &puzzle_hash)
        .map_err(|error| ChiaAdapterError::InvalidAddress(error.to_string()))
}

/// Decodes a network-bound Chia address and requires a Bech32m checksum.
pub fn decode_address(scope: ChainScope, address: &str) -> Result<[u8; 32], ChiaAdapterError> {
    let profile = scope_profile(scope)?;
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|error| ChiaAdapterError::InvalidAddress(error.to_string()))?;
    let actual_hrp = checked.hrp().to_string();
    if actual_hrp != profile.address_hrp {
        return Err(ChiaAdapterError::WrongAddressPrefix {
            expected: profile.address_hrp.to_owned(),
            actual: actual_hrp,
        });
    }
    let payload = checked.byte_iter().collect::<Vec<_>>();
    payload
        .try_into()
        .map_err(|payload: Vec<u8>| ChiaAdapterError::InvalidPuzzleHashLength(payload.len()))
}

/// Selects the hardened legacy wallet derivation or the public-key-compatible unhardened path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletDerivationKind {
    Hardened,
    Unhardened,
}

/// The standard Chia wallet path `m/12381/8444/2/index` and its derivation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletDerivationPath {
    index: u32,
    kind: WalletDerivationKind,
}

impl WalletDerivationPath {
    pub const fn components(self) -> [u32; 4] {
        [12381, 8444, 2, self.index]
    }

    pub const fn kind(self) -> WalletDerivationKind {
        self.kind
    }
}

impl fmt::Display for WalletDerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "m/12381/8444/2/{}", self.index)?;
        if self.kind == WalletDerivationKind::Hardened {
            formatter.write_str(" (hardened)")?;
        }
        Ok(())
    }
}

pub const fn wallet_derivation_path(
    index: u32,
    kind: WalletDerivationKind,
) -> WalletDerivationPath {
    WalletDerivationPath { index, kind }
}

/// Derives a standard wallet secret key using Chia's official BLS derivation helpers.
pub fn derive_wallet_secret_key(
    master: &SecretKey,
    index: u32,
    kind: WalletDerivationKind,
) -> SecretKey {
    match kind {
        WalletDerivationKind::Hardened => master_to_wallet_hardened(master, index),
        WalletDerivationKind::Unhardened => master_to_wallet_unhardened(master, index),
    }
}

/// Derives a standard unhardened wallet public key from a master public key.
pub fn derive_wallet_public_key(master: &PublicKey, index: u32) -> PublicKey {
    master_to_wallet_unhardened(master, index)
}

fn synthetic_offset(public_key: &PublicKey, hidden_puzzle_hash: &[u8; 32]) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(public_key.to_bytes());
    hasher.update(hidden_puzzle_hash);
    let digest = hasher.finalize();
    // Chia's CLVM integer conversion is signed big-endian. Normalize twice so
    // a digest with its high bit set still lands in the positive scalar field.
    let value = BigInt::from_signed_bytes_be(&digest);
    let group_order = BigInt::from_signed_bytes_be(&BLS_GROUP_ORDER);
    let offset = ((value % &group_order) + &group_order) % &group_order;
    let offset_bytes = offset.to_bytes_be().1;
    let mut padded = [0_u8; 32];
    padded[32 - offset_bytes.len()..].copy_from_slice(&offset_bytes);
    SecretKey::from_bytes(&padded).expect("the synthetic offset is reduced modulo the group order")
}

/// Derives the synthetic secret key for Chia's standard hidden puzzle.
pub fn derive_synthetic_secret_key(secret_key: &SecretKey) -> SecretKey {
    secret_key + &synthetic_offset(&secret_key.public_key(), &DEFAULT_HIDDEN_PUZZLE_HASH)
}

/// Derives the synthetic public key for Chia's standard hidden puzzle.
pub fn derive_synthetic_public_key(public_key: &PublicKey) -> PublicKey {
    public_key + &synthetic_offset(public_key, &DEFAULT_HIDDEN_PUZZLE_HASH).public_key()
}

/// Signs with Chia's AugSchemeMPL ciphersuite and returns a fixed 96-byte G2 signature.
pub fn sign_augmented(
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<[u8; 96], ChiaAdapterError> {
    if secret_key.to_bytes() == [0; 32] {
        return Err(ChiaAdapterError::InvalidSecretKey);
    }
    Ok(sign(secret_key, message).to_bytes())
}

/// Verifies a fixed-size G1 public key and G2 AugSchemeMPL signature.
pub fn verify_augmented(
    public_key: [u8; 48],
    message: &[u8],
    signature: [u8; 96],
) -> Result<bool, ChiaAdapterError> {
    let public_key = PublicKey::from_bytes(&public_key)
        .map_err(|error| ChiaAdapterError::InvalidPublicKey(error.to_string()))?;
    if public_key.is_inf() {
        return Err(ChiaAdapterError::IdentityPublicKey);
    }
    let signature = Signature::from_bytes(&signature)
        .map_err(|error| ChiaAdapterError::InvalidSignature(error.to_string()))?;
    if signature == Signature::default() {
        return Err(ChiaAdapterError::IdentitySignature);
    }
    Ok(verify(&signature, &public_key, message))
}

/// One public-key/message pair for AugSchemeMPL aggregate verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AugmentedVerification {
    public_key: [u8; 48],
    message: Vec<u8>,
}

impl AugmentedVerification {
    pub fn new(public_key: [u8; 48], message: impl AsRef<[u8]>) -> Self {
        Self {
            public_key,
            message: message.as_ref().to_vec(),
        }
    }
}

/// Verifies an aggregate using Chia's public-key-prefixed AugSchemeMPL messages.
pub fn verify_aggregate_augmented(
    entries: &[AugmentedVerification],
    signature: [u8; 96],
) -> Result<bool, ChiaAdapterError> {
    if entries.is_empty() {
        return Err(ChiaAdapterError::EmptySignatureSet);
    }
    let signature = Signature::from_bytes(&signature)
        .map_err(|error| ChiaAdapterError::InvalidSignature(error.to_string()))?;
    if signature == Signature::default() {
        return Err(ChiaAdapterError::IdentitySignature);
    }

    let parsed = entries
        .iter()
        .map(|entry| {
            let public_key = PublicKey::from_bytes(&entry.public_key)
                .map_err(|error| ChiaAdapterError::InvalidPublicKey(error.to_string()))?;
            if public_key.is_inf() {
                return Err(ChiaAdapterError::IdentityPublicKey);
            }
            Ok((public_key, entry.message.as_slice()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(aggregate_verify(&signature, parsed))
}

/// Aggregates complete G2 signatures. This is ordinary BLS aggregation, not threshold signing.
pub fn aggregate_signatures(signatures: &[[u8; 96]]) -> Result<[u8; 96], ChiaAdapterError> {
    if signatures.is_empty() {
        return Err(ChiaAdapterError::EmptySignatureSet);
    }
    let parsed = signatures
        .iter()
        .map(|bytes| {
            let signature = Signature::from_bytes(bytes)
                .map_err(|error| ChiaAdapterError::InvalidSignature(error.to_string()))?;
            if signature == Signature::default() {
                return Err(ChiaAdapterError::IdentitySignature);
            }
            Ok(signature)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate = aggregate(&parsed);
    if aggregate == Signature::default() {
        return Err(ChiaAdapterError::IdentitySignature);
    }
    Ok(aggregate.to_bytes())
}

/// A network-bound `AGG_SIG_ME` signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggSigMe {
    final_message: Vec<u8>,
}

impl AggSigMe {
    pub fn new(
        scope: ChainScope,
        condition_message: &[u8],
        coin_id: [u8; 32],
    ) -> Result<Self, ChiaAdapterError> {
        let profile = scope_profile(scope)?;
        let mut final_message = Vec::with_capacity(condition_message.len() + 64);
        final_message.extend_from_slice(condition_message);
        final_message.extend_from_slice(&coin_id);
        final_message.extend_from_slice(&profile.agg_sig_me_additional_data);
        Ok(Self { final_message })
    }

    pub fn final_message(&self) -> &[u8] {
        &self.final_message
    }

    pub fn sign(&self, secret_key: &SecretKey) -> Result<[u8; 96], ChiaAdapterError> {
        sign_augmented(secret_key, &self.final_message)
    }

    pub fn verify(
        &self,
        public_key: [u8; 48],
        signature: [u8; 96],
    ) -> Result<bool, ChiaAdapterError> {
        verify_augmented(public_key, &self.final_message, signature)
    }
}

/// One verified candidate partial for 2-of-3 threshold interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignatureShare {
    pub participant_id: u16,
    pub signature: [u8; 96],
}

impl BlsSignatureShare {
    pub const fn new(participant_id: u16, signature: [u8; 96]) -> Self {
        Self {
            participant_id,
            signature,
        }
    }
}

/// Declares whether dealer input is already the exact key Chia will verify.
///
/// Chia hardened derivation and synthetic-key offsets are not linear operations
/// that can be independently applied to Shamir shares. Version 1 therefore
/// accepts only `FinalSigningKey`: callers must derive and synthesize the group
/// key before the trusted dealer splits it. The other variants exist so those
/// unsafe requests fail closed rather than silently producing another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdBlsDealerKeyKind {
    FinalSigningKey,
    HardenedWalletMaster,
    UnsynthesizedWalletKey,
}

/// Public Feldman commitments for the degree-one polynomial `C0 + x*C1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdBlsCommitment {
    group_public_key: [u8; 48],
    coefficient_public_key: [u8; 48],
}

impl ThresholdBlsCommitment {
    /// Imports and subgroup-validates both public coefficients.
    pub fn import(
        group_public_key: [u8; 48],
        coefficient_public_key: [u8; 48],
    ) -> Result<Self, ChiaAdapterError> {
        parse_threshold_public_key(&group_public_key)?;
        parse_threshold_public_key(&coefficient_public_key)?;
        Ok(Self {
            group_public_key,
            coefficient_public_key,
        })
    }

    pub const fn group_public_key(&self) -> [u8; 48] {
        self.group_public_key
    }

    pub const fn coefficient_public_key(&self) -> [u8; 48] {
        self.coefficient_public_key
    }

    fn share_public_key(&self, participant_id: u16) -> Result<BlstPublicKey, ChiaAdapterError> {
        validate_threshold_participant(participant_id)?;
        let group = parse_threshold_public_key(&self.group_public_key)?;
        let coefficient = parse_threshold_public_key(&self.coefficient_public_key)?;
        let mut share = BlstAggregatePublicKey::from_public_key(&group);
        for _ in 0..participant_id {
            share.add_public_key(&coefficient, true).map_err(|error| {
                ChiaAdapterError::InvalidThresholdCommitment(format!("{error:?}"))
            })?;
        }
        let share = share.to_public_key();
        share
            .validate()
            .map_err(|error| ChiaAdapterError::InvalidThresholdCommitment(format!("{error:?}")))?;
        Ok(share)
    }
}

/// A single participant's scalar share.
///
/// The backing `blst` secret key zeroizes on drop. It is intentionally not
/// `Clone`, serializable, comparable, or printable. Export is explicit and the
/// returned buffer also zeroizes on drop.
pub struct ThresholdBlsSecretShare {
    participant_id: u16,
    secret_key: BlstSecretKey,
}

impl fmt::Debug for ThresholdBlsSecretShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThresholdBlsSecretShare")
            .field("participant_id", &self.participant_id)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl ThresholdBlsSecretShare {
    /// Imports one share delivered by the offline dealer.
    ///
    /// The owned input buffer is wiped after `blst` has copied it into its
    /// zeroizing scalar type. The participant id is validated before parsing.
    pub fn import_for_signing(
        participant_id: u16,
        secret_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ChiaAdapterError> {
        validate_threshold_participant(participant_id)?;
        let secret_key = parse_threshold_secret_key(secret_key.as_ref())?;
        Ok(Self {
            participant_id,
            secret_key,
        })
    }

    pub const fn participant_id(&self) -> u16 {
        self.participant_id
    }

    /// Explicit export boundary for provisioning an offline-dealer share.
    pub fn export_for_provisioning(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = self.secret_key.to_bytes();
        let exported = Zeroizing::new(bytes);
        bytes.zeroize();
        exported
    }
}

impl Zeroize for ThresholdBlsSecretShare {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        self.participant_id.zeroize();
    }
}

impl Drop for ThresholdBlsSecretShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for ThresholdBlsSecretShare {}

/// Result of a trusted, offline 2-of-3 dealer split.
///
/// This is not a DKG. Version 1 requires the dealer to create/export each
/// share over an independently authenticated secure channel and then destroy
/// its local secret material.
#[derive(Debug)]
pub struct ThresholdBlsDealerOutput {
    commitment: ThresholdBlsCommitment,
    shares: [ThresholdBlsSecretShare; 3],
}

impl ThresholdBlsDealerOutput {
    pub const fn commitment(&self) -> &ThresholdBlsCommitment {
        &self.commitment
    }

    pub const fn shares(&self) -> &[ThresholdBlsSecretShare; 3] {
        &self.shares
    }
}

/// Splits an already-derived, already-synthesized Chia signing scalar with the
/// degree-one polynomial `f(x) = secret + coefficient*x` for participant ids
/// 1, 2, and 3.
///
/// This v1 boundary is an offline trusted dealer, not DKG. Inputs and all
/// intermediate byte buffers are wiped when they leave scope. Production
/// callers must also wipe any source copy retained before this call.
pub fn dealer_split_threshold_secret_2_of_3(
    key_kind: ThresholdBlsDealerKeyKind,
    mut group_secret: [u8; 32],
    mut coefficient: [u8; 32],
) -> Result<ThresholdBlsDealerOutput, ChiaAdapterError> {
    let owned_group_secret = Zeroizing::new(group_secret);
    let owned_coefficient = Zeroizing::new(coefficient);
    group_secret.zeroize();
    coefficient.zeroize();
    let group_secret = owned_group_secret;
    let coefficient = owned_coefficient;
    if key_kind != ThresholdBlsDealerKeyKind::FinalSigningKey {
        return Err(ChiaAdapterError::ThresholdKeyMustBeFinalSigningKey);
    }

    let group_key = parse_threshold_secret_key(group_secret.as_ref())?;
    let coefficient_key = parse_threshold_secret_key(coefficient.as_ref())?;
    let commitment = ThresholdBlsCommitment::import(
        group_key.sk_to_pk().to_bytes(),
        coefficient_key.sk_to_pk().to_bytes(),
    )?;

    let make_share = |participant_id: u16| {
        let mut share_bytes = Zeroizing::new(*group_secret);
        for _ in 0..participant_id {
            let next = add_threshold_scalars_mod_order(&share_bytes, &coefficient);
            share_bytes.zeroize();
            *share_bytes = *next;
        }
        let secret_key = parse_threshold_secret_key(share_bytes.as_ref())?;
        Ok(ThresholdBlsSecretShare {
            participant_id,
            secret_key,
        })
    };
    let shares = [make_share(1)?, make_share(2)?, make_share(3)?];

    Ok(ThresholdBlsDealerOutput { commitment, shares })
}

/// Signs one partial using Chia's AugSchemeMPL hash-to-curve input
/// `group_public_key || message`.
///
/// Using the share public key as augmentation would make each participant hash
/// to a different curve point and cannot produce a threshold signature.
pub fn sign_threshold_share_2_of_3(
    commitment: &ThresholdBlsCommitment,
    share: &ThresholdBlsSecretShare,
    message: &[u8],
) -> Result<BlsSignatureShare, ChiaAdapterError> {
    validate_threshold_participant(share.participant_id)?;
    let expected = commitment.share_public_key(share.participant_id)?;
    if expected.to_bytes() != share.secret_key.sk_to_pk().to_bytes() {
        return Err(ChiaAdapterError::ThresholdShareCommitmentMismatch {
            participant_id: share.participant_id,
        });
    }
    let signature =
        share
            .secret_key
            .sign(message, CHIA_AUG_SCHEME_DST, &commitment.group_public_key);
    if signature.validate(true) != Ok(()) {
        return Err(ChiaAdapterError::InvalidThresholdPartial {
            participant_id: share.participant_id,
        });
    }
    Ok(BlsSignatureShare::new(
        share.participant_id,
        signature.to_bytes(),
    ))
}

/// Verifies and interpolates exactly two distinct partials at `x = 0`.
///
/// Every partial is checked against `C0 + id*C1` before interpolation. The
/// resulting G2 point is finally verified through the existing Chia augmented
/// verifier under `C0`, so point arithmetic alone is never treated as success.
pub fn interpolate_threshold_signature_2_of_3(
    commitment: &ThresholdBlsCommitment,
    message: &[u8],
    shares: &[BlsSignatureShare],
) -> Result<[u8; 96], ChiaAdapterError> {
    if shares.len() != 2 {
        return Err(ChiaAdapterError::InsufficientThresholdShares {
            actual: shares.len(),
        });
    }
    let first_id = shares[0].participant_id;
    let second_id = shares[1].participant_id;
    validate_threshold_participant(first_id)?;
    validate_threshold_participant(second_id)?;
    if first_id == second_id {
        return Err(ChiaAdapterError::DuplicateThresholdParticipant(first_id));
    }

    let mut signatures = Vec::with_capacity(2);
    for share in shares {
        let share_public_key = commitment.share_public_key(share.participant_id)?;
        let signature = BlstSignature::from_bytes(&share.signature).map_err(|_| {
            ChiaAdapterError::InvalidThresholdPartial {
                participant_id: share.participant_id,
            }
        })?;
        let verification = signature.verify(
            true,
            message,
            CHIA_AUG_SCHEME_DST,
            &commitment.group_public_key,
            &share_public_key,
            true,
        );
        if verification != BLST_ERROR::BLST_SUCCESS {
            return Err(ChiaAdapterError::InvalidThresholdPartial {
                participant_id: share.participant_id,
            });
        }
        signatures.push(signature);
    }

    let mut scalars = Zeroizing::new(Vec::with_capacity(64));
    for participant_id in [first_id, second_id] {
        let mut lambda = lagrange_coefficient_2_of_3(participant_id, first_id, second_id);
        lambda.reverse();
        scalars.extend_from_slice(&lambda);
        lambda.zeroize();
    }
    let interpolated = signatures
        .as_slice()
        .mult(scalars.as_slice(), 255)
        .to_signature();
    interpolated
        .validate(false)
        .map_err(|_| ChiaAdapterError::InvalidThresholdFinalSignature)?;
    let bytes = interpolated.to_bytes();
    if !verify_augmented(commitment.group_public_key, message, bytes)? {
        return Err(ChiaAdapterError::InvalidThresholdFinalSignature);
    }
    Ok(bytes)
}

fn validate_threshold_participant(participant_id: u16) -> Result<(), ChiaAdapterError> {
    if (1..=3).contains(&participant_id) {
        Ok(())
    } else {
        Err(ChiaAdapterError::InvalidThresholdParticipant(
            participant_id,
        ))
    }
}

fn parse_threshold_secret_key(bytes: &[u8]) -> Result<BlstSecretKey, ChiaAdapterError> {
    BlstSecretKey::from_bytes(bytes).map_err(|_| ChiaAdapterError::InvalidSecretKey)
}

fn parse_threshold_public_key(bytes: &[u8; 48]) -> Result<BlstPublicKey, ChiaAdapterError> {
    BlstPublicKey::key_validate(bytes)
        .map_err(|error| ChiaAdapterError::InvalidThresholdCommitment(format!("{error:?}")))
}

fn add_threshold_scalars_mod_order(lhs: &[u8; 32], rhs: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut sum = [0_u8; 32];
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let value = u16::from(lhs[index]) + u16::from(rhs[index]) + carry;
        sum[index] = value as u8;
        carry = value >> 8;
    }
    debug_assert_eq!(
        carry, 0,
        "two normalized BLS scalars cannot overflow 256 bits"
    );
    if sum >= BLS_GROUP_ORDER {
        subtract_threshold_order(&mut sum);
    }
    let output = Zeroizing::new(sum);
    sum.zeroize();
    output
}

fn subtract_threshold_order(value: &mut [u8; 32]) {
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let difference = i16::from(value[index]) - i16::from(BLS_GROUP_ORDER[index]) - borrow;
        if difference < 0 {
            value[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            value[index] = difference as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0);
}

fn lagrange_coefficient_2_of_3(participant_id: u16, first: u16, second: u16) -> [u8; 32] {
    let other = if participant_id == first {
        second
    } else {
        first
    };
    match (participant_id, other) {
        (1, 2) => scalar_from_small(2),
        (2, 1) => scalar_order_minus(1),
        (1, 3) => scalar_three_halves(),
        (3, 1) => scalar_negative_half(),
        (2, 3) => scalar_from_small(3),
        (3, 2) => scalar_order_minus(2),
        _ => unreachable!("participant ids are validated and distinct"),
    }
}

fn scalar_from_small(value: u8) -> [u8; 32] {
    let mut scalar = [0_u8; 32];
    scalar[31] = value;
    scalar
}

fn scalar_order_minus(value: u8) -> [u8; 32] {
    let mut scalar = BLS_GROUP_ORDER;
    let mut borrow = u16::from(value);
    for index in (0..32).rev() {
        if borrow == 0 {
            break;
        }
        let subtract = borrow & 0xff;
        let current = u16::from(scalar[index]);
        if current >= subtract {
            scalar[index] = (current - subtract) as u8;
            borrow >>= 8;
        } else {
            scalar[index] = (current + 256 - subtract) as u8;
            borrow = (borrow >> 8) + 1;
        }
    }
    scalar
}

fn scalar_negative_half() -> [u8; 32] {
    // (r - 1) / 2
    divide_scalar_by_two(scalar_order_minus(1))
}

fn scalar_three_halves() -> [u8; 32] {
    // (r + 3) / 2 = (r - 1) / 2 + 2
    *add_threshold_scalars_mod_order(&scalar_negative_half(), &scalar_from_small(2))
}

fn divide_scalar_by_two(mut value: [u8; 32]) -> [u8; 32] {
    let mut carry = 0_u8;
    for byte in &mut value {
        let next_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next_carry;
    }
    value
}

/// Chain-domain declaration for Chia mainnet and testnet11.
#[derive(Debug, Clone, Copy)]
pub struct ChiaChainSuite {
    scope: ChainScope,
}

impl ChiaChainSuite {
    pub fn new(scope: ChainScope) -> Result<Self, ChiaAdapterError> {
        scope_profile(scope)?;
        Ok(Self { scope })
    }
}

impl ChainSuite for ChiaChainSuite {
    fn scope(&self) -> ChainScope {
        self.scope
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: true,
            transaction_review: false,
            final_signature_verification: false,
            broadcast: false,
        }
    }

    fn review_transaction(
        &self,
        _transaction_material: &[u8],
    ) -> Result<ReviewArtifact, ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation {
            operation: "Chia transaction review",
        })
    }

    fn verify_finalized_signature(
        &self,
        _review: &ReviewArtifact,
        _finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation {
            operation: "Chia finalized signature verification",
        })
    }
}

/// Signing-domain declaration for Chia's native AugSchemeMPL coordinator.
#[derive(Debug, Clone, Copy)]
pub struct ChiaSigningSuite {
    scope: ChainScope,
    descriptor: SigningSuiteDescriptor,
}

impl ChiaSigningSuite {
    pub fn new(scope: ChainScope) -> Result<Self, ChiaAdapterError> {
        scope_profile(scope)?;
        let descriptor = resolve_builtin_suite(&scope, SigningSuiteId::CHIA_BLS12381_AUG_NATIVE_V1)
            .expect("validated Chia scope and matching signing suite id");
        Ok(Self { scope, descriptor })
    }
}

impl SigningSuite for ChiaSigningSuite {
    fn descriptor(&self) -> SigningSuiteDescriptor {
        self.descriptor
    }

    fn supports(&self, chain_scope: &ChainScope) -> bool {
        *chain_scope == self.scope
    }
}
