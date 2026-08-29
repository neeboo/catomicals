#![forbid(unsafe_code)]

//! Chia chain adapter.

use std::fmt;

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
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
    #[error("2-of-3 threshold BLS interpolation is not supported by this backend")]
    ThresholdSigningUnsupported,
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

/// Future input contract for a Shamir/Lagrange BLS signature share.
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

/// Reserved 2-of-3 interpolation boundary. The current backend has no threshold-share support.
pub fn interpolate_threshold_signature_2_of_3(
    _shares: &[BlsSignatureShare],
) -> Result<[u8; 96], ChiaAdapterError> {
    Err(ChiaAdapterError::ThresholdSigningUnsupported)
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
