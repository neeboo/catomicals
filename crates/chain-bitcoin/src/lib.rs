#![forbid(unsafe_code)]

//! Bitcoin and Fractal Bitcoin chain adapter.

use std::{fmt, str::FromStr};

use bitcoin::{
    Address, AddressType, CompressedPublicKey, Network, ScriptBuf, Transaction, TxOut,
    XOnlyPublicKey,
    address::{NetworkChecked, NetworkUnchecked},
    bip32::{ChildNumber, DerivationPath},
    consensus::{deserialize, serialize},
    hashes::Hash as _,
    key::Secp256k1,
    secp256k1::{Message, schnorr},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite,
    FractalBitcoinNetwork, ReviewArtifact, ReviewContractError,
};
use catomicals_signing_domain::{
    SigningSuite, SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REVIEW_MATERIAL_SCHEMA_VERSION: u16 = 1;
const SUPPORTED_CHAIN_SCOPE_SCHEMA_VERSION: u16 = 1;
const REVIEW_MATERIAL_MARKER: &str = "\ncatomicals-review-material-v1:";

/// Errors produced before Bitcoin-family consensus operations are attempted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitcoinAdapterError {
    #[error("network `{network}` belongs to `{actual}`, not `{declared}`")]
    MismatchedChainNetwork {
        declared: ChainId,
        actual: ChainId,
        network: ChainNetwork,
    },
    #[error("chain scope `{0:?}` is not a Bitcoin-family scope")]
    UnsupportedChainScope(ChainScope),
    #[error("unsupported chain scope schema version {actual}; expected {expected}")]
    UnsupportedScopeSchemaVersion { expected: u16, actual: u16 },
    #[error("mainnet scope `{scope:?}` is not activated for signing")]
    MainnetNotActivated { scope: ChainScope },
    #[error("BIP32 {field} index {index} must be less than 2^31")]
    InvalidDerivationIndex { field: &'static str, index: u32 },
    #[error("BIP44 change index must be 0 or 1, got {0}")]
    InvalidChange(u32),
    #[error("invalid Bitcoin-family address: {0}")]
    InvalidAddress(String),
    #[error("address is not valid for chain scope `{scope:?}`")]
    InvalidAddressNetwork { scope: ChainScope },
    #[error("expected {expected:?} address, got {actual:?}")]
    UnexpectedAddressKind {
        expected: AddressKind,
        actual: Option<AddressKind>,
    },
    #[error("object is bound to `{actual:?}`, not `{expected:?}`")]
    ScopeMismatch {
        expected: ChainScope,
        actual: ChainScope,
    },
    #[error("expected {expected} prevouts, got {actual}")]
    PrevoutCountMismatch { expected: usize, actual: usize },
    #[error("signing input index {input_index} is out of range for {input_count} inputs")]
    InputIndexOutOfRange {
        input_index: usize,
        input_count: usize,
    },
    #[error("signing input {input_index} does not spend a P2TR output")]
    SigningInputNotTaproot { input_index: usize },
    #[error("transaction already contains scriptSig or witness data")]
    TransactionAlreadySigned,
    #[error("unable to derive the BIP341 key-spend signature hash")]
    TaprootSighash,
    #[error("invalid Taproot signature encoding")]
    InvalidTaprootSignatureEncoding,
    #[error("signature sighash type {actual} does not match reviewed type {expected}")]
    SignatureSighashMismatch {
        expected: TapSighashType,
        actual: TapSighashType,
    },
    #[error("Taproot signature does not verify")]
    InvalidTaprootSignature,
    #[error("reviewed P2TR output key does not match the chain suite key")]
    TaprootOutputKeyMismatch,
    #[error("invalid Taproot review material: {0}")]
    InvalidReviewMaterial(String),
    #[error("unsupported Taproot review material schema version {actual}; expected {expected}")]
    UnsupportedReviewMaterialVersion { expected: u16, actual: u16 },
}

/// The two standard single-key address policies supported by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressKind {
    /// BIP84 native SegWit P2WPKH.
    P2wpkh,
    /// BIP86 key-path-only Taproot P2TR.
    P2tr,
}

impl AddressKind {
    const fn purpose(self) -> u32 {
        match self {
            Self::P2wpkh => 84,
            Self::P2tr => 86,
        }
    }
}

/// A BIP32 path paired with the chain scope that gives it meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedDerivationPath {
    scope: ChainScope,
    kind: AddressKind,
    path: DerivationPath,
}

impl ScopedDerivationPath {
    pub const fn scope(&self) -> ChainScope {
        self.scope
    }

    pub const fn kind(&self) -> AddressKind {
        self.kind
    }

    pub const fn path(&self) -> &DerivationPath {
        &self.path
    }
}

#[derive(Debug, Clone, Copy)]
struct ScopeProfile {
    mainnet: bool,
}

fn scope_profile(scope: ChainScope) -> Result<ScopeProfile, BitcoinAdapterError> {
    if scope.schema_version != SUPPORTED_CHAIN_SCOPE_SCHEMA_VERSION {
        return Err(BitcoinAdapterError::UnsupportedScopeSchemaVersion {
            expected: SUPPORTED_CHAIN_SCOPE_SCHEMA_VERSION,
            actual: scope.schema_version,
        });
    }
    let actual = scope.network.chain_id();
    if actual != scope.chain {
        return Err(BitcoinAdapterError::MismatchedChainNetwork {
            declared: scope.chain,
            actual,
            network: scope.network,
        });
    }

    let mainnet = match scope.network {
        ChainNetwork::Bitcoin(BitcoinNetwork::Mainnet)
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Mainnet) => true,
        ChainNetwork::Bitcoin(
            BitcoinNetwork::Testnet3
            | BitcoinNetwork::Testnet4
            | BitcoinNetwork::Signet
            | BitcoinNetwork::Regtest,
        )
        | ChainNetwork::FractalBitcoin(
            FractalBitcoinNetwork::Testnet3
            | FractalBitcoinNetwork::Testnet4
            | FractalBitcoinNetwork::Signet
            | FractalBitcoinNetwork::Regtest,
        ) => false,
        _ => return Err(BitcoinAdapterError::UnsupportedChainScope(scope)),
    };
    Ok(ScopeProfile { mainnet })
}

fn address_network(scope: ChainScope) -> Result<Network, BitcoinAdapterError> {
    scope_profile(scope)?;
    match scope.network {
        ChainNetwork::Bitcoin(BitcoinNetwork::Mainnet)
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Mainnet)
        // Fractal's official testnet3 intentionally retains Bitcoin mainnet
        // base58, extended-key and Bech32 prefixes.
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet3) => Ok(Network::Bitcoin),
        ChainNetwork::Bitcoin(BitcoinNetwork::Testnet3) => Ok(Network::Testnet),
        ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4)
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet4) => Ok(Network::Testnet4),
        ChainNetwork::Bitcoin(BitcoinNetwork::Signet)
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet) => Ok(Network::Signet),
        ChainNetwork::Bitcoin(BitcoinNetwork::Regtest)
        | ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Regtest) => Ok(Network::Regtest),
        _ => Err(BitcoinAdapterError::UnsupportedChainScope(scope)),
    }
}

fn checked_index(field: &'static str, index: u32) -> Result<u32, BitcoinAdapterError> {
    if index >= 1 << 31 {
        return Err(BitcoinAdapterError::InvalidDerivationIndex { field, index });
    }
    Ok(index)
}

/// Builds a BIP84 or BIP86 path while retaining a separate Bitcoin/Fractal binding.
pub fn derivation_path(
    scope: ChainScope,
    kind: AddressKind,
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<ScopedDerivationPath, BitcoinAdapterError> {
    let profile = scope_profile(scope)?;
    let account = checked_index("account", account)?;
    let address_index = checked_index("address_index", address_index)?;
    if change > 1 {
        return Err(BitcoinAdapterError::InvalidChange(change));
    }

    let coin_type = u32::from(!profile.mainnet);
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(kind.purpose()).expect("BIP purpose is in range"),
        ChildNumber::from_hardened_idx(coin_type).expect("coin type is in range"),
        ChildNumber::from_hardened_idx(account).expect("account was range checked"),
        ChildNumber::from_normal_idx(change).expect("change was range checked"),
        ChildNumber::from_normal_idx(address_index).expect("address index was range checked"),
    ]);

    Ok(ScopedDerivationPath { scope, kind, path })
}

/// A checked address whose chain identity is explicit even when its text is ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAddress {
    scope: ChainScope,
    kind: AddressKind,
    address: Address<NetworkChecked>,
}

impl ScopedAddress {
    pub const fn scope(&self) -> ChainScope {
        self.scope
    }

    pub const fn kind(&self) -> AddressKind {
        self.kind
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    pub fn require_scope(
        &self,
        expected: ChainScope,
    ) -> Result<&Address<NetworkChecked>, BitcoinAdapterError> {
        if expected != self.scope {
            return Err(BitcoinAdapterError::ScopeMismatch {
                expected,
                actual: self.scope,
            });
        }
        Ok(&self.address)
    }
}

impl fmt::Display for ScopedAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address.fmt(formatter)
    }
}

/// Derives the native SegWit address for a BIP84 compressed public key.
pub fn derive_p2wpkh_address(
    scope: ChainScope,
    public_key: &CompressedPublicKey,
) -> Result<ScopedAddress, BitcoinAdapterError> {
    let network = address_network(scope)?;
    Ok(ScopedAddress {
        scope,
        kind: AddressKind::P2wpkh,
        address: Address::p2wpkh(public_key, network),
    })
}

/// Derives a key-path-only BIP86 Taproot address from its internal key.
pub fn derive_p2tr_address(
    scope: ChainScope,
    internal_key: XOnlyPublicKey,
) -> Result<ScopedAddress, BitcoinAdapterError> {
    let network = address_network(scope)?;
    let secp = Secp256k1::verification_only();
    Ok(ScopedAddress {
        scope,
        kind: AddressKind::P2tr,
        address: Address::p2tr(&secp, internal_key, None, network),
    })
}

fn address_kind(address_type: Option<AddressType>) -> Option<AddressKind> {
    match address_type {
        Some(AddressType::P2wpkh) => Some(AddressKind::P2wpkh),
        Some(AddressType::P2tr) => Some(AddressKind::P2tr),
        _ => None,
    }
}

/// Parses an address against explicit chain, concrete network and address-kind context.
pub fn parse_address(
    scope: ChainScope,
    expected_kind: AddressKind,
    value: &str,
) -> Result<ScopedAddress, BitcoinAdapterError> {
    let network = address_network(scope)?;
    let unchecked = Address::<NetworkUnchecked>::from_str(value)
        .map_err(|error| BitcoinAdapterError::InvalidAddress(error.to_string()))?;
    let address = unchecked
        .require_network(network)
        .map_err(|_| BitcoinAdapterError::InvalidAddressNetwork { scope })?;
    let actual = address_kind(address.address_type());
    if actual != Some(expected_kind) {
        return Err(BitcoinAdapterError::UnexpectedAddressKind {
            expected: expected_kind,
            actual,
        });
    }
    Ok(ScopedAddress {
        scope,
        kind: expected_kind,
        address,
    })
}

/// Complete BIP341 key-spend inputs, still carrying their chain binding.
#[derive(Debug, Clone)]
pub struct TaprootKeySpendRequest {
    scope: ChainScope,
    transaction: Transaction,
    prevouts: Vec<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
}

impl TaprootKeySpendRequest {
    pub fn new(
        scope: ChainScope,
        transaction: Transaction,
        prevouts: Vec<TxOut>,
        input_index: usize,
        sighash_type: TapSighashType,
    ) -> Result<Self, BitcoinAdapterError> {
        scope_profile(scope)?;
        if prevouts.len() != transaction.input.len() {
            return Err(BitcoinAdapterError::PrevoutCountMismatch {
                expected: transaction.input.len(),
                actual: prevouts.len(),
            });
        }
        if input_index >= transaction.input.len() {
            return Err(BitcoinAdapterError::InputIndexOutOfRange {
                input_index,
                input_count: transaction.input.len(),
            });
        }
        if !prevouts[input_index].script_pubkey.is_p2tr() {
            return Err(BitcoinAdapterError::SigningInputNotTaproot { input_index });
        }
        if transaction
            .input
            .iter()
            .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
        {
            return Err(BitcoinAdapterError::TransactionAlreadySigned);
        }
        Ok(Self {
            scope,
            transaction,
            prevouts,
            input_index,
            sighash_type,
        })
    }

    pub const fn scope(&self) -> ChainScope {
        self.scope
    }

    pub const fn input_index(&self) -> usize {
        self.input_index
    }

    pub const fn sighash_type(&self) -> TapSighashType {
        self.sighash_type
    }
}

/// Consensus signing digest paired with non-consensus chain and network context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaprootSigningPayload {
    scope: ChainScope,
    input_index: usize,
    sighash_type: TapSighashType,
    sighash: [u8; 32],
}

impl TaprootSigningPayload {
    pub const fn scope(&self) -> ChainScope {
        self.scope
    }

    pub const fn input_index(&self) -> usize {
        self.input_index
    }

    pub const fn sighash_type(&self) -> TapSighashType {
        self.sighash_type
    }

    pub const fn sighash(&self) -> [u8; 32] {
        self.sighash
    }

    pub fn require_scope(&self, expected: ChainScope) -> Result<(), BitcoinAdapterError> {
        if expected != self.scope {
            return Err(BitcoinAdapterError::ScopeMismatch {
                expected,
                actual: self.scope,
            });
        }
        Ok(())
    }
}

/// Derives the exact BIP341 key-spend digest. The chain binding is retained beside it.
pub fn taproot_key_spend_payload(
    request: &TaprootKeySpendRequest,
) -> Result<TaprootSigningPayload, BitcoinAdapterError> {
    if scope_profile(request.scope)?.mainnet {
        return Err(BitcoinAdapterError::MainnetNotActivated {
            scope: request.scope,
        });
    }
    let mut cache = SighashCache::new(&request.transaction);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            request.input_index,
            &Prevouts::All(&request.prevouts),
            request.sighash_type,
        )
        .map_err(|_| BitcoinAdapterError::TaprootSighash)?;
    Ok(TaprootSigningPayload {
        scope: request.scope,
        input_index: request.input_index,
        sighash_type: request.sighash_type,
        sighash: sighash.to_byte_array(),
    })
}

/// Converts a raw BIP340 result into BIP341's canonical 64/65-byte witness element.
pub fn assemble_taproot_key_spend_signature(
    signature: [u8; 64],
    sighash_type: TapSighashType,
) -> Result<Vec<u8>, BitcoinAdapterError> {
    let signature = schnorr::Signature::from_slice(&signature)
        .map_err(|_| BitcoinAdapterError::InvalidTaprootSignatureEncoding)?;
    Ok(taproot::Signature {
        signature,
        sighash_type,
    }
    .to_vec())
}

/// Verifies a finalized BIP341 witness element against its reviewed output key.
pub fn verify_taproot_key_spend_signature(
    payload: &TaprootSigningPayload,
    output_key: XOnlyPublicKey,
    finalized_signature: &[u8],
) -> Result<(), BitcoinAdapterError> {
    if finalized_signature.len() == 65 && finalized_signature[64] == 0 {
        return Err(BitcoinAdapterError::InvalidTaprootSignatureEncoding);
    }
    let signature = taproot::Signature::from_slice(finalized_signature)
        .map_err(|_| BitcoinAdapterError::InvalidTaprootSignatureEncoding)?;
    if signature.sighash_type != payload.sighash_type {
        return Err(BitcoinAdapterError::SignatureSighashMismatch {
            expected: payload.sighash_type,
            actual: signature.sighash_type,
        });
    }
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest(payload.sighash);
    secp.verify_schnorr(&signature.signature, &message, &output_key)
        .map_err(|_| BitcoinAdapterError::InvalidTaprootSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewPrevout {
    value_sat: u64,
    script_pubkey_hex: String,
}

/// Canonical, versioned bytes accepted by [`BitcoinChainSuite::review_transaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaprootReviewMaterial {
    schema_version: u16,
    scope: ChainScope,
    raw_unsigned_tx_hex: String,
    prevouts: Vec<ReviewPrevout>,
    input_index: usize,
    sighash_type: u8,
}

impl TaprootReviewMaterial {
    pub fn from_request(request: &TaprootKeySpendRequest) -> Result<Self, BitcoinAdapterError> {
        Ok(Self {
            schema_version: REVIEW_MATERIAL_SCHEMA_VERSION,
            scope: request.scope,
            raw_unsigned_tx_hex: hex::encode(serialize(&request.transaction)),
            prevouts: request
                .prevouts
                .iter()
                .map(|prevout| ReviewPrevout {
                    value_sat: prevout.value.to_sat(),
                    script_pubkey_hex: hex::encode(prevout.script_pubkey.as_bytes()),
                })
                .collect(),
            input_index: request.input_index,
            sighash_type: request.sighash_type as u8,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, BitcoinAdapterError> {
        serde_json::to_vec(self)
            .map_err(|error| BitcoinAdapterError::InvalidReviewMaterial(error.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, BitcoinAdapterError> {
        let material: Self = serde_json::from_slice(bytes)
            .map_err(|error| BitcoinAdapterError::InvalidReviewMaterial(error.to_string()))?;
        if material.schema_version != REVIEW_MATERIAL_SCHEMA_VERSION {
            return Err(BitcoinAdapterError::UnsupportedReviewMaterialVersion {
                expected: REVIEW_MATERIAL_SCHEMA_VERSION,
                actual: material.schema_version,
            });
        }
        Ok(material)
    }

    fn to_request(&self) -> Result<TaprootKeySpendRequest, BitcoinAdapterError> {
        let raw = hex::decode(&self.raw_unsigned_tx_hex)
            .map_err(|error| BitcoinAdapterError::InvalidReviewMaterial(error.to_string()))?;
        let transaction: Transaction = deserialize(&raw)
            .map_err(|error| BitcoinAdapterError::InvalidReviewMaterial(error.to_string()))?;
        if serialize(&transaction) != raw {
            return Err(BitcoinAdapterError::InvalidReviewMaterial(
                "non-canonical transaction encoding".into(),
            ));
        }
        let prevouts = self
            .prevouts
            .iter()
            .map(|prevout| {
                let script = hex::decode(&prevout.script_pubkey_hex).map_err(|error| {
                    BitcoinAdapterError::InvalidReviewMaterial(error.to_string())
                })?;
                Ok(TxOut {
                    value: bitcoin::Amount::from_sat(prevout.value_sat),
                    script_pubkey: ScriptBuf::from_bytes(script),
                })
            })
            .collect::<Result<Vec<_>, BitcoinAdapterError>>()?;
        let sighash_type = TapSighashType::from_consensus_u8(self.sighash_type)
            .map_err(|error| BitcoinAdapterError::InvalidReviewMaterial(error.to_string()))?;
        TaprootKeySpendRequest::new(
            self.scope,
            transaction,
            prevouts,
            self.input_index,
            sighash_type,
        )
    }
}

fn p2tr_output_key(script: &bitcoin::Script) -> Result<XOnlyPublicKey, BitcoinAdapterError> {
    if !script.is_p2tr() {
        return Err(BitcoinAdapterError::SigningInputNotTaproot { input_index: 0 });
    }
    XOnlyPublicKey::from_slice(&script.as_bytes()[2..34])
        .map_err(|_| BitcoinAdapterError::InvalidReviewMaterial("invalid P2TR output key".into()))
}

fn review_error(error: BitcoinAdapterError) -> ReviewContractError {
    ReviewContractError::InvalidFinalizedSignature(error.to_string())
}

/// Chain adapter bound to one concrete scope and Taproot output key.
#[derive(Debug, Clone)]
pub struct BitcoinChainSuite {
    scope: ChainScope,
    output_key: XOnlyPublicKey,
}

impl BitcoinChainSuite {
    pub fn new(scope: ChainScope, output_key: XOnlyPublicKey) -> Result<Self, BitcoinAdapterError> {
        if scope_profile(scope)?.mainnet {
            return Err(BitcoinAdapterError::MainnetNotActivated { scope });
        }
        Ok(Self { scope, output_key })
    }

    pub const fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }
}

impl ChainSuite for BitcoinChainSuite {
    fn scope(&self) -> ChainScope {
        self.scope
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: true,
            transaction_review: true,
            final_signature_verification: true,
            broadcast: false,
        }
    }

    fn review_transaction(
        &self,
        transaction_material: &[u8],
    ) -> Result<ReviewArtifact, ReviewContractError> {
        let material = match TaprootReviewMaterial::decode(transaction_material) {
            Ok(material) => material,
            Err(BitcoinAdapterError::UnsupportedReviewMaterialVersion { expected, actual }) => {
                return Err(ReviewContractError::UnsupportedSchemaVersion { expected, actual });
            }
            Err(error) => return Err(review_error(error)),
        };
        let canonical_material = material.encode().map_err(review_error)?;
        if canonical_material != transaction_material {
            return Err(review_error(BitcoinAdapterError::InvalidReviewMaterial(
                "non-canonical review material encoding".into(),
            )));
        }
        if material.scope != self.scope {
            return Err(review_error(BitcoinAdapterError::ScopeMismatch {
                expected: self.scope,
                actual: material.scope,
            }));
        }
        let request = material.to_request().map_err(review_error)?;
        let reviewed_key = p2tr_output_key(&request.prevouts[request.input_index].script_pubkey)
            .map_err(review_error)?;
        if reviewed_key != self.output_key {
            return Err(review_error(BitcoinAdapterError::TaprootOutputKeyMismatch));
        }
        let payload = taproot_key_spend_payload(&request).map_err(review_error)?;
        let review_digest: [u8; 32] = Sha256::digest(&canonical_material).into();
        let canonical_material = String::from_utf8(canonical_material).map_err(|error| {
            review_error(BitcoinAdapterError::InvalidReviewMaterial(
                error.to_string(),
            ))
        })?;
        ReviewArtifact::new(
            self.scope,
            review_digest,
            payload.sighash,
            format!(
                "{} Taproot key spend input {} using {}{}{}",
                self.scope.chain,
                request.input_index,
                request.sighash_type,
                REVIEW_MATERIAL_MARKER,
                canonical_material,
            ),
        )
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        if review.schema_version != 1 {
            return Err(ReviewContractError::UnsupportedSchemaVersion {
                expected: 1,
                actual: review.schema_version,
            });
        }
        if review.scope != self.scope {
            return Err(review_error(BitcoinAdapterError::ScopeMismatch {
                expected: self.scope,
                actual: review.scope,
            }));
        }
        let (_, canonical_material) = review
            .summary
            .rsplit_once(REVIEW_MATERIAL_MARKER)
            .ok_or_else(|| {
                review_error(BitcoinAdapterError::InvalidReviewMaterial(
                    "review artifact does not contain canonical material".into(),
                ))
            })?;
        let expected = self
            .review_transaction(canonical_material.as_bytes())
            .map_err(|error| {
                review_error(BitcoinAdapterError::InvalidReviewMaterial(format!(
                    "review artifact cannot be reproduced: {error}"
                )))
            })?;
        if expected != *review {
            return Err(review_error(BitcoinAdapterError::InvalidReviewMaterial(
                "review artifact binding mismatch".into(),
            )));
        }
        let material =
            TaprootReviewMaterial::decode(canonical_material.as_bytes()).map_err(review_error)?;
        let request = material.to_request().map_err(review_error)?;
        let payload = taproot_key_spend_payload(&request).map_err(review_error)?;
        verify_taproot_key_spend_signature(&payload, self.output_key, finalized_signature)
            .map_err(review_error)
    }
}

/// Signing-suite declaration. FROST execution remains in the signer backend.
#[derive(Debug, Clone, Copy)]
pub struct BitcoinSigningSuite {
    scope: ChainScope,
    descriptor: SigningSuiteDescriptor,
}

impl BitcoinSigningSuite {
    pub fn new(scope: ChainScope) -> Result<Self, BitcoinAdapterError> {
        if scope_profile(scope)?.mainnet {
            return Err(BitcoinAdapterError::MainnetNotActivated { scope });
        }
        let suite_id = match scope.chain {
            ChainId::Bitcoin => SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            ChainId::FractalBitcoin => SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
            _ => return Err(BitcoinAdapterError::UnsupportedChainScope(scope)),
        };
        let descriptor = resolve_builtin_suite(&scope, suite_id)
            .expect("validated Bitcoin-family scope and matching suite id");
        Ok(Self { scope, descriptor })
    }
}

impl SigningSuite for BitcoinSigningSuite {
    fn descriptor(&self) -> SigningSuiteDescriptor {
        self.descriptor
    }

    fn supports(&self, chain_scope: &ChainScope) -> bool {
        *chain_scope == self.scope
    }
}
