#![forbid(unsafe_code)]

//! Bitcoin and Fractal Bitcoin chain adapter.

use std::{fmt, str::FromStr};

use bitcoin::{
    Address, AddressType, CompressedPublicKey, Network, ScriptBuf, Transaction, TxOut, Txid, Wtxid,
    XOnlyPublicKey,
    address::{NetworkChecked, NetworkUnchecked},
    bip32::{ChildNumber, DerivationPath},
    consensus::{deserialize, serialize},
    hashes::Hash as _,
    key::{Secp256k1, TweakedPublicKey},
    secp256k1::{Message, schnorr},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainCapabilities, ChainId, ChainNetwork, ChainScope, ChainSuite,
    FractalBitcoinNetwork, MAX_REVIEW_MATERIAL_BYTES, REVIEW_ARTIFACT_SCHEMA_VERSION,
    ReviewArtifact, ReviewContractError,
};
use catomicals_signing_domain::{
    ReviewBinding, SigningSuite, SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REVIEW_MATERIAL_SCHEMA_VERSION: u16 = 1;
const SUPPORTED_CHAIN_SCOPE_SCHEMA_VERSION: u16 = 1;

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
    #[error("finalized transaction does not match the reviewed unsigned transaction")]
    FinalizedTransactionMismatch,
    #[error("finalized Taproot key-spend witness must contain exactly one signature")]
    InvalidTaprootWitness,
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

/// Derives a P2TR address when `output_key` is already the final BIP341 key.
///
/// Threshold BIP340 wallets commonly provision the FROST group key as the
/// actual Taproot output key. Passing that key to [`derive_p2tr_address`]
/// would treat it as an internal key and apply TapTweak, producing an output
/// the unchanged FROST shares cannot spend.
pub fn derive_p2tr_output_key_address(
    scope: ChainScope,
    output_key: XOnlyPublicKey,
) -> Result<ScopedAddress, BitcoinAdapterError> {
    let network = address_network(scope)?;
    Ok(ScopedAddress {
        scope,
        kind: AddressKind::P2tr,
        address: Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(output_key),
            network,
        ),
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

/// A signed transaction whose witness has been assembled from one exact,
/// reproducible review artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedTaprootKeySpend {
    scope: ChainScope,
    input_index: usize,
    transaction: Transaction,
}

/// Errors exposed by the Fractal wallet execution and node-RPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FractalExecutionError {
    #[error("scope is not Fractal Bitcoin: {0:?}")]
    WrongChain(ChainScope),
    #[error("Fractal adapter rejected the request: {0}")]
    Adapter(String),
    #[error("transaction review failed: {0}")]
    Review(String),
    #[error("review binding does not match the reproduced transaction review")]
    ReviewBindingMismatch,
    #[error("Fractal wallet execution only permits Taproot SIGHASH_DEFAULT, got {actual:?}")]
    UnsupportedSighash { actual: TapSighashType },
    #[error("signing session id must not be all zeroes")]
    InvalidSigningSessionId,
    #[error("Fractal FROST signing coordinator failed: {0}")]
    SigningCoordinator(String),
    #[error("Fractal RPC scope mismatch: expected {expected:?}, got {actual:?}")]
    ScopeMismatch {
        expected: ChainScope,
        actual: ChainScope,
    },
    #[error("Fractal node RPC transport failed: {0}")]
    RpcTransport(String),
    #[error("Fractal node reports network `{actual}`, expected `{expected}")]
    NodeNetworkMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("Fractal node identity check failed: {reason}")]
    NodeIdentityMismatch { reason: String },
    #[error("Fractal node returned an invalid RPC response: {0}")]
    InvalidRpcResponse(String),
    #[error("Fractal node rejected the transaction: {reason}")]
    MempoolRejected { reason: String },
    #[error("Fractal node returned txid {actual}, expected {expected}")]
    RpcTransactionMismatch { expected: Txid, actual: Txid },
    #[error("Fractal node returned wtxid {actual}, expected {expected}")]
    RpcWitnessTransactionMismatch { expected: Wtxid, actual: Wtxid },
}

impl FinalizedTaprootKeySpend {
    pub const fn scope(&self) -> ChainScope {
        self.scope
    }

    pub const fn input_index(&self) -> usize {
        self.input_index
    }

    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn into_transaction(self) -> Transaction {
        self.transaction
    }
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

    /// Verifies a 64-byte aggregate FROST result against the exact review and
    /// installs its canonical BIP341 witness on the reviewed input.
    pub fn finalize_reviewed_key_spend(
        &self,
        review: &ReviewArtifact,
        aggregate_signature: [u8; 64],
    ) -> Result<FinalizedTaprootKeySpend, ReviewContractError> {
        let material =
            TaprootReviewMaterial::decode(&review.reviewed_material).map_err(review_error)?;
        let request = material.to_request().map_err(review_error)?;
        let finalized_signature =
            assemble_taproot_key_spend_signature(aggregate_signature, request.sighash_type)
                .map_err(review_error)?;

        self.verify_finalized_signature(review, &finalized_signature)?;

        let mut transaction = request.transaction;
        transaction.input[request.input_index]
            .witness
            .push(finalized_signature);
        let finalized = FinalizedTaprootKeySpend {
            scope: self.scope,
            input_index: request.input_index,
            transaction,
        };
        self.verify_finalized_key_spend(review, &finalized)?;
        Ok(finalized)
    }

    /// Replays the review contract against the actual witness-bearing
    /// transaction. This catches transaction, scope, input and witness drift
    /// before the signed bytes are handed to a broadcaster.
    pub fn verify_finalized_key_spend(
        &self,
        review: &ReviewArtifact,
        finalized: &FinalizedTaprootKeySpend,
    ) -> Result<(), ReviewContractError> {
        if finalized.scope != self.scope {
            return Err(review_error(BitcoinAdapterError::ScopeMismatch {
                expected: self.scope,
                actual: finalized.scope,
            }));
        }

        let material =
            TaprootReviewMaterial::decode(&review.reviewed_material).map_err(review_error)?;
        let request = material.to_request().map_err(review_error)?;
        if finalized.input_index != request.input_index {
            return Err(review_error(
                BitcoinAdapterError::FinalizedTransactionMismatch,
            ));
        }

        self.verify_finalized_transaction(review, &finalized.transaction)
    }

    /// Verifies the exact transaction bytes intended for broadcast against a
    /// prior review. Only the reviewed input may contain one key-spend witness.
    pub fn verify_finalized_transaction(
        &self,
        review: &ReviewArtifact,
        transaction: &Transaction,
    ) -> Result<(), ReviewContractError> {
        let material =
            TaprootReviewMaterial::decode(&review.reviewed_material).map_err(review_error)?;
        let request = material.to_request().map_err(review_error)?;
        if transaction.input.len() != request.transaction.input.len()
            || transaction.output != request.transaction.output
        {
            return Err(review_error(
                BitcoinAdapterError::FinalizedTransactionMismatch,
            ));
        }

        let witness = &transaction.input[request.input_index].witness;
        if witness.len() != 1 {
            return Err(review_error(BitcoinAdapterError::InvalidTaprootWitness));
        }
        let finalized_signature = witness
            .iter()
            .next()
            .ok_or_else(|| review_error(BitcoinAdapterError::InvalidTaprootWitness))?;

        let mut unsigned = transaction.clone();
        unsigned.input[request.input_index].witness.clear();
        if unsigned != request.transaction {
            return Err(review_error(
                BitcoinAdapterError::FinalizedTransactionMismatch,
            ));
        }

        self.verify_finalized_signature(review, finalized_signature)
    }
}

/// The review-bound signing message handed from the Fractal chain adapter to
/// a wallet signing coordinator.
#[derive(Debug, PartialEq, Eq)]
pub struct FractalFrostSigningRequest {
    review: ReviewArtifact,
    binding: ReviewBinding,
    signing_session_id: [u8; 32],
}

impl FractalFrostSigningRequest {
    pub const fn scope(&self) -> ChainScope {
        self.review.scope
    }

    pub const fn review_binding(&self) -> &ReviewBinding {
        &self.binding
    }

    pub const fn signing_message(&self) -> [u8; 32] {
        self.review.signing_message_digest
    }

    pub const fn signing_session_id(&self) -> [u8; 32] {
        self.signing_session_id
    }

    pub const fn review(&self) -> &ReviewArtifact {
        &self.review
    }
}

/// Exact authority and consensus context passed to the trusted wallet signing
/// coordinator. FROST participants must authorize all three values together.
#[derive(Debug, Clone, Copy)]
pub struct FractalFrostSessionContext<'a> {
    signing_session_id: [u8; 32],
    review_binding: &'a ReviewBinding,
    signing_message: [u8; 32],
}

impl FractalFrostSessionContext<'_> {
    pub const fn signing_session_id(&self) -> [u8; 32] {
        self.signing_session_id
    }

    pub const fn review_binding(&self) -> &ReviewBinding {
        self.review_binding
    }

    pub const fn signing_message(&self) -> [u8; 32] {
        self.signing_message
    }
}

/// Trusted wallet-side FROST coordinator boundary. Implementations are
/// responsible for persisting and consuming the complete session context
/// before returning an aggregate consensus signature.
pub trait FractalFrostSigner {
    fn sign(&mut self, session: &FractalFrostSessionContext<'_>) -> Result<[u8; 64], String>;
}

/// Final Fractal witness produced from a complete signing-authority binding.
///
/// Raw transaction bytes intentionally stay private so wallet callers use the
/// preflight-enforcing node adapter instead of bypassing policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FractalFinalizedKeySpend {
    review_binding: ReviewBinding,
    finalized: FinalizedTaprootKeySpend,
    witness: Vec<u8>,
}

impl FractalFinalizedKeySpend {
    pub const fn scope(&self) -> ChainScope {
        self.finalized.scope()
    }

    pub const fn review_binding(&self) -> &ReviewBinding {
        &self.review_binding
    }

    pub fn witness(&self) -> &[u8] {
        &self.witness
    }

    pub fn txid(&self) -> Txid {
        self.finalized.transaction().compute_txid()
    }

    pub fn wtxid(&self) -> Wtxid {
        self.finalized.transaction().compute_wtxid()
    }
}

/// Narrow Fractal transaction adapter used by wallet runtimes. It creates an
/// opaque, complete review binding and consumes that request when installing
/// an aggregate FROST result.
#[derive(Debug, Clone)]
pub struct FractalFrostExecutionAdapter {
    suite: BitcoinChainSuite,
    signer_set_id: String,
    signer_set_epoch: u64,
}

impl FractalFrostExecutionAdapter {
    pub fn new(
        scope: ChainScope,
        output_key: XOnlyPublicKey,
        signer_set_id: impl Into<String>,
        signer_set_epoch: u64,
    ) -> Result<Self, FractalExecutionError> {
        if scope.chain != ChainId::FractalBitcoin {
            return Err(FractalExecutionError::WrongChain(scope));
        }
        let suite = BitcoinChainSuite::new(scope, output_key)
            .map_err(|error| FractalExecutionError::Adapter(error.to_string()))?;
        let signer_set_id = signer_set_id.into();
        ReviewBinding::new(
            scope,
            SigningSuiteId::FractalBitcoinBip340FrostV1,
            signer_set_id.clone(),
            signer_set_epoch,
            REVIEW_ARTIFACT_SCHEMA_VERSION,
            [0; 32],
        )
        .map_err(|error| FractalExecutionError::Adapter(error.to_string()))?;
        Ok(Self {
            suite,
            signer_set_id,
            signer_set_epoch,
        })
    }

    pub fn prepare(
        &self,
        transaction_material: &[u8],
        signing_session_id: [u8; 32],
    ) -> Result<FractalFrostSigningRequest, FractalExecutionError> {
        if signing_session_id == [0; 32] {
            return Err(FractalExecutionError::InvalidSigningSessionId);
        }
        let material = TaprootReviewMaterial::decode(transaction_material)
            .map_err(|error| FractalExecutionError::Review(error.to_string()))?;
        let request = material
            .to_request()
            .map_err(|error| FractalExecutionError::Review(error.to_string()))?;
        if request.sighash_type != TapSighashType::Default {
            return Err(FractalExecutionError::UnsupportedSighash {
                actual: request.sighash_type,
            });
        }
        let review = self
            .suite
            .review_transaction(transaction_material)
            .map_err(|error| FractalExecutionError::Review(error.to_string()))?;
        let binding = ReviewBinding::new(
            self.suite.scope(),
            SigningSuiteId::FractalBitcoinBip340FrostV1,
            self.signer_set_id.clone(),
            self.signer_set_epoch,
            review.schema_version,
            review.review_digest,
        )
        .map_err(|error| FractalExecutionError::Adapter(error.to_string()))?;
        Ok(FractalFrostSigningRequest {
            review,
            binding,
            signing_session_id,
        })
    }

    pub fn finalize_with_signer<S>(
        &self,
        signing: FractalFrostSigningRequest,
        signer: &mut S,
    ) -> Result<FractalFinalizedKeySpend, FractalExecutionError>
    where
        S: FractalFrostSigner,
    {
        let expected_binding = ReviewBinding::new(
            self.suite.scope(),
            SigningSuiteId::FractalBitcoinBip340FrostV1,
            self.signer_set_id.clone(),
            self.signer_set_epoch,
            signing.review.schema_version,
            signing.review.review_digest,
        )
        .map_err(|error| FractalExecutionError::Adapter(error.to_string()))?;
        if signing.binding != expected_binding {
            return Err(FractalExecutionError::ReviewBindingMismatch);
        }
        let session = FractalFrostSessionContext {
            signing_session_id: signing.signing_session_id,
            review_binding: &signing.binding,
            signing_message: signing.review.signing_message_digest,
        };
        let aggregate_signature = signer
            .sign(&session)
            .map_err(FractalExecutionError::SigningCoordinator)?;
        let finalized = self
            .suite
            .finalize_reviewed_key_spend(signing.review(), aggregate_signature)
            .map_err(|error| FractalExecutionError::Review(error.to_string()))?;
        let witness = finalized.transaction().input[finalized.input_index()]
            .witness
            .iter()
            .next()
            .ok_or_else(|| {
                FractalExecutionError::Review("finalized witness is missing".to_owned())
            })?
            .to_vec();
        Ok(FractalFinalizedKeySpend {
            review_binding: signing.binding,
            finalized,
            witness,
        })
    }
}

/// Minimal transport contract for a Bitcoin-Core-compatible Fractal node.
/// Authentication, HTTP and timeout policy stay outside the chain adapter.
pub trait FractalNodeRpcTransport {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String>;
}

/// Opaque proof that this exact raw transaction passed `testmempoolaccept`.
#[derive(Debug, PartialEq, Eq)]
pub struct AcceptedFractalTransaction {
    scope: ChainScope,
    txid: Txid,
    raw_transaction_hex: String,
}

impl AcceptedFractalTransaction {
    pub const fn txid(&self) -> Txid {
        self.txid
    }
}

/// Typed Fractal node calls that force preflight before broadcast.
#[derive(Debug, Clone)]
pub struct FractalNodeRpc<T> {
    scope: ChainScope,
    transport: T,
}

impl<T> FractalNodeRpc<T>
where
    T: FractalNodeRpcTransport,
{
    pub fn connect(scope: ChainScope, transport: T) -> Result<Self, FractalExecutionError> {
        if scope.chain != ChainId::FractalBitcoin {
            return Err(FractalExecutionError::WrongChain(scope));
        }
        scope_profile(scope).map_err(|error| FractalExecutionError::Adapter(error.to_string()))?;
        let rpc = Self { scope, transport };
        rpc.verify_node_identity()?;
        Ok(rpc)
    }

    pub fn test_mempool_accept(
        &self,
        finalized: &FractalFinalizedKeySpend,
    ) -> Result<AcceptedFractalTransaction, FractalExecutionError> {
        if finalized.scope() != self.scope {
            return Err(FractalExecutionError::ScopeMismatch {
                expected: self.scope,
                actual: finalized.scope(),
            });
        }
        let expected_txid = finalized.finalized.transaction().compute_txid();
        let expected_wtxid = finalized.finalized.transaction().compute_wtxid();
        let raw_transaction_hex = hex::encode(serialize(finalized.finalized.transaction()));
        let response = self
            .transport
            .call(
                "testmempoolaccept",
                serde_json::json!([[raw_transaction_hex.clone()]]),
            )
            .map_err(FractalExecutionError::RpcTransport)?;
        let entries = response.as_array().ok_or_else(|| {
            FractalExecutionError::InvalidRpcResponse(
                "testmempoolaccept result must be an array".to_owned(),
            )
        })?;
        if entries.len() != 1 {
            return Err(FractalExecutionError::InvalidRpcResponse(
                "testmempoolaccept must return exactly one result".to_owned(),
            ));
        }
        let entry = entries[0].as_object().ok_or_else(|| {
            FractalExecutionError::InvalidRpcResponse(
                "testmempoolaccept entry must be an object".to_owned(),
            )
        })?;
        let actual_txid = parse_rpc_txid(entry.get("txid"), "txid")?;
        if actual_txid != expected_txid {
            return Err(FractalExecutionError::RpcTransactionMismatch {
                expected: expected_txid,
                actual: actual_txid,
            });
        }
        let actual_wtxid = parse_rpc_wtxid(entry.get("wtxid"), "wtxid")?;
        if actual_wtxid != expected_wtxid {
            return Err(FractalExecutionError::RpcWitnessTransactionMismatch {
                expected: expected_wtxid,
                actual: actual_wtxid,
            });
        }
        let allowed = entry
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                FractalExecutionError::InvalidRpcResponse("allowed must be a boolean".to_owned())
            })?;
        if !allowed {
            let reason = entry
                .get("reject-reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("node rejected transaction")
                .to_owned();
            return Err(FractalExecutionError::MempoolRejected { reason });
        }
        Ok(AcceptedFractalTransaction {
            scope: self.scope,
            txid: expected_txid,
            raw_transaction_hex,
        })
    }

    /// Re-runs node policy preflight and sends the same raw transaction over
    /// this transport only after acceptance.
    pub fn preflight_and_broadcast(
        &self,
        finalized: &FractalFinalizedKeySpend,
    ) -> Result<Txid, FractalExecutionError> {
        let accepted = self.test_mempool_accept(finalized)?;
        self.broadcast_accepted(accepted)
    }

    fn broadcast_accepted(
        &self,
        accepted: AcceptedFractalTransaction,
    ) -> Result<Txid, FractalExecutionError> {
        if accepted.scope != self.scope {
            return Err(FractalExecutionError::ScopeMismatch {
                expected: self.scope,
                actual: accepted.scope,
            });
        }
        let response = self
            .transport
            .call(
                "sendrawtransaction",
                serde_json::json!([accepted.raw_transaction_hex]),
            )
            .map_err(FractalExecutionError::RpcTransport)?;
        let actual = parse_rpc_txid(Some(&response), "sendrawtransaction result")?;
        if actual != accepted.txid {
            return Err(FractalExecutionError::RpcTransactionMismatch {
                expected: accepted.txid,
                actual,
            });
        }
        Ok(actual)
    }

    fn verify_node_identity(&self) -> Result<(), FractalExecutionError> {
        let blockchain_info = self
            .transport
            .call("getblockchaininfo", serde_json::json!([]))
            .map_err(FractalExecutionError::RpcTransport)?;
        let actual_network = blockchain_info
            .get("chain")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FractalExecutionError::InvalidRpcResponse(
                    "getblockchaininfo.chain must be a string".to_owned(),
                )
            })?;
        let expected_network = fractal_rpc_chain_name(self.scope)?;
        if actual_network != expected_network {
            return Err(FractalExecutionError::NodeNetworkMismatch {
                expected: expected_network,
                actual: actual_network.to_owned(),
            });
        }

        let help = self
            .transport
            .call("help", serde_json::json!(["createindexerblock"]))
            .map_err(|error| FractalExecutionError::NodeIdentityMismatch { reason: error })?;
        let help = help
            .as_str()
            .ok_or_else(|| FractalExecutionError::NodeIdentityMismatch {
                reason: "help createindexerblock must return text".to_owned(),
            })?;
        if !help.contains("createindexerblock") || !help.contains("submitindexerblock") {
            return Err(FractalExecutionError::NodeIdentityMismatch {
                reason: "Fractal indexer-mining RPCs are unavailable".to_owned(),
            });
        }
        Ok(())
    }
}

fn fractal_rpc_chain_name(scope: ChainScope) -> Result<&'static str, FractalExecutionError> {
    match scope.network {
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Mainnet) => Ok("main"),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet3) => Ok("test"),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet4) => Ok("testnet4"),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet) => Ok("signet"),
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Regtest) => Ok("regtest"),
        _ => Err(FractalExecutionError::WrongChain(scope)),
    }
}

fn parse_rpc_txid(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<Txid, FractalExecutionError> {
    let value = value.and_then(serde_json::Value::as_str).ok_or_else(|| {
        FractalExecutionError::InvalidRpcResponse(format!("{field} must be a string"))
    })?;
    Txid::from_str(value).map_err(|_| {
        FractalExecutionError::InvalidRpcResponse(format!("{field} is not a valid txid"))
    })
}

fn parse_rpc_wtxid(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<Wtxid, FractalExecutionError> {
    let value = value.and_then(serde_json::Value::as_str).ok_or_else(|| {
        FractalExecutionError::InvalidRpcResponse(format!("{field} must be a string"))
    })?;
    Wtxid::from_str(value).map_err(|_| {
        FractalExecutionError::InvalidRpcResponse(format!("{field} is not a valid wtxid"))
    })
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
        if transaction_material.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ReviewContractError::ReviewedMaterialTooLong {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
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
        ReviewArtifact::new(
            self.scope,
            review_digest,
            payload.sighash,
            format!(
                "{} Taproot key spend input {} using {}",
                self.scope.chain, request.input_index, request.sighash_type,
            ),
            canonical_material,
        )
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        if review.schema_version != REVIEW_ARTIFACT_SCHEMA_VERSION {
            return Err(ReviewContractError::UnsupportedSchemaVersion {
                expected: REVIEW_ARTIFACT_SCHEMA_VERSION,
                actual: review.schema_version,
            });
        }
        if review.scope != self.scope {
            return Err(review_error(BitcoinAdapterError::ScopeMismatch {
                expected: self.scope,
                actual: review.scope,
            }));
        }
        let expected = self
            .review_transaction(&review.reviewed_material)
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
            TaprootReviewMaterial::decode(&review.reviewed_material).map_err(review_error)?;
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
