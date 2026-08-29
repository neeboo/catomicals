use std::{fmt, str::FromStr};

use catomicals_chain_domain::{ChainId, ChainScope};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigningContractError {
    #[error("unsupported signing suite id `{0}`")]
    UnsupportedSuiteId(String),
    #[error("signing suite `{suite_id}` is not supported for `{chain_scope:?}`")]
    UnsupportedCombination {
        chain_scope: ChainScope,
        suite_id: SigningSuiteId,
    },
    #[error("signer set id must contain 1 to {max_bytes} bytes")]
    InvalidSignerSetId { max_bytes: usize },
    #[error("review schema version must be non-zero")]
    InvalidReviewSchemaVersion,
    #[error("unsupported review binding schema version {actual}; expected {expected}")]
    UnsupportedBindingSchemaVersion { expected: u16, actual: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    #[serde(rename = "bip340-taproot-schnorr")]
    Bip340TaprootSchnorr,
    #[serde(rename = "secp256k1-schnorr")]
    Secp256k1Schnorr,
    #[serde(rename = "bitcoin-cash-schnorr")]
    BitcoinCashSchnorr,
    #[serde(rename = "secp256k1-ecdsa")]
    Secp256k1Ecdsa,
    #[serde(rename = "bls12-381-aug-scheme")]
    Bls12381AugScheme,
    #[serde(rename = "ergo-sigma")]
    ErgoSigma,
}

impl SigningAlgorithm {
    pub const ALL: [Self; 6] = [
        Self::Bip340TaprootSchnorr,
        Self::Secp256k1Schnorr,
        Self::BitcoinCashSchnorr,
        Self::Secp256k1Ecdsa,
        Self::Bls12381AugScheme,
        Self::ErgoSigma,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bip340TaprootSchnorr => "bip340-taproot-schnorr",
            Self::Secp256k1Schnorr => "secp256k1-schnorr",
            Self::BitcoinCashSchnorr => "bitcoin-cash-schnorr",
            Self::Secp256k1Ecdsa => "secp256k1-ecdsa",
            Self::Bls12381AugScheme => "bls12-381-aug-scheme",
            Self::ErgoSigma => "ergo-sigma",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningExecutionMode {
    #[serde(rename = "threshold-interactive")]
    ThresholdInteractive,
    #[serde(rename = "single-signer-isolated")]
    SingleSignerIsolated,
    #[serde(rename = "native-chain-coordinator")]
    NativeChainCoordinator,
}

impl SigningExecutionMode {
    pub const ALL: [Self; 3] = [
        Self::ThresholdInteractive,
        Self::SingleSignerIsolated,
        Self::NativeChainCoordinator,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThresholdInteractive => "threshold-interactive",
            Self::SingleSignerIsolated => "single-signer-isolated",
            Self::NativeChainCoordinator => "native-chain-coordinator",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningSuiteId {
    BitcoinBip340FrostV1,
    BitcoinBip340IsolatedV1,
    FractalBitcoinBip340FrostV1,
    BitcoinCashSchnorrIsolatedV1,
    BitcoinCashEcdsaIsolatedV1,
    BsvEcdsaIsolatedV1,
    KaspaSchnorrFrostV1,
    KaspaEcdsaIsolatedV1,
    ChiaBls12381AugNativeV1,
    ErgoSigmaNativeV1,
}

impl SigningSuiteId {
    pub const BITCOIN_BIP340_FROST_V1: Self = Self::BitcoinBip340FrostV1;
    pub const BITCOIN_BIP340_ISOLATED_V1: Self = Self::BitcoinBip340IsolatedV1;
    pub const FRACTAL_BITCOIN_BIP340_FROST_V1: Self = Self::FractalBitcoinBip340FrostV1;
    pub const BITCOIN_CASH_SCHNORR_ISOLATED_V1: Self = Self::BitcoinCashSchnorrIsolatedV1;
    pub const BITCOIN_CASH_ECDSA_ISOLATED_V1: Self = Self::BitcoinCashEcdsaIsolatedV1;
    pub const BSV_ECDSA_ISOLATED_V1: Self = Self::BsvEcdsaIsolatedV1;
    pub const KASPA_SCHNORR_FROST_V1: Self = Self::KaspaSchnorrFrostV1;
    pub const KASPA_ECDSA_ISOLATED_V1: Self = Self::KaspaEcdsaIsolatedV1;
    pub const CHIA_BLS12381_AUG_NATIVE_V1: Self = Self::ChiaBls12381AugNativeV1;
    pub const ERGO_SIGMA_NATIVE_V1: Self = Self::ErgoSigmaNativeV1;

    pub const ALL: [Self; 10] = [
        Self::BitcoinBip340FrostV1,
        Self::BitcoinBip340IsolatedV1,
        Self::FractalBitcoinBip340FrostV1,
        Self::BitcoinCashSchnorrIsolatedV1,
        Self::BitcoinCashEcdsaIsolatedV1,
        Self::BsvEcdsaIsolatedV1,
        Self::KaspaSchnorrFrostV1,
        Self::KaspaEcdsaIsolatedV1,
        Self::ChiaBls12381AugNativeV1,
        Self::ErgoSigmaNativeV1,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinBip340FrostV1 => "btc.bip340.frost-secp256k1-tr.v1",
            Self::BitcoinBip340IsolatedV1 => "btc.bip340.isolated.v1",
            Self::FractalBitcoinBip340FrostV1 => "fractal-bitcoin.bip340.frost-secp256k1-tr.v1",
            Self::BitcoinCashSchnorrIsolatedV1 => "bch.schnorr.isolated.v1",
            Self::BitcoinCashEcdsaIsolatedV1 => "bch.ecdsa.isolated.v1",
            Self::BsvEcdsaIsolatedV1 => "bsv.ecdsa.isolated.v1",
            Self::KaspaSchnorrFrostV1 => "kaspa.schnorr.frost-secp256k1.v1",
            Self::KaspaEcdsaIsolatedV1 => "kaspa.ecdsa.isolated.v1",
            Self::ChiaBls12381AugNativeV1 => "chia.bls12-381.aug.native.v1",
            Self::ErgoSigmaNativeV1 => "ergo.sigma.native.v1",
        }
    }

    const fn chain_id(self) -> ChainId {
        match self {
            Self::BitcoinBip340FrostV1 | Self::BitcoinBip340IsolatedV1 => ChainId::Bitcoin,
            Self::FractalBitcoinBip340FrostV1 => ChainId::FractalBitcoin,
            Self::BitcoinCashSchnorrIsolatedV1 | Self::BitcoinCashEcdsaIsolatedV1 => {
                ChainId::BitcoinCash
            }
            Self::BsvEcdsaIsolatedV1 => ChainId::Bsv,
            Self::KaspaSchnorrFrostV1 | Self::KaspaEcdsaIsolatedV1 => ChainId::Kaspa,
            Self::ChiaBls12381AugNativeV1 => ChainId::Chia,
            Self::ErgoSigmaNativeV1 => ChainId::Ergo,
        }
    }
}

impl fmt::Display for SigningSuiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SigningSuiteId {
    type Err = SigningContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|suite| suite.as_str() == value)
            .ok_or_else(|| SigningContractError::UnsupportedSuiteId(value.to_owned()))
    }
}

impl Serialize for SigningSuiteId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SigningSuiteId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub produces_consensus_signature: bool,
    pub independently_verifiable: bool,
    pub interactive_threshold: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSuiteDescriptor {
    pub schema_version: u16,
    pub id: SigningSuiteId,
    pub algorithm: SigningAlgorithm,
    pub execution_mode: SigningExecutionMode,
    pub capabilities: Capabilities,
}

pub trait SigningSuite: Send + Sync {
    fn descriptor(&self) -> SigningSuiteDescriptor;
    fn supports(&self, chain_scope: &ChainScope) -> bool;
}

pub fn resolve_builtin_suite(
    chain_scope: &ChainScope,
    suite_id: SigningSuiteId,
) -> Result<SigningSuiteDescriptor, SigningContractError> {
    if chain_scope.chain != chain_scope.network.chain_id()
        || chain_scope.chain != suite_id.chain_id()
    {
        return Err(SigningContractError::UnsupportedCombination {
            chain_scope: *chain_scope,
            suite_id,
        });
    }

    let (algorithm, execution_mode) = match suite_id {
        SigningSuiteId::BitcoinBip340FrostV1 | SigningSuiteId::FractalBitcoinBip340FrostV1 => (
            SigningAlgorithm::Bip340TaprootSchnorr,
            SigningExecutionMode::ThresholdInteractive,
        ),
        SigningSuiteId::BitcoinBip340IsolatedV1 => (
            SigningAlgorithm::Bip340TaprootSchnorr,
            SigningExecutionMode::SingleSignerIsolated,
        ),
        SigningSuiteId::BitcoinCashSchnorrIsolatedV1 => (
            SigningAlgorithm::BitcoinCashSchnorr,
            SigningExecutionMode::SingleSignerIsolated,
        ),
        SigningSuiteId::BitcoinCashEcdsaIsolatedV1 | SigningSuiteId::BsvEcdsaIsolatedV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::SingleSignerIsolated,
        ),
        SigningSuiteId::KaspaSchnorrFrostV1 => (
            SigningAlgorithm::Secp256k1Schnorr,
            SigningExecutionMode::ThresholdInteractive,
        ),
        SigningSuiteId::KaspaEcdsaIsolatedV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::SingleSignerIsolated,
        ),
        SigningSuiteId::ChiaBls12381AugNativeV1 => (
            SigningAlgorithm::Bls12381AugScheme,
            SigningExecutionMode::NativeChainCoordinator,
        ),
        SigningSuiteId::ErgoSigmaNativeV1 => (
            SigningAlgorithm::ErgoSigma,
            SigningExecutionMode::NativeChainCoordinator,
        ),
    };

    Ok(SigningSuiteDescriptor {
        schema_version: 1,
        id: suite_id,
        algorithm,
        execution_mode,
        capabilities: Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: execution_mode == SigningExecutionMode::ThresholdInteractive,
        },
    })
}
