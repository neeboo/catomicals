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
    #[error("signing suite `{suite_id}` is declaration-only and cannot execute signing")]
    SuiteNotExecutable { suite_id: SigningSuiteId },
    #[error("signer set id must contain 1 to {max_bytes} bytes")]
    InvalidSignerSetId { max_bytes: usize },
    #[error("review schema version must be non-zero")]
    InvalidReviewSchemaVersion,
    #[error("unsupported review binding schema version {actual}; expected {expected}")]
    UnsupportedBindingSchemaVersion { expected: u16, actual: u16 },
    #[error("unsupported signing suite descriptor schema version {actual}; expected {expected}")]
    UnsupportedDescriptorSchemaVersion { expected: u16, actual: u16 },
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
    #[serde(rename = "threshold-non-interactive")]
    ThresholdNonInteractive,
    #[serde(rename = "single-signer-isolated")]
    SingleSignerIsolated,
    #[serde(rename = "native-chain-coordinator")]
    NativeChainCoordinator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerBackendRequirement {
    #[serde(rename = "frost-secp256k1-tr")]
    FrostSecp256k1Tr,
    #[serde(rename = "frost-secp256k1-kaspa")]
    FrostSecp256k1Kaspa,
    #[serde(rename = "cb-mpc-threshold-ecdsa")]
    CbMpcThresholdEcdsa,
    #[serde(rename = "isolated-bip340")]
    IsolatedBip340,
    #[serde(rename = "isolated-secp256k1-ecdsa")]
    IsolatedSecp256k1Ecdsa,
    #[serde(rename = "isolated-bitcoin-cash-schnorr")]
    IsolatedBitcoinCashSchnorr,
    #[serde(rename = "chia-bls-aug")]
    ChiaBlsAug,
    #[serde(rename = "chia-bls-aug-threshold-2of3")]
    ChiaBlsAugThreshold2of3,
    #[serde(rename = "ergo-sigma")]
    ErgoSigma,
    #[serde(rename = "ergo-sigma-p2pk")]
    ErgoSigmaP2pk,
    #[serde(rename = "ergo-sigma-p2pk-threshold-2of3")]
    ErgoSigmaP2pkThreshold2of3,
}

impl SignerBackendRequirement {
    pub const ALL: [Self; 11] = [
        Self::FrostSecp256k1Tr,
        Self::FrostSecp256k1Kaspa,
        Self::CbMpcThresholdEcdsa,
        Self::IsolatedBip340,
        Self::IsolatedSecp256k1Ecdsa,
        Self::IsolatedBitcoinCashSchnorr,
        Self::ChiaBlsAug,
        Self::ChiaBlsAugThreshold2of3,
        Self::ErgoSigma,
        Self::ErgoSigmaP2pk,
        Self::ErgoSigmaP2pkThreshold2of3,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrostSecp256k1Tr => "frost-secp256k1-tr",
            Self::FrostSecp256k1Kaspa => "frost-secp256k1-kaspa",
            Self::CbMpcThresholdEcdsa => "cb-mpc-threshold-ecdsa",
            Self::IsolatedBip340 => "isolated-bip340",
            Self::IsolatedSecp256k1Ecdsa => "isolated-secp256k1-ecdsa",
            Self::IsolatedBitcoinCashSchnorr => "isolated-bitcoin-cash-schnorr",
            Self::ChiaBlsAug => "chia-bls-aug",
            Self::ChiaBlsAugThreshold2of3 => "chia-bls-aug-threshold-2of3",
            Self::ErgoSigma => "ergo-sigma",
            Self::ErgoSigmaP2pk => "ergo-sigma-p2pk",
            Self::ErgoSigmaP2pkThreshold2of3 => "ergo-sigma-p2pk-threshold-2of3",
        }
    }
}

impl SigningExecutionMode {
    pub const ALL: [Self; 4] = [
        Self::ThresholdInteractive,
        Self::ThresholdNonInteractive,
        Self::SingleSignerIsolated,
        Self::NativeChainCoordinator,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThresholdInteractive => "threshold-interactive",
            Self::ThresholdNonInteractive => "threshold-non-interactive",
            Self::SingleSignerIsolated => "single-signer-isolated",
            Self::NativeChainCoordinator => "native-chain-coordinator",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAvailability {
    #[serde(rename = "declaration-only")]
    DeclarationOnly,
    #[serde(rename = "executable")]
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningSuiteId {
    BitcoinBip340FrostV1,
    BitcoinBip340IsolatedV1,
    FractalBitcoinBip340FrostV1,
    BitcoinCashSchnorrIsolatedV1,
    BitcoinCashEcdsaIsolatedV1,
    BitcoinCashEcdsaCbMpcV1,
    BsvEcdsaIsolatedV1,
    BsvEcdsaCbMpcV1,
    KaspaSchnorrFrostV1,
    KaspaEcdsaIsolatedV1,
    KaspaEcdsaCbMpcV1,
    ChiaBls12381AugNativeV1,
    ChiaBls12381AugThreshold2of3V1,
    ErgoSigmaNativeV1,
    ErgoSigmaP2pkIsolatedV1,
    ErgoSigmaP2pkThreshold2of3V1,
}

impl SigningSuiteId {
    pub const BITCOIN_BIP340_FROST_V1: Self = Self::BitcoinBip340FrostV1;
    pub const BITCOIN_BIP340_ISOLATED_V1: Self = Self::BitcoinBip340IsolatedV1;
    pub const FRACTAL_BITCOIN_BIP340_FROST_V1: Self = Self::FractalBitcoinBip340FrostV1;
    pub const BITCOIN_CASH_SCHNORR_ISOLATED_V1: Self = Self::BitcoinCashSchnorrIsolatedV1;
    pub const BITCOIN_CASH_ECDSA_ISOLATED_V1: Self = Self::BitcoinCashEcdsaIsolatedV1;
    pub const BITCOIN_CASH_ECDSA_CB_MPC_V1: Self = Self::BitcoinCashEcdsaCbMpcV1;
    pub const BSV_ECDSA_ISOLATED_V1: Self = Self::BsvEcdsaIsolatedV1;
    pub const BSV_ECDSA_CB_MPC_V1: Self = Self::BsvEcdsaCbMpcV1;
    pub const KASPA_SCHNORR_FROST_V1: Self = Self::KaspaSchnorrFrostV1;
    pub const KASPA_ECDSA_ISOLATED_V1: Self = Self::KaspaEcdsaIsolatedV1;
    pub const KASPA_ECDSA_CB_MPC_V1: Self = Self::KaspaEcdsaCbMpcV1;
    pub const CHIA_BLS12381_AUG_NATIVE_V1: Self = Self::ChiaBls12381AugNativeV1;
    pub const CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1: Self = Self::ChiaBls12381AugThreshold2of3V1;
    pub const ERGO_SIGMA_NATIVE_V1: Self = Self::ErgoSigmaNativeV1;
    pub const ERGO_SIGMA_P2PK_ISOLATED_V1: Self = Self::ErgoSigmaP2pkIsolatedV1;
    pub const ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1: Self = Self::ErgoSigmaP2pkThreshold2of3V1;

    pub const ALL: [Self; 16] = [
        Self::BitcoinBip340FrostV1,
        Self::BitcoinBip340IsolatedV1,
        Self::FractalBitcoinBip340FrostV1,
        Self::BitcoinCashSchnorrIsolatedV1,
        Self::BitcoinCashEcdsaIsolatedV1,
        Self::BitcoinCashEcdsaCbMpcV1,
        Self::BsvEcdsaIsolatedV1,
        Self::BsvEcdsaCbMpcV1,
        Self::KaspaSchnorrFrostV1,
        Self::KaspaEcdsaIsolatedV1,
        Self::KaspaEcdsaCbMpcV1,
        Self::ChiaBls12381AugNativeV1,
        Self::ChiaBls12381AugThreshold2of3V1,
        Self::ErgoSigmaNativeV1,
        Self::ErgoSigmaP2pkIsolatedV1,
        Self::ErgoSigmaP2pkThreshold2of3V1,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinBip340FrostV1 => "btc.bip340.frost-secp256k1-tr.v1",
            Self::BitcoinBip340IsolatedV1 => "btc.bip340.isolated.v1",
            Self::FractalBitcoinBip340FrostV1 => "fractal-bitcoin.bip340.frost-secp256k1-tr.v1",
            Self::BitcoinCashSchnorrIsolatedV1 => "bch.schnorr.isolated.v1",
            Self::BitcoinCashEcdsaIsolatedV1 => "bch.ecdsa.isolated.v1",
            Self::BitcoinCashEcdsaCbMpcV1 => "bch.ecdsa.cb-mpc.v1",
            Self::BsvEcdsaIsolatedV1 => "bsv.ecdsa.isolated.v1",
            Self::BsvEcdsaCbMpcV1 => "bsv.ecdsa.cb-mpc.v1",
            Self::KaspaSchnorrFrostV1 => "kaspa.schnorr.frost-secp256k1.v1",
            Self::KaspaEcdsaIsolatedV1 => "kaspa.ecdsa.isolated.v1",
            Self::KaspaEcdsaCbMpcV1 => "kaspa.ecdsa.cb-mpc.v1",
            Self::ChiaBls12381AugNativeV1 => "chia.bls12-381.aug.native.v1",
            Self::ChiaBls12381AugThreshold2of3V1 => "chia.bls12-381.aug.threshold-2of3.v1",
            Self::ErgoSigmaNativeV1 => "ergo.sigma.native.v1",
            Self::ErgoSigmaP2pkIsolatedV1 => "ergo.sigma.p2pk.isolated.v1",
            Self::ErgoSigmaP2pkThreshold2of3V1 => "ergo.sigma.p2pk.threshold-2of3.v1",
        }
    }

    const fn chain_id(self) -> ChainId {
        match self {
            Self::BitcoinBip340FrostV1 | Self::BitcoinBip340IsolatedV1 => ChainId::Bitcoin,
            Self::FractalBitcoinBip340FrostV1 => ChainId::FractalBitcoin,
            Self::BitcoinCashSchnorrIsolatedV1
            | Self::BitcoinCashEcdsaIsolatedV1
            | Self::BitcoinCashEcdsaCbMpcV1 => ChainId::BitcoinCash,
            Self::BsvEcdsaIsolatedV1 | Self::BsvEcdsaCbMpcV1 => ChainId::Bsv,
            Self::KaspaSchnorrFrostV1 | Self::KaspaEcdsaIsolatedV1 | Self::KaspaEcdsaCbMpcV1 => {
                ChainId::Kaspa
            }
            Self::ChiaBls12381AugNativeV1 | Self::ChiaBls12381AugThreshold2of3V1 => ChainId::Chia,
            Self::ErgoSigmaNativeV1
            | Self::ErgoSigmaP2pkIsolatedV1
            | Self::ErgoSigmaP2pkThreshold2of3V1 => ChainId::Ergo,
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
    pub non_interactive_threshold: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSuiteDescriptor {
    pub schema_version: u16,
    pub id: SigningSuiteId,
    pub algorithm: SigningAlgorithm,
    pub execution_mode: SigningExecutionMode,
    pub backend_requirement: SignerBackendRequirement,
    pub capabilities: Capabilities,
    pub availability: SigningAvailability,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningSuiteDescriptorWire {
    schema_version: u16,
    id: SigningSuiteId,
    algorithm: SigningAlgorithm,
    execution_mode: SigningExecutionMode,
    backend_requirement: SignerBackendRequirement,
    capabilities: Capabilities,
    availability: SigningAvailability,
}

impl<'de> Deserialize<'de> for SigningSuiteDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SigningSuiteDescriptorWire::deserialize(deserializer)?;
        if wire.schema_version != 2 {
            return Err(de::Error::custom(
                SigningContractError::UnsupportedDescriptorSchemaVersion {
                    expected: 2,
                    actual: wire.schema_version,
                },
            ));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            id: wire.id,
            algorithm: wire.algorithm,
            execution_mode: wire.execution_mode,
            backend_requirement: wire.backend_requirement,
            capabilities: wire.capabilities,
            availability: wire.availability,
        })
    }
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

    const CONSENSUS_SINGLE_SIGNER: Capabilities = Capabilities {
        produces_consensus_signature: true,
        independently_verifiable: true,
        interactive_threshold: false,
        non_interactive_threshold: false,
    };
    const CONSENSUS_THRESHOLD: Capabilities = Capabilities {
        produces_consensus_signature: true,
        independently_verifiable: true,
        interactive_threshold: true,
        non_interactive_threshold: false,
    };
    const CONSENSUS_NON_INTERACTIVE_THRESHOLD: Capabilities = Capabilities {
        produces_consensus_signature: true,
        independently_verifiable: true,
        interactive_threshold: false,
        non_interactive_threshold: true,
    };
    const DECLARATION_ONLY: Capabilities = Capabilities {
        produces_consensus_signature: false,
        independently_verifiable: false,
        interactive_threshold: false,
        non_interactive_threshold: false,
    };

    let (algorithm, execution_mode, backend_requirement, capabilities) = match suite_id {
        SigningSuiteId::BitcoinBip340FrostV1 | SigningSuiteId::FractalBitcoinBip340FrostV1 => (
            SigningAlgorithm::Bip340TaprootSchnorr,
            SigningExecutionMode::ThresholdInteractive,
            SignerBackendRequirement::FrostSecp256k1Tr,
            CONSENSUS_THRESHOLD,
        ),
        SigningSuiteId::BitcoinBip340IsolatedV1 => (
            SigningAlgorithm::Bip340TaprootSchnorr,
            SigningExecutionMode::SingleSignerIsolated,
            SignerBackendRequirement::IsolatedBip340,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::BitcoinCashSchnorrIsolatedV1 => (
            SigningAlgorithm::BitcoinCashSchnorr,
            SigningExecutionMode::SingleSignerIsolated,
            SignerBackendRequirement::IsolatedBitcoinCashSchnorr,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::BitcoinCashEcdsaIsolatedV1 | SigningSuiteId::BsvEcdsaIsolatedV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::SingleSignerIsolated,
            SignerBackendRequirement::IsolatedSecp256k1Ecdsa,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::BitcoinCashEcdsaCbMpcV1 | SigningSuiteId::BsvEcdsaCbMpcV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::ThresholdInteractive,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
            CONSENSUS_THRESHOLD,
        ),
        SigningSuiteId::KaspaSchnorrFrostV1 => (
            SigningAlgorithm::Secp256k1Schnorr,
            SigningExecutionMode::ThresholdInteractive,
            SignerBackendRequirement::FrostSecp256k1Kaspa,
            CONSENSUS_THRESHOLD,
        ),
        SigningSuiteId::KaspaEcdsaIsolatedV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::SingleSignerIsolated,
            SignerBackendRequirement::IsolatedSecp256k1Ecdsa,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::KaspaEcdsaCbMpcV1 => (
            SigningAlgorithm::Secp256k1Ecdsa,
            SigningExecutionMode::ThresholdInteractive,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
            CONSENSUS_THRESHOLD,
        ),
        SigningSuiteId::ChiaBls12381AugNativeV1 => (
            SigningAlgorithm::Bls12381AugScheme,
            SigningExecutionMode::NativeChainCoordinator,
            SignerBackendRequirement::ChiaBlsAug,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::ChiaBls12381AugThreshold2of3V1 => (
            SigningAlgorithm::Bls12381AugScheme,
            SigningExecutionMode::ThresholdNonInteractive,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            CONSENSUS_NON_INTERACTIVE_THRESHOLD,
        ),
        SigningSuiteId::ErgoSigmaNativeV1 => (
            SigningAlgorithm::ErgoSigma,
            SigningExecutionMode::NativeChainCoordinator,
            SignerBackendRequirement::ErgoSigma,
            DECLARATION_ONLY,
        ),
        SigningSuiteId::ErgoSigmaP2pkIsolatedV1 => (
            SigningAlgorithm::ErgoSigma,
            SigningExecutionMode::SingleSignerIsolated,
            SignerBackendRequirement::ErgoSigmaP2pk,
            CONSENSUS_SINGLE_SIGNER,
        ),
        SigningSuiteId::ErgoSigmaP2pkThreshold2of3V1 => (
            SigningAlgorithm::ErgoSigma,
            SigningExecutionMode::ThresholdInteractive,
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
            CONSENSUS_THRESHOLD,
        ),
    };

    let availability = match suite_id {
        SigningSuiteId::BitcoinBip340FrostV1
        | SigningSuiteId::FractalBitcoinBip340FrostV1
        | SigningSuiteId::BitcoinCashEcdsaCbMpcV1
        | SigningSuiteId::BsvEcdsaCbMpcV1
        | SigningSuiteId::KaspaEcdsaCbMpcV1
        | SigningSuiteId::ChiaBls12381AugThreshold2of3V1
        | SigningSuiteId::ErgoSigmaP2pkIsolatedV1
        | SigningSuiteId::ErgoSigmaP2pkThreshold2of3V1 => SigningAvailability::Executable,
        SigningSuiteId::BitcoinBip340IsolatedV1
        | SigningSuiteId::BitcoinCashSchnorrIsolatedV1
        | SigningSuiteId::BitcoinCashEcdsaIsolatedV1
        | SigningSuiteId::BsvEcdsaIsolatedV1
        | SigningSuiteId::KaspaSchnorrFrostV1
        | SigningSuiteId::KaspaEcdsaIsolatedV1
        | SigningSuiteId::ChiaBls12381AugNativeV1
        | SigningSuiteId::ErgoSigmaNativeV1 => SigningAvailability::DeclarationOnly,
    };

    Ok(SigningSuiteDescriptor {
        schema_version: 2,
        id: suite_id,
        algorithm,
        execution_mode,
        backend_requirement,
        capabilities,
        availability,
    })
}

pub fn require_executable_suite(
    chain_scope: &ChainScope,
    suite_id: SigningSuiteId,
) -> Result<SigningSuiteDescriptor, SigningContractError> {
    let descriptor = resolve_builtin_suite(chain_scope, suite_id)?;
    if descriptor.availability != SigningAvailability::Executable {
        return Err(SigningContractError::SuiteNotExecutable { suite_id });
    }
    Ok(descriptor)
}
