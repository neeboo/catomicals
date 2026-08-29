use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const CHAIN_SCOPE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainDomainError {
    #[error("unsupported chain id `{0}`")]
    UnsupportedChainId(String),
    #[error("unsupported concrete chain network `{0}`")]
    UnsupportedChainNetwork(String),
    #[error("unsupported RPC preset id `{0}`")]
    UnsupportedRpcPresetId(String),
    #[error("unsupported {contract} schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        contract: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("network `{network}` belongs to `{actual}`, not `{declared}`")]
    MismatchedChainNetwork {
        declared: ChainId,
        actual: ChainId,
        network: ChainNetwork,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainId {
    Bitcoin,
    BitcoinCash,
    Bsv,
    FractalBitcoin,
    Kaspa,
    Chia,
    Ergo,
}

impl ChainId {
    pub const ALL: [Self; 7] = [
        Self::Bitcoin,
        Self::BitcoinCash,
        Self::Bsv,
        Self::FractalBitcoin,
        Self::Kaspa,
        Self::Chia,
        Self::Ergo,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::BitcoinCash => "bitcoin-cash",
            Self::Bsv => "bsv",
            Self::FractalBitcoin => "fractal-bitcoin",
            Self::Kaspa => "kaspa",
            Self::Chia => "chia",
            Self::Ergo => "ergo",
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ChainId {
    type Err = ChainDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "bitcoin" => Ok(Self::Bitcoin),
            "bitcoin-cash" => Ok(Self::BitcoinCash),
            "bsv" => Ok(Self::Bsv),
            "fractal-bitcoin" => Ok(Self::FractalBitcoin),
            "kaspa" => Ok(Self::Kaspa),
            "chia" => Ok(Self::Chia),
            "ergo" => Ok(Self::Ergo),
            _ => Err(ChainDomainError::UnsupportedChainId(value.to_owned())),
        }
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinCashNetwork {
    Mainnet,
    Testnet3,
    Testnet4,
    Chipnet,
    Scalenet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BsvNetwork {
    Mainnet,
    Testnet,
    Stn,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FractalBitcoinNetwork {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KaspaNetwork {
    Mainnet,
    Testnet10,
    Testnet11,
    Simnet,
    Devnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChiaNetwork {
    Mainnet,
    Testnet11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErgoNetwork {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainNetwork {
    Bitcoin(BitcoinNetwork),
    BitcoinCash(BitcoinCashNetwork),
    Bsv(BsvNetwork),
    FractalBitcoin(FractalBitcoinNetwork),
    Kaspa(KaspaNetwork),
    Chia(ChiaNetwork),
    Ergo(ErgoNetwork),
}

impl ChainNetwork {
    pub const ALL: [Self; 29] = [
        Self::Bitcoin(BitcoinNetwork::Mainnet),
        Self::Bitcoin(BitcoinNetwork::Testnet3),
        Self::Bitcoin(BitcoinNetwork::Testnet4),
        Self::Bitcoin(BitcoinNetwork::Signet),
        Self::Bitcoin(BitcoinNetwork::Regtest),
        Self::BitcoinCash(BitcoinCashNetwork::Mainnet),
        Self::BitcoinCash(BitcoinCashNetwork::Testnet3),
        Self::BitcoinCash(BitcoinCashNetwork::Testnet4),
        Self::BitcoinCash(BitcoinCashNetwork::Chipnet),
        Self::BitcoinCash(BitcoinCashNetwork::Scalenet),
        Self::BitcoinCash(BitcoinCashNetwork::Regtest),
        Self::Bsv(BsvNetwork::Mainnet),
        Self::Bsv(BsvNetwork::Testnet),
        Self::Bsv(BsvNetwork::Stn),
        Self::Bsv(BsvNetwork::Regtest),
        Self::FractalBitcoin(FractalBitcoinNetwork::Mainnet),
        Self::FractalBitcoin(FractalBitcoinNetwork::Testnet3),
        Self::FractalBitcoin(FractalBitcoinNetwork::Testnet4),
        Self::FractalBitcoin(FractalBitcoinNetwork::Signet),
        Self::FractalBitcoin(FractalBitcoinNetwork::Regtest),
        Self::Kaspa(KaspaNetwork::Mainnet),
        Self::Kaspa(KaspaNetwork::Testnet10),
        Self::Kaspa(KaspaNetwork::Testnet11),
        Self::Kaspa(KaspaNetwork::Simnet),
        Self::Kaspa(KaspaNetwork::Devnet),
        Self::Chia(ChiaNetwork::Mainnet),
        Self::Chia(ChiaNetwork::Testnet11),
        Self::Ergo(ErgoNetwork::Mainnet),
        Self::Ergo(ErgoNetwork::Testnet),
    ];

    pub const fn chain_id(self) -> ChainId {
        match self {
            Self::Bitcoin(_) => ChainId::Bitcoin,
            Self::BitcoinCash(_) => ChainId::BitcoinCash,
            Self::Bsv(_) => ChainId::Bsv,
            Self::FractalBitcoin(_) => ChainId::FractalBitcoin,
            Self::Kaspa(_) => ChainId::Kaspa,
            Self::Chia(_) => ChainId::Chia,
            Self::Ergo(_) => ChainId::Ergo,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bitcoin(BitcoinNetwork::Mainnet) => "bitcoin.mainnet",
            Self::Bitcoin(BitcoinNetwork::Testnet3) => "bitcoin.testnet3",
            Self::Bitcoin(BitcoinNetwork::Testnet4) => "bitcoin.testnet4",
            Self::Bitcoin(BitcoinNetwork::Signet) => "bitcoin.signet",
            Self::Bitcoin(BitcoinNetwork::Regtest) => "bitcoin.regtest",
            Self::BitcoinCash(BitcoinCashNetwork::Mainnet) => "bitcoin-cash.mainnet",
            Self::BitcoinCash(BitcoinCashNetwork::Testnet3) => "bitcoin-cash.testnet3",
            Self::BitcoinCash(BitcoinCashNetwork::Testnet4) => "bitcoin-cash.testnet4",
            Self::BitcoinCash(BitcoinCashNetwork::Chipnet) => "bitcoin-cash.chipnet",
            Self::BitcoinCash(BitcoinCashNetwork::Scalenet) => "bitcoin-cash.scalenet",
            Self::BitcoinCash(BitcoinCashNetwork::Regtest) => "bitcoin-cash.regtest",
            Self::Bsv(BsvNetwork::Mainnet) => "bsv.mainnet",
            Self::Bsv(BsvNetwork::Testnet) => "bsv.testnet",
            Self::Bsv(BsvNetwork::Stn) => "bsv.stn",
            Self::Bsv(BsvNetwork::Regtest) => "bsv.regtest",
            Self::FractalBitcoin(FractalBitcoinNetwork::Mainnet) => "fractal-bitcoin.mainnet",
            Self::FractalBitcoin(FractalBitcoinNetwork::Testnet3) => "fractal-bitcoin.testnet3",
            Self::FractalBitcoin(FractalBitcoinNetwork::Testnet4) => "fractal-bitcoin.testnet4",
            Self::FractalBitcoin(FractalBitcoinNetwork::Signet) => "fractal-bitcoin.signet",
            Self::FractalBitcoin(FractalBitcoinNetwork::Regtest) => "fractal-bitcoin.regtest",
            Self::Kaspa(KaspaNetwork::Mainnet) => "kaspa.mainnet",
            Self::Kaspa(KaspaNetwork::Testnet10) => "kaspa.testnet10",
            Self::Kaspa(KaspaNetwork::Testnet11) => "kaspa.testnet11",
            Self::Kaspa(KaspaNetwork::Simnet) => "kaspa.simnet",
            Self::Kaspa(KaspaNetwork::Devnet) => "kaspa.devnet",
            Self::Chia(ChiaNetwork::Mainnet) => "chia.mainnet",
            Self::Chia(ChiaNetwork::Testnet11) => "chia.testnet11",
            Self::Ergo(ErgoNetwork::Mainnet) => "ergo.mainnet",
            Self::Ergo(ErgoNetwork::Testnet) => "ergo.testnet",
        }
    }
}

impl fmt::Display for ChainNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ChainNetwork {
    type Err = ChainDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|network| network.as_str() == value)
            .ok_or_else(|| ChainDomainError::UnsupportedChainNetwork(value.to_owned()))
    }
}

impl Serialize for ChainNetwork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChainNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainScope {
    pub schema_version: u16,
    pub chain: ChainId,
    pub network: ChainNetwork,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainScopeWire {
    schema_version: u16,
    chain: ChainId,
    network: ChainNetwork,
}

impl<'de> Deserialize<'de> for ChainScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ChainScopeWire::deserialize(deserializer)?;
        if wire.schema_version != CHAIN_SCOPE_SCHEMA_VERSION {
            return Err(de::Error::custom(
                ChainDomainError::UnsupportedSchemaVersion {
                    contract: "chain scope",
                    expected: CHAIN_SCOPE_SCHEMA_VERSION,
                    actual: wire.schema_version,
                },
            ));
        }
        Self::new(wire.chain, wire.network).map_err(de::Error::custom)
    }
}

impl ChainScope {
    pub fn new(chain: ChainId, network: ChainNetwork) -> Result<Self, ChainDomainError> {
        let actual = network.chain_id();
        if chain != actual {
            return Err(ChainDomainError::MismatchedChainNetwork {
                declared: chain,
                actual,
                network,
            });
        }
        Ok(Self {
            schema_version: CHAIN_SCOPE_SCHEMA_VERSION,
            chain,
            network,
        })
    }

    pub const fn for_network(network: ChainNetwork) -> Self {
        Self {
            schema_version: CHAIN_SCOPE_SCHEMA_VERSION,
            chain: network.chain_id(),
            network,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpcPresetId {
    BitcoinInquisition,
    BitcoinMainnet,
    BitcoinTestnet3,
    BitcoinTestnet4,
    BitcoinSignet,
    BitcoinRegtest,
    FractalBitcoinMainnet,
    FractalBitcoinTestnet3,
    FractalBitcoinTestnet4,
    FractalBitcoinSignet,
    FractalBitcoinRegtest,
    BitcoinCashMainnet,
    BitcoinCashTestnet3,
    BitcoinCashTestnet4,
    BitcoinCashChipnet,
    BitcoinCashScalenet,
    BitcoinCashRegtest,
    BsvMainnet,
    BsvTestnet,
    BsvStn,
    BsvRegtest,
    KaspaMainnet,
    KaspaTestnet10,
    KaspaTestnet11,
    KaspaSimnet,
    KaspaDevnet,
    ChiaMainnet,
    ChiaTestnet11,
    ErgoMainnet,
    ErgoTestnet,
}

impl RpcPresetId {
    pub const ALL: [Self; 30] = [
        Self::BitcoinInquisition,
        Self::BitcoinMainnet,
        Self::BitcoinTestnet3,
        Self::BitcoinTestnet4,
        Self::BitcoinSignet,
        Self::BitcoinRegtest,
        Self::FractalBitcoinMainnet,
        Self::FractalBitcoinTestnet3,
        Self::FractalBitcoinTestnet4,
        Self::FractalBitcoinSignet,
        Self::FractalBitcoinRegtest,
        Self::BitcoinCashMainnet,
        Self::BitcoinCashTestnet3,
        Self::BitcoinCashTestnet4,
        Self::BitcoinCashChipnet,
        Self::BitcoinCashScalenet,
        Self::BitcoinCashRegtest,
        Self::BsvMainnet,
        Self::BsvTestnet,
        Self::BsvStn,
        Self::BsvRegtest,
        Self::KaspaMainnet,
        Self::KaspaTestnet10,
        Self::KaspaTestnet11,
        Self::KaspaSimnet,
        Self::KaspaDevnet,
        Self::ChiaMainnet,
        Self::ChiaTestnet11,
        Self::ErgoMainnet,
        Self::ErgoTestnet,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinInquisition => "bitcoin-inquisition",
            Self::BitcoinMainnet => "bitcoin-mainnet",
            Self::BitcoinTestnet3 => "bitcoin-testnet3",
            Self::BitcoinTestnet4 => "bitcoin-testnet4",
            Self::BitcoinSignet => "bitcoin-signet",
            Self::BitcoinRegtest => "bitcoin-regtest",
            Self::FractalBitcoinMainnet => "fractal-bitcoin-mainnet",
            Self::FractalBitcoinTestnet3 => "fractal-bitcoin-testnet3",
            Self::FractalBitcoinTestnet4 => "fractal-bitcoin-testnet4",
            Self::FractalBitcoinSignet => "fractal-bitcoin-signet",
            Self::FractalBitcoinRegtest => "fractal-bitcoin-regtest",
            Self::BitcoinCashMainnet => "bitcoin-cash-mainnet",
            Self::BitcoinCashTestnet3 => "bitcoin-cash-testnet3",
            Self::BitcoinCashTestnet4 => "bitcoin-cash-testnet4",
            Self::BitcoinCashChipnet => "bitcoin-cash-chipnet",
            Self::BitcoinCashScalenet => "bitcoin-cash-scalenet",
            Self::BitcoinCashRegtest => "bitcoin-cash-regtest",
            Self::BsvMainnet => "bsv-mainnet",
            Self::BsvTestnet => "bsv-testnet",
            Self::BsvStn => "bsv-stn",
            Self::BsvRegtest => "bsv-regtest",
            Self::KaspaMainnet => "kaspa-mainnet",
            Self::KaspaTestnet10 => "kaspa-testnet-10",
            Self::KaspaTestnet11 => "kaspa-testnet-11",
            Self::KaspaSimnet => "kaspa-simnet",
            Self::KaspaDevnet => "kaspa-devnet",
            Self::ChiaMainnet => "chia-mainnet",
            Self::ChiaTestnet11 => "chia-testnet11",
            Self::ErgoMainnet => "ergo-mainnet",
            Self::ErgoTestnet => "ergo-testnet",
        }
    }

    pub const fn chain_network(self) -> ChainNetwork {
        match self {
            Self::BitcoinInquisition | Self::BitcoinSignet => {
                ChainNetwork::Bitcoin(BitcoinNetwork::Signet)
            }
            Self::BitcoinMainnet => ChainNetwork::Bitcoin(BitcoinNetwork::Mainnet),
            Self::BitcoinTestnet3 => ChainNetwork::Bitcoin(BitcoinNetwork::Testnet3),
            Self::BitcoinTestnet4 => ChainNetwork::Bitcoin(BitcoinNetwork::Testnet4),
            Self::BitcoinRegtest => ChainNetwork::Bitcoin(BitcoinNetwork::Regtest),
            Self::FractalBitcoinMainnet => {
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Mainnet)
            }
            Self::FractalBitcoinTestnet3 => {
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet3)
            }
            Self::FractalBitcoinTestnet4 => {
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Testnet4)
            }
            Self::FractalBitcoinSignet => {
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet)
            }
            Self::FractalBitcoinRegtest => {
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Regtest)
            }
            Self::BitcoinCashMainnet => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Mainnet),
            Self::BitcoinCashTestnet3 => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Testnet3),
            Self::BitcoinCashTestnet4 => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Testnet4),
            Self::BitcoinCashChipnet => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
            Self::BitcoinCashScalenet => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Scalenet),
            Self::BitcoinCashRegtest => ChainNetwork::BitcoinCash(BitcoinCashNetwork::Regtest),
            Self::BsvMainnet => ChainNetwork::Bsv(BsvNetwork::Mainnet),
            Self::BsvTestnet => ChainNetwork::Bsv(BsvNetwork::Testnet),
            Self::BsvStn => ChainNetwork::Bsv(BsvNetwork::Stn),
            Self::BsvRegtest => ChainNetwork::Bsv(BsvNetwork::Regtest),
            Self::KaspaMainnet => ChainNetwork::Kaspa(KaspaNetwork::Mainnet),
            Self::KaspaTestnet10 => ChainNetwork::Kaspa(KaspaNetwork::Testnet10),
            Self::KaspaTestnet11 => ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
            Self::KaspaSimnet => ChainNetwork::Kaspa(KaspaNetwork::Simnet),
            Self::KaspaDevnet => ChainNetwork::Kaspa(KaspaNetwork::Devnet),
            Self::ChiaMainnet => ChainNetwork::Chia(ChiaNetwork::Mainnet),
            Self::ChiaTestnet11 => ChainNetwork::Chia(ChiaNetwork::Testnet11),
            Self::ErgoMainnet => ChainNetwork::Ergo(ErgoNetwork::Mainnet),
            Self::ErgoTestnet => ChainNetwork::Ergo(ErgoNetwork::Testnet),
        }
    }

    pub const fn chain_id(self) -> ChainId {
        self.chain_network().chain_id()
    }
}

impl fmt::Display for RpcPresetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RpcPresetId {
    type Err = ChainDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.as_str() == value)
            .ok_or_else(|| ChainDomainError::UnsupportedRpcPresetId(value.to_owned()))
    }
}

impl Serialize for RpcPresetId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RpcPresetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}
