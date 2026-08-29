use catomicals_chain_domain::KaspaNetwork;
use kaspa_addresses::{Address, Prefix, Version};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    PubKeyXOnly,
    PubKeyEcdsa,
    ScriptHash,
}

impl AddressKind {
    const fn payload_len(self) -> usize {
        match self {
            Self::PubKeyXOnly | Self::ScriptHash => 32,
            Self::PubKeyEcdsa => 33,
        }
    }

    const fn version(self) -> Version {
        match self {
            Self::PubKeyXOnly => Version::PubKey,
            Self::PubKeyEcdsa => Version::PubKeyECDSA,
            Self::ScriptHash => Version::ScriptHash,
        }
    }
}

impl From<Version> for AddressKind {
    fn from(version: Version) -> Self {
        match version {
            Version::PubKey => Self::PubKeyXOnly,
            Version::PubKeyECDSA => Self::PubKeyEcdsa,
            Version::ScriptHash => Self::ScriptHash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KaspaAddress {
    network: KaspaNetwork,
    kind: AddressKind,
    payload: Vec<u8>,
    encoded: String,
}

impl KaspaAddress {
    pub const fn network(&self) -> KaspaNetwork {
        self.network
    }

    pub const fn kind(&self) -> AddressKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KaspaAdapterError {
    #[error("invalid {kind:?} payload length {actual}; expected {expected}")]
    InvalidPayloadLength {
        kind: AddressKind,
        expected: usize,
        actual: usize,
    },
    #[error("invalid Kaspa address: {0}")]
    InvalidAddress(String),
    #[error("address prefix `{actual}` does not match network {network:?} (`{expected}`)")]
    WrongNetworkPrefix {
        network: KaspaNetwork,
        expected: &'static str,
        actual: String,
    },
    #[error("derivation index `{field}` must be below 2^31; got {value}")]
    InvalidDerivationIndex { field: &'static str, value: u32 },
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid Kaspa review material: {0}")]
    InvalidReviewMaterial(String),
    #[error("review material has {entries} UTXOs for {inputs} transaction inputs")]
    MismatchedUtxoCount { inputs: usize, entries: usize },
    #[error("input index {input_index} is outside {inputs} transaction inputs")]
    InvalidInputIndex { input_index: usize, inputs: usize },
    #[error("review material exceeds {max_bytes} bytes")]
    ReviewMaterialTooLarge { max_bytes: usize },
}

pub fn encode_address(
    network: KaspaNetwork,
    kind: AddressKind,
    payload: &[u8],
) -> Result<String, KaspaAdapterError> {
    validate_payload(kind, payload)?;
    Ok(Address::new(prefix(network), kind.version(), payload).to_string())
}

pub fn parse_address(
    network: KaspaNetwork,
    encoded: &str,
) -> Result<KaspaAddress, KaspaAdapterError> {
    let address = Address::try_from(encoded)
        .map_err(|error| KaspaAdapterError::InvalidAddress(error.to_string()))?;
    let expected = prefix(network);
    if address.prefix != expected {
        return Err(KaspaAdapterError::WrongNetworkPrefix {
            network,
            expected: prefix_name(expected),
            actual: address.prefix.to_string(),
        });
    }

    let kind = AddressKind::from(address.version);
    validate_payload(kind, address.payload.as_slice())?;
    Ok(KaspaAddress {
        network,
        kind,
        payload: address.payload.to_vec(),
        encoded: address.to_string(),
    })
}

fn validate_payload(kind: AddressKind, payload: &[u8]) -> Result<(), KaspaAdapterError> {
    let expected = kind.payload_len();
    if payload.len() != expected {
        return Err(KaspaAdapterError::InvalidPayloadLength {
            kind,
            expected,
            actual: payload.len(),
        });
    }
    Ok(())
}

const fn prefix(network: KaspaNetwork) -> Prefix {
    match network {
        KaspaNetwork::Mainnet => Prefix::Mainnet,
        KaspaNetwork::Testnet10 | KaspaNetwork::Testnet11 => Prefix::Testnet,
        KaspaNetwork::Simnet => Prefix::Simnet,
        KaspaNetwork::Devnet => Prefix::Devnet,
    }
}

const fn prefix_name(prefix: Prefix) -> &'static str {
    match prefix {
        Prefix::Mainnet => "kaspa",
        Prefix::Testnet => "kaspatest",
        Prefix::Simnet => "kaspasim",
        Prefix::Devnet => "kaspadev",
    }
}
