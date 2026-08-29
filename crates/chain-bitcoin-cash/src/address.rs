use catomicals_chain_domain::BitcoinCashNetwork;
use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::Error;

const CASHADDR_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
}

/// Network identity that is actually encoded by CashAddr or legacy Base58.
///
/// BCH testnet3, testnet4, chipnet, and scalenet intentionally share the
/// `bchtest` prefix and legacy version bytes, so an address cannot identify
/// one member of that family by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressNetwork {
    Mainnet,
    TestFamily,
    Regtest,
    LegacyNonMainnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub network: AddressNetwork,
    pub kind: AddressKind,
    pub hash: [u8; 20],
}

impl Address {
    pub const fn new(network: BitcoinCashNetwork, kind: AddressKind, hash: [u8; 20]) -> Self {
        Self {
            network: address_network(network),
            kind,
            hash,
        }
    }

    pub fn p2pkh_from_public_key(
        network: BitcoinCashNetwork,
        public_key: &[u8],
    ) -> Result<Self, Error> {
        PublicKey::from_slice(public_key).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self::new(network, AddressKind::P2pkh, hash160(public_key)))
    }

    pub fn p2sh_from_redeem_script(network: BitcoinCashNetwork, redeem_script: &[u8]) -> Self {
        Self::new(network, AddressKind::P2sh, hash160(redeem_script))
    }

    /// Requires an address to carry a unique identity for the requested network.
    ///
    /// Test-family addresses fail closed because their wire representation does
    /// not distinguish testnet3, testnet4, chipnet, or scalenet.
    pub fn require_exact_network(self, expected: BitcoinCashNetwork) -> Result<Self, Error> {
        match (self.network, address_network(expected)) {
            (AddressNetwork::TestFamily, AddressNetwork::TestFamily)
            | (AddressNetwork::LegacyNonMainnet, _) => Err(Error::AmbiguousAddressNetwork),
            (actual, expected) if actual == expected => Ok(self),
            (actual, _) => Err(Error::WrongNetwork {
                expected,
                actual: address_network_name(actual),
            }),
        }
    }

    pub fn to_cashaddr(self) -> Result<String, Error> {
        let prefix = cashaddr_prefix(self.network).ok_or(Error::AmbiguousAddressNetwork)?;
        let version = match self.kind {
            AddressKind::P2pkh => 0,
            AddressKind::P2sh => 8,
        };
        let mut bytes = Vec::with_capacity(21);
        bytes.push(version);
        bytes.extend_from_slice(&self.hash);
        let mut payload = convert_bits(&bytes, 8, 5, true).expect("fixed payload is valid");
        let mut checksum_input = prefix_expand(prefix);
        checksum_input.extend_from_slice(&payload);
        checksum_input.extend_from_slice(&[0; 8]);
        let checksum = polymod(&checksum_input);
        payload.extend((0..8).map(|shift| ((checksum >> (5 * (7 - shift))) & 31) as u8));

        let encoded: String = payload
            .into_iter()
            .map(|value| char::from(CASHADDR_CHARSET[usize::from(value)]))
            .collect();
        Ok(format!("{prefix}:{encoded}"))
    }

    pub fn parse_cashaddr(
        expected_network: BitcoinCashNetwork,
        encoded: &str,
    ) -> Result<Self, Error> {
        let has_lower = encoded.bytes().any(|byte| byte.is_ascii_lowercase());
        let has_upper = encoded.bytes().any(|byte| byte.is_ascii_uppercase());
        if has_lower && has_upper {
            return Err(Error::MixedCaseAddress);
        }
        if !encoded.is_ascii() {
            return Err(Error::InvalidAddressEncoding);
        }

        let normalized = encoded.to_ascii_lowercase();
        let (prefix, payload_text) = match normalized.split_once(':') {
            Some((prefix, payload)) if !payload.contains(':') => (prefix, payload),
            Some(_) => return Err(Error::InvalidAddressEncoding),
            None => (
                cashaddr_prefix(address_network(expected_network))
                    .ok_or(Error::InvalidAddressEncoding)?,
                normalized.as_str(),
            ),
        };
        if prefix.is_empty() || payload_text.len() < 8 {
            return Err(Error::InvalidAddressEncoding);
        }
        let network = require_cashaddr_network(expected_network, prefix)?;

        let payload = payload_text
            .bytes()
            .map(|byte| {
                CASHADDR_CHARSET
                    .iter()
                    .position(|candidate| *candidate == byte)
                    .map(|index| index as u8)
                    .ok_or(Error::InvalidAddressEncoding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut checksum_input = prefix_expand(prefix);
        checksum_input.extend_from_slice(&payload);
        if polymod(&checksum_input) != 0 {
            return Err(Error::InvalidChecksum);
        }

        let data = convert_bits(&payload[..payload.len() - 8], 5, 8, false)?;
        if data.len() != 21 {
            return Err(Error::InvalidAddressPayload);
        }
        let kind = match data[0] {
            0 => AddressKind::P2pkh,
            8 => AddressKind::P2sh,
            _ => return Err(Error::InvalidAddressPayload),
        };
        let hash = data[1..]
            .try_into()
            .map_err(|_| Error::InvalidAddressPayload)?;
        Ok(Self {
            network,
            kind,
            hash,
        })
    }

    pub fn to_legacy(self) -> String {
        let version = legacy_version(self.network, self.kind);
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(&self.hash);
        bs58::encode(payload).with_check().into_string()
    }

    pub fn parse_legacy(
        expected_network: BitcoinCashNetwork,
        encoded: &str,
    ) -> Result<Self, Error> {
        let payload =
            bs58::decode(encoded)
                .with_check(None)
                .into_vec()
                .map_err(|error| match error {
                    bs58::decode::Error::InvalidChecksum { .. } => Error::InvalidChecksum,
                    _ => Error::InvalidAddressEncoding,
                })?;
        if payload.len() != 21 {
            return Err(Error::InvalidAddressPayload);
        }
        let (kind, network) = match payload[0] {
            0 => (AddressKind::P2pkh, AddressNetwork::Mainnet),
            5 => (AddressKind::P2sh, AddressNetwork::Mainnet),
            111 => (AddressKind::P2pkh, AddressNetwork::LegacyNonMainnet),
            196 => (AddressKind::P2sh, AddressNetwork::LegacyNonMainnet),
            _ => return Err(Error::InvalidAddressPayload),
        };
        let expected_address_network = address_network(expected_network);
        let compatible = network == expected_address_network
            || (network == AddressNetwork::LegacyNonMainnet
                && expected_address_network != AddressNetwork::Mainnet);
        if !compatible {
            return Err(Error::WrongNetwork {
                expected: expected_network,
                actual: address_network_name(network),
            });
        }
        let hash = payload[1..]
            .try_into()
            .map_err(|_| Error::InvalidAddressPayload)?;
        Ok(Self {
            network,
            kind,
            hash,
        })
    }
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(bytes)).into()
}

const fn address_network(network: BitcoinCashNetwork) -> AddressNetwork {
    match network {
        BitcoinCashNetwork::Mainnet => AddressNetwork::Mainnet,
        BitcoinCashNetwork::Regtest => AddressNetwork::Regtest,
        BitcoinCashNetwork::Testnet3
        | BitcoinCashNetwork::Testnet4
        | BitcoinCashNetwork::Scalenet
        | BitcoinCashNetwork::Chipnet => AddressNetwork::TestFamily,
    }
}

const fn cashaddr_prefix(network: AddressNetwork) -> Option<&'static str> {
    match network {
        AddressNetwork::Mainnet => Some("bitcoincash"),
        AddressNetwork::TestFamily => Some("bchtest"),
        AddressNetwork::Regtest => Some("bchreg"),
        AddressNetwork::LegacyNonMainnet => None,
    }
}

fn require_cashaddr_network(
    expected_network: BitcoinCashNetwork,
    actual_prefix: &str,
) -> Result<AddressNetwork, Error> {
    let actual_network = match actual_prefix {
        "bitcoincash" => AddressNetwork::Mainnet,
        "bchtest" => AddressNetwork::TestFamily,
        "bchreg" => AddressNetwork::Regtest,
        _ => {
            return Err(Error::WrongNetwork {
                expected: expected_network,
                actual: "unknown",
            });
        }
    };
    if actual_network == address_network(expected_network) {
        return Ok(actual_network);
    }
    Err(Error::WrongNetwork {
        expected: expected_network,
        actual: address_network_name(actual_network),
    })
}

const fn address_network_name(network: AddressNetwork) -> &'static str {
    match network {
        AddressNetwork::Mainnet => "mainnet",
        AddressNetwork::TestFamily => "test-family",
        AddressNetwork::Regtest => "regtest",
        AddressNetwork::LegacyNonMainnet => "legacy non-mainnet family",
    }
}

const fn legacy_version(network: AddressNetwork, kind: AddressKind) -> u8 {
    match (network, kind) {
        (AddressNetwork::Mainnet, AddressKind::P2pkh) => 0,
        (AddressNetwork::Mainnet, AddressKind::P2sh) => 5,
        (AddressNetwork::TestFamily, AddressKind::P2pkh) => 111,
        (AddressNetwork::TestFamily, AddressKind::P2sh) => 196,
        (AddressNetwork::Regtest, AddressKind::P2pkh) => 111,
        (AddressNetwork::Regtest, AddressKind::P2sh) => 196,
        (AddressNetwork::LegacyNonMainnet, AddressKind::P2pkh) => 111,
        (AddressNetwork::LegacyNonMainnet, AddressKind::P2sh) => 196,
    }
}

fn prefix_expand(prefix: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(prefix.len() + 1);
    expanded.extend(prefix.bytes().map(|byte| byte & 31));
    expanded.push(0);
    expanded
}

fn polymod(values: &[u8]) -> u64 {
    const GENERATORS: [u64; 5] = [
        0x98f2_bc8e61,
        0x79b7_6d99e2,
        0xf33e_5fb3c4,
        0xae2e_abe2a8,
        0x1e4f_43e470,
    ];
    let mut checksum = 1_u64;
    for value in values {
        let high = checksum >> 35;
        checksum = ((checksum & 0x0007_ffff_ffff) << 5) ^ u64::from(*value);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if (high >> bit) & 1 != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum ^ 1
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Error> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let max_value = (1_u32 << to) - 1;
    let max_accumulator = (1_u32 << (from + to - 1)) - 1;
    let mut result = Vec::new();

    for value in data {
        if u32::from(*value) >> from != 0 {
            return Err(Error::InvalidAddressPayload);
        }
        accumulator = ((accumulator << from) | u32::from(*value)) & max_accumulator;
        bits += from;
        while bits >= to {
            bits -= to;
            result.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits != 0 {
            result.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return Err(Error::InvalidAddressPayload);
    }
    Ok(result)
}
