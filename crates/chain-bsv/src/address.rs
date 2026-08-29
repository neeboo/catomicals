use std::fmt;

use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::{BsvError, BsvNetwork};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2pkh,
    P2sh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressNetworkResolution {
    Exact(BsvNetwork),
    Ambiguous {
        compatible_networks: [BsvNetwork; 3],
    },
}

const TEST_FAMILY_NETWORKS: [BsvNetwork; 3] =
    [BsvNetwork::Testnet, BsvNetwork::Stn, BsvNetwork::Regtest];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    network: BsvNetwork,
    address_type: AddressType,
    payload: [u8; 20],
}

impl Address {
    pub fn from_payload(
        network: BsvNetwork,
        address_type: AddressType,
        payload: &[u8],
    ) -> Result<Self, BsvError> {
        let payload = payload
            .try_into()
            .map_err(|_| BsvError::InvalidAddressPayload)?;
        Ok(Self {
            network,
            address_type,
            payload,
        })
    }

    pub fn p2pkh_from_public_key(network: BsvNetwork, public_key: &[u8]) -> Result<Self, BsvError> {
        let public_key =
            PublicKey::from_slice(public_key).map_err(|_| BsvError::InvalidPublicKey)?;
        Self::from_payload(
            network,
            AddressType::P2pkh,
            &hash160(&public_key.serialize()),
        )
    }

    pub fn p2sh_from_redeem_script(
        network: BsvNetwork,
        redeem_script: &[u8],
    ) -> Result<Self, BsvError> {
        Self::from_payload(network, AddressType::P2sh, &hash160(redeem_script))
    }

    pub fn parse_for_network(value: &str, network: BsvNetwork) -> Result<Self, BsvError> {
        let decoded = decode_address(value)?;
        let address_type = address_type(decoded[0]).ok_or(BsvError::WrongAddressNetwork {
            network,
            version: decoded[0],
        })?;
        match (Self::resolve_network(value)?, network_class(network)) {
            (AddressNetworkResolution::Exact(BsvNetwork::Mainnet), NetworkClass::Mainnet) => {}
            (AddressNetworkResolution::Ambiguous { .. }, NetworkClass::TestFamily) => {
                return Err(BsvError::AmbiguousAddressNetwork {
                    requested: network,
                    compatible_networks: TEST_FAMILY_NETWORKS,
                });
            }
            _ => {
                return Err(BsvError::WrongAddressNetwork {
                    network,
                    version: decoded[0],
                });
            }
        }
        Self::from_payload(network, address_type, &decoded[1..])
    }

    pub fn resolve_network(value: &str) -> Result<AddressNetworkResolution, BsvError> {
        let decoded = decode_address(value)?;
        match decoded[0] {
            0 | 5 => Ok(AddressNetworkResolution::Exact(BsvNetwork::Mainnet)),
            111 | 196 => Ok(AddressNetworkResolution::Ambiguous {
                compatible_networks: TEST_FAMILY_NETWORKS,
            }),
            version => Err(BsvError::InvalidAddress(format!(
                "unsupported Base58Check version {version:#04x}"
            ))),
        }
    }

    pub const fn network(&self) -> BsvNetwork {
        self.network
    }

    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }

    pub const fn payload(&self) -> &[u8; 20] {
        &self.payload
    }

    fn version(&self) -> u8 {
        match (network_class(self.network), self.address_type) {
            (NetworkClass::Mainnet, AddressType::P2pkh) => 0,
            (NetworkClass::Mainnet, AddressType::P2sh) => 5,
            (NetworkClass::TestFamily, AddressType::P2pkh) => 111,
            (NetworkClass::TestFamily, AddressType::P2sh) => 196,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(21);
        bytes.push(self.version());
        bytes.extend_from_slice(&self.payload);
        formatter.write_str(&bs58::encode(bytes).with_check().into_string())
    }
}

#[derive(Clone, Copy)]
enum NetworkClass {
    Mainnet,
    TestFamily,
}

const fn network_class(network: BsvNetwork) -> NetworkClass {
    match network {
        BsvNetwork::Mainnet => NetworkClass::Mainnet,
        BsvNetwork::Testnet | BsvNetwork::Stn | BsvNetwork::Regtest => NetworkClass::TestFamily,
    }
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha256 = Sha256::digest(bytes);
    Ripemd160::digest(sha256).into()
}

fn decode_address(value: &str) -> Result<Vec<u8>, BsvError> {
    let decoded = bs58::decode(value)
        .with_check(None)
        .into_vec()
        .map_err(|error| BsvError::InvalidAddress(error.to_string()))?;
    if decoded.len() != 21 {
        return Err(BsvError::InvalidAddressPayload);
    }
    Ok(decoded)
}

const fn address_type(version: u8) -> Option<AddressType> {
    match version {
        0 | 111 => Some(AddressType::P2pkh),
        5 | 196 => Some(AddressType::P2sh),
        _ => None,
    }
}
