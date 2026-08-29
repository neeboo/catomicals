use std::fmt;

use catomicals_chain_domain::ErgoNetwork;
use ergo_lib::ergotree_ir::{
    chain::address::{Address, AddressEncoder, AddressEncoderError, NetworkPrefix},
    ergo_tree::ErgoTree,
    serialization::SigmaSerializable,
};

use crate::ErgoAdapterError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErgoAddressKind {
    P2Pk,
    PayToScript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoAddress {
    network: ErgoNetwork,
    kind: ErgoAddressKind,
    address: Address,
}

impl ErgoAddress {
    pub const fn network(&self) -> ErgoNetwork {
        self.network
    }

    pub const fn kind(&self) -> ErgoAddressKind {
        self.kind
    }

    pub fn content_bytes(&self) -> Vec<u8> {
        self.address.content_bytes()
    }

    /// Returns the canonical serialized ErgoTree protected by this address.
    pub fn ergo_tree_bytes(&self) -> Result<Vec<u8>, ErgoAdapterError> {
        let tree = self
            .address
            .script()
            .map_err(|error| ErgoAdapterError::InvalidAddress(error.to_string()))?;
        tree.sigma_serialize_bytes()
            .map_err(|error| ErgoAdapterError::InvalidAddress(error.to_string()))
    }
}

impl fmt::Display for ErgoAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            &AddressEncoder::new(network_prefix(self.network)).address_to_str(&self.address),
        )
    }
}

/// Parses a checksummed address for one explicit Ergo network.
///
/// P2PK public points and P2S ErgoTrees are parsed by sigma-rust. P2SH is kept
/// outside the initial adapter contract because spending also requires the
/// redeem script through context variable 1.
pub fn parse_address(network: ErgoNetwork, value: &str) -> Result<ErgoAddress, ErgoAdapterError> {
    let encoder = AddressEncoder::new(network_prefix(network));
    let address = encoder
        .parse_address_from_str(value)
        .map_err(|error| address_error(network, error))?;

    checked_address(network, address)
}

pub fn p2pk_address(
    network: ErgoNetwork,
    compressed_public_key: &[u8],
) -> Result<ErgoAddress, ErgoAdapterError> {
    let address = Address::p2pk_from_pk_bytes(compressed_public_key)
        .map_err(|error| ErgoAdapterError::InvalidAddress(error.to_string()))?;
    checked_address(network, address)
}

pub fn pay_to_script_address(
    network: ErgoNetwork,
    ergo_tree_bytes: &[u8],
) -> Result<ErgoAddress, ErgoAdapterError> {
    ErgoTree::sigma_parse_bytes(ergo_tree_bytes)
        .map_err(|error| ErgoAdapterError::InvalidAddress(error.to_string()))?;
    checked_address(network, Address::P2S(ergo_tree_bytes.to_vec()))
}

fn checked_address(
    network: ErgoNetwork,
    address: Address,
) -> Result<ErgoAddress, ErgoAdapterError> {
    let kind = match &address {
        Address::P2Pk(_) => ErgoAddressKind::P2Pk,
        Address::P2S(_) => {
            address
                .script()
                .map_err(|error| ErgoAdapterError::InvalidAddress(error.to_string()))?;
            ErgoAddressKind::PayToScript
        }
        Address::P2SH(_) => return Err(ErgoAdapterError::UnsupportedAddressKind),
    };

    Ok(ErgoAddress {
        network,
        kind,
        address,
    })
}

fn address_error(network: ErgoNetwork, error: AddressEncoderError) -> ErgoAdapterError {
    match error {
        AddressEncoderError::InvalidNetwork(_) => {
            ErgoAdapterError::InvalidAddressNetwork { expected: network }
        }
        error => ErgoAdapterError::InvalidAddress(error.to_string()),
    }
}

const fn network_prefix(network: ErgoNetwork) -> NetworkPrefix {
    match network {
        ErgoNetwork::Mainnet => NetworkPrefix::Mainnet,
        ErgoNetwork::Testnet => NetworkPrefix::Testnet,
    }
}
