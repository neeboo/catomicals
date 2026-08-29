#![forbid(unsafe_code)]

//! Ergo chain adapter.

mod address;
mod derivation;
mod suite;

pub use address::{
    ErgoAddress, ErgoAddressKind, p2pk_address, parse_address, pay_to_script_address,
};
pub use derivation::{ERGO_COIN_TYPE, ErgoDerivationPath, derive_eip3_path};
pub use suite::{ErgoChainSuite, ErgoSignerBackend, ErgoSignerMode, ErgoSigningSuite};

use catomicals_signing_domain::SigningContractError;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ErgoAdapterError {
    #[error("invalid Ergo address: {0}")]
    InvalidAddress(String),
    #[error("Ergo address does not belong to {expected:?}")]
    InvalidAddressNetwork {
        expected: catomicals_chain_domain::ErgoNetwork,
    },
    #[error("Ergo P2SH addresses are outside this adapter's P2PK/P2S contract")]
    UnsupportedAddressKind,
    #[error("invalid EIP-3 {field} index {value}")]
    InvalidDerivationIndex { field: &'static str, value: u32 },
    #[error("Ergo Sigma signing execution is not implemented")]
    SigmaSigningUnavailable,
    #[error("Ergo multi-party Sigma proving is not implemented")]
    SigmaMultisigUnavailable,
    #[error("{backend:?} cannot satisfy Ergo {mode:?} signing")]
    IncompatibleSignerBackend {
        mode: ErgoSignerMode,
        backend: ErgoSignerBackend,
    },
    #[error(transparent)]
    SigningContract(#[from] SigningContractError),
}
