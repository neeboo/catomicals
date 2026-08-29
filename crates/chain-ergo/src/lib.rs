#![forbid(unsafe_code)]

//! Ergo chain adapter.

mod address;
mod derivation;
mod review;
mod suite;

pub use address::{
    ErgoAddress, ErgoAddressKind, p2pk_address, parse_address, pay_to_script_address,
};
pub use derivation::{ERGO_COIN_TYPE, ErgoDerivationPath, derive_eip3_path};
pub use review::ErgoReviewMaterialV1;
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
    #[error("invalid Ergo review material: {0}")]
    InvalidReviewMaterial(String),
    #[error("unsupported Ergo review material schema version {actual}; expected {expected}")]
    UnsupportedReviewMaterialVersion { expected: u16, actual: u16 },
    #[error("Ergo review material declares {actual:?}, expected {expected:?}")]
    ReviewNetworkMismatch {
        expected: catomicals_chain_domain::ErgoNetwork,
        actual: catomicals_chain_domain::ErgoNetwork,
    },
    #[error("Ergo P2PK v1 does not support input {input_index}'s script")]
    UnsupportedInputScript { input_index: usize },
    #[error("invalid Ergo P2PK secret key")]
    InvalidSecretKey,
    #[error("Ergo Sigma signing failed: {0}")]
    SigmaSigning(String),
    #[error("invalid signed Ergo transaction: {0}")]
    InvalidSignedTransaction(String),
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
