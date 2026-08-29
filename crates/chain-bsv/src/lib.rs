#![forbid(unsafe_code)]

//! Bitcoin SV chain adapter.

mod address;
mod derivation;
mod signing;
mod suite;
mod transaction;

pub use address::{Address, AddressType};
pub use catomicals_chain_domain::BsvNetwork;
pub use derivation::Bip44Path;
pub use signing::{append_sighash_byte, sign_digest, verify_transaction_signature};
pub use suite::BsvChainSuite;
pub use transaction::{
    BsvSigningRequest, ForkIdSighashType, Transaction, TxInput, TxOutput, fork_id_sighash,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BsvError {
    #[error("invalid Base58Check address: {0}")]
    InvalidAddress(String),
    #[error("address version {version:#04x} is not valid for {network:?}")]
    WrongAddressNetwork { network: BsvNetwork, version: u8 },
    #[error("address payload must be exactly 20 bytes")]
    InvalidAddressPayload,
    #[error("invalid BIP44 path: {0}")]
    InvalidDerivationPath(String),
    #[error("transaction input index {index} is out of bounds")]
    InputIndexOutOfBounds { index: usize },
    #[error("SIGHASH_SINGLE input {index} has no corresponding output")]
    MissingSingleOutput { index: usize },
    #[error("invalid BSV ForkID sighash type {0:#04x}")]
    InvalidSighashType(u8),
    #[error("invalid secp256k1 public key")]
    InvalidPublicKey,
    #[error("invalid secp256k1 ECDSA secret key")]
    InvalidSecretKey,
    #[error("invalid strict-DER ECDSA signature")]
    InvalidDerSignature,
    #[error("non-canonical high-S ECDSA signature")]
    HighSSignature,
    #[error("ECDSA signature verification failed")]
    SignatureVerificationFailed,
    #[error("signing material is invalid: {0}")]
    InvalidSigningMaterial(String),
    #[error("signing material declares {declared:?}, but suite is {configured:?}")]
    WrongSigningNetwork {
        configured: BsvNetwork,
        declared: BsvNetwork,
    },
    #[error("backend {backend:?} cannot satisfy BSV {mode:?} signing")]
    IncompatibleSignerBackend {
        mode: catomicals_signing_domain::SigningExecutionMode,
        backend: catomicals_signing_domain::SignerBackendRequirement,
    },
    #[error("invalid BSV signing-suite contract: {0}")]
    InvalidSigningSuite(String),
}
