#![forbid(unsafe_code)]

//! Bitcoin Cash chain adapter.

mod address;
mod derivation;
mod signature;
mod suite;
mod transaction;

pub use address::{Address, AddressKind, AddressNetwork};
pub use catomicals_chain_domain::BitcoinCashNetwork;
pub use derivation::Bip44Path;
pub use signature::{
    BitcoinCashEcdsaSuite, BitcoinCashSchnorrMessage, BitcoinCashSchnorrSignature,
    BitcoinCashSchnorrSuite, EcdsaBackend, assemble_ecdsa_transaction_signature,
    assemble_schnorr_transaction_signature, sign_ecdsa, verify_ecdsa_transaction_signature,
    verify_schnorr, verify_schnorr_transaction_signature,
};
pub use suite::{BitcoinCashChainSuite, BitcoinCashSignatureAlgorithm, BitcoinCashSigningRequest};
pub use transaction::{ForkIdSighashType, OutPoint, Transaction, TxIn, TxOut, fork_id_sighash};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("address uses mixed upper and lower case")]
    MixedCaseAddress,
    #[error("address checksum is invalid")]
    InvalidChecksum,
    #[error("address encoding is invalid")]
    InvalidAddressEncoding,
    #[error("address payload is invalid")]
    InvalidAddressPayload,
    #[error("address is for `{actual}` rather than `{expected:?}`")]
    WrongNetwork {
        expected: BitcoinCashNetwork,
        actual: &'static str,
    },
    #[error("address identifies the shared BCH test-family, not one exact test network")]
    AmbiguousAddressNetwork,
    #[error("public key encoding is invalid")]
    InvalidPublicKey,
    #[error("BIP44 change must be 0 or 1, got {0}")]
    InvalidChange(u32),
    #[error("BIP44 index `{field}` must be less than 2^31, got {value}")]
    InvalidDerivationIndex { field: &'static str, value: u32 },
    #[error("BIP44 path must match m/44'/145'/account'/change/index")]
    InvalidDerivationPath,
    #[error("transaction exceeds {max_bytes} bytes")]
    TransactionTooLarge { max_bytes: usize },
    #[error("transaction is truncated or malformed")]
    MalformedTransaction,
    #[error("transaction uses a non-canonical variable integer")]
    NonCanonicalVarInt,
    #[error("transaction has trailing data")]
    TrailingTransactionData,
    #[error("transaction contains too many `{field}` entries")]
    TooManyTransactionElements { field: &'static str },
    #[error("input index {index} is outside transaction input count {input_count}")]
    InputIndexOutOfBounds { index: usize, input_count: usize },
    #[error("Bitcoin Cash signature hash type is missing SIGHASH_FORKID")]
    MissingForkId,
    #[error("unsupported Bitcoin Cash signature hash type {0:#x}")]
    UnsupportedSighashType(u32),
    #[error("signature hash type {0:#x} cannot bind a complete transaction review")]
    UnsafeReviewSighashType(u32),
    #[error("transaction signature serialization supports BCH fork id 0, got {0:#x}")]
    UnsupportedForkId(u32),
    #[error("secp256k1 secret key is invalid")]
    InvalidSecretKey,
    #[error("signature encoding is invalid or non-standard")]
    InvalidSignatureEncoding,
    #[error("signature hash type byte {actual:#x} does not match expected {expected:#x}")]
    SignatureHashTypeMismatch { expected: u8, actual: u8 },
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("Bitcoin Cash Schnorr signature must be 64 bytes, got {actual}")]
    InvalidSchnorrSignatureLength { actual: usize },
    #[error("Bitcoin Cash signing request encoding is invalid")]
    InvalidSigningRequest,
    #[error("Bitcoin Cash signing request network id {0} is unknown")]
    UnknownSigningRequestNetwork(u8),
}
