#![forbid(unsafe_code)]

//! Ergo chain adapter.

mod address;
mod derivation;
mod review;
mod suite;
mod threshold;

pub use address::{
    ErgoAddress, ErgoAddressKind, p2pk_address, parse_address, pay_to_script_address,
};
pub use derivation::{ERGO_COIN_TYPE, ErgoDerivationPath, derive_eip3_path};
pub use review::ErgoReviewMaterialV1;
pub use suite::{ErgoChainSuite, ErgoSignerBackend, ErgoSignerMode, ErgoSigningSuite};
pub use threshold::{
    ErgoP2pkProof, ErgoThresholdCommitment, ErgoThresholdCommitments, ErgoThresholdDealerOutput,
    ErgoThresholdNonceReplayGuard, ErgoThresholdNonceReservation,
    ErgoThresholdP2pkRuntimeDescriptor, ErgoThresholdSecretShare, ErgoThresholdSignatureShare,
    ErgoThresholdSigningNonces, ErgoThresholdSigningPackage, ErgoThresholdSigningRequest,
    aggregate_threshold_p2pk_proof_2_of_3, assemble_threshold_p2pk_transaction,
    dealer_split_threshold_secret_2_of_3, generate_threshold_nonces_2_of_3,
    sign_threshold_share_2_of_3, validate_threshold_secret_share,
};

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
    #[error("invalid Ergo threshold scalar: {0}")]
    InvalidThresholdScalar(&'static str),
    #[error("Ergo threshold participant id must be in 1..=3, got {0}")]
    InvalidThresholdParticipant(u16),
    #[error("Ergo threshold participant {0} appears more than once")]
    DuplicateThresholdParticipant(u16),
    #[error("Ergo 2-of-3 signing requires exactly two participants, got {actual}")]
    InvalidThresholdQuorum { actual: usize },
    #[error("invalid Ergo threshold commitment: {0}")]
    InvalidThresholdCommitment(String),
    #[error("Ergo threshold share {participant_id} does not match its public commitment")]
    ThresholdShareCommitmentMismatch { participant_id: u16 },
    #[error("Ergo threshold nonce commitment for participant {participant_id} does not match")]
    ThresholdNonceCommitmentMismatch { participant_id: u16 },
    #[error(
        "Ergo threshold partial from participant {participant_id} is bound to another transcript"
    )]
    ThresholdTranscriptMismatch { participant_id: u16 },
    #[error("Ergo threshold signing package belongs to another signer commitment")]
    ThresholdSigningPackageMismatch,
    #[error("Ergo threshold signing package belongs to another approved review binding")]
    ThresholdReviewBindingMismatch,
    #[error("Ergo threshold signing session id must be non-zero")]
    InvalidThresholdSession,
    #[error("Ergo threshold nonce or package belongs to another signing session")]
    ThresholdSessionMismatch,
    #[error("Ergo threshold nonce replay guard rejected the operation: {0}")]
    ThresholdNonceReplay(String),
    #[error("Ergo threshold request does not match the registered 2-of-3 signing suite")]
    ThresholdSuiteContractMismatch,
    #[error("invalid Ergo threshold partial from participant {participant_id}")]
    InvalidThresholdPartial { participant_id: u16 },
    #[error("the aggregated Ergo threshold proof failed native Sigma verification")]
    InvalidThresholdFinalProof,
    #[error("Ergo threshold transaction needs {expected} input proofs, got {actual}")]
    ThresholdProofCount { expected: usize, actual: usize },
    #[error("Ergo input {input_index} is not controlled by the threshold group key")]
    ThresholdInputKeyMismatch { input_index: usize },
    #[error("Ergo Sigma script multisig is not a registered threshold P2PK signing suite")]
    SigmaMultisigUnavailable,
    #[error("{backend:?} cannot satisfy Ergo {mode:?} signing")]
    IncompatibleSignerBackend {
        mode: ErgoSignerMode,
        backend: ErgoSignerBackend,
    },
    #[error(transparent)]
    SigningContract(#[from] SigningContractError),
}
