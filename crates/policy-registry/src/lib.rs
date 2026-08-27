//! Immutable, content-addressed policy compilation for the current Catomicals
//! Inquisition Signet experiments.

mod activation;
mod artifact;
mod compile;
mod document;

pub use activation::{ActivationProposal, ActivationProposalInput};
pub use artifact::{PolicyArtifact, PolicyTestVector, VectorInput, VectorResult};
pub use compile::{PolicyBundle, ValidationRun, compile_policy_json, inspect_bundle};
pub use document::{
    BitcoinNetwork, DigestAlgorithm, IssuanceInput, ListingInput, NetworkProfile, OpCatRequirement,
    PolicyDocument, ProtocolInput, ReceiptInput, SuccessorRuleInput,
};

pub const POLICY_SCHEMA_VERSION: u16 = 1;
pub const POLICY_CANONICALIZATION: &str = "catomicals-policy-jcs-v1";
pub const POLICY_COMPILER_VERSION: &str =
    concat!("catomicals-policy-registry/", env!("CARGO_PKG_VERSION"));
pub const INQUISITION_SIGNET_PROFILE: &str = "bitcoin-inquisition-signet-v29.4-op-cat";
pub const MAX_POLICY_DOCUMENT_BYTES: usize = 64 * 1024;
pub const MAX_METADATA_BYTES: usize = 4 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 128 * 1024;
pub const MAX_ARTIFACT_SET_BYTES: usize = 1024 * 1024;
pub const MAX_VECTOR_SET_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("policy JSON is invalid or non-strict: {0}")]
    InvalidJson(String),
    #[error("policy profile is unsupported: {0}")]
    UnsupportedProfile(String),
    #[error("issuance input is invalid: {0}")]
    InvalidIssuance(String),
    #[error("fixed-price listing input is invalid: {0}")]
    InvalidListing(String),
    #[error("policy or compiled content exceeds a fixed size limit: {0}")]
    LimitExceeded(&'static str),
    #[error("policy hash does not match the canonical document")]
    PolicyHashMismatch,
    #[error("compiled artifact content or digest does not match")]
    ArtifactMismatch,
    #[error("artifact-set digest does not match")]
    ArtifactSetMismatch,
    #[error("test-vector digest or execution result does not match")]
    VectorMismatch,
    #[error("validation run does not bind the compiled policy and results")]
    ValidationRunMismatch,
    #[error("bundle bytes are not canonical JCS")]
    NonCanonicalBundle,
}

pub type Result<T> = std::result::Result<T, CompileError>;

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn jcs<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| CompileError::InvalidJson(error.to_string()))
}
