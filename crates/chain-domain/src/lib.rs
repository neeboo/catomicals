//! Consensus-facing identities and review contracts for supported chains.

mod network;
mod review;
mod suite;

pub use network::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainDomainError, ChainId, ChainNetwork,
    ChainScope, ChiaNetwork, ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork, RpcPresetId,
};
pub use review::{
    MAX_REVIEW_MATERIAL_BYTES, MAX_REVIEW_SUMMARY_BYTES, REVIEW_ARTIFACT_SCHEMA_VERSION,
    ReviewArtifact, ReviewContractError,
};
pub use suite::{ChainCapabilities, ChainSuite};
