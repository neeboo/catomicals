use serde::{Deserialize, Serialize};

use crate::{ChainScope, ReviewArtifact, ReviewContractError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCapabilities {
    pub address_derivation: bool,
    pub transaction_review: bool,
    pub final_signature_verification: bool,
    pub broadcast: bool,
}

pub trait ChainSuite: Send + Sync {
    fn scope(&self) -> ChainScope;
    fn capabilities(&self) -> ChainCapabilities;
    fn review_transaction(
        &self,
        transaction_material: &[u8],
    ) -> Result<ReviewArtifact, ReviewContractError>;
    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError>;
}
