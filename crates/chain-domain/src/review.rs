use serde::{Deserialize, Deserializer, Serialize};

use crate::ChainScope;

pub const MAX_REVIEW_SUMMARY_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewContractError {
    #[error("review summary exceeds {max_bytes} bytes")]
    SummaryTooLong { max_bytes: usize },
    #[error("chain suite does not support `{operation}`")]
    UnsupportedOperation { operation: &'static str },
    #[error("finalized signature is invalid: {0}")]
    InvalidFinalizedSignature(String),
    #[error("unsupported review artifact schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u16, actual: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewArtifact {
    pub schema_version: u16,
    pub scope: ChainScope,
    pub review_digest: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub summary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewArtifactWire {
    schema_version: u16,
    scope: ChainScope,
    review_digest: [u8; 32],
    signing_message_digest: [u8; 32],
    summary: String,
}

impl<'de> Deserialize<'de> for ReviewArtifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewArtifactWire::deserialize(deserializer)?;
        if wire.schema_version != 1 {
            return Err(serde::de::Error::custom(
                ReviewContractError::UnsupportedSchemaVersion {
                    expected: 1,
                    actual: wire.schema_version,
                },
            ));
        }
        Self::new(
            wire.scope,
            wire.review_digest,
            wire.signing_message_digest,
            wire.summary,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ReviewArtifact {
    pub fn new(
        scope: ChainScope,
        review_digest: [u8; 32],
        signing_message_digest: [u8; 32],
        summary: String,
    ) -> Result<Self, ReviewContractError> {
        if summary.len() > MAX_REVIEW_SUMMARY_BYTES {
            return Err(ReviewContractError::SummaryTooLong {
                max_bytes: MAX_REVIEW_SUMMARY_BYTES,
            });
        }
        Ok(Self {
            schema_version: 1,
            scope,
            review_digest,
            signing_message_digest,
            summary,
        })
    }
}
