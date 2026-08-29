use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};

use crate::ChainScope;

pub const MAX_REVIEW_SUMMARY_BYTES: usize = 4 * 1024;
/// Maximum canonical transaction-review input retained for final verification.
pub const MAX_REVIEW_MATERIAL_BYTES: usize = 1_000_000;
pub const REVIEW_ARTIFACT_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewContractError {
    #[error("review summary exceeds {max_bytes} bytes")]
    SummaryTooLong { max_bytes: usize },
    #[error("reviewed material is required")]
    MissingReviewedMaterial,
    #[error("reviewed material exceeds {max_bytes} bytes")]
    ReviewedMaterialTooLong { max_bytes: usize },
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
    /// Human-readable display only. Consensus and signature checks must not parse this field.
    pub summary: String,
    /// Canonical input that the chain suite must review again before accepting a signature.
    pub reviewed_material: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewArtifactWire {
    schema_version: u16,
    scope: ChainScope,
    review_digest: [u8; 32],
    signing_message_digest: [u8; 32],
    summary: String,
    #[serde(deserialize_with = "deserialize_reviewed_material")]
    reviewed_material: Vec<u8>,
}

impl<'de> Deserialize<'de> for ReviewArtifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewArtifactWire::deserialize(deserializer)?;
        if wire.schema_version != REVIEW_ARTIFACT_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                ReviewContractError::UnsupportedSchemaVersion {
                    expected: REVIEW_ARTIFACT_SCHEMA_VERSION,
                    actual: wire.schema_version,
                },
            ));
        }
        Self::new(
            wire.scope,
            wire.review_digest,
            wire.signing_message_digest,
            wire.summary,
            wire.reviewed_material,
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
        reviewed_material: Vec<u8>,
    ) -> Result<Self, ReviewContractError> {
        if summary.len() > MAX_REVIEW_SUMMARY_BYTES {
            return Err(ReviewContractError::SummaryTooLong {
                max_bytes: MAX_REVIEW_SUMMARY_BYTES,
            });
        }
        if reviewed_material.is_empty() {
            return Err(ReviewContractError::MissingReviewedMaterial);
        }
        if reviewed_material.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ReviewContractError::ReviewedMaterialTooLong {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
        Ok(Self {
            schema_version: REVIEW_ARTIFACT_SCHEMA_VERSION,
            scope,
            review_digest,
            signing_message_digest,
            summary,
            reviewed_material,
        })
    }
}

fn deserialize_reviewed_material<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBytesVisitor;

    impl<'de> Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a non-empty byte sequence of at most {MAX_REVIEW_MATERIAL_BYTES} bytes"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_REVIEW_MATERIAL_BYTES)
            {
                return Err(serde::de::Error::custom(
                    ReviewContractError::ReviewedMaterialTooLong {
                        max_bytes: MAX_REVIEW_MATERIAL_BYTES,
                    },
                ));
            }
            let mut bytes = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(MAX_REVIEW_MATERIAL_BYTES),
            );
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_REVIEW_MATERIAL_BYTES {
                    return Err(serde::de::Error::custom(
                        ReviewContractError::ReviewedMaterialTooLong {
                            max_bytes: MAX_REVIEW_MATERIAL_BYTES,
                        },
                    ));
                }
                bytes.push(byte);
            }
            if bytes.is_empty() {
                return Err(serde::de::Error::custom(
                    ReviewContractError::MissingReviewedMaterial,
                ));
            }
            Ok(bytes)
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_deserialized_bytes(bytes)
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_deserialized_byte_count::<E>(&bytes)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_seq(BoundedBytesVisitor)
}

fn validate_deserialized_bytes<E>(bytes: &[u8]) -> Result<Vec<u8>, E>
where
    E: serde::de::Error,
{
    validate_deserialized_byte_count::<E>(bytes)?;
    Ok(bytes.to_vec())
}

fn validate_deserialized_byte_count<E>(bytes: &[u8]) -> Result<(), E>
where
    E: serde::de::Error,
{
    if bytes.is_empty() {
        return Err(E::custom(ReviewContractError::MissingReviewedMaterial));
    }
    if bytes.len() > MAX_REVIEW_MATERIAL_BYTES {
        return Err(E::custom(ReviewContractError::ReviewedMaterialTooLong {
            max_bytes: MAX_REVIEW_MATERIAL_BYTES,
        }));
    }
    Ok(())
}
