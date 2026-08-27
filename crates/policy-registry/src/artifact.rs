use serde::{Deserialize, Serialize};

use crate::{CompileError, MAX_ARTIFACT_BYTES, PolicyDocument, Result, sha256_digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifact {
    pub artifact_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<u8>,
    pub media_type: String,
    pub content_ref: String,
    pub content_hex: String,
    pub content_digest: String,
}

impl PolicyArtifact {
    pub(crate) fn new(
        kind: impl Into<String>,
        lane: Option<u8>,
        media_type: impl Into<String>,
        content: Vec<u8>,
    ) -> Result<Self> {
        if content.len() > MAX_ARTIFACT_BYTES {
            return Err(CompileError::LimitExceeded("single artifact"));
        }
        let kind = kind.into();
        let content_digest = sha256_digest(&content);
        let lane_label = lane.map_or_else(|| "global".to_owned(), |value| value.to_string());
        let artifact_id = format!("{kind}:{lane_label}:{content_digest}");
        Ok(Self {
            content_ref: format!("inline:{artifact_id}"),
            artifact_id,
            kind,
            lane,
            media_type: media_type.into(),
            content_hex: hex::encode(content),
            content_digest,
        })
    }

    pub fn validate(&self) -> Result<Vec<u8>> {
        let content = hex::decode(&self.content_hex).map_err(|_| CompileError::ArtifactMismatch)?;
        if content.len() > MAX_ARTIFACT_BYTES || sha256_digest(&content) != self.content_digest {
            return Err(CompileError::ArtifactMismatch);
        }
        let lane_label = self
            .lane
            .map_or_else(|| "global".to_owned(), |value| value.to_string());
        if self.artifact_id != format!("{}:{lane_label}:{}", self.kind, self.content_digest) {
            return Err(CompileError::ArtifactMismatch);
        }
        if self.content_ref != format!("inline:{}", self.artifact_id) {
            return Err(CompileError::ArtifactMismatch);
        }
        Ok(content)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum VectorInput {
    CompileDocument {
        document: PolicyDocument,
    },
    VerifyPolicyHash {
        document: PolicyDocument,
        claimed_policy_hash: String,
    },
    VerifyArtifact {
        artifact: PolicyArtifact,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestVector {
    pub vector_id: String,
    pub input: VectorInput,
    pub expected_accept: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorResult {
    pub vector_id: String,
    pub expected_accept: bool,
    pub actual_accept: bool,
    pub passed: bool,
}
