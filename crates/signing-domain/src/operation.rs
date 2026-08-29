use catomicals_chain_domain::ChainScope;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{SigningContractError, SigningSuiteId, resolve_builtin_suite};

pub const MAX_SIGNER_SET_ID_BYTES: usize = 128;
const REVIEW_BINDING_DOMAIN: &[u8] = b"catomicals.review-binding.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBinding {
    pub schema_version: u16,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub signer_set_id: String,
    pub signer_set_epoch: u64,
    pub review_schema_version: u16,
    pub review_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBindingWire {
    schema_version: u16,
    chain_scope: ChainScope,
    signing_suite_id: SigningSuiteId,
    signer_set_id: String,
    signer_set_epoch: u64,
    review_schema_version: u16,
    review_digest: [u8; 32],
}

impl<'de> Deserialize<'de> for ReviewBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewBindingWire::deserialize(deserializer)?;
        if wire.schema_version != 1 {
            return Err(serde::de::Error::custom(
                SigningContractError::UnsupportedBindingSchemaVersion {
                    expected: 1,
                    actual: wire.schema_version,
                },
            ));
        }
        Self::new(
            wire.chain_scope,
            wire.signing_suite_id,
            wire.signer_set_id,
            wire.signer_set_epoch,
            wire.review_schema_version,
            wire.review_digest,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ReviewBinding {
    pub fn new(
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        signer_set_id: impl Into<String>,
        signer_set_epoch: u64,
        review_schema_version: u16,
        review_digest: [u8; 32],
    ) -> Result<Self, SigningContractError> {
        resolve_builtin_suite(&chain_scope, signing_suite_id)?;
        let signer_set_id = signer_set_id.into();
        if signer_set_id.is_empty() || signer_set_id.len() > MAX_SIGNER_SET_ID_BYTES {
            return Err(SigningContractError::InvalidSignerSetId {
                max_bytes: MAX_SIGNER_SET_ID_BYTES,
            });
        }
        if review_schema_version == 0 {
            return Err(SigningContractError::InvalidReviewSchemaVersion);
        }

        Ok(Self {
            schema_version: 1,
            chain_scope,
            signing_suite_id,
            signer_set_id,
            signer_set_epoch,
            review_schema_version,
            review_digest,
        })
    }

    pub fn domain_separator(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(REVIEW_BINDING_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        append_field(&mut bytes, self.chain_scope.chain.as_str().as_bytes());
        append_field(&mut bytes, self.chain_scope.network.as_str().as_bytes());
        append_field(&mut bytes, self.signing_suite_id.as_str().as_bytes());
        append_field(&mut bytes, self.signer_set_id.as_bytes());
        bytes.extend_from_slice(&self.signer_set_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.review_schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.review_digest);
        bytes
    }
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("bounded contract field fits in u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
}
