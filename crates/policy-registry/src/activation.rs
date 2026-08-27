use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CompileError, INQUISITION_SIGNET_PROFILE, Result, jcs, sha256_digest};

const ACTIVATION_DOMAIN: &str = "catomicals-policy-activation-proposal-v1";

/// Exact data reviewed by a later authority chain. Creating this value grants
/// no signing authority and consumes no signing nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProposalInput {
    pub activation_id: Uuid,
    pub binding_id: Uuid,
    pub policy_hash: String,
    pub wallet_id: Uuid,
    pub wallet_epoch: u64,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub chain_profile: String,
    pub artifact_set_digest: String,
    pub validation_run_digest: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProposal {
    pub activation_id: Uuid,
    pub binding_id: Uuid,
    pub policy_hash: String,
    pub wallet_id: Uuid,
    pub wallet_epoch: u64,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub chain_profile: String,
    pub artifact_set_digest: String,
    pub validation_run_digest: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub approval_digest: String,
}

#[derive(Serialize)]
struct ApprovalDigest<'a> {
    domain: &'static str,
    input: &'a ActivationProposalInput,
}

impl ActivationProposal {
    pub fn new(input: ActivationProposalInput) -> Result<Self> {
        if input.wallet_epoch == 0 || input.signer_epoch == 0 {
            return Err(CompileError::UnsupportedProfile(
                "wallet and signer epochs must be nonzero".to_owned(),
            ));
        }
        if input.chain_profile != INQUISITION_SIGNET_PROFILE {
            return Err(CompileError::UnsupportedProfile(
                "activation chain profile must be the fixed Inquisition Signet profile".to_owned(),
            ));
        }
        for digest in [
            &input.policy_hash,
            &input.artifact_set_digest,
            &input.validation_run_digest,
        ] {
            if !valid_sha256(digest) {
                return Err(CompileError::UnsupportedProfile(
                    "activation digests must be sha256:<64 lowercase hex>".to_owned(),
                ));
            }
        }
        if input.expires_at <= input.created_at {
            return Err(CompileError::UnsupportedProfile(
                "activation expiry must be after proposal creation".to_owned(),
            ));
        }
        let approval_digest = sha256_digest(&jcs(&ApprovalDigest {
            domain: ACTIVATION_DOMAIN,
            input: &input,
        })?);
        Ok(Self {
            activation_id: input.activation_id,
            binding_id: input.binding_id,
            policy_hash: input.policy_hash,
            wallet_id: input.wallet_id,
            wallet_epoch: input.wallet_epoch,
            signer_set_id: input.signer_set_id,
            signer_epoch: input.signer_epoch,
            chain_profile: input.chain_profile,
            artifact_set_digest: input.artifact_set_digest,
            validation_run_digest: input.validation_run_digest,
            expires_at: input.expires_at,
            created_at: input.created_at,
            approval_digest,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let expected = Self::new(ActivationProposalInput {
            activation_id: self.activation_id,
            binding_id: self.binding_id,
            policy_hash: self.policy_hash.clone(),
            wallet_id: self.wallet_id,
            wallet_epoch: self.wallet_epoch,
            signer_set_id: self.signer_set_id,
            signer_epoch: self.signer_epoch,
            chain_profile: self.chain_profile.clone(),
            artifact_set_digest: self.artifact_set_digest.clone(),
            validation_run_digest: self.validation_run_digest.clone(),
            expires_at: self.expires_at,
            created_at: self.created_at,
        })?;
        if expected == *self {
            Ok(())
        } else {
            Err(CompileError::ValidationRunMismatch)
        }
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
