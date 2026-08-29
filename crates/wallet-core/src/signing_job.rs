//! Chain-neutral wallet signing contracts.

use catomicals_chain_domain::{ChainScope, ChainSuite, ReviewArtifact};
use catomicals_signing_domain::{
    ReviewBinding, SignerBackendRequirement, SigningSuiteId, require_executable_suite,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerProfile {
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: SignerBackendRequirement,
    pub signer_set_id: String,
    pub authorization_signer_id: String,
    pub signer_epoch: u64,
    pub threshold: u16,
    pub max_signers: u16,
    pub verification_key: Vec<u8>,
    /// Opaque handle only. Wallet state never stores a private share.
    pub secret_ref: String,
}

impl SignerProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: Uuid,
        wallet_id: Uuid,
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        backend_requirement: SignerBackendRequirement,
        signer_set_id: String,
        authorization_signer_id: String,
        signer_epoch: u64,
        threshold: u16,
        max_signers: u16,
        verification_key: Vec<u8>,
        secret_ref: String,
    ) -> Result<Self, SigningJobError> {
        let descriptor = require_executable_suite(&chain_scope, signing_suite_id)
            .map_err(|error| SigningJobError::InvalidProfile(error.to_string()))?;
        if descriptor.backend_requirement != backend_requirement
            || profile_id.is_nil()
            || wallet_id.is_nil()
            || signer_set_id.is_empty()
            || signer_set_id.len() > 128
            || authorization_signer_id.is_empty()
            || authorization_signer_id.len() > 128
            || signer_epoch == 0
            || threshold == 0
            || threshold > max_signers
            || verification_key.is_empty()
            || secret_ref.is_empty()
        {
            return Err(SigningJobError::InvalidProfile(
                "signer profile fields do not match the executable suite".to_owned(),
            ));
        }
        Ok(Self {
            profile_id,
            wallet_id,
            chain_scope,
            signing_suite_id,
            backend_requirement,
            signer_set_id,
            authorization_signer_id,
            signer_epoch,
            threshold,
            max_signers,
            verification_key,
            secret_ref,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBinding {
    pub binding_id: Uuid,
    pub profile_id: Uuid,
    pub chain_scope: ChainScope,
    pub address: String,
    pub verification_key_digest: [u8; 32],
}

impl AddressBinding {
    pub fn new(
        binding_id: Uuid,
        profile: &SignerProfile,
        address: String,
        verification_key_digest: [u8; 32],
    ) -> Result<Self, SigningJobError> {
        if binding_id.is_nil() || address.trim().is_empty() || verification_key_digest == [0; 32] {
            return Err(SigningJobError::InvalidAddressBinding);
        }
        Ok(Self {
            binding_id,
            profile_id: profile.profile_id,
            chain_scope: profile.chain_scope,
            address,
            verification_key_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningJob {
    pub job_id: Uuid,
    pub intent_id: Uuid,
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: SignerBackendRequirement,
    pub review: ReviewArtifact,
    pub review_binding: ReviewBinding,
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub online_parties: [String; 2],
    pub receiver: String,
    pub session_id: [u8; 32],
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainSigningJobStatus {
    Signing,
    Finalized,
    Aborted,
    Expired,
    Failed,
}

/// Public, non-secret recovery state for one durable chain signing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSigningJobState {
    pub job_id: Uuid,
    pub intent_id: Uuid,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: SignerBackendRequirement,
    pub review_schema_version: u16,
    pub review_digest: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub online_parties: [String; 2],
    pub receiver: String,
    pub operation_binding_digest: [u8; 32],
    pub status: ChainSigningJobStatus,
    pub final_signature: Option<Vec<u8>>,
    pub terminal_reason: Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateChainSigningJobRequest {
    pub authorization_id: Uuid,
    pub operation_binding_digest: [u8; 32],
    pub job: SigningJob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSigningExecution {
    pub job: SigningJob,
    pub operation_binding_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainSigningExecutorKey {
    pub profile_id: Uuid,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: String,
}

impl ChainSigningExecutorKey {
    pub fn from_job(job: &SigningJob) -> Self {
        Self {
            profile_id: job.profile_id,
            signing_suite_id: job.signing_suite_id,
            backend_requirement: job.backend_requirement.as_str().to_owned(),
        }
    }
}

/// A finalized consensus signature that has already passed the chain suite's
/// independent verifier. Its bytes cannot be constructed without that check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChainSignature(Vec<u8>);

impl VerifiedChainSignature {
    pub fn verify(
        suite: &dyn ChainSuite,
        execution: &ChainSigningExecution,
        signature: Vec<u8>,
    ) -> Result<Self, SigningJobError> {
        if suite.scope() != execution.job.chain_scope {
            return Err(SigningJobError::ProfileDrift);
        }
        suite
            .verify_finalized_signature(&execution.job.review, &signature)
            .map_err(|error| SigningJobError::FinalVerification(error.to_string()))?;
        Ok(Self(signature))
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub trait ChainSigningExecutor: Send + Sync {
    fn key(&self) -> ChainSigningExecutorKey;

    fn execute(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<VerifiedChainSignature, SigningJobError>;
}

#[derive(Default)]
pub struct ChainSigningExecutorRegistry {
    executors: HashMap<ChainSigningExecutorKey, Arc<dyn ChainSigningExecutor>>,
}

impl ChainSigningExecutorRegistry {
    pub fn register(&mut self, executor: Box<dyn ChainSigningExecutor>) {
        self.executors.insert(executor.key(), Arc::from(executor));
    }

    pub fn resolve(&self, job: &SigningJob) -> Option<&dyn ChainSigningExecutor> {
        self.executors
            .get(&ChainSigningExecutorKey::from_job(job))
            .map(Arc::as_ref)
    }

    pub(crate) fn resolve_shared(&self, job: &SigningJob) -> Option<Arc<dyn ChainSigningExecutor>> {
        self.executors
            .get(&ChainSigningExecutorKey::from_job(job))
            .cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigningJobError {
    #[error("invalid signer profile: {0}")]
    InvalidProfile(String),
    #[error("invalid address binding")]
    InvalidAddressBinding,
    #[error("signing job does not match its signer profile")]
    ProfileDrift,
    #[error("transaction review failed: {0}")]
    Review(String),
    #[error("signing backend failed: {0}")]
    Backend(String),
    #[error("signing operation was interrupted")]
    Interrupted,
    #[error("signing operation timed out")]
    TimedOut,
    #[error("final signature failed chain verification: {0}")]
    FinalVerification(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use catomicals_chain_domain::{BitcoinCashNetwork, ChainNetwork};

    struct NeverExecutor(ChainSigningExecutorKey);

    impl ChainSigningExecutor for NeverExecutor {
        fn key(&self) -> ChainSigningExecutorKey {
            self.0.clone()
        }

        fn execute(
            &self,
            _execution: &ChainSigningExecution,
            _now: i64,
        ) -> Result<VerifiedChainSignature, SigningJobError> {
            Err(SigningJobError::Backend("not called".to_owned()))
        }
    }

    fn job() -> SigningJob {
        let scope = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
        let review =
            ReviewArtifact::new(scope, [1; 32], [2; 32], "test".to_owned(), vec![1]).unwrap();
        SigningJob {
            job_id: Uuid::from_bytes([1; 16]),
            intent_id: Uuid::from_bytes([2; 16]),
            profile_id: Uuid::from_bytes([3; 16]),
            wallet_id: Uuid::from_bytes([4; 16]),
            chain_scope: scope,
            signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
            review: review.clone(),
            review_binding: ReviewBinding::new(
                scope,
                SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
                "set",
                1,
                review.schema_version,
                review.review_digest,
            )
            .unwrap(),
            policy_snapshot_digest: [5; 32],
            chain_snapshot_digest: [6; 32],
            online_parties: ["a".to_owned(), "b".to_owned()],
            receiver: "a".to_owned(),
            session_id: [7; 32],
            expires_at: 20,
            created_at: 10,
        }
    }

    #[test]
    fn executor_registry_rejects_wrong_profile_suite_and_backend() {
        let expected = job();
        let mut registry = ChainSigningExecutorRegistry::default();
        registry.register(Box::new(NeverExecutor(ChainSigningExecutorKey::from_job(
            &expected,
        ))));
        assert!(registry.resolve(&expected).is_some());

        let mut wrong_profile = expected.clone();
        wrong_profile.profile_id = Uuid::from_bytes([8; 16]);
        assert!(registry.resolve(&wrong_profile).is_none());

        let mut wrong_suite = expected.clone();
        wrong_suite.signing_suite_id = SigningSuiteId::BITCOIN_CASH_ECDSA_ISOLATED_V1;
        assert!(registry.resolve(&wrong_suite).is_none());

        let mut wrong_backend = expected;
        wrong_backend.backend_requirement = SignerBackendRequirement::IsolatedSecp256k1Ecdsa;
        assert!(registry.resolve(&wrong_backend).is_none());
    }
}
