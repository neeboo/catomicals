//! Bitcoin 2-of-3 FROST executor for the chain-neutral signing-job runtime.

use std::sync::Mutex;

use catomicals_chain_bitcoin::BitcoinChainSuite;
use catomicals_chain_domain::{ChainId, ChainSuite};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SignerProfile,
    SigningJobError, VerifiedChainSignature,
};

/// Complete durable authority claim for one Bitcoin FROST execution.
///
/// Implementations must commit this record before either FROST round begins.
/// A second claim of the same record must fail after process restart as well as
/// within one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinExecutionClaim {
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: SignerBackendRequirement,
    pub session_id: [u8; 32],
    pub review_domain_separator: Vec<u8>,
    pub signing_message_digest: [u8; 32],
    pub operation_binding_digest: [u8; 32],
    pub claimed_at: i64,
}

impl BitcoinExecutionClaim {
    /// Stable uniqueness key for one FROST session under one registered
    /// authority. Review or operation drift cannot turn a consumed session
    /// into a new signing opportunity.
    pub fn replay_key(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"catomicals/bitcoin-frost-session-claim/v1\0");
        digest.update(self.wallet_id.as_bytes());
        digest.update(self.profile_id.as_bytes());
        digest.update(self.signing_suite_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.backend_requirement.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.session_id);
        digest.finalize().into()
    }
}

/// Persistent replay boundary. This is intentionally separate from signer
/// nonce storage so the complete wallet authority tuple is claimed before any
/// participant is contacted.
pub trait BitcoinExecutionClaimStore: Send {
    fn claim(&mut self, replay_key: [u8; 32], claim: &BitcoinExecutionClaim) -> Result<(), String>;
}

/// Existing FROST orchestration boundary.
///
/// Concrete implementations use `catomicals-threshold` providers or the
/// durable personal signing coordinator. Private shares and secret nonces do
/// not cross this interface.
pub trait BitcoinThresholdCoordinator: Send {
    fn sign(
        &mut self,
        execution: &ChainSigningExecution,
        claim: &BitcoinExecutionClaim,
        now: i64,
    ) -> Result<[u8; 64], String>;
}

struct BitcoinExecutorState {
    coordinator: Box<dyn BitcoinThresholdCoordinator>,
    claims: Box<dyn BitcoinExecutionClaimStore>,
}

/// Exact-routed Bitcoin threshold executor.
pub struct BitcoinThresholdChainSigningExecutor {
    key: ChainSigningExecutorKey,
    profile: SignerProfile,
    suite: BitcoinChainSuite,
    state: Mutex<BitcoinExecutorState>,
}

impl core::fmt::Debug for BitcoinThresholdChainSigningExecutor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BitcoinThresholdChainSigningExecutor")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl BitcoinThresholdChainSigningExecutor {
    pub fn new(
        profile: SignerProfile,
        suite: BitcoinChainSuite,
        coordinator: Box<dyn BitcoinThresholdCoordinator>,
        claims: Box<dyn BitcoinExecutionClaimStore>,
    ) -> Result<Self, SigningJobError> {
        if profile.chain_scope.chain != ChainId::Bitcoin
            || profile.signing_suite_id != SigningSuiteId::BITCOIN_BIP340_FROST_V1
            || profile.backend_requirement != SignerBackendRequirement::FrostSecp256k1Tr
            || profile.threshold != 2
            || profile.max_signers != 3
            || suite.scope() != profile.chain_scope
            || profile.verification_key.as_slice() != suite.output_key().serialize()
        {
            return Err(SigningJobError::InvalidProfile(
                "Bitcoin executor requires the registered 2-of-3 FROST Taproot profile".to_owned(),
            ));
        }
        let key = ChainSigningExecutorKey {
            profile_id: profile.profile_id,
            signing_suite_id: profile.signing_suite_id,
            backend_requirement: profile.backend_requirement.as_str().to_owned(),
        };
        Ok(Self {
            key,
            profile,
            suite,
            state: Mutex::new(BitcoinExecutorState {
                coordinator,
                claims,
            }),
        })
    }

    fn validate_execution(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<BitcoinExecutionClaim, SigningJobError> {
        let job = &execution.job;
        if job.profile_id != self.profile.profile_id
            || job.wallet_id != self.profile.wallet_id
            || job.chain_scope != self.profile.chain_scope
            || job.signing_suite_id != self.profile.signing_suite_id
            || job.backend_requirement != self.profile.backend_requirement
            || job.review.scope != job.chain_scope
            || job.review_binding.chain_scope != job.chain_scope
            || job.review_binding.signing_suite_id != job.signing_suite_id
            || job.review_binding.signer_set_id != self.profile.signer_set_id
            || job.review_binding.signer_set_epoch != self.profile.signer_epoch
            || job.review_binding.review_schema_version != job.review.schema_version
            || job.review_binding.review_digest != job.review.review_digest
            || job.session_id == [0; 32]
            || execution.operation_binding_digest == [0; 32]
            || now < job.created_at
            || now > job.expires_at
        {
            return Err(SigningJobError::ProfileDrift);
        }

        let reproduced = self
            .suite
            .review_transaction(&job.review.reviewed_material)
            .map_err(|error| SigningJobError::Review(error.to_string()))?;
        if reproduced != job.review {
            return Err(SigningJobError::Review(
                "Bitcoin transaction review does not reproduce".to_owned(),
            ));
        }

        Ok(BitcoinExecutionClaim {
            profile_id: job.profile_id,
            wallet_id: job.wallet_id,
            signing_suite_id: job.signing_suite_id,
            backend_requirement: job.backend_requirement,
            session_id: job.session_id,
            review_domain_separator: job.review_binding.domain_separator(),
            signing_message_digest: job.review.signing_message_digest,
            operation_binding_digest: execution.operation_binding_digest,
            claimed_at: now,
        })
    }
}

impl ChainSigningExecutor for BitcoinThresholdChainSigningExecutor {
    fn key(&self) -> ChainSigningExecutorKey {
        self.key.clone()
    }

    fn execute(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<VerifiedChainSignature, SigningJobError> {
        let claim = self.validate_execution(execution, now)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| SigningJobError::Backend("Bitcoin executor lock poisoned".to_owned()))?;
        state
            .claims
            .claim(claim.replay_key(), &claim)
            .map_err(SigningJobError::Backend)?;
        let aggregate_signature = state
            .coordinator
            .sign(execution, &claim, now)
            .map_err(SigningJobError::Backend)?;
        let finalized = self
            .suite
            .finalize_reviewed_key_spend(&execution.job.review, aggregate_signature)
            .map_err(|error| SigningJobError::FinalVerification(error.to_string()))?;
        let finalized_signature = finalized.transaction().input[finalized.input_index()]
            .witness
            .iter()
            .next()
            .ok_or_else(|| {
                SigningJobError::FinalVerification("Bitcoin witness is missing".to_owned())
            })?
            .to_vec();
        VerifiedChainSignature::verify(&self.suite, execution, finalized_signature)
    }
}
