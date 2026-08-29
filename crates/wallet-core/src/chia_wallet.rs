//! Chia threshold SpendBundle executor.

use std::sync::Mutex;

use catomicals_chain_chia::{BlsSignatureShare, ThresholdBlsCommitment};
use catomicals_chain_domain::{ChainId, ChainSuite};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};

use crate::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SignerProfile,
    SigningJob, SigningJobError, VerifiedChainSignature,
};

/// Durable claim for one reviewed Chia signing operation. Providers may keep
/// their own request replay records as well; this wallet-level claim prevents
/// a restarted executor from asking two shares to sign twice.
pub trait ChiaExecutionClaimStore: Send {
    fn claim(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String>;
}

/// Opaque signer-side share boundary. `secret_ref` is a handle used only to
/// prove that the two providers are independently configured; no share bytes
/// enter wallet memory or durable state.
pub trait ChiaThresholdShareProvider: Send {
    fn secret_ref(&self) -> &str;

    fn sign_reviewed_share(
        &mut self,
        job: &SigningJob,
        commitment: &ThresholdBlsCommitment,
    ) -> Result<BlsSignatureShare, String>;
}

/// Chain finalization boundary. Implementations combine the two verified
/// public partials with the exact reviewed standard spend and return the
/// canonical Streamable SpendBundle bytes.
pub trait ChiaThresholdSpendFinalizer: Send {
    fn finalize(
        &mut self,
        job: &SigningJob,
        commitment: &ThresholdBlsCommitment,
        shares: &[BlsSignatureShare; 2],
    ) -> Result<Vec<u8>, String>;
}

struct ChiaExecutorState {
    providers: [Box<dyn ChiaThresholdShareProvider>; 2],
    finalizer: Box<dyn ChiaThresholdSpendFinalizer>,
    claims: Box<dyn ChiaExecutionClaimStore>,
}

pub struct ChiaThresholdChainSigningExecutor {
    key: ChainSigningExecutorKey,
    profile: SignerProfile,
    suite: Box<dyn ChainSuite>,
    commitment: ThresholdBlsCommitment,
    state: Mutex<ChiaExecutorState>,
}

impl core::fmt::Debug for ChiaThresholdChainSigningExecutor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChiaThresholdChainSigningExecutor")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl ChiaThresholdChainSigningExecutor {
    pub fn new(
        profile: SignerProfile,
        suite: Box<dyn ChainSuite>,
        commitment: ThresholdBlsCommitment,
        first: Box<dyn ChiaThresholdShareProvider>,
        second: Box<dyn ChiaThresholdShareProvider>,
        finalizer: Box<dyn ChiaThresholdSpendFinalizer>,
        claims: Box<dyn ChiaExecutionClaimStore>,
    ) -> Result<Self, SigningJobError> {
        if profile.chain_scope.chain != ChainId::Chia
            || profile.signing_suite_id != SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1
            || profile.backend_requirement != SignerBackendRequirement::ChiaBlsAugThreshold2of3
            || profile.threshold != 2
            || profile.max_signers != 3
            || profile.verification_key.as_slice() != commitment.group_public_key()
            || suite.scope() != profile.chain_scope
            || first.secret_ref().is_empty()
            || second.secret_ref().is_empty()
            || first.secret_ref() == second.secret_ref()
        {
            return Err(SigningJobError::InvalidProfile(
                "Chia executor requires two distinct opaque 2-of-3 BLS providers".to_owned(),
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
            commitment,
            state: Mutex::new(ChiaExecutorState {
                providers: [first, second],
                finalizer,
                claims,
            }),
        })
    }

    fn validate_execution(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<(), SigningJobError> {
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
            || now < job.created_at
            || now > job.expires_at
        {
            return Err(SigningJobError::ProfileDrift);
        }
        Ok(())
    }
}

impl ChainSigningExecutor for ChiaThresholdChainSigningExecutor {
    fn key(&self) -> ChainSigningExecutorKey {
        self.key.clone()
    }

    fn execute(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<VerifiedChainSignature, SigningJobError> {
        self.validate_execution(execution, now)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| SigningJobError::Backend("Chia executor lock poisoned".to_owned()))?;
        state
            .claims
            .claim(
                execution.job.session_id,
                &execution.job.review_binding.domain_separator(),
                execution.operation_binding_digest,
            )
            .map_err(SigningJobError::Backend)?;
        let first = state.providers[0]
            .sign_reviewed_share(&execution.job, &self.commitment)
            .map_err(SigningJobError::Backend)?;
        let second = state.providers[1]
            .sign_reviewed_share(&execution.job, &self.commitment)
            .map_err(SigningJobError::Backend)?;
        if first.participant_id == second.participant_id {
            return Err(SigningJobError::Backend(
                "Chia threshold providers returned the same participant".to_owned(),
            ));
        }
        let ChiaExecutorState { finalizer, .. } = &mut *state;
        let finalized = finalizer
            .finalize(&execution.job, &self.commitment, &[first, second])
            .map_err(SigningJobError::Backend)?;
        VerifiedChainSignature::verify(self.suite.as_ref(), execution, finalized)
    }
}
