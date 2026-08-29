//! Ergo native Sigma P2PK threshold executor.

use std::sync::Mutex;

use catomicals_chain_domain::{ChainId, ChainSuite};
use catomicals_chain_ergo::{
    ErgoReviewMaterialV1, ErgoThresholdCommitment, ErgoThresholdCommitments,
    ErgoThresholdSignatureShare, ErgoThresholdSigningPackage, ErgoThresholdSigningRequest,
    aggregate_threshold_p2pk_proof_2_of_3, assemble_threshold_p2pk_transaction,
};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use sha2::{Digest, Sha256};

use crate::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SignerProfile,
    SigningJob, SigningJobError, VerifiedChainSignature,
};

/// Durable, restart-safe replay boundary owned outside the wallet executor.
pub trait ErgoNonceReplayStore: Send {
    fn claim_operation(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String>;
}

/// Opaque signer provider. It owns the share and its chain-level
/// `ErgoThresholdNonceReplayGuard`; wallet code sees only commitments and
/// publicly verifiable partial responses.
pub trait ErgoThresholdShareProvider: Send {
    fn secret_ref(&self) -> &str;

    fn reserve(
        &mut self,
        request: &ErgoThresholdSigningRequest,
    ) -> Result<ErgoThresholdCommitments, String>;

    fn sign(
        &mut self,
        request: &ErgoThresholdSigningRequest,
        package: &ErgoThresholdSigningPackage,
    ) -> Result<ErgoThresholdSignatureShare, String>;
}

pub trait ErgoThresholdProofAssembler: Send {
    fn finalize(
        &mut self,
        job: &SigningJob,
        commitment: &ErgoThresholdCommitment,
        providers: &mut [&mut dyn ErgoThresholdShareProvider; 2],
    ) -> Result<Vec<u8>, String>;
}

/// Native assembler for the 56-byte Ergo Sigma proof. A separate signing
/// session is derived for every input so provider nonces cannot be reused.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeErgoThresholdProofAssembler;

impl ErgoThresholdProofAssembler for NativeErgoThresholdProofAssembler {
    fn finalize(
        &mut self,
        job: &SigningJob,
        commitment: &ErgoThresholdCommitment,
        providers: &mut [&mut dyn ErgoThresholdShareProvider; 2],
    ) -> Result<Vec<u8>, String> {
        let material = ErgoReviewMaterialV1::decode(&job.review.reviewed_material)
            .map_err(|error| error.to_string())?;
        let mut proofs = Vec::with_capacity(material.unsigned_tx.inputs.len());
        for input_index in 0..material.unsigned_tx.inputs.len() {
            let session_id = input_session_id(job.session_id, input_index)?;
            let request =
                ErgoThresholdSigningRequest::new(&job.review, &job.review_binding, session_id)
                    .map_err(|error| error.to_string())?;
            let first = providers[0].reserve(&request)?;
            let second = providers[1].reserve(&request)?;
            if first.participant_id == second.participant_id {
                return Err("Ergo providers returned the same participant".to_owned());
            }
            let package =
                ErgoThresholdSigningPackage::for_review(commitment, &request, &[first, second])
                    .map_err(|error| error.to_string())?;
            let first = providers[0].sign(&request, &package)?;
            let second = providers[1].sign(&request, &package)?;
            proofs.push(
                aggregate_threshold_p2pk_proof_2_of_3(commitment, &package, &[first, second])
                    .map_err(|error| error.to_string())?,
            );
        }
        assemble_threshold_p2pk_transaction(&job.review, &job.review_binding, commitment, &proofs)
            .map_err(|error| error.to_string())
    }
}

fn input_session_id(base: [u8; 32], input_index: usize) -> Result<[u8; 32], String> {
    let input_index = u64::try_from(input_index).map_err(|_| "Ergo input index overflow")?;
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals/ergo-threshold/input-session/v1\0");
    hasher.update(base);
    hasher.update(input_index.to_be_bytes());
    let derived: [u8; 32] = hasher.finalize().into();
    if derived == [0; 32] {
        return Err("derived Ergo signing session is invalid".to_owned());
    }
    Ok(derived)
}

struct ErgoExecutorState {
    providers: [Box<dyn ErgoThresholdShareProvider>; 2],
    assembler: Box<dyn ErgoThresholdProofAssembler>,
    replay: Box<dyn ErgoNonceReplayStore>,
}

pub struct ErgoThresholdChainSigningExecutor {
    key: ChainSigningExecutorKey,
    profile: SignerProfile,
    suite: Box<dyn ChainSuite>,
    commitment: ErgoThresholdCommitment,
    state: Mutex<ErgoExecutorState>,
}

impl core::fmt::Debug for ErgoThresholdChainSigningExecutor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ErgoThresholdChainSigningExecutor")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl ErgoThresholdChainSigningExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: SignerProfile,
        suite: Box<dyn ChainSuite>,
        commitment: ErgoThresholdCommitment,
        first: Box<dyn ErgoThresholdShareProvider>,
        second: Box<dyn ErgoThresholdShareProvider>,
        assembler: Box<dyn ErgoThresholdProofAssembler>,
        replay: Box<dyn ErgoNonceReplayStore>,
    ) -> Result<Self, SigningJobError> {
        if profile.chain_scope.chain != ChainId::Ergo
            || profile.signing_suite_id != SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1
            || profile.backend_requirement != SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
            || profile.threshold != 2
            || profile.max_signers != 3
            || profile.verification_key.as_slice() != commitment.group_public_key()
            || suite.scope() != profile.chain_scope
            || first.secret_ref().is_empty()
            || second.secret_ref().is_empty()
            || first.secret_ref() == second.secret_ref()
        {
            return Err(SigningJobError::InvalidProfile(
                "Ergo executor requires two distinct opaque native P2PK threshold providers"
                    .to_owned(),
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
            state: Mutex::new(ErgoExecutorState {
                providers: [first, second],
                assembler,
                replay,
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

impl ChainSigningExecutor for ErgoThresholdChainSigningExecutor {
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
            .map_err(|_| SigningJobError::Backend("Ergo executor lock poisoned".to_owned()))?;
        state
            .replay
            .claim_operation(
                execution.job.session_id,
                &execution.job.review_binding.domain_separator(),
                execution.operation_binding_digest,
            )
            .map_err(SigningJobError::Backend)?;
        let ErgoExecutorState {
            providers,
            assembler,
            ..
        } = &mut *state;
        let (left, right) = providers.split_at_mut(1);
        let mut providers: [&mut dyn ErgoThresholdShareProvider; 2] =
            [left[0].as_mut(), right[0].as_mut()];
        let finalized = assembler
            .finalize(&execution.job, &self.commitment, &mut providers)
            .map_err(SigningJobError::Backend)?;
        VerifiedChainSignature::verify(self.suite.as_ref(), execution, finalized)
    }
}
