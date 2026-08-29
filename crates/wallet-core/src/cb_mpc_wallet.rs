//! Wallet scheduler adapter for the cb-mpc threshold ECDSA backend.

use catomicals_cb_mpc_signer::{
    ApprovedCbMpcSignRequest, ApprovedCbMpcSignRequestParts, CanonicalEcdsaSignature,
    CbMpcCancellation, CbMpcError, CbMpcProfile, CbMpcRuntime, CbMpcSignerSet, LocalCbMpcProvider,
    PartyId, SessionClaimNamespace, SessionTransport,
};
use catomicals_chain_domain::{ChainSuite, ReviewArtifact};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement};
use uuid::Uuid;

use crate::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SignerProfile,
    SigningJob, SigningJobError, VerifiedChainSignature,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningJobRequest {
    pub job_id: Uuid,
    pub intent_id: Uuid,
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub online_parties: [PartyId; 2],
    pub receiver: PartyId,
    pub session_id: [u8; 32],
    pub expires_at: i64,
}

pub trait CbMpcConsensusSignatureAssembler: Send + Sync {
    fn assemble(
        &self,
        job: &SigningJob,
        signature: &CanonicalEcdsaSignature,
    ) -> Result<Vec<u8>, String>;
}

pub struct CbMpcWalletCoordinator {
    profile: SignerProfile,
    cb_mpc_profile: CbMpcProfile,
    signer_set: CbMpcSignerSet,
    group_public_key: [u8; 33],
    runtime: CbMpcRuntime,
}

/// Owning wallet-node executor. Provider shares stay inside the opaque
/// providers, transports expose only protocol messages, and only a chain-
/// verified final signature crosses back into the durable wallet state.
pub struct CbMpcChainSigningExecutor {
    key: ChainSigningExecutorKey,
    suite: Box<dyn ChainSuite>,
    coordinator: CbMpcWalletCoordinator,
    providers: [LocalCbMpcProvider; 2],
    transports: [Box<dyn SessionTransport>; 2],
    assembler: Box<dyn CbMpcConsensusSignatureAssembler>,
    cancellation: CbMpcCancellation,
}

impl CbMpcChainSigningExecutor {
    pub fn new(
        suite: Box<dyn ChainSuite>,
        coordinator: CbMpcWalletCoordinator,
        providers: [LocalCbMpcProvider; 2],
        transports: [Box<dyn SessionTransport>; 2],
        assembler: Box<dyn CbMpcConsensusSignatureAssembler>,
        cancellation: CbMpcCancellation,
    ) -> Result<Self, SigningJobError> {
        if suite.scope() != coordinator.profile.chain_scope {
            return Err(SigningJobError::ProfileDrift);
        }
        let key = ChainSigningExecutorKey {
            profile_id: coordinator.profile.profile_id,
            signing_suite_id: coordinator.profile.signing_suite_id,
            backend_requirement: coordinator.profile.backend_requirement.as_str().to_owned(),
        };
        Ok(Self {
            key,
            suite,
            coordinator,
            providers,
            transports,
            assembler,
            cancellation,
        })
    }
}

impl ChainSigningExecutor for CbMpcChainSigningExecutor {
    fn key(&self) -> ChainSigningExecutorKey {
        self.key.clone()
    }

    fn execute(
        &self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<VerifiedChainSignature, SigningJobError> {
        let signature = self.coordinator.sign_job(
            self.suite.as_ref(),
            &execution.job,
            [&self.providers[0], &self.providers[1]],
            [self.transports[0].as_ref(), self.transports[1].as_ref()],
            self.assembler.as_ref(),
            &self.cancellation,
            now,
        )?;
        VerifiedChainSignature::verify(self.suite.as_ref(), execution, signature)
    }
}

impl CbMpcWalletCoordinator {
    pub fn new(
        profile: SignerProfile,
        signer_set: CbMpcSignerSet,
        runtime: CbMpcRuntime,
    ) -> Result<Self, SigningJobError> {
        if profile.backend_requirement != SignerBackendRequirement::CbMpcThresholdEcdsa
            || profile.threshold != 2
            || profile.max_signers != 3
            || profile.signer_set_id != signer_set.id()
            || profile.signer_epoch != signer_set.epoch()
            || profile.verification_key.len() != 33
        {
            return Err(SigningJobError::ProfileDrift);
        }
        let cb_mpc_profile = CbMpcProfile::from_signing_suite_id(profile.signing_suite_id)
            .ok_or(SigningJobError::ProfileDrift)?;
        if cb_mpc_profile.chain_id() != profile.chain_scope.chain {
            return Err(SigningJobError::ProfileDrift);
        }
        let group_public_key = profile
            .verification_key
            .as_slice()
            .try_into()
            .map_err(|_| SigningJobError::ProfileDrift)?;
        Ok(Self {
            profile,
            cb_mpc_profile,
            signer_set,
            group_public_key,
            runtime,
        })
    }

    pub fn prepare_job(
        &self,
        suite: &dyn ChainSuite,
        transaction_material: &[u8],
        request: SigningJobRequest,
        now: i64,
    ) -> Result<SigningJob, SigningJobError> {
        if suite.scope() != self.profile.chain_scope || request.job_id.is_nil() {
            return Err(SigningJobError::ProfileDrift);
        }
        let review = suite
            .review_transaction(transaction_material)
            .map_err(|error| SigningJobError::Review(error.to_string()))?;
        let review_binding = ReviewBinding::new(
            self.profile.chain_scope,
            self.profile.signing_suite_id,
            self.profile.signer_set_id.clone(),
            self.profile.signer_epoch,
            review.schema_version,
            review.review_digest,
        )
        .map_err(|error| SigningJobError::Review(error.to_string()))?;
        let job = SigningJob {
            job_id: request.job_id,
            intent_id: request.intent_id,
            profile_id: self.profile.profile_id,
            wallet_id: self.profile.wallet_id,
            chain_scope: self.profile.chain_scope,
            signing_suite_id: self.profile.signing_suite_id,
            backend_requirement: self.profile.backend_requirement,
            review,
            review_binding,
            policy_snapshot_digest: request.policy_snapshot_digest,
            chain_snapshot_digest: request.chain_snapshot_digest,
            online_parties: request
                .online_parties
                .clone()
                .map(|party| party.as_str().to_owned()),
            receiver: request.receiver.as_str().to_owned(),
            session_id: request.session_id,
            expires_at: request.expires_at,
            created_at: now,
        };
        self.approved_request(&job, request.online_parties, request.receiver, now)?;
        Ok(job)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_job(
        &self,
        suite: &dyn ChainSuite,
        job: &SigningJob,
        providers: [&LocalCbMpcProvider; 2],
        transports: [&dyn SessionTransport; 2],
        assembler: &dyn CbMpcConsensusSignatureAssembler,
        cancellation: &CbMpcCancellation,
        now: i64,
    ) -> Result<Vec<u8>, SigningJobError> {
        let online_parties = [providers[0].party().clone(), providers[1].party().clone()];
        if online_parties
            .iter()
            .map(PartyId::as_str)
            .ne(job.online_parties.iter().map(String::as_str))
            || providers
                .iter()
                .all(|provider| provider.party().as_str() != job.receiver)
        {
            return Err(SigningJobError::ProfileDrift);
        }
        let approved = self.approved_request(
            job,
            online_parties,
            PartyId::new(job.receiver.clone()).map_err(|_| SigningJobError::ProfileDrift)?,
            now,
        )?;
        let signature = self
            .runtime
            .sign_with_providers(&approved, providers, transports, cancellation, now)
            .map_err(|error| match error {
                CbMpcError::Interrupted | CbMpcError::TransportTerminated => {
                    SigningJobError::Interrupted
                }
                CbMpcError::TransportTimeout => SigningJobError::TimedOut,
                other => SigningJobError::Backend(other.to_string()),
            })?;
        let finalized = assembler
            .assemble(job, &signature)
            .map_err(SigningJobError::Backend)?;
        suite
            .verify_finalized_signature(&job.review, &finalized)
            .map_err(|error| SigningJobError::FinalVerification(error.to_string()))?;
        Ok(finalized)
    }

    fn approved_request(
        &self,
        job: &SigningJob,
        online_parties: [PartyId; 2],
        receiver: PartyId,
        now: i64,
    ) -> Result<ApprovedCbMpcSignRequest, SigningJobError> {
        if job.profile_id != self.profile.profile_id
            || job.wallet_id != self.profile.wallet_id
            || job.chain_scope != self.profile.chain_scope
            || job.signing_suite_id != self.profile.signing_suite_id
            || job.backend_requirement != self.profile.backend_requirement
        {
            return Err(SigningJobError::ProfileDrift);
        }
        ApprovedCbMpcSignRequest::new(
            ApprovedCbMpcSignRequestParts {
                claim_namespace: SessionClaimNamespace::new(
                    *self.profile.wallet_id.as_bytes(),
                    *self.profile.profile_id.as_bytes(),
                    self.profile.signing_suite_id,
                    self.profile.backend_requirement,
                )
                .map_err(|error| SigningJobError::Backend(error.to_string()))?,
                profile: self.cb_mpc_profile,
                review: ReviewArtifact::clone(&job.review),
                review_binding: job.review_binding.clone(),
                signer_set: self.signer_set.clone(),
                group_public_key: self.group_public_key,
                policy_snapshot_digest: job.policy_snapshot_digest,
                chain_snapshot_digest: job.chain_snapshot_digest,
                online_parties: online_parties.to_vec(),
                receiver,
                session_id: job.session_id,
                expires_at: job.expires_at,
            },
            now,
        )
        .map_err(|error| SigningJobError::Backend(error.to_string()))
    }
}
