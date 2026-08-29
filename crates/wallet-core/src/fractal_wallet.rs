//! Fractal Bitcoin threshold executor.

use std::sync::Mutex;

use catomicals_chain_bitcoin::{
    FractalFrostExecutionAdapter, FractalFrostSessionContext, FractalFrostSigner,
};
use catomicals_chain_domain::{ChainId, ChainSuite};
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};

use crate::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SignerProfile,
    SigningJobError, VerifiedChainSignature,
};

/// Durable claim boundary for the complete Fractal signing authority tuple.
pub trait FractalExecutionClaimStore: Send {
    fn claim(
        &mut self,
        session_id: [u8; 32],
        review_domain_separator: &[u8],
        bip341_digest: [u8; 32],
        operation_binding_digest: [u8; 32],
    ) -> Result<(), String>;
}

/// Wallet coordinator boundary. Concrete implementations may use the
/// threshold-signer provider protocol and `ThresholdSessionMachine`; secret
/// shares and nonces never cross this interface.
pub trait FractalThresholdCoordinator: Send {
    fn sign(
        &mut self,
        execution: &ChainSigningExecution,
        session: &FractalFrostSessionContext<'_>,
        now: i64,
    ) -> Result<[u8; 64], String>;
}

/// Chain-owned finalizer seam, useful for tests and for keeping the wallet
/// scheduler independent from transaction serialization.
pub trait FractalThresholdFinalizer: Send {
    fn finalize(
        &mut self,
        execution: &ChainSigningExecution,
        coordinator: &mut dyn FractalThresholdCoordinator,
        now: i64,
    ) -> Result<Vec<u8>, String>;
}

/// Production finalizer backed by the Fractal chain adapter. It reproduces the
/// reviewed transaction, asks the coordinator for one aggregate FROST result,
/// and returns only the verified Taproot witness.
pub struct NativeFractalThresholdFinalizer {
    adapter: FractalFrostExecutionAdapter,
}

impl NativeFractalThresholdFinalizer {
    pub const fn new(adapter: FractalFrostExecutionAdapter) -> Self {
        Self { adapter }
    }
}

struct CoordinatorBridge<'a> {
    execution: &'a ChainSigningExecution,
    coordinator: &'a mut dyn FractalThresholdCoordinator,
    now: i64,
}

impl FractalFrostSigner for CoordinatorBridge<'_> {
    fn sign(&mut self, session: &FractalFrostSessionContext<'_>) -> Result<[u8; 64], String> {
        self.coordinator.sign(self.execution, session, self.now)
    }
}

impl FractalThresholdFinalizer for NativeFractalThresholdFinalizer {
    fn finalize(
        &mut self,
        execution: &ChainSigningExecution,
        coordinator: &mut dyn FractalThresholdCoordinator,
        now: i64,
    ) -> Result<Vec<u8>, String> {
        let signing = self
            .adapter
            .prepare(
                &execution.job.review.reviewed_material,
                execution.job.session_id,
            )
            .map_err(|error| error.to_string())?;
        if signing.review() != &execution.job.review
            || signing.review_binding() != &execution.job.review_binding
            || signing.signing_message() != execution.job.review.signing_message_digest
        {
            return Err("Fractal review or signer binding drifted".to_owned());
        }
        let mut bridge = CoordinatorBridge {
            execution,
            coordinator,
            now,
        };
        self.adapter
            .finalize_with_signer(signing, &mut bridge)
            .map(|finalized| finalized.witness().to_vec())
            .map_err(|error| error.to_string())
    }
}

struct FractalExecutorState {
    coordinator: Box<dyn FractalThresholdCoordinator>,
    claims: Box<dyn FractalExecutionClaimStore>,
    finalizer: Box<dyn FractalThresholdFinalizer>,
}

pub struct FractalThresholdChainSigningExecutor {
    key: ChainSigningExecutorKey,
    profile: SignerProfile,
    suite: Box<dyn ChainSuite>,
    state: Mutex<FractalExecutorState>,
}

impl core::fmt::Debug for FractalThresholdChainSigningExecutor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FractalThresholdChainSigningExecutor")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl FractalThresholdChainSigningExecutor {
    pub fn new(
        profile: SignerProfile,
        suite: Box<dyn ChainSuite>,
        coordinator: Box<dyn FractalThresholdCoordinator>,
        claims: Box<dyn FractalExecutionClaimStore>,
        finalizer: Box<dyn FractalThresholdFinalizer>,
    ) -> Result<Self, SigningJobError> {
        if profile.chain_scope.chain != ChainId::FractalBitcoin
            || profile.signing_suite_id != SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1
            || profile.backend_requirement != SignerBackendRequirement::FrostSecp256k1Tr
            || profile.threshold != 2
            || profile.max_signers != 3
            || suite.scope() != profile.chain_scope
        {
            return Err(SigningJobError::InvalidProfile(
                "Fractal executor requires the registered 2-of-3 FROST profile".to_owned(),
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
            state: Mutex::new(FractalExecutorState {
                coordinator,
                claims,
                finalizer,
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

impl ChainSigningExecutor for FractalThresholdChainSigningExecutor {
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
            .map_err(|_| SigningJobError::Backend("Fractal executor lock poisoned".to_owned()))?;
        state
            .claims
            .claim(
                execution.job.session_id,
                &execution.job.review_binding.domain_separator(),
                execution.job.review.signing_message_digest,
                execution.operation_binding_digest,
            )
            .map_err(SigningJobError::Backend)?;
        let FractalExecutorState {
            coordinator,
            finalizer,
            ..
        } = &mut *state;
        let finalized = finalizer
            .finalize(execution, coordinator.as_mut(), now)
            .map_err(SigningJobError::Backend)?;
        VerifiedChainSignature::verify(self.suite.as_ref(), execution, finalized)
    }
}
