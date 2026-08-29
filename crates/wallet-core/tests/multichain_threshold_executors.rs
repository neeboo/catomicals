use std::sync::{Arc, Mutex};

use catomicals_chain_chia::{
    BlsSignatureShare, ThresholdBlsCommitment, ThresholdBlsDealerKeyKind,
    dealer_split_threshold_secret_2_of_3 as split_chia,
};
use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ChiaNetwork, ErgoNetwork,
    FractalBitcoinNetwork, ReviewArtifact, ReviewContractError,
};
use catomicals_chain_ergo::{
    ErgoThresholdCommitment, ErgoThresholdCommitments, ErgoThresholdSignatureShare,
    ErgoThresholdSigningPackage, ErgoThresholdSigningRequest,
    dealer_split_threshold_secret_2_of_3 as split_ergo,
};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{
    ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorRegistry,
    ChiaExecutionClaimStore, ChiaThresholdChainSigningExecutor, ChiaThresholdShareProvider,
    ChiaThresholdSpendFinalizer, ErgoNonceReplayStore, ErgoThresholdChainSigningExecutor,
    ErgoThresholdProofAssembler, ErgoThresholdShareProvider, FractalExecutionClaimStore,
    FractalThresholdChainSigningExecutor, FractalThresholdCoordinator, FractalThresholdFinalizer,
    SignerProfile, SigningJob, SigningJobError,
};
use uuid::Uuid;

#[derive(Clone)]
struct AcceptingSuite {
    scope: ChainScope,
    accepted: Vec<u8>,
}

impl ChainSuite for AcceptingSuite {
    fn scope(&self) -> ChainScope {
        self.scope
    }
    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: true,
            transaction_review: true,
            final_signature_verification: true,
            broadcast: false,
        }
    }
    fn review_transaction(&self, _: &[u8]) -> Result<ReviewArtifact, ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation { operation: "test" })
    }
    fn verify_finalized_signature(
        &self,
        _: &ReviewArtifact,
        bytes: &[u8],
    ) -> Result<(), ReviewContractError> {
        if bytes == self.accepted {
            Ok(())
        } else {
            Err(ReviewContractError::InvalidFinalizedSignature(
                "wrong bytes".into(),
            ))
        }
    }
}

fn manual_profile(
    scope: ChainScope,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
) -> SignerProfile {
    SignerProfile {
        profile_id: Uuid::from_bytes([3; 16]),
        wallet_id: Uuid::from_bytes([4; 16]),
        chain_scope: scope,
        signing_suite_id: suite,
        backend_requirement: backend,
        signer_set_id: "set".into(),
        authorization_signer_id: "auth".into(),
        signer_epoch: 1,
        threshold: 2,
        max_signers: 3,
        verification_key: vec![9; 48],
        secret_ref: "opaque://group".into(),
    }
}

fn execution(profile: &SignerProfile) -> ChainSigningExecution {
    let review = ReviewArtifact::new(
        profile.chain_scope,
        [1; 32],
        [2; 32],
        "review".into(),
        vec![7],
    )
    .unwrap();
    let binding = ReviewBinding::new(
        profile.chain_scope,
        profile.signing_suite_id,
        profile.signer_set_id.clone(),
        profile.signer_epoch,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();
    ChainSigningExecution {
        operation_binding_digest: [8; 32],
        job: SigningJob {
            job_id: Uuid::from_bytes([5; 16]),
            intent_id: Uuid::from_bytes([6; 16]),
            profile_id: profile.profile_id,
            wallet_id: profile.wallet_id,
            chain_scope: profile.chain_scope,
            signing_suite_id: profile.signing_suite_id,
            backend_requirement: profile.backend_requirement,
            review,
            review_binding: binding,
            policy_snapshot_digest: [10; 32],
            chain_snapshot_digest: [11; 32],
            online_parties: ["one".into(), "two".into()],
            receiver: "one".into(),
            session_id: [12; 32],
            expires_at: 200,
            created_at: 100,
        },
    }
}

struct ClaimStore(Arc<Mutex<usize>>);
impl FractalExecutionClaimStore for ClaimStore {
    fn claim(&mut self, _: [u8; 32], _: &[u8], _: [u8; 32], _: [u8; 32]) -> Result<(), String> {
        let mut calls = self.0.lock().unwrap();
        if *calls != 0 {
            return Err("replay".into());
        }
        *calls += 1;
        Ok(())
    }
}
struct FractalCoordinator;
impl FractalThresholdCoordinator for FractalCoordinator {
    fn sign(
        &mut self,
        _: &ChainSigningExecution,
        _: &catomicals_chain_bitcoin::FractalFrostSessionContext<'_>,
        _: i64,
    ) -> Result<[u8; 64], String> {
        Ok([42; 64])
    }
}
struct FractalFinalizer;
impl FractalThresholdFinalizer for FractalFinalizer {
    fn finalize(
        &mut self,
        _: &ChainSigningExecution,
        _: &mut dyn FractalThresholdCoordinator,
        _: i64,
    ) -> Result<Vec<u8>, String> {
        Ok(vec![42; 64])
    }
}

#[test]
fn fractal_executor_key_is_exact_and_replay_claim_survives_second_dispatch() {
    let scope =
        ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet));
    let profile = manual_profile(
        scope,
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
    );
    let claims = Arc::new(Mutex::new(0));
    let executor = FractalThresholdChainSigningExecutor::new(
        profile.clone(),
        Box::new(AcceptingSuite {
            scope,
            accepted: vec![42; 64],
        }),
        Box::new(FractalCoordinator),
        Box::new(ClaimStore(Arc::clone(&claims))),
        Box::new(FractalFinalizer),
    )
    .unwrap();
    let run = execution(&profile);
    executor.execute(&run, 150).unwrap();
    assert!(matches!(
        executor.execute(&run, 151),
        Err(SigningJobError::Backend(_))
    ));
    let mut drifted = run.clone();
    drifted.job.profile_id = Uuid::new_v4();
    assert!(matches!(
        executor.execute(&drifted, 152),
        Err(SigningJobError::ProfileDrift)
    ));
}

struct ChiaProvider(&'static str, u16);
impl ChiaThresholdShareProvider for ChiaProvider {
    fn secret_ref(&self) -> &str {
        self.0
    }
    fn sign_reviewed_share(
        &mut self,
        _: &SigningJob,
        _: &ThresholdBlsCommitment,
    ) -> Result<BlsSignatureShare, String> {
        Ok(BlsSignatureShare::new(self.1, [self.1 as u8; 96]))
    }
}
struct ChiaClaims(Arc<Mutex<usize>>);
impl ChiaExecutionClaimStore for ChiaClaims {
    fn claim(&mut self, _: [u8; 32], _: &[u8], _: [u8; 32]) -> Result<(), String> {
        let mut calls = self.0.lock().unwrap();
        if *calls != 0 {
            return Err("replay".into());
        }
        *calls += 1;
        Ok(())
    }
}
struct ChiaFinalizer;
impl ChiaThresholdSpendFinalizer for ChiaFinalizer {
    fn finalize(
        &mut self,
        _: &SigningJob,
        _: &ThresholdBlsCommitment,
        _: &[BlsSignatureShare; 2],
    ) -> Result<Vec<u8>, String> {
        Ok(vec![31])
    }
}

#[test]
fn chia_executor_uses_two_opaque_providers_and_chain_verifies_final_bundle() {
    let scope = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    let mut profile = manual_profile(
        scope,
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
    );
    let dealer = split_chia(ThresholdBlsDealerKeyKind::FinalSigningKey, [1; 32], [2; 32]).unwrap();
    let commitment = dealer.commitment().clone();
    profile.verification_key = commitment.group_public_key().to_vec();
    let claims = Arc::new(Mutex::new(0));
    let executor = ChiaThresholdChainSigningExecutor::new(
        profile.clone(),
        Box::new(AcceptingSuite {
            scope,
            accepted: vec![31],
        }),
        commitment,
        Box::new(ChiaProvider("hsm://share/1", 1)),
        Box::new(ChiaProvider("hsm://share/2", 2)),
        Box::new(ChiaFinalizer),
        Box::new(ChiaClaims(Arc::clone(&claims))),
    )
    .unwrap();
    assert_eq!(executor.key().profile_id, profile.profile_id);
    let run = execution(&profile);
    executor.execute(&run, 150).unwrap();
    let restarted = ChiaThresholdChainSigningExecutor::new(
        profile.clone(),
        Box::new(AcceptingSuite {
            scope,
            accepted: vec![31],
        }),
        dealer.commitment().clone(),
        Box::new(ChiaProvider("hsm://share/1", 1)),
        Box::new(ChiaProvider("hsm://share/2", 2)),
        Box::new(ChiaFinalizer),
        Box::new(ChiaClaims(Arc::clone(&claims))),
    )
    .unwrap();
    assert!(matches!(
        restarted.execute(&run, 151),
        Err(SigningJobError::Backend(_))
    ));
    let mut registry = ChainSigningExecutorRegistry::default();
    registry.register(Box::new(restarted));
    assert!(registry.resolve(&run.job).is_some());
    let mut wrong = run.job.clone();
    wrong.backend_requirement = SignerBackendRequirement::ChiaBlsAug;
    assert!(registry.resolve(&wrong).is_none());
}

struct ErgoReplay(Arc<Mutex<usize>>);
impl ErgoNonceReplayStore for ErgoReplay {
    fn claim_operation(&mut self, _: [u8; 32], _: &[u8], _: [u8; 32]) -> Result<(), String> {
        let mut calls = self.0.lock().unwrap();
        if *calls != 0 {
            return Err("replay".into());
        }
        *calls += 1;
        Ok(())
    }
}
struct ErgoProvider(&'static str);
impl ErgoThresholdShareProvider for ErgoProvider {
    fn secret_ref(&self) -> &str {
        self.0
    }
    fn reserve(
        &mut self,
        _: &ErgoThresholdSigningRequest,
    ) -> Result<ErgoThresholdCommitments, String> {
        Err("fixture only".into())
    }
    fn sign(
        &mut self,
        _: &ErgoThresholdSigningRequest,
        _: &ErgoThresholdSigningPackage,
    ) -> Result<ErgoThresholdSignatureShare, String> {
        Err("fixture only".into())
    }
}
struct ErgoAssembler;
impl ErgoThresholdProofAssembler for ErgoAssembler {
    fn finalize(
        &mut self,
        _: &SigningJob,
        _: &ErgoThresholdCommitment,
        _: &mut [&mut dyn ErgoThresholdShareProvider; 2],
    ) -> Result<Vec<u8>, String> {
        Ok(vec![56])
    }
}

#[test]
fn ergo_executor_rejects_duplicate_secret_handles_before_signing() {
    let scope = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    let mut profile = manual_profile(
        scope,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
    );
    let dealer = split_ergo([1; 32], [2; 32]).unwrap();
    let commitment = dealer.commitment().clone();
    profile.verification_key = commitment.group_public_key().to_vec();
    let error = ErgoThresholdChainSigningExecutor::new(
        profile,
        Box::new(AcceptingSuite {
            scope,
            accepted: vec![56],
        }),
        commitment,
        Box::new(ErgoProvider("hsm://same")),
        Box::new(ErgoProvider("hsm://same")),
        Box::new(ErgoAssembler),
        Box::new(ErgoReplay(Arc::new(Mutex::new(0)))),
    )
    .unwrap_err();
    assert!(matches!(error, SigningJobError::InvalidProfile(_)));
}

#[test]
fn ergo_executor_finalizes_once_and_restart_preserves_replay_claim() {
    let scope = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    let mut profile = manual_profile(
        scope,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
    );
    let dealer = split_ergo([1; 32], [2; 32]).unwrap();
    let commitment = dealer.commitment().clone();
    profile.verification_key = commitment.group_public_key().to_vec();
    let replay = Arc::new(Mutex::new(0));
    let make = || {
        ErgoThresholdChainSigningExecutor::new(
            profile.clone(),
            Box::new(AcceptingSuite {
                scope,
                accepted: vec![56],
            }),
            commitment.clone(),
            Box::new(ErgoProvider("hsm://share/1")),
            Box::new(ErgoProvider("hsm://share/2")),
            Box::new(ErgoAssembler),
            Box::new(ErgoReplay(Arc::clone(&replay))),
        )
        .unwrap()
    };
    let run = execution(&profile);
    make().execute(&run, 150).unwrap();
    assert!(matches!(
        make().execute(&run, 151),
        Err(SigningJobError::Backend(_))
    ));
}
