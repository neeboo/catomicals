use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash, sighash::TapSighashType, transaction,
};
use catomicals_chain_bitcoin::{
    BitcoinChainSuite, TaprootKeySpendRequest, TaprootReviewMaterial,
    derive_p2tr_output_key_address,
};
use catomicals_chain_domain::{BitcoinNetwork, ChainNetwork, ChainScope, ChainSuite};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    AuthorizationError, FrostCoordinator, LocalDkgOutput, LocalFrostParticipant, NonceGuard,
    SigningAuthorization, group_pubkey_xonly, participant_identifier, run_local_dkg,
    signature_to_bytes,
};
use catomicals_wallet::{
    BitcoinExecutionClaim, BitcoinExecutionClaimStore, BitcoinThresholdChainSigningExecutor,
    BitcoinThresholdCoordinator, ChainSigningExecution, ChainSigningExecutor, SignerProfile,
    SigningJob, SigningJobError,
};
use uuid::Uuid;

#[derive(Debug)]
struct ExactAuthorization {
    session_id: [u8; 32],
    message: [u8; 32],
    signer_id: u16,
    consumed: bool,
}

impl SigningAuthorization for ExactAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        _now: i64,
    ) -> Result<(), AuthorizationError> {
        if self.consumed {
            return Err(AuthorizationError::AlreadyConsumed);
        }
        if session_id != &self.session_id {
            return Err(AuthorizationError::WrongSession);
        }
        if message != &self.message {
            return Err(AuthorizationError::WrongMessage);
        }
        if signer_id != self.signer_id {
            return Err(AuthorizationError::WrongSigner);
        }
        self.consumed = true;
        Ok(())
    }
}

struct RealCoordinator(Option<LocalDkgOutput>);

impl BitcoinThresholdCoordinator for RealCoordinator {
    fn sign(
        &mut self,
        execution: &ChainSigningExecution,
        claim: &BitcoinExecutionClaim,
        now: i64,
    ) -> Result<[u8; 64], String> {
        assert_eq!(claim.profile_id, execution.job.profile_id);
        assert_eq!(claim.signing_suite_id, execution.job.signing_suite_id);
        assert_eq!(claim.backend_requirement, execution.job.backend_requirement);
        assert_eq!(claim.session_id, execution.job.session_id);
        assert_eq!(
            claim.signing_message_digest,
            execution.job.review.signing_message_digest
        );
        assert_eq!(
            claim.operation_binding_digest,
            execution.operation_binding_digest
        );
        assert_eq!(claim.claimed_at, now);
        assert_eq!(
            claim.review_domain_separator,
            execution.job.review_binding.domain_separator()
        );

        let mut dkg = self.0.take().ok_or("coordinator already consumed")?;
        let mut coordinator = FrostCoordinator::new(
            claim.session_id,
            claim.signing_message_digest,
            2,
            dkg.public_key_package.clone(),
        );
        let mut participants = BTreeMap::new();
        for signer_id in [1_u16, 2] {
            let identifier = participant_identifier(signer_id).map_err(|e| e.to_string())?;
            let key = dkg
                .key_packages
                .remove(&identifier)
                .ok_or("missing participant key")?;
            let mut participant = LocalFrostParticipant::new(signer_id, key, NonceGuard::new())
                .map_err(|e| e.to_string())?;
            let commitment = participant
                .round1(claim.session_id, claim.signing_message_digest)
                .map_err(|e| e.to_string())?;
            coordinator
                .add_commitment(signer_id, commitment)
                .map_err(|e| e.to_string())?;
            participants.insert(signer_id, participant);
        }
        let session = coordinator.signing_session().map_err(|e| e.to_string())?;
        for (signer_id, participant) in &mut participants {
            let mut authorization = ExactAuthorization {
                session_id: claim.session_id,
                message: claim.signing_message_digest,
                signer_id: *signer_id,
                consumed: false,
            };
            let share = participant
                .round2(&session, &mut authorization, now)
                .map_err(|e| e.to_string())?;
            coordinator
                .add_signature_share(*signer_id, share)
                .map_err(|e| e.to_string())?;
        }
        signature_to_bytes(&coordinator.finalize().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

struct NeverCoordinator;

impl BitcoinThresholdCoordinator for NeverCoordinator {
    fn sign(
        &mut self,
        _: &ChainSigningExecution,
        _: &BitcoinExecutionClaim,
        _: i64,
    ) -> Result<[u8; 64], String> {
        panic!("a persisted replay claim must fail before signing")
    }
}

type PersistedClaims = Vec<([u8; 32], BitcoinExecutionClaim)>;
type ExecutionMutation = Box<dyn Fn(&mut ChainSigningExecution)>;

#[derive(Clone, Default)]
struct DurableClaims(Arc<Mutex<PersistedClaims>>);

impl BitcoinExecutionClaimStore for DurableClaims {
    fn claim(&mut self, replay_key: [u8; 32], claim: &BitcoinExecutionClaim) -> Result<(), String> {
        let mut claims = self.0.lock().map_err(|_| "claim lock poisoned")?;
        if claims
            .iter()
            .any(|(existing_key, _)| existing_key == &replay_key)
        {
            return Err("replay".to_owned());
        }
        assert_eq!(replay_key, claim.replay_key());
        claims.push((replay_key, claim.clone()));
        Ok(())
    }
}

fn unsigned_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([42; 32]), 1),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    }
}

fn fixture() -> (
    SignerProfile,
    BitcoinChainSuite,
    ChainSigningExecution,
    LocalDkgOutput,
) {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let dkg = run_local_dkg(3, 2).expect("2-of-3 DKG");
    let group_key = group_pubkey_xonly(&dkg.public_key_package).expect("group key");
    let output_key = bitcoin::XOnlyPublicKey::from_slice(&group_key).expect("x-only key");
    let address = derive_p2tr_output_key_address(scope, output_key).expect("address");
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Default,
    )
    .expect("review request");
    let suite = BitcoinChainSuite::new(scope, output_key).expect("suite");
    let material = TaprootReviewMaterial::from_request(&request)
        .expect("material")
        .encode()
        .expect("canonical material");
    let review = suite.review_transaction(&material).expect("review");
    let profile = SignerProfile::new(
        Uuid::from_bytes([3; 16]),
        Uuid::from_bytes([4; 16]),
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        "bitcoin-primary-2-of-3".into(),
        "passkey:owner".into(),
        7,
        2,
        3,
        group_key.to_vec(),
        "personal://bitcoin/share-set".into(),
    )
    .expect("profile");
    let review_binding = ReviewBinding::new(
        scope,
        profile.signing_suite_id,
        profile.signer_set_id.clone(),
        profile.signer_epoch,
        review.schema_version,
        review.review_digest,
    )
    .expect("binding");
    let execution = ChainSigningExecution {
        operation_binding_digest: [8; 32],
        job: SigningJob {
            job_id: Uuid::from_bytes([5; 16]),
            intent_id: Uuid::from_bytes([6; 16]),
            profile_id: profile.profile_id,
            wallet_id: profile.wallet_id,
            chain_scope: scope,
            signing_suite_id: profile.signing_suite_id,
            backend_requirement: profile.backend_requirement,
            review,
            review_binding,
            policy_snapshot_digest: [10; 32],
            chain_snapshot_digest: [11; 32],
            online_parties: ["desktop".into(), "backup".into()],
            receiver: "desktop".into(),
            session_id: [12; 32],
            expires_at: 200,
            created_at: 100,
        },
    };
    (profile, suite, execution, dkg)
}

#[test]
fn bitcoin_executor_uses_real_frost_and_chain_verifies_the_final_witness() {
    let (profile, suite, execution, dkg) = fixture();
    let claims = DurableClaims::default();
    let executor = BitcoinThresholdChainSigningExecutor::new(
        profile,
        suite,
        Box::new(RealCoordinator(Some(dkg))),
        Box::new(claims.clone()),
    )
    .expect("executor");

    executor
        .execute(&execution, 150)
        .expect("real FROST execution");
    let recorded = claims.0.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1.operation_binding_digest, [8; 32]);
}

#[test]
fn bitcoin_executor_rejects_authority_and_operation_drift_before_signing() {
    let (profile, suite, execution, dkg) = fixture();
    let regtest_scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Regtest));
    let wrong_suite = BitcoinChainSuite::new(regtest_scope, suite.output_key()).expect("suite");
    assert!(matches!(
        BitcoinThresholdChainSigningExecutor::new(
            profile.clone(),
            wrong_suite,
            Box::new(NeverCoordinator),
            Box::new(DurableClaims::default()),
        ),
        Err(SigningJobError::InvalidProfile(_))
    ));

    let executor = BitcoinThresholdChainSigningExecutor::new(
        profile,
        suite,
        Box::new(RealCoordinator(Some(dkg))),
        Box::new(DurableClaims::default()),
    )
    .expect("executor");
    let mut mutations: Vec<ExecutionMutation> = vec![
        Box::new(|run| run.job.profile_id = Uuid::new_v4()),
        Box::new(|run| run.job.signing_suite_id = SigningSuiteId::BITCOIN_BIP340_ISOLATED_V1),
        Box::new(|run| run.job.backend_requirement = SignerBackendRequirement::IsolatedBip340),
        Box::new(|run| run.job.review_binding.review_digest = [91; 32]),
        Box::new(|run| run.job.session_id = [0; 32]),
        Box::new(|run| run.operation_binding_digest = [0; 32]),
    ];
    for mutate in mutations.drain(..) {
        let mut drifted = execution.clone();
        mutate(&mut drifted);
        assert!(matches!(
            executor.execute(&drifted, 150),
            Err(SigningJobError::ProfileDrift)
        ));
    }
}

#[test]
fn bitcoin_executor_persists_replay_claim_across_restart() {
    let (profile, suite, execution, dkg) = fixture();
    let claims = DurableClaims::default();
    BitcoinThresholdChainSigningExecutor::new(
        profile.clone(),
        suite.clone(),
        Box::new(RealCoordinator(Some(dkg))),
        Box::new(claims.clone()),
    )
    .expect("first executor")
    .execute(&execution, 150)
    .expect("first execution");

    let restarted = BitcoinThresholdChainSigningExecutor::new(
        profile,
        suite,
        Box::new(NeverCoordinator),
        Box::new(claims),
    )
    .expect("restarted executor");
    assert!(matches!(
        restarted.execute(&execution, 151),
        Err(SigningJobError::Backend(_))
    ));
}

#[test]
fn bitcoin_executor_rejects_same_session_with_drifted_operation_after_restart() {
    let (profile, suite, execution, dkg) = fixture();
    let claims = DurableClaims::default();
    BitcoinThresholdChainSigningExecutor::new(
        profile.clone(),
        suite.clone(),
        Box::new(RealCoordinator(Some(dkg))),
        Box::new(claims.clone()),
    )
    .expect("first executor")
    .execute(&execution, 150)
    .expect("first execution");

    let mut drifted = execution;
    drifted.operation_binding_digest = [99; 32];
    let restarted = BitcoinThresholdChainSigningExecutor::new(
        profile,
        suite,
        Box::new(NeverCoordinator),
        Box::new(claims),
    )
    .expect("restarted executor");
    assert!(matches!(
        restarted.execute(&drifted, 151),
        Err(SigningJobError::Backend(_))
    ));
}
