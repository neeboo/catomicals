#![cfg(feature = "native-cbmpc")]

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    CbMpcCancellation, CbMpcRuntime, CbMpcRuntimeLimits, CbMpcSignerSet, DurableSessionClaimStore,
    PartyId, SessionTransport, TransportFailure, generate_native_provider_2_of_3,
};
use catomicals_chain_bitcoin_cash::{
    BitcoinCashChainSuite, BitcoinCashNetwork, BitcoinCashSignatureAlgorithm,
    BitcoinCashSigningRequest, ForkIdSighashType, OutPoint, Transaction, TxIn, TxOut,
};
use catomicals_chain_domain::{ChainNetwork, ChainScope, ReviewArtifact};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
use catomicals_wallet::{
    ApprovalCompletionState, ApprovalStartState, AuthorizationState, BitcoinNetwork,
    CbMpcChainSigningExecutor, CbMpcConsensusSignatureAssembler, CbMpcWalletCoordinator,
    ChainSigningExecution, ChainSigningJobState, ChainSigningJobStatus,
    CreateChainSigningJobRequest, FrostNonceClaimState, IntentStatus, PasskeyState,
    RelyingPartyConfig, SIGNING_PROTOCOL_VERSION, SignerProfile, SigningAction, SigningIntent,
    SigningJob, SigningJobRequest, SigningPhase, StorageDescriptor, StorageMode, WalletNodeError,
    WalletNodeService, WalletStore, WalletStoreError, WebauthnProfileState,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    available: Condvar,
}
struct Network(Vec<Vec<Queue>>);
impl Network {
    fn new(parties: usize) -> Arc<Self> {
        Arc::new(Self(
            (0..parties)
                .map(|_| {
                    (0..parties)
                        .map(|_| Queue {
                            frames: Mutex::new(VecDeque::new()),
                            available: Condvar::new(),
                        })
                        .collect()
                })
                .collect(),
        ))
    }
    fn transport(self: &Arc<Self>, party: usize) -> MemoryTransport {
        MemoryTransport {
            network: Arc::clone(self),
            party,
        }
    }
}
struct MemoryTransport {
    network: Arc<Network>,
    party: usize,
}
impl SessionTransport for MemoryTransport {
    fn send(&self, receiver: usize, frame: &[u8], _: Instant) -> Result<(), TransportFailure> {
        let queue = &self.network.0[receiver][self.party];
        queue.frames.lock().unwrap().push_back(frame.to_vec());
        queue.available.notify_one();
        Ok(())
    }
    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        let queue = &self.network.0[self.party][sender];
        let mut frames = queue.frames.lock().unwrap();
        loop {
            if let Some(frame) = frames.pop_front() {
                return Ok(frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TransportFailure::Timeout);
            }
            let (next, timeout) = queue
                .available
                .wait_timeout(frames, deadline - now)
                .unwrap();
            frames = next;
            if timeout.timed_out() && frames.is_empty() {
                return Err(TransportFailure::Timeout);
            }
        }
    }
}

struct ForkIdAssembler;
impl CbMpcConsensusSignatureAssembler for ForkIdAssembler {
    fn assemble(
        &self,
        _job: &catomicals_wallet::SigningJob,
        signature: &catomicals_cb_mpc_signer::CanonicalEcdsaSignature,
    ) -> Result<Vec<u8>, String> {
        let mut wire = signature.der().to_vec();
        wire.push(0x41);
        Ok(wire)
    }
}

struct NodeSigningStore {
    wallet_id: Uuid,
    profile: WebauthnProfileState,
    intent: SigningIntent,
    authorization: Option<AuthorizationState>,
    execution: Option<ChainSigningExecution>,
    executor_claimed: bool,
    state: Option<ChainSigningJobState>,
}

impl NodeSigningStore {
    fn new(intent: SigningIntent, authorization: AuthorizationState) -> Self {
        Self {
            wallet_id: intent.wallet_id,
            profile: WebauthnProfileState {
                wallet_id: intent.wallet_id,
                user_id: Uuid::new_v4(),
                rp_id: "localhost".to_owned(),
                rp_origin: "http://localhost:5173".to_owned(),
                record_version: 1,
                updated_at: NOW - 1,
            },
            intent,
            authorization: Some(authorization),
            execution: None,
            executor_claimed: false,
            state: None,
        }
    }
}

impl WalletStore for NodeSigningStore {
    fn descriptor(&self) -> StorageDescriptor {
        StorageDescriptor {
            mode: StorageMode::Durable,
            schema_version: Some(6),
            recovery_epoch: Some(1),
            startup_invalidated_ceremonies: 0,
        }
    }

    fn wallet_id(&self) -> Option<Uuid> {
        Some(self.wallet_id)
    }

    fn insert_intent(&mut self, _intent: SigningIntent) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new("fixture intent is immutable"))
    }

    fn get_intent(&self, id: &Uuid) -> Option<SigningIntent> {
        (self.intent.id == *id).then(|| self.intent.clone())
    }

    fn list_intents(&self) -> Vec<SigningIntent> {
        vec![self.intent.clone()]
    }

    fn update_intent(&mut self, intent: SigningIntent, _now: i64) -> Result<(), WalletStoreError> {
        self.intent = intent;
        Ok(())
    }

    fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError> {
        Ok(Some(self.profile.clone()))
    }

    fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError> {
        self.profile = profile;
        Ok(())
    }

    fn insert_passkey(&mut self, _passkey: PasskeyState) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new("fixture does not enroll Passkeys"))
    }

    fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError> {
        Ok(Vec::new())
    }

    fn begin_approval(&mut self, _state: ApprovalStartState) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new("fixture approval already exists"))
    }

    fn complete_approval(
        &mut self,
        _state: ApprovalCompletionState,
    ) -> Result<AuthorizationState, WalletStoreError> {
        Err(WalletStoreError::new("fixture approval already exists"))
    }

    fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletStoreError> {
        Ok(self
            .authorization
            .iter()
            .filter(|authorization| authorization.expires_at >= now)
            .cloned()
            .collect())
    }

    fn claim_frost_nonce(&mut self, _claim: FrostNonceClaimState) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new("fixture uses the chain job claim"))
    }

    fn create_chain_signing_job(
        &mut self,
        request: CreateChainSigningJobRequest,
        now: i64,
    ) -> Result<ChainSigningJobState, WalletStoreError> {
        let authorization = self
            .authorization
            .take()
            .ok_or_else(|| WalletStoreError::new("authorization already consumed"))?;
        if authorization.id != request.authorization_id
            || authorization.intent_id != request.job.intent_id
            || authorization.binding_digest != request.operation_binding_digest
        {
            return Err(WalletStoreError::new("authorization binding mismatch"));
        }
        let job = request.job;
        let state = ChainSigningJobState {
            job_id: job.job_id,
            intent_id: job.intent_id,
            wallet_id: job.wallet_id,
            profile_id: job.profile_id,
            chain_scope: job.chain_scope,
            signing_suite_id: job.signing_suite_id,
            backend_requirement: job.backend_requirement,
            review_schema_version: job.review.schema_version,
            review_digest: job.review.review_digest,
            signing_message_digest: job.review.signing_message_digest,
            policy_snapshot_digest: job.policy_snapshot_digest,
            chain_snapshot_digest: job.chain_snapshot_digest,
            session_id: job.session_id,
            online_parties: job.online_parties.clone(),
            receiver: job.receiver.clone(),
            operation_binding_digest: request.operation_binding_digest,
            status: ChainSigningJobStatus::Signing,
            final_signature: None,
            terminal_reason: None,
            expires_at: job.expires_at,
            created_at: job.created_at,
            updated_at: now,
        };
        self.execution = Some(ChainSigningExecution {
            job,
            operation_binding_digest: request.operation_binding_digest,
        });
        self.intent.status = IntentStatus::Signing;
        self.state = Some(state.clone());
        Ok(state)
    }

    fn chain_signing_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ChainSigningJobState>, WalletStoreError> {
        Ok(self
            .state
            .as_ref()
            .filter(|state| state.job_id == job_id)
            .cloned())
    }

    fn chain_signing_execution(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ChainSigningExecution>, WalletStoreError> {
        Ok(self
            .execution
            .as_ref()
            .filter(|execution| execution.job.job_id == job_id)
            .cloned())
    }

    fn claim_chain_executor(
        &mut self,
        execution: &ChainSigningExecution,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        let stored = self
            .execution
            .as_ref()
            .filter(|stored| {
                stored.job.job_id == execution.job.job_id
                    && stored.operation_binding_digest == execution.operation_binding_digest
            })
            .ok_or_else(|| WalletStoreError::new("signing job binding mismatch"))?;
        let state = self
            .state
            .as_ref()
            .filter(|state| {
                state.job_id == execution.job.job_id
                    && state.operation_binding_digest == execution.operation_binding_digest
                    && state.status == ChainSigningJobStatus::Signing
            })
            .ok_or_else(|| WalletStoreError::new("signing job is not executable"))?;
        let _ = (stored, state);
        if self.executor_claimed {
            return Err(WalletStoreError::new(
                "chain executor claim already consumed",
            ));
        }
        self.executor_claimed = true;
        Ok(())
    }

    fn finalize_chain_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        final_signature: Vec<u8>,
        now: i64,
    ) -> Result<(), WalletStoreError> {
        let state = self
            .state
            .as_mut()
            .filter(|state| state.job_id == job_id)
            .ok_or_else(|| WalletStoreError::new("signing job missing"))?;
        if state.operation_binding_digest != operation_binding_digest
            || state.status != ChainSigningJobStatus::Signing
        {
            return Err(WalletStoreError::new("signing job binding mismatch"));
        }
        state.status = ChainSigningJobStatus::Finalized;
        state.final_signature = Some(final_signature);
        state.updated_at = now;
        self.intent.status = IntentStatus::Signed;
        Ok(())
    }

    fn terminate_chain_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        status: ChainSigningJobStatus,
        reason: String,
        now: i64,
    ) -> Result<(), WalletStoreError> {
        let state = self
            .state
            .as_mut()
            .filter(|state| state.job_id == job_id)
            .ok_or_else(|| WalletStoreError::new("signing job missing"))?;
        if state.operation_binding_digest != operation_binding_digest {
            return Err(WalletStoreError::new("signing job binding mismatch"));
        }
        state.status = status;
        state.terminal_reason = Some(reason);
        state.updated_at = now;
        Ok(())
    }
}

fn parties() -> Vec<PartyId> {
    ["desktop", "mobile", "onepassword"]
        .map(|id| PartyId::new(id).unwrap())
        .to_vec()
}
fn signer_set() -> CbMpcSignerSet {
    CbMpcSignerSet::new("personal-wallet", 7, 2, parties()).unwrap()
}
fn limits() -> CbMpcRuntimeLimits {
    CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(90),
        4 * 1024 * 1024,
    )
    .unwrap()
}
fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

fn future_job(wallet_id: Uuid, intent_id: Uuid) -> SigningJob {
    let scope = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    let review = ReviewArtifact::new(
        scope,
        [71; 32],
        [72; 32],
        "future BCH spend".to_owned(),
        vec![0xaa],
    )
    .unwrap();
    SigningJob {
        job_id: Uuid::new_v4(),
        intent_id,
        profile_id: Uuid::new_v4(),
        wallet_id,
        chain_scope: scope,
        signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
        review: review.clone(),
        review_binding: ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            "personal-wallet",
            7,
            review.schema_version,
            review.review_digest,
        )
        .unwrap(),
        policy_snapshot_digest: [73; 32],
        chain_snapshot_digest: [74; 32],
        online_parties: ["desktop".to_owned(), "mobile".to_owned()],
        receiver: "desktop".to_owned(),
        session_id: [75; 32],
        expires_at: NOW + 120,
        created_at: NOW + 10,
    }
}

#[test]
fn node_reports_that_a_signing_job_has_not_started_yet() {
    let wallet_id = Uuid::new_v4();
    let intent_id = Uuid::new_v4();
    let job = future_job(wallet_id, intent_id);
    let intent = SigningIntent {
        id: intent_id,
        network: BitcoinNetwork::Signet,
        protocol_version: SIGNING_PROTOCOL_VERSION,
        action: SigningAction::SignTaprootTransaction,
        wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: job.review.signing_message_digest,
        session_id: job.session_id,
        expiry: job.expires_at,
        nonce: [76; 32],
        covhub: None,
        status: IntentStatus::Approved,
        created_at: NOW - 1,
    };
    let operation_binding_digest = intent.digest();
    let authorization_id = Uuid::new_v4();
    let store = NodeSigningStore::new(
        intent,
        AuthorizationState {
            id: authorization_id,
            intent_id,
            binding_digest: operation_binding_digest,
            expires_at: job.expires_at,
            issued_at: NOW - 1,
        },
    );
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    node.create_chain_signing_job(
        CreateChainSigningJobRequest {
            authorization_id,
            operation_binding_digest,
            job: job.clone(),
        },
        NOW,
    )
    .unwrap();

    assert_eq!(
        node.execute_chain_signing_job(job.job_id, NOW),
        Err(WalletNodeError::SigningJobNotStarted)
    );
}

#[test]
fn node_rejects_a_review_binding_that_does_not_match_the_signing_job() {
    let wallet_id = Uuid::new_v4();
    let intent_id = Uuid::new_v4();
    let mut job = future_job(wallet_id, intent_id);
    job.created_at = NOW;
    job.review_binding = ReviewBinding::new(
        job.chain_scope,
        job.signing_suite_id,
        "personal-wallet",
        7,
        job.review.schema_version,
        [99; 32],
    )
    .unwrap();
    let intent = SigningIntent {
        id: intent_id,
        network: BitcoinNetwork::Signet,
        protocol_version: SIGNING_PROTOCOL_VERSION,
        action: SigningAction::SignTaprootTransaction,
        wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: job.review.signing_message_digest,
        session_id: job.session_id,
        expiry: job.expires_at,
        nonce: [77; 32],
        covhub: None,
        status: IntentStatus::Approved,
        created_at: NOW - 1,
    };
    let operation_binding_digest = intent.digest();
    let authorization_id = Uuid::new_v4();
    let store = NodeSigningStore::new(
        intent,
        AuthorizationState {
            id: authorization_id,
            intent_id,
            binding_digest: operation_binding_digest,
            expires_at: job.expires_at,
            issued_at: NOW - 1,
        },
    );
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();

    assert_eq!(
        node.create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id,
                operation_binding_digest,
                job,
            },
            NOW,
        ),
        Err(WalletNodeError::IntentBindingMismatch)
    );
}

#[test]
fn chain_neutral_wallet_job_reviews_real_digest_routes_cb_mpc_and_verifies_final_signature() {
    let dkg_network = Network::new(3);
    let dkg = [
        dkg_network.transport(0),
        dkg_network.transport(1),
        dkg_network.transport(2),
    ];
    let providers = generate_native_provider_2_of_3(
        &signer_set(),
        [&dkg[0], &dkg[1], &dkg[2]],
        limits(),
        &CbMpcCancellation::new(),
    )
    .unwrap();
    let group_key = providers[0].group_public_key();
    let scope = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    let profile = SignerProfile::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        scope,
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        "personal-wallet".to_owned(),
        "frost:participant-1".to_owned(),
        7,
        2,
        3,
        group_key.to_vec(),
        "encrypted-file://cb-mpc/share-1".to_owned(),
    )
    .unwrap();
    let suite = BitcoinCashChainSuite::new(
        BitcoinCashNetwork::Chipnet,
        BitcoinCashSignatureAlgorithm::Ecdsa,
        &group_key,
        ForkIdSighashType::ALL,
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: [3; 32],
                output_index: 1,
            },
            script_sig: vec![],
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOut {
            value: 49_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 7,
    };
    let material = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Chipnet,
        transaction,
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::ALL,
    )
    .encode();
    let (_root, root) = private_tempdir();
    let runtime = CbMpcRuntime::new_native(
        limits(),
        Arc::new(DurableSessionClaimStore::open(&root.join("claims")).unwrap()),
    )
    .unwrap();
    let coordinator = CbMpcWalletCoordinator::new(profile.clone(), signer_set(), runtime).unwrap();
    let job = coordinator
        .prepare_job(
            &suite,
            &material,
            SigningJobRequest {
                job_id: Uuid::new_v4(),
                intent_id: Uuid::new_v4(),
                policy_snapshot_digest: [41; 32],
                chain_snapshot_digest: [42; 32],
                online_parties: [parties()[0].clone(), parties()[1].clone()],
                receiver: parties()[0].clone(),
                session_id: [51; 32],
                expires_at: NOW + 120,
            },
            NOW,
        )
        .unwrap();
    assert_ne!(job.review.signing_message_digest, [0; 32]);
    assert_eq!(job.online_parties, ["desktop", "mobile"]);
    assert_eq!(job.receiver, "desktop");

    let intent = SigningIntent {
        id: job.intent_id,
        network: BitcoinNetwork::Signet,
        protocol_version: SIGNING_PROTOCOL_VERSION,
        action: SigningAction::SignTaprootTransaction,
        wallet_id: job.wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: job.review.signing_message_digest,
        session_id: job.session_id,
        expiry: job.expires_at,
        nonce: [61; 32],
        covhub: None,
        status: IntentStatus::Approved,
        created_at: NOW - 1,
    };
    let operation_binding_digest = intent.digest();
    let authorization_id = Uuid::new_v4();
    let store = NodeSigningStore::new(
        intent,
        AuthorizationState {
            id: authorization_id,
            intent_id: job.intent_id,
            binding_digest: operation_binding_digest,
            expires_at: job.expires_at,
            issued_at: NOW - 1,
        },
    );
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    let created = node
        .create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id,
                operation_binding_digest,
                job: job.clone(),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(created.status, ChainSigningJobStatus::Signing);
    assert!(created.final_signature.is_none());
    assert_eq!(
        node.signing_status(job.intent_id, NOW).unwrap().phase,
        SigningPhase::Signing
    );
    assert_eq!(
        node.signer_round1(job.intent_id, NOW),
        Err(WalletNodeError::IntentNotPending)
    );

    let [provider0, provider1, _provider2] = providers;
    let sign_network = Network::new(2);
    let executor = CbMpcChainSigningExecutor::new(
        Box::new(suite),
        coordinator,
        [provider0, provider1],
        [
            Box::new(sign_network.transport(0)),
            Box::new(sign_network.transport(1)),
        ],
        Box::new(ForkIdAssembler),
        CbMpcCancellation::new(),
    )
    .unwrap();
    node.register_chain_signing_executor(Box::new(executor));

    let finalized = node.execute_chain_signing_job(job.job_id, NOW + 1).unwrap();
    assert_eq!(finalized.status, ChainSigningJobStatus::Finalized);
    assert_eq!(
        finalized
            .final_signature
            .as_deref()
            .and_then(|wire| wire.last()),
        Some(&0x41)
    );
    assert_eq!(
        node.chain_signing_job(job.job_id, NOW + 1).unwrap(),
        finalized
    );
    assert_eq!(
        node.read_intent(job.intent_id).unwrap().status,
        IntentStatus::Signed
    );
}

#[test]
fn signer_profile_rejects_backend_or_scope_drift() {
    let scope = ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet));
    let result = SignerProfile::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        scope,
        SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        "personal-wallet".to_owned(),
        "frost:participant-1".to_owned(),
        7,
        2,
        3,
        vec![2; 33],
        "encrypted-file://cb-mpc/share-1".to_owned(),
    );
    assert!(result.is_err());
}
