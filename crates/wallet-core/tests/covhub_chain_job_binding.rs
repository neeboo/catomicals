//! CovHub -> chain signing job binding tests.
//!
//! A Passkey-approved CovHub pending intent is immutable: before the wallet
//! consumes the Passkey authorization or changes any durable state, the new
//! `ChainSigningJob` request must match the intent's CovHub binding in every
//! applicable field (exact native chain scope, review digest, signing message
//! digest, profile id, and the executable signing suite/profile relationship)
//! plus the intent session and expiry. Adversarial field substitutions must
//! fail closed and leave the authorization and intent state fully reusable.

use catomicals_chain_domain::{ChainNetwork, ChainScope, KaspaNetwork, ReviewArtifact};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    FrostCoordinator, FrostSession, LocalFrostParticipant, NonceGuard, participant_identifier,
    run_local_dkg,
};
use catomicals_wallet::{
    ApprovalCompletionState, ApprovalStartState, AuthorizationState, BitcoinNetwork,
    ChainSigningExecution, ChainSigningJobState, ChainSigningJobStatus,
    CreateChainSigningJobRequest, FrostNonceClaimState, IntentStatus, PasskeyState,
    RelyingPartyConfig, SIGNING_PROTOCOL_VERSION, SignerProfile, SigningAction, SigningIntent,
    SigningJob, StorageDescriptor, StorageMode, WalletNodeError, WalletNodeService, WalletStore,
    WalletStoreError, WebauthnProfileState,
    covhub::{CovhubBinding, CovhubIntentStatus, CovhubSigningIntent},
};
use uuid::Uuid;

const NOW: i64 = 1_788_220_000;

fn kaspa_testnet11_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11))
}

fn kaspa_testnet10_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet10))
}

fn signet_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Bitcoin(
        catomicals_chain_domain::BitcoinNetwork::Signet,
    ))
}

/// A locally executable Kaspa Testnet11 CB-MPC signer profile. Kaspa stays a
/// native `ChainScope`; it is never encoded as a Bitcoin Signet placeholder.
fn kaspa_testnet11_profile() -> SignerProfile {
    SignerProfile::new(
        Uuid::from_bytes([0x21; 16]),
        Uuid::from_bytes([0x22; 16]),
        kaspa_testnet11_scope(),
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        "signer-set-1".to_owned(),
        "cbmpc:party-1".to_owned(),
        1,
        2,
        3,
        vec![0x33; 33],
        "opaque-handle-placeholder".to_owned(),
    )
    .unwrap()
}

/// A second, locally executable Bitcoin Signet FROST profile that a hostile
/// request might try to substitute for the CovHub-bound profile.
fn signet_profile() -> SignerProfile {
    SignerProfile::new(
        Uuid::from_bytes([0x31; 16]),
        Uuid::from_bytes([0x22; 16]),
        signet_scope(),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        "signer-set-1".to_owned(),
        "frost:participant-1".to_owned(),
        1,
        2,
        3,
        vec![0x44; 33],
        "opaque-handle-placeholder".to_owned(),
    )
    .unwrap()
}

fn covhub_intent(profile: &SignerProfile, intent_id: Uuid) -> CovhubSigningIntent {
    CovhubSigningIntent {
        version: 1,
        intent_id,
        proposal_id: "proposal:kaspa-testnet11-spend".to_owned(),
        proposal_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        canvas_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_owned(),
        code_confirmation_digest:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        chain_scope: profile.chain_scope,
        review_digest: [0x81; 32],
        signing_message_digest: [0x82; 32],
        session_id: [0x83; 32],
        profile_id: profile.profile_id,
        expires_at: NOW + 3600,
        created_at: NOW,
        status: CovhubIntentStatus::Pending,
    }
}

/// The durable wallet intent the human Passkey-approved. The legacy
/// `network`/`action` container fields carry the narrow `CovhubDelegated`
/// markers even for a Kaspa Testnet11 intent: they never claim a Bitcoin
/// Signet taproot authority. The CovHub binding carries the native chain
/// scope, which is the sole approval and execution authority.
fn approved_intent(profile: &SignerProfile, covhub: &CovhubSigningIntent) -> SigningIntent {
    SigningIntent {
        id: covhub.intent_id,
        network: BitcoinNetwork::CovhubDelegated,
        protocol_version: SIGNING_PROTOCOL_VERSION,
        action: SigningAction::CovhubDelegated,
        wallet_id: profile.wallet_id,
        signer_id: 1,
        personal_signing_policy: None,
        tx_digest: covhub.signing_message_digest,
        session_id: covhub.session_id,
        expiry: covhub.expires_at,
        nonce: [0x99; 32],
        covhub: Some(CovhubBinding::from_covhub_intent(covhub)),
        status: IntentStatus::Approved,
        created_at: NOW - 10,
    }
}

fn matching_job(intent: &SigningIntent, profile: &SignerProfile) -> SigningJob {
    let covhub = intent.covhub.as_ref().expect("covhub-bound intent");
    let review = ReviewArtifact::new(
        covhub.chain_scope,
        covhub.review_digest,
        covhub.signing_message_digest,
        "kaspa testnet11 spend".to_owned(),
        vec![0xaa, 0xbb],
    )
    .unwrap();
    SigningJob {
        job_id: Uuid::new_v4(),
        intent_id: intent.id,
        profile_id: covhub.profile_id,
        wallet_id: intent.wallet_id,
        chain_scope: covhub.chain_scope,
        signing_suite_id: profile.signing_suite_id,
        backend_requirement: profile.backend_requirement,
        review: review.clone(),
        review_binding: ReviewBinding::new(
            covhub.chain_scope,
            profile.signing_suite_id,
            profile.signer_set_id.clone(),
            profile.signer_epoch,
            review.schema_version,
            review.review_digest,
        )
        .unwrap(),
        policy_snapshot_digest: [0x91; 32],
        chain_snapshot_digest: [0x92; 32],
        online_parties: ["desktop".to_owned(), "mobile".to_owned()],
        receiver: "desktop".to_owned(),
        session_id: intent.session_id,
        expires_at: intent.expiry,
        created_at: NOW,
    }
}

/// In-memory wallet store for the node binding tests: reports the CovHub
/// intent, the one signer profile, and the one unexpired Passkey
/// authorization, and records whether a job was actually created.
struct CovhubJobStore {
    wallet_id: Uuid,
    intent: SigningIntent,
    profile: SignerProfile,
    authorization: Option<AuthorizationState>,
    state: Option<ChainSigningJobState>,
    jobs_created: usize,
}

impl CovhubJobStore {
    fn new(
        intent: SigningIntent,
        profile: SignerProfile,
        authorization: AuthorizationState,
    ) -> Self {
        let wallet_id = intent.wallet_id;
        Self {
            wallet_id,
            intent,
            profile,
            authorization: Some(authorization),
            state: None,
            jobs_created: 0,
        }
    }
}

impl WalletStore for CovhubJobStore {
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
        Ok(Some(WebauthnProfileState {
            wallet_id: self.wallet_id,
            user_id: Uuid::new_v4(),
            rp_id: "localhost".to_owned(),
            rp_origin: "http://localhost:5173".to_owned(),
            record_version: 1,
            updated_at: NOW - 1,
        }))
    }

    fn set_webauthn_profile(
        &mut self,
        _profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError> {
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

    fn signer_profiles(
        &self,
    ) -> Result<Vec<(SignerProfile, Vec<catomicals_wallet::AddressBinding>)>, WalletStoreError>
    {
        Ok(vec![(self.profile.clone(), Vec::new())])
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
        self.intent.status = IntentStatus::Signing;
        self.state = Some(state.clone());
        self.jobs_created += 1;
        Ok(state)
    }

    fn chain_signing_job(
        &self,
        _job_id: Uuid,
    ) -> Result<Option<ChainSigningJobState>, WalletStoreError> {
        Ok(self.state.clone())
    }

    fn chain_signing_execution(
        &self,
        _job_id: Uuid,
    ) -> Result<Option<ChainSigningExecution>, WalletStoreError> {
        Ok(None)
    }

    fn claim_chain_executor(
        &mut self,
        _execution: &ChainSigningExecution,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Ok(())
    }

    fn finalize_chain_signing_job(
        &mut self,
        _job_id: Uuid,
        _operation_binding_digest: [u8; 32],
        _final_signature: Vec<u8>,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Ok(())
    }

    fn terminate_chain_signing_job(
        &mut self,
        _job_id: Uuid,
        _operation_binding_digest: [u8; 32],
        _status: ChainSigningJobStatus,
        _reason: String,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Ok(())
    }
}

/// Assert that a job request mutated by `mutate` fails closed with
/// `IntentBindingMismatch`, that the intent is still `Approved`, and that the
/// Passkey authorization is still reusable by a subsequent exact request.
fn assert_mutation_fails_closed(
    intent: &SigningIntent,
    profile: &SignerProfile,
    authorization: &AuthorizationState,
    mutate: impl FnOnce(&mut SigningJob),
) {
    let store = CovhubJobStore::new(intent.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    let mut drifted = matching_job(intent, profile);
    mutate(&mut drifted);
    let result = node.create_chain_signing_job(
        CreateChainSigningJobRequest {
            authorization_id: authorization.id,
            operation_binding_digest: intent.digest(),
            job: drifted,
        },
        NOW,
    );
    assert_eq!(result, Err(WalletNodeError::IntentBindingMismatch));
    // No state change: the intent stays approved and the authorization is
    // still usable by the exact matching request.
    assert_eq!(
        node.read_intent(intent.id).unwrap().status,
        IntentStatus::Approved
    );
    let exact = node
        .create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest: intent.digest(),
                job: matching_job(intent, profile),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(exact.status, ChainSigningJobStatus::Signing);
}

#[test]
fn matching_covhub_job_uses_native_kaspa_scope_not_the_signet_placeholder() {
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x41; 16]));
    let intent = approved_intent(&profile, &covhub);

    // The narrow delegated markers occupy the legacy container fields: this
    // Kaspa Testnet11 intent never claims to be a Bitcoin Signet taproot
    // intent. The native Kaspa Testnet11 scope is the sole chain authority.
    assert_eq!(intent.network, BitcoinNetwork::CovhubDelegated);
    assert_eq!(intent.action, SigningAction::CovhubDelegated);
    assert!(intent.covhub_legacy_fields_are_delegated());
    assert_eq!(
        intent.authoritative_chain_scope(),
        Some(kaspa_testnet11_scope())
    );

    let operation_binding_digest = intent.digest();
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x42; 16]),
        intent_id: intent.id,
        binding_digest: operation_binding_digest,
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };
    let store = CovhubJobStore::new(intent.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    let created = node
        .create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest,
                job: matching_job(&intent, &profile),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(created.status, ChainSigningJobStatus::Signing);
    assert_eq!(created.chain_scope, kaspa_testnet11_scope());
    assert_eq!(created.profile_id, profile.profile_id);
    assert_eq!(
        created.signing_suite_id,
        SigningSuiteId::KASPA_ECDSA_CB_MPC_V1
    );
    assert_eq!(
        node.read_intent(intent.id).unwrap().status,
        IntentStatus::Signing
    );
    // The authorization was consumed exactly once.
    assert_eq!(
        node.create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest,
                job: matching_job(&intent, &profile),
            },
            NOW,
        ),
        Err(WalletNodeError::AuthorizationUnavailable)
    );
}

#[test]
fn covhub_job_creation_rejects_chain_and_network_substitution() {
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x43; 16]));
    let intent = approved_intent(&profile, &covhub);
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x44; 16]),
        intent_id: intent.id,
        binding_digest: intent.digest(),
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };

    // Swap the whole chain (Kaspa -> Bitcoin) while keeping the review binding
    // internally consistent so only the CovHub binding can catch it.
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.chain_scope = signet_scope();
        job.review.scope = signet_scope();
        job.signing_suite_id = SigningSuiteId::BITCOIN_BIP340_FROST_V1;
        job.backend_requirement = SignerBackendRequirement::FrostSecp256k1Tr;
        job.review_binding = ReviewBinding::new(
            signet_scope(),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            profile.signer_set_id.clone(),
            profile.signer_epoch,
            job.review.schema_version,
            job.review.review_digest,
        )
        .unwrap();
    });

    // Swap only the network within the Kaspa chain (Testnet11 -> Testnet10).
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.chain_scope = kaspa_testnet10_scope();
        job.review.scope = kaspa_testnet10_scope();
        job.review_binding = ReviewBinding::new(
            kaspa_testnet10_scope(),
            job.signing_suite_id,
            profile.signer_set_id.clone(),
            profile.signer_epoch,
            job.review.schema_version,
            job.review.review_digest,
        )
        .unwrap();
    });
}

#[test]
fn covhub_job_creation_rejects_digest_session_expiry_and_suite_drift() {
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x45; 16]));
    let intent = approved_intent(&profile, &covhub);
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x46; 16]),
        intent_id: intent.id,
        binding_digest: intent.digest(),
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };

    // Review digest substitution (kept consistent with the review binding).
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.review.review_digest = [0xfe; 32];
        job.review_binding.review_digest = [0xfe; 32];
    });

    // Signing message digest substitution.
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.review.signing_message_digest = [0xfd; 32];
    });

    // Session substitution.
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.session_id = [0xfc; 32];
    });

    // Expiry substitution to a different future time.
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.expires_at = intent.expiry + 60;
    });

    // Signing suite substitution (kept consistent with the review binding).
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.signing_suite_id = SigningSuiteId::KASPA_SCHNORR_FROST_V1;
        job.backend_requirement = SignerBackendRequirement::FrostSecp256k1Kaspa;
        job.review_binding = ReviewBinding::new(
            job.chain_scope,
            job.signing_suite_id,
            profile.signer_set_id.clone(),
            profile.signer_epoch,
            job.review.schema_version,
            job.review.review_digest,
        )
        .unwrap();
    });
}

#[test]
fn covhub_job_creation_rejects_profile_substitution() {
    let profile = kaspa_testnet11_profile();
    let other_profile = signet_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x47; 16]));
    let intent = approved_intent(&profile, &covhub);
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x48; 16]),
        intent_id: intent.id,
        binding_digest: intent.digest(),
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };

    // Try to route the approved Kaspa intent to a different profile. Only the
    // profile id is swapped; the suite stays consistent with the job scope so
    // the CovHub profile binding is what must reject the request.
    assert_mutation_fails_closed(&intent, &profile, &authorization, |job| {
        job.profile_id = other_profile.profile_id;
    });
}

#[test]
fn covhub_job_creation_rejects_an_intent_digest_that_no_longer_matches() {
    // A CovHub-bound job may never be created against an intent whose
    // immutable fields differ from what the Passkey approval authorized.
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x49; 16]));
    let intent = approved_intent(&profile, &covhub);

    // The authorization was approved for this exact digest...
    let operation_binding_digest = intent.digest();
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x4a; 16]),
        intent_id: intent.id,
        binding_digest: operation_binding_digest,
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };
    // ...but the recovered intent's session was tampered after approval. The
    // stored intent digest no longer matches the authorization, so the job
    // must be rejected before any state changes.
    let mut tampered = intent.clone();
    tampered.session_id = [0xfb; 32];
    let store = CovhubJobStore::new(tampered.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    let mut job = matching_job(&intent, &profile);
    job.session_id = tampered.session_id;
    assert_eq!(
        node.create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest,
                job,
            },
            NOW,
        ),
        Err(WalletNodeError::IntentBindingMismatch)
    );
    assert_eq!(
        node.read_intent(intent.id).unwrap().status,
        IntentStatus::Approved
    );
}

/// A real FROST signing session for the legacy round-2 rejection test. The
/// CovHub rejection happens before the session is ever used, but the round-2
/// API still needs a concrete session value.
fn legacy_frost_session(intent: &SigningIntent) -> FrostSession {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let mut participant = LocalFrostParticipant::new(
        1,
        dkg.key_packages
            .remove(&participant_identifier(1).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    let commitments = participant
        .round1(intent.session_id, intent.tx_digest)
        .unwrap();
    let mut other = LocalFrostParticipant::new(
        2,
        dkg.key_packages
            .remove(&participant_identifier(2).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    let other_commitments = other.round1(intent.session_id, intent.tx_digest).unwrap();
    let mut coordinator = FrostCoordinator::new(
        intent.session_id,
        intent.tx_digest,
        2,
        dkg.public_key_package,
    );
    coordinator.add_commitment(1, commitments).unwrap();
    coordinator.add_commitment(2, other_commitments).unwrap();
    coordinator.signing_session().unwrap()
}

#[test]
fn covhub_intent_is_rejected_from_legacy_signer_rounds_before_state_mutation() {
    // A Kaspa Testnet11 CovHub intent must never be signable through the
    // legacy Bitcoin Signet FROST rounds. Both legacy rounds reject before any
    // FROST nonce is generated, before the durable authorization is consumed,
    // and before any intent state changes; the same Passkey authorization must
    // remain fully usable by the native chain signing job path afterwards.
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x4b; 16]));
    let intent = approved_intent(&profile, &covhub);
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x4c; 16]),
        intent_id: intent.id,
        binding_digest: intent.digest(),
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };
    let store = CovhubJobStore::new(intent.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();

    // Legacy round 1 rejects repeatedly without consuming anything.
    assert_eq!(
        node.signer_round1(intent.id, NOW),
        Err(WalletNodeError::CovhubLegacyPathRejected)
    );
    assert_eq!(
        node.signer_round1(intent.id, NOW),
        Err(WalletNodeError::CovhubLegacyPathRejected)
    );

    // Legacy round 2 rejects before the frost nonce claim / authorization
    // removal, even when a valid FROST session is supplied.
    let session = legacy_frost_session(&intent);
    assert_eq!(
        node.signer_round2(intent.id, &session, NOW),
        Err(WalletNodeError::CovhubLegacyPathRejected)
    );
    assert_eq!(
        node.signer_round2(intent.id, &session, NOW),
        Err(WalletNodeError::CovhubLegacyPathRejected)
    );

    // No state mutated: the intent is still Approved and the untouched
    // authorization still creates the exact native chain signing job.
    assert_eq!(
        node.read_intent(intent.id).unwrap().status,
        IntentStatus::Approved
    );
    let created = node
        .create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest: intent.digest(),
                job: matching_job(&intent, &profile),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(created.status, ChainSigningJobStatus::Signing);
    assert_eq!(created.chain_scope, kaspa_testnet11_scope());
}

#[test]
fn covhub_intent_with_bitcoin_signet_placeholder_fields_grants_no_authority() {
    // A stale/hostile covhub intent whose legacy container fields still claim
    // Bitcoin Signet / taproot must fail closed at job creation: the
    // placeholder has no authorization effect, and the exact job bound to the
    // binding's native chain scope remains creatable.
    let profile = kaspa_testnet11_profile();
    let covhub = covhub_intent(&profile, Uuid::from_bytes([0x4d; 16]));
    let mut intent = approved_intent(&profile, &covhub);
    intent.network = BitcoinNetwork::Signet;
    intent.action = SigningAction::SignTaprootTransaction;
    assert!(!intent.covhub_legacy_fields_are_delegated());
    let authorization = AuthorizationState {
        id: Uuid::from_bytes([0x4e; 16]),
        intent_id: intent.id,
        binding_digest: intent.digest(),
        expires_at: intent.expiry,
        issued_at: NOW - 1,
    };
    let store = CovhubJobStore::new(intent.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();

    // Job creation rejects the Signet-placeholder intent before state changes.
    assert_eq!(
        node.create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest: intent.digest(),
                job: matching_job(&intent, &profile),
            },
            NOW,
        ),
        Err(WalletNodeError::IntentBindingMismatch)
    );
    assert_eq!(
        node.read_intent(intent.id).unwrap().status,
        IntentStatus::Approved
    );

    // The legacy signer rounds also reject it (before any mutation).
    assert_eq!(
        node.signer_round1(intent.id, NOW),
        Err(WalletNodeError::CovhubLegacyPathRejected)
    );

    // The binding's native Kaspa scope still governs an exact request: the
    // authorization is fully reusable by the native path.
    let mut exact = intent.clone();
    exact.network = BitcoinNetwork::CovhubDelegated;
    exact.action = SigningAction::CovhubDelegated;
    let store = CovhubJobStore::new(exact.clone(), profile.clone(), authorization.clone());
    let mut node = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    let created = node
        .create_chain_signing_job(
            CreateChainSigningJobRequest {
                authorization_id: authorization.id,
                operation_binding_digest: exact.digest(),
                job: matching_job(&exact, &profile),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(created.status, ChainSigningJobStatus::Signing);
    assert_eq!(created.chain_scope, kaspa_testnet11_scope());
}
