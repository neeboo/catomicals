//! Translation layer between wallet-domain storage records and SQLite-backed
//! authority storage. SQL and connection details remain in `wallet-storage`.

use std::collections::HashMap;
use std::path::Path;

use catomicals_signing_domain::ReviewBinding;
use catomicals_wallet_storage::{
    ApprovalNonce, ChainExecutorClaim, CredentialState, FrostNonceAuthorizationClaim, IntentAction,
    IntentMaterial, IntentMaterialKind, IntentNetwork, NewPasskeyApprovalCeremony,
    NewPasskeyRecord, NewSigningJob, NewTransactionIntentV2, PasskeyApprovalCompletion,
    RestoreState, SigningJobStatus, StoredSigningJob, TransactionIntentStatus, WalletStorage,
    WebauthnProfile,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    AddressBinding, ChainSigningExecution, ChainSigningJobState, ChainSigningJobStatus,
    CreateChainSigningJobRequest, IntentStatus, SignerProfile, SigningIntent, SigningJob,
    store::{
        ApprovalCompletionState, ApprovalStartState, AuthorizationState, FrostNonceClaimState,
        PasskeyState, StorageDescriptor, StorageMode, WalletStore, WalletStoreError,
        WebauthnProfileState,
    },
};

const PASSKEY_FORMAT: &str = "webauthn-rs-passkey-json-v1";
const COMPATIBILITY_SNAPSHOT: &str = "compatibility:no-authoritative-node-snapshot";

pub struct DurableWalletStore {
    storage: WalletStorage,
    intents: Vec<SigningIntent>,
    descriptor: StorageDescriptor,
    wallet_id: Uuid,
}

impl core::fmt::Debug for DurableWalletStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableWalletStore")
            .field("descriptor", &self.descriptor)
            .field("wallet_id", &self.wallet_id)
            .field("intents", &self.intents.len())
            .finish()
    }
}

impl DurableWalletStore {
    pub fn initialize(
        path: impl AsRef<Path>,
        wallet_id: Uuid,
        now: i64,
    ) -> Result<Self, WalletStoreError> {
        let storage = WalletStorage::initialize(path, wallet_id, now).map_err(store_error)?;
        Self::from_storage(storage)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalletStoreError> {
        let storage = WalletStorage::open(path).map_err(store_error)?;
        Self::from_storage(storage)
    }

    /// Returns the persisted recovery phase used to gate signer startup.
    pub fn restore_state(&self) -> Result<RestoreState, WalletStoreError> {
        self.storage
            .wallet_metadata()
            .map(|metadata| metadata.restore_state)
            .map_err(store_error)
    }

    fn from_storage(storage: WalletStorage) -> Result<Self, WalletStoreError> {
        let metadata = storage.wallet_metadata().map_err(store_error)?;
        let descriptor = StorageDescriptor {
            mode: StorageMode::Durable,
            schema_version: Some(storage.schema_version().map_err(store_error)?),
            recovery_epoch: Some(metadata.epoch),
            startup_invalidated_ceremonies: storage.startup_invalidated_ceremonies(),
        };
        let materials: HashMap<_, _> = storage
            .list_intent_materials(IntentMaterialKind::PolicyInput)
            .map_err(store_error)?
            .into_iter()
            .map(|material| (material.intent_id, material))
            .collect();
        let intents = storage
            .list_transaction_intents_v2()
            .map_err(store_error)?
            .into_iter()
            .map(|record| {
                let material = materials
                    .get(&record.id)
                    .ok_or_else(|| WalletStoreError::new("intent material is missing"))?;
                let payload_bytes =
                    serde_json::to_vec(&material.payload_json).map_err(|error| {
                        WalletStoreError::new(format!("invalid intent material: {error}"))
                    })?;
                if <[u8; 32]>::from(Sha256::digest(payload_bytes)) != material.payload_hash {
                    return Err(WalletStoreError::new("intent material hash mismatch"));
                }
                let mut intent: SigningIntent =
                    serde_json::from_value(material.payload_json.clone()).map_err(|error| {
                        WalletStoreError::new(format!("invalid intent material: {error}"))
                    })?;
                let expected_policy_hash = intent_policy_hash(&intent);
                if intent.id != record.id
                    || intent.wallet_id != record.wallet_id
                    || intent.tx_digest != record.tx_digest
                    || intent.session_id != record.session_id
                    || intent.nonce != record.approval_nonce.0
                    || record.policy_hash != expected_policy_hash
                    || u32::from(intent.protocol_version) != record.protocol_version
                    || record.network != IntentNetwork::Signet
                    || record.action != IntentAction::Spend
                    || record.signer_id != signer_label(intent.signer_id)
                {
                    return Err(WalletStoreError::new("intent material binding mismatch"));
                }
                intent.status = from_storage_status(record.status);
                Ok(intent)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            storage,
            intents,
            descriptor,
            wallet_id: metadata.wallet_id,
        })
    }

    fn replace_projection(&mut self, intent: SigningIntent) {
        if let Some(existing) = self.intents.iter_mut().find(|item| item.id == intent.id) {
            *existing = intent;
        } else {
            self.intents.push(intent);
            self.intents.sort_by_key(|item| (item.created_at, item.id));
        }
    }
}

impl WalletStore for DurableWalletStore {
    fn descriptor(&self) -> StorageDescriptor {
        self.descriptor.clone()
    }

    fn wallet_id(&self) -> Option<Uuid> {
        Some(self.wallet_id)
    }

    fn insert_intent(&mut self, intent: SigningIntent) -> Result<(), WalletStoreError> {
        if intent.wallet_id != self.wallet_id {
            return Err(WalletStoreError::new(
                "intent wallet id does not match durable wallet",
            ));
        }
        let payload_json = serde_json::to_value(&intent).map_err(|error| {
            WalletStoreError::new(format!("intent serialization failed: {error}"))
        })?;
        let payload_bytes = serde_json::to_vec(&payload_json).map_err(|error| {
            WalletStoreError::new(format!("intent serialization failed: {error}"))
        })?;
        let policy_hash = intent_policy_hash(&intent);
        self.storage
            .create_transaction_intent_v2(
                NewTransactionIntentV2 {
                    id: intent.id,
                    tx_digest: intent.tx_digest,
                    policy_hash,
                    session_id: intent.session_id,
                    network: IntentNetwork::Signet,
                    protocol_version: u32::from(intent.protocol_version),
                    action: IntentAction::Spend,
                    signer_id: signer_label(intent.signer_id),
                    approval_nonce: ApprovalNonce(intent.nonce),
                    intent_schema_version: 2,
                    expires_at: intent.expiry,
                    created_at: intent.created_at,
                },
                IntentMaterial {
                    intent_id: intent.id,
                    kind: IntentMaterialKind::PolicyInput,
                    payload_json,
                    payload_hash: Sha256::digest(payload_bytes).into(),
                    node_snapshot_id: COMPATIBILITY_SNAPSHOT.to_owned(),
                },
            )
            .map_err(store_error)?;
        self.replace_projection(intent);
        Ok(())
    }

    fn get_intent(&self, id: &Uuid) -> Option<SigningIntent> {
        self.intents.iter().find(|intent| &intent.id == id).cloned()
    }

    fn list_intents(&self) -> Vec<SigningIntent> {
        self.intents.clone()
    }

    fn update_intent(&mut self, intent: SigningIntent, now: i64) -> Result<(), WalletStoreError> {
        let current = self
            .get_intent(&intent.id)
            .ok_or_else(|| WalletStoreError::new("intent is missing"))?;
        let expected = to_storage_status(current.status);
        let next = to_storage_status(intent.status);
        self.storage
            .transition_transaction_intent(intent.id, expected, next, now)
            .map_err(store_error)?;
        self.replace_projection(intent);
        Ok(())
    }

    fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError> {
        self.storage
            .webauthn_profile()
            .map_err(store_error)?
            .map(|profile| {
                Ok(WebauthnProfileState {
                    wallet_id: profile.wallet_id,
                    user_id: Uuid::parse_str(&profile.user_id).map_err(|error| {
                        WalletStoreError::new(format!("invalid WebAuthn user id: {error}"))
                    })?,
                    rp_id: profile.rp_id,
                    rp_origin: profile.rp_origin,
                    record_version: profile.record_version,
                    updated_at: profile.updated_at,
                })
            })
            .transpose()
    }

    fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError> {
        self.storage
            .set_webauthn_profile(WebauthnProfile {
                wallet_id: profile.wallet_id,
                user_id: profile.user_id.to_string(),
                rp_id: profile.rp_id,
                rp_origin: profile.rp_origin,
                record_version: profile.record_version,
                updated_at: profile.updated_at,
            })
            .map_err(store_error)
    }

    fn insert_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletStoreError> {
        if passkey.record_version != 1 || passkey.format != PASSKEY_FORMAT {
            return Err(WalletStoreError::new("unsupported Passkey record format"));
        }
        self.storage
            .insert_passkey_record(NewPasskeyRecord {
                credential_id: passkey.credential_id,
                label: passkey.label,
                passkey_json: passkey.passkey_json,
                format: passkey.format,
                credential_state: CredentialState::Active,
                enrolled_at: passkey.enrolled_at,
            })
            .map_err(store_error)
    }

    fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError> {
        self.storage
            .list_passkey_records()
            .map_err(store_error)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| PasskeyState {
                        credential_id: record.credential_id,
                        label: record.label,
                        passkey_json: record.passkey_json,
                        format: record.format,
                        record_version: record.record_version,
                        enrolled_at: record.enrolled_at,
                    })
                    .collect()
            })
    }

    fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletStoreError> {
        self.storage
            .begin_passkey_approval(NewPasskeyApprovalCeremony {
                id: state.ceremony_id,
                intent_id: state.intent_id,
                credential_id: state.credential_id,
                binding_digest: state.binding_digest,
                started_at: state.started_at,
                expires_at: state.expires_at,
            })
            .map_err(store_error)
    }

    fn complete_approval(
        &mut self,
        state: ApprovalCompletionState,
    ) -> Result<AuthorizationState, WalletStoreError> {
        let record = self
            .storage
            .complete_passkey_approval_atomic(PasskeyApprovalCompletion {
                ceremony_id: state.ceremony_id,
                intent_id: state.intent_id,
                credential_id: state.credential_id,
                expected_credential_record_version: state.expected_credential_record_version,
                updated_passkey_json: state.updated_passkey_json,
                binding_digest: state.binding_digest,
                authorization_id: state.authorization_id,
                authorization_expires_at: state.authorization_expires_at,
                rp_id: state.rp_id,
                rp_origin: state.rp_origin,
                approved_at: state.approved_at,
            })
            .map_err(store_error)?;
        if let Some(intent) = self
            .intents
            .iter_mut()
            .find(|intent| intent.id == state.intent_id)
        {
            intent.status = IntentStatus::Approved;
        }
        Ok(AuthorizationState {
            id: record.id,
            intent_id: record.intent_id,
            binding_digest: record.binding_digest,
            expires_at: record.expires_at,
            issued_at: record.issued_at,
        })
    }

    fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletStoreError> {
        self.storage
            .list_available_authorizations(now)
            .map_err(store_error)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| AuthorizationState {
                        id: record.id,
                        intent_id: record.intent_id,
                        binding_digest: record.binding_digest,
                        expires_at: record.expires_at,
                        issued_at: record.issued_at,
                    })
                    .collect()
            })
    }

    fn claim_frost_nonce(&mut self, claim: FrostNonceClaimState) -> Result<(), WalletStoreError> {
        self.storage
            .consume_authorization_and_claim_frost_nonce(FrostNonceAuthorizationClaim {
                authorization_id: claim.authorization_id,
                intent_id: claim.intent_id,
                signer_id: signer_label(claim.signer_id),
                session_id: claim.session_id,
                fingerprint: claim.fingerprint,
                claimed_at: claim.claimed_at,
            })
            .map_err(store_error)
    }

    fn signer_profiles(
        &self,
    ) -> Result<Vec<(SignerProfile, Vec<AddressBinding>)>, WalletStoreError> {
        self.storage
            .signer_profile_inventory(self.wallet_id)
            .map_err(store_error)
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| {
                        let profile = record.profile;
                        (
                            SignerProfile {
                                profile_id: profile.profile_id,
                                wallet_id: profile.wallet_id,
                                chain_scope: profile.chain_scope,
                                signing_suite_id: profile.signing_suite_id,
                                backend_requirement: profile.backend_requirement,
                                signer_set_id: profile.signer_set_id,
                                authorization_signer_id: profile.authorization_signer_id,
                                signer_epoch: profile.signer_epoch,
                                threshold: profile.threshold,
                                max_signers: profile.max_signers,
                                verification_key: profile.verification_key,
                                secret_ref: record.secret_ref,
                            },
                            record
                                .address_bindings
                                .into_iter()
                                .map(|binding| AddressBinding {
                                    binding_id: binding.binding_id,
                                    profile_id: binding.profile_id,
                                    chain_scope: binding.chain_scope,
                                    address: binding.address,
                                    verification_key_digest: binding.verification_key_digest,
                                })
                                .collect(),
                        )
                    })
                    .collect()
            })
    }

    fn create_chain_signing_job(
        &mut self,
        request: CreateChainSigningJobRequest,
        now: i64,
    ) -> Result<ChainSigningJobState, WalletStoreError> {
        let profile = self
            .storage
            .signer_profile(request.job.profile_id)
            .map_err(store_error)?
            .ok_or_else(|| WalletStoreError::new("chain signing profile is missing"))?;
        let binding = &request.job.review_binding;
        if binding.chain_scope != request.job.chain_scope
            || binding.signing_suite_id != request.job.signing_suite_id
            || binding.signer_set_id != profile.signer_set_id
            || binding.signer_set_epoch != profile.signer_epoch
            || binding.review_schema_version != request.job.review.schema_version
            || binding.review_digest != request.job.review.review_digest
        {
            return Err(WalletStoreError::new(
                "chain signing review binding mismatch",
            ));
        }
        let job = request.job;
        let intent_id = job.intent_id;
        let stored = self
            .storage
            .create_signing_job(
                request.authorization_id,
                NewSigningJob {
                    job_id: job.job_id,
                    wallet_id: job.wallet_id,
                    profile_id: job.profile_id,
                    intent_id: job.intent_id,
                    chain_scope: job.chain_scope,
                    signing_suite_id: job.signing_suite_id,
                    backend_requirement: job.backend_requirement,
                    review_schema_version: job.review.schema_version,
                    review_artifact: job.review.clone(),
                    review_digest: job.review.review_digest,
                    signing_message_digest: job.review.signing_message_digest,
                    policy_snapshot_digest: job.policy_snapshot_digest,
                    chain_snapshot_digest: job.chain_snapshot_digest,
                    session_id: job.session_id,
                    selected_parties: job.online_parties,
                    receiver: job.receiver,
                    expires_at: job.expires_at,
                    created_at: job.created_at,
                },
                request.operation_binding_digest,
                now,
            )
            .map_err(store_error)?;
        if let Some(intent) = self
            .intents
            .iter_mut()
            .find(|intent| intent.id == intent_id)
        {
            intent.status = IntentStatus::Signing;
        }
        chain_signing_state(stored)
    }

    fn chain_signing_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ChainSigningJobState>, WalletStoreError> {
        self.storage
            .signing_job(job_id)
            .map_err(store_error)?
            .map(chain_signing_state)
            .transpose()
    }

    fn chain_signing_execution(
        &self,
        job_id: Uuid,
    ) -> Result<Option<ChainSigningExecution>, WalletStoreError> {
        let Some(record) = self.storage.signing_job(job_id).map_err(store_error)? else {
            return Ok(None);
        };
        if record.status != SigningJobStatus::Signing {
            return Err(WalletStoreError::new("chain signing job is not executable"));
        }
        let profile = self
            .storage
            .signer_profile(record.profile_id)
            .map_err(store_error)?
            .ok_or_else(|| WalletStoreError::new("chain signing profile is missing"))?;
        let review_binding = ReviewBinding::new(
            record.chain_scope,
            record.signing_suite_id,
            profile.signer_set_id,
            profile.signer_epoch,
            record.review_schema_version,
            record.review_digest,
        )
        .map_err(|error| WalletStoreError::new(error.to_string()))?;
        let operation_binding_digest = record.operation_binding_digest.ok_or_else(|| {
            WalletStoreError::new("authorized chain signing job is missing its binding")
        })?;
        Ok(Some(ChainSigningExecution {
            job: SigningJob {
                job_id: record.job_id,
                intent_id: record.intent_id,
                profile_id: record.profile_id,
                wallet_id: record.wallet_id,
                chain_scope: record.chain_scope,
                signing_suite_id: record.signing_suite_id,
                backend_requirement: record.backend_requirement,
                review: record.review_artifact,
                review_binding,
                policy_snapshot_digest: record.policy_snapshot_digest,
                chain_snapshot_digest: record.chain_snapshot_digest,
                online_parties: record.selected_parties,
                receiver: record.receiver,
                session_id: record.session_id,
                expires_at: record.expires_at,
                created_at: record.created_at,
            },
            operation_binding_digest,
        }))
    }

    fn claim_chain_executor(
        &mut self,
        execution: &ChainSigningExecution,
        now: i64,
    ) -> Result<(), WalletStoreError> {
        self.storage
            .claim_chain_executor(ChainExecutorClaim {
                wallet_id: execution.job.wallet_id,
                profile_id: execution.job.profile_id,
                signing_suite_id: execution.job.signing_suite_id,
                backend_requirement: execution.job.backend_requirement,
                session_id: execution.job.session_id,
                review_domain_digest: Sha256::digest(
                    execution.job.review_binding.domain_separator(),
                )
                .into(),
                signing_message_digest: execution.job.review.signing_message_digest,
                operation_binding_digest: execution.operation_binding_digest,
                claimed_at: now,
            })
            .map_err(store_error)
    }

    fn finalize_chain_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        final_signature: Vec<u8>,
        now: i64,
    ) -> Result<(), WalletStoreError> {
        let intent_id = self
            .storage
            .signing_job(job_id)
            .map_err(store_error)?
            .ok_or_else(|| WalletStoreError::new("chain signing job is missing"))?
            .intent_id;
        self.storage
            .complete_signing_job(job_id, operation_binding_digest, final_signature, now)
            .map_err(store_error)?;
        if let Some(intent) = self
            .intents
            .iter_mut()
            .find(|intent| intent.id == intent_id)
        {
            intent.status = IntentStatus::Signed;
        }
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
        let status = match status {
            ChainSigningJobStatus::Aborted => SigningJobStatus::Aborted,
            ChainSigningJobStatus::Expired => SigningJobStatus::Expired,
            ChainSigningJobStatus::Failed => SigningJobStatus::Failed,
            ChainSigningJobStatus::Signing | ChainSigningJobStatus::Finalized => {
                return Err(WalletStoreError::new("invalid terminal chain job status"));
            }
        };
        let intent_id = self
            .storage
            .signing_job(job_id)
            .map_err(store_error)?
            .ok_or_else(|| WalletStoreError::new("chain signing job is missing"))?
            .intent_id;
        self.storage
            .terminate_signing_job(job_id, operation_binding_digest, status, &reason, now)
            .map_err(store_error)?;
        if let Some(intent) = self
            .intents
            .iter_mut()
            .find(|intent| intent.id == intent_id)
        {
            intent.status = IntentStatus::Expired;
        }
        Ok(())
    }
}

fn chain_signing_state(record: StoredSigningJob) -> Result<ChainSigningJobState, WalletStoreError> {
    let status = match record.status {
        SigningJobStatus::Signing => ChainSigningJobStatus::Signing,
        SigningJobStatus::Finalized => ChainSigningJobStatus::Finalized,
        SigningJobStatus::Aborted => ChainSigningJobStatus::Aborted,
        SigningJobStatus::Expired => ChainSigningJobStatus::Expired,
        SigningJobStatus::Failed => ChainSigningJobStatus::Failed,
        SigningJobStatus::Prepared => {
            return Err(WalletStoreError::new(
                "unauthorized prepared signing job found in durable storage",
            ));
        }
    };
    Ok(ChainSigningJobState {
        job_id: record.job_id,
        intent_id: record.intent_id,
        wallet_id: record.wallet_id,
        profile_id: record.profile_id,
        chain_scope: record.chain_scope,
        signing_suite_id: record.signing_suite_id,
        backend_requirement: record.backend_requirement,
        review_schema_version: record.review_schema_version,
        review_digest: record.review_digest,
        signing_message_digest: record.signing_message_digest,
        policy_snapshot_digest: record.policy_snapshot_digest,
        chain_snapshot_digest: record.chain_snapshot_digest,
        session_id: record.session_id,
        online_parties: record.selected_parties,
        receiver: record.receiver,
        operation_binding_digest: record.operation_binding_digest.ok_or_else(|| {
            WalletStoreError::new("authorized signing job is missing its operation binding")
        })?,
        status,
        final_signature: record.final_signature,
        terminal_reason: record.terminal_reason,
        expires_at: record.expires_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn signer_label(signer_id: u16) -> String {
    format!("frost:participant-{signer_id}")
}

fn compatibility_policy_hash() -> [u8; 32] {
    Sha256::digest(b"catomicals/wallet-core/unclassified-taproot-policy-v1").into()
}

fn intent_policy_hash(intent: &SigningIntent) -> [u8; 32] {
    intent
        .personal_signing_policy
        .as_ref()
        .map_or_else(compatibility_policy_hash, |policy| policy.policy_digest)
}

fn to_storage_status(status: IntentStatus) -> TransactionIntentStatus {
    match status {
        IntentStatus::Pending => TransactionIntentStatus::Pending,
        IntentStatus::Approved => TransactionIntentStatus::Approved,
        IntentStatus::Signing => TransactionIntentStatus::Signing,
        IntentStatus::Cancelled => TransactionIntentStatus::Cancelled,
        IntentStatus::Expired => TransactionIntentStatus::Expired,
        IntentStatus::Signed => TransactionIntentStatus::Signed,
    }
}

fn from_storage_status(status: TransactionIntentStatus) -> IntentStatus {
    match status {
        TransactionIntentStatus::Pending => IntentStatus::Pending,
        TransactionIntentStatus::Approved => IntentStatus::Approved,
        TransactionIntentStatus::Signing => IntentStatus::Signing,
        TransactionIntentStatus::Signed => IntentStatus::Signed,
        TransactionIntentStatus::Cancelled => IntentStatus::Cancelled,
        TransactionIntentStatus::Expired | TransactionIntentStatus::Invalidated => {
            IntentStatus::Expired
        }
    }
}

fn store_error(error: impl std::fmt::Display) -> WalletStoreError {
    WalletStoreError::new(error.to_string())
}
