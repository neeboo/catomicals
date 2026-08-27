//! Translation layer between wallet-domain storage records and SQLite-backed
//! authority storage. SQL and connection details remain in `wallet-storage`.

use std::collections::HashMap;
use std::path::Path;

use catomicals_wallet_storage::{
    ApprovalNonce, CredentialState, FrostNonceAuthorizationClaim, IntentAction, IntentMaterial,
    IntentMaterialKind, IntentNetwork, NewPasskeyApprovalCeremony, NewPasskeyRecord,
    NewTransactionIntentV2, PasskeyApprovalCompletion, TransactionIntentStatus, WalletStorage,
    WebauthnProfile,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    IntentStatus, SigningIntent,
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
                if intent.id != record.id
                    || intent.wallet_id != record.wallet_id
                    || intent.tx_digest != record.tx_digest
                    || intent.session_id != record.session_id
                    || intent.nonce != record.approval_nonce.0
                    || record.policy_hash != compatibility_policy_hash()
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
        let policy_hash = compatibility_policy_hash();
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
}

fn signer_label(signer_id: u16) -> String {
    format!("frost:participant-{signer_id}")
}

fn compatibility_policy_hash() -> [u8; 32] {
    Sha256::digest(b"catomicals/wallet-core/unclassified-taproot-policy-v1").into()
}

fn to_storage_status(status: IntentStatus) -> TransactionIntentStatus {
    match status {
        IntentStatus::Pending => TransactionIntentStatus::Pending,
        IntentStatus::Approved => TransactionIntentStatus::Approved,
        IntentStatus::Cancelled => TransactionIntentStatus::Cancelled,
        IntentStatus::Expired => TransactionIntentStatus::Expired,
        IntentStatus::Signed => TransactionIntentStatus::Signed,
    }
}

fn from_storage_status(status: TransactionIntentStatus) -> IntentStatus {
    match status {
        TransactionIntentStatus::Pending => IntentStatus::Pending,
        TransactionIntentStatus::Approved | TransactionIntentStatus::Signing => {
            IntentStatus::Approved
        }
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
