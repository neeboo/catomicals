//! Storage port for wallet authority state.
//!
//! Domain code depends on this trait and never handles database connections,
//! SQL, paths, or migration details. The in-memory implementation preserves
//! the development server behavior; the durable adapter translates these
//! values to `wallet-storage` records.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AddressBinding, ChainSigningExecution, ChainSigningJobState, CreateChainSigningJobRequest,
    SignerProfile,
    intent::{IntentId, SigningIntent},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    Compatibility,
    Durable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDescriptor {
    pub mode: StorageMode,
    pub schema_version: Option<i32>,
    pub recovery_epoch: Option<u64>,
    pub startup_invalidated_ceremonies: u64,
}

impl StorageDescriptor {
    pub fn compatibility() -> Self {
        Self {
            mode: StorageMode::Compatibility,
            schema_version: None,
            recovery_epoch: None,
            startup_invalidated_ceremonies: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("wallet authority storage failed: {message}")]
pub struct WalletStoreError {
    message: String,
}

impl WalletStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Public WebAuthn credential state. It contains a credential public key and
/// counters, never an authenticator secret or a Bitcoin signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyState {
    pub credential_id: String,
    pub label: String,
    pub passkey_json: String,
    pub format: String,
    pub record_version: u64,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnProfileState {
    pub wallet_id: Uuid,
    pub user_id: Uuid,
    pub rp_id: String,
    pub rp_origin: String,
    pub record_version: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStartState {
    pub ceremony_id: Uuid,
    pub intent_id: IntentId,
    pub credential_id: String,
    pub binding_digest: [u8; 32],
    pub started_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCompletionState {
    pub ceremony_id: Uuid,
    pub intent_id: IntentId,
    pub credential_id: String,
    pub expected_credential_record_version: u64,
    pub updated_passkey_json: String,
    pub binding_digest: [u8; 32],
    pub authorization_id: Uuid,
    pub authorization_expires_at: i64,
    pub rp_id: String,
    pub rp_origin: String,
    pub approved_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationState {
    pub id: Uuid,
    pub intent_id: IntentId,
    pub binding_digest: [u8; 32],
    pub expires_at: i64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostNonceClaimState {
    pub authorization_id: Uuid,
    pub intent_id: IntentId,
    pub signer_id: u16,
    pub session_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub claimed_at: i64,
}

/// Storage interface used by wallet-domain services.
pub trait WalletStore: Send {
    fn descriptor(&self) -> StorageDescriptor;
    fn wallet_id(&self) -> Option<Uuid>;

    fn insert_intent(&mut self, intent: SigningIntent) -> Result<(), WalletStoreError>;
    fn get_intent(&self, id: &IntentId) -> Option<SigningIntent>;
    fn list_intents(&self) -> Vec<SigningIntent>;
    fn update_intent(&mut self, intent: SigningIntent, now: i64) -> Result<(), WalletStoreError>;

    fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError>;
    fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError>;
    fn insert_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletStoreError>;
    fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError>;

    fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletStoreError>;
    fn complete_approval(
        &mut self,
        state: ApprovalCompletionState,
    ) -> Result<AuthorizationState, WalletStoreError>;
    fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletStoreError>;
    fn claim_frost_nonce(&mut self, claim: FrostNonceClaimState) -> Result<(), WalletStoreError>;

    /// Public signer metadata used to restore chain executors at startup.
    /// The profile's `secret_ref` is an opaque backend handle, never key or
    /// threshold-share material.
    fn signer_profiles(
        &self,
    ) -> Result<Vec<(SignerProfile, Vec<AddressBinding>)>, WalletStoreError> {
        Ok(Vec::new())
    }

    fn create_chain_signing_job(
        &mut self,
        _request: CreateChainSigningJobRequest,
        _now: i64,
    ) -> Result<ChainSigningJobState, WalletStoreError> {
        Err(WalletStoreError::new(
            "chain signing requires durable authority storage",
        ))
    }

    fn chain_signing_job(
        &self,
        _job_id: Uuid,
    ) -> Result<Option<ChainSigningJobState>, WalletStoreError> {
        Ok(None)
    }

    fn chain_signing_execution(
        &self,
        _job_id: Uuid,
    ) -> Result<Option<ChainSigningExecution>, WalletStoreError> {
        Ok(None)
    }

    /// Persist the one-time boundary immediately before a chain executor may
    /// contact any signer. Durable stores must reject a repeated claim after
    /// restart.
    fn claim_chain_executor(
        &mut self,
        _execution: &ChainSigningExecution,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new(
            "chain executor claims require durable authority storage",
        ))
    }

    fn finalize_chain_signing_job(
        &mut self,
        _job_id: Uuid,
        _operation_binding_digest: [u8; 32],
        _final_signature: Vec<u8>,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new(
            "chain signing requires durable authority storage",
        ))
    }

    fn terminate_chain_signing_job(
        &mut self,
        _job_id: Uuid,
        _operation_binding_digest: [u8; 32],
        _status: crate::ChainSigningJobStatus,
        _reason: String,
        _now: i64,
    ) -> Result<(), WalletStoreError> {
        Err(WalletStoreError::new(
            "chain signing requires durable authority storage",
        ))
    }
}

/// Default process-local store used when `wallet serve` has no `--data-dir`.
#[derive(Debug, Default)]
pub struct InMemoryWalletStore {
    intents: HashMap<IntentId, SigningIntent>,
    profile: Option<WebauthnProfileState>,
    passkeys: Vec<PasskeyState>,
    approvals: HashMap<Uuid, ApprovalStartState>,
    authorizations: HashMap<IntentId, AuthorizationState>,
    nonce_claims: HashMap<[u8; 32], FrostNonceClaimState>,
}

impl InMemoryWalletStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WalletStore for InMemoryWalletStore {
    fn descriptor(&self) -> StorageDescriptor {
        StorageDescriptor::compatibility()
    }

    fn wallet_id(&self) -> Option<Uuid> {
        self.profile.as_ref().map(|profile| profile.wallet_id)
    }

    fn insert_intent(&mut self, intent: SigningIntent) -> Result<(), WalletStoreError> {
        self.intents.insert(intent.id, intent);
        Ok(())
    }

    fn get_intent(&self, id: &IntentId) -> Option<SigningIntent> {
        self.intents.get(id).cloned()
    }

    fn list_intents(&self) -> Vec<SigningIntent> {
        let mut intents: Vec<_> = self.intents.values().cloned().collect();
        intents.sort_by_key(|intent| (intent.created_at, intent.id));
        intents
    }

    fn update_intent(&mut self, intent: SigningIntent, _now: i64) -> Result<(), WalletStoreError> {
        self.intents.insert(intent.id, intent);
        Ok(())
    }

    fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError> {
        Ok(self.profile.clone())
    }

    fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletStoreError> {
        self.profile = Some(profile);
        Ok(())
    }

    fn insert_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletStoreError> {
        self.passkeys.push(passkey);
        Ok(())
    }

    fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError> {
        Ok(self.passkeys.clone())
    }

    fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletStoreError> {
        self.approvals.insert(state.ceremony_id, state);
        Ok(())
    }

    fn complete_approval(
        &mut self,
        state: ApprovalCompletionState,
    ) -> Result<AuthorizationState, WalletStoreError> {
        let ceremony = self
            .approvals
            .remove(&state.ceremony_id)
            .ok_or_else(|| WalletStoreError::new("approval ceremony is unavailable"))?;
        if ceremony.intent_id != state.intent_id
            || ceremony.credential_id != state.credential_id
            || ceremony.binding_digest != state.binding_digest
        {
            return Err(WalletStoreError::new("approval binding mismatch"));
        }
        let passkey = self
            .passkeys
            .iter_mut()
            .find(|passkey| passkey.credential_id == state.credential_id)
            .ok_or_else(|| WalletStoreError::new("passkey is unavailable"))?;
        if passkey.record_version != state.expected_credential_record_version {
            return Err(WalletStoreError::new("passkey record version conflict"));
        }
        passkey.record_version += 1;
        passkey.passkey_json = state.updated_passkey_json;
        let authorization = AuthorizationState {
            id: state.authorization_id,
            intent_id: state.intent_id,
            binding_digest: state.binding_digest,
            expires_at: state.authorization_expires_at,
            issued_at: state.approved_at,
        };
        self.authorizations
            .insert(state.intent_id, authorization.clone());
        if let Some(intent) = self.intents.get_mut(&state.intent_id) {
            intent.status = crate::IntentStatus::Approved;
        }
        Ok(authorization)
    }

    fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletStoreError> {
        Ok(self
            .authorizations
            .values()
            .filter(|authorization| authorization.expires_at >= now)
            .cloned()
            .collect())
    }

    fn claim_frost_nonce(&mut self, claim: FrostNonceClaimState) -> Result<(), WalletStoreError> {
        if self.nonce_claims.contains_key(&claim.fingerprint) {
            return Err(WalletStoreError::new("FROST nonce already claimed"));
        }
        let authorization = self
            .authorizations
            .remove(&claim.intent_id)
            .ok_or_else(|| WalletStoreError::new("authorization is unavailable"))?;
        if authorization.id != claim.authorization_id {
            return Err(WalletStoreError::new("authorization binding mismatch"));
        }
        self.nonce_claims.insert(claim.fingerprint, claim);
        Ok(())
    }
}
