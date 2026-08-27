//! In-memory intent and credential stores for the wallet node.
//!
//! The wallet node deliberately holds *no* FROST shares: agents can propose and
//! read intents but cannot extract any signing material through this store.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::intent::{IntentId, IntentStatus, SigningIntent};

/// A WebAuthn credential enrolled with the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub label: String,
    /// base64url COSE public key (as delivered by the authenticator).
    pub cose_public_key: Option<String>,
    pub enrolled_at: i64,
}

/// Storage interface kept intentionally tiny.
pub trait WalletStore {
    fn insert_intent(&mut self, intent: SigningIntent);
    fn get_intent(&self, id: &IntentId) -> Option<SigningIntent>;
    fn list_intents(&self) -> Vec<SigningIntent>;
    fn update_intent(&mut self, intent: SigningIntent);
    fn insert_credential(&mut self, cred: CredentialRecord);
    fn list_credentials(&self) -> Vec<CredentialRecord>;
}

/// Default in-memory store (single-node foundation).
#[derive(Debug, Default)]
pub struct InMemoryWalletStore {
    intents: HashMap<IntentId, SigningIntent>,
    credentials: Vec<CredentialRecord>,
}

impl InMemoryWalletStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Transition helper used by the API.
    pub fn set_status(&mut self, id: &IntentId, status: IntentStatus) -> Option<SigningIntent> {
        let intent = self.intents.get_mut(id)?;
        intent.status = status;
        Some(intent.clone())
    }
}

impl WalletStore for InMemoryWalletStore {
    fn insert_intent(&mut self, intent: SigningIntent) {
        self.intents.insert(intent.id, intent);
    }
    fn get_intent(&self, id: &IntentId) -> Option<SigningIntent> {
        self.intents.get(id).cloned()
    }
    fn list_intents(&self) -> Vec<SigningIntent> {
        self.intents.values().cloned().collect()
    }
    fn update_intent(&mut self, intent: SigningIntent) {
        self.intents.insert(intent.id, intent);
    }
    fn insert_credential(&mut self, cred: CredentialRecord) {
        self.credentials.push(cred);
    }
    fn list_credentials(&self) -> Vec<CredentialRecord> {
        self.credentials.clone()
    }
}
