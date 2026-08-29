//! Secret-free chat message types for proposing wallet actions.
//!
//! Chat can create an immutable signing intent, but it never accepts an
//! authenticator response or produces a signing authorization. Approval stays
//! on the wallet node's WebAuthn intent endpoints.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{BitcoinNetwork, IntentId, IntentStatus, SigningAction, WalletId};

pub const MAX_CHAT_MESSAGE_BYTES: usize = 2_000;
pub const MAX_CHAT_MESSAGES: usize = 500;

pub type ChatMessageId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageRole {
    User,
    Wallet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageKind {
    Text,
    WalletAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatAuthorizationState {
    PasskeyRequired,
    Approved,
    Signing,
    Cancelled,
    Expired,
    Signed,
}

impl ChatAuthorizationState {
    pub(crate) fn from_intent(status: IntentStatus, expired: bool) -> Self {
        match status {
            IntentStatus::Pending if expired => Self::Expired,
            IntentStatus::Pending => Self::PasskeyRequired,
            IntentStatus::Approved => Self::Approved,
            IntentStatus::Signing => Self::Signing,
            IntentStatus::Cancelled => Self::Cancelled,
            IntentStatus::Expired => Self::Expired,
            IntentStatus::Signed => Self::Signed,
        }
    }
}

/// The only wallet-affecting operation accepted by the chat API.
/// Unknown fields are rejected so callers cannot smuggle verifier or approval
/// material into a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatWalletActionRequest {
    SignTaprootTransaction {
        wallet_id: WalletId,
        signer_id: u16,
        #[serde(with = "crate::api::hex_array32")]
        tx_digest: [u8; 32],
        #[serde(with = "crate::api::hex_array32")]
        session_id: [u8; 32],
        expiry: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateChatMessageRequest {
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_action: Option<ChatWalletActionRequest>,
}

/// Public, exact binding shown in chat. It intentionally omits the intent
/// nonce and every authorization or signer-secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatIntentBinding {
    pub intent_id: IntentId,
    pub intent_digest_hex: String,
    pub network: BitcoinNetwork,
    pub action: SigningAction,
    pub wallet_id: WalletId,
    pub signer_id: u16,
    pub tx_digest_hex: String,
    pub session_id_hex: String,
    pub expiry: i64,
    pub status: IntentStatus,
    pub authorization: ChatAuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: ChatMessageId,
    pub role: ChatMessageRole,
    pub kind: ChatMessageKind,
    pub content: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_action: Option<ChatIntentBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatExchange {
    pub user_message: ChatMessage,
    pub wallet_message: ChatMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatState {
    pub messages: Vec<ChatMessage>,
    pub pending_wallet_actions: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct ChatRecord {
    pub id: ChatMessageId,
    pub role: ChatMessageRole,
    pub kind: ChatMessageKind,
    pub content: String,
    pub created_at: i64,
    pub intent_id: Option<IntentId>,
}

#[derive(Debug, Default)]
pub(crate) struct ChatStore {
    records: Vec<ChatRecord>,
}

impl ChatStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_exchange(
        &mut self,
        content: String,
        intent_id: Option<IntentId>,
        now: i64,
    ) -> (ChatRecord, ChatRecord) {
        let user = ChatRecord {
            id: Uuid::new_v4(),
            role: ChatMessageRole::User,
            kind: ChatMessageKind::Text,
            content,
            created_at: now,
            intent_id: None,
        };
        let wallet = ChatRecord {
            id: Uuid::new_v4(),
            role: ChatMessageRole::Wallet,
            kind: if intent_id.is_some() {
                ChatMessageKind::WalletAction
            } else {
                ChatMessageKind::Text
            },
            content: if intent_id.is_some() {
                "Signing intent prepared. Review the exact binding, then approve it with your Passkey. Chat cannot approve or sign it.".into()
            } else {
                "I can prepare an exact-bound Taproot signing intent. Wallet-affecting actions always require Passkey approval before the signer is released.".into()
            },
            created_at: now,
            intent_id,
        };
        self.records.push(user.clone());
        self.records.push(wallet.clone());
        (user, wallet)
    }

    pub fn records(&self) -> &[ChatRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn get(&self, id: ChatMessageId) -> Option<&ChatRecord> {
        self.records.iter().find(|message| message.id == id)
    }
}
