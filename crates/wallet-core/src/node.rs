//! Typed wallet-node façade. Secret-bearing values remain inside this type.

use std::collections::HashMap;

use catomicals_threshold::{
    FrostSession, LocalFrostParticipant, PublicKeyPackage, SignatureShare, SigningCommitments,
    SigningError,
};
use catomicals_trading::{AgentTradingApi, TradeSigningRequest, WalletTradingApi};
use serde::{Deserialize, Serialize};

use crate::{
    ChatAuthorizationState, ChatExchange, ChatIntentBinding, ChatMessage, ChatMessageId, ChatState,
    ChatWalletActionRequest, CreateChatMessageRequest, CreateIntentRequest, IntentId, IntentStatus,
    MAX_CHAT_MESSAGE_BYTES, MAX_CHAT_MESSAGES, SigningAuthorization, SigningIntent, WalletApi,
    WalletError, WalletSnapshot,
    chat::{ChatRecord, ChatStore},
    transaction::{
        TransactionReview, TransactionReviewRequest, inspect_transaction as review_transaction,
    },
    webauthn::{
        ApprovalFinishRequest, ApprovalFinishResponse, ApprovalStartResponse, CredentialSummary,
        PasskeyRegistrationFinishRequest, PasskeyRegistrationFinishResponse,
        PasskeyRegistrationStartRequest, PasskeyRegistrationStartResponse, RelyingPartyConfig,
        WebAuthnRelyingParty,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPhase {
    PendingApproval,
    Approved,
    RoundOneReady,
    ShareProduced,
    Signed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletNodeStatus {
    pub network: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub persistence: String,
    pub secret_storage: String,
    pub production_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSignerStatus {
    pub signer_id: Option<u16>,
    pub configured: bool,
    pub min_signers: u16,
    pub group_pubkey_xonly: Option<String>,
    pub approved_actions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSigningStatus {
    pub intent_id: IntentId,
    pub signer_id: u16,
    pub session_id_hex: String,
    pub message_hex: String,
    pub phase: SigningPhase,
    pub expires_at: i64,
}

/// A protected-trade signing request. The caller supplies raw transaction
/// material, while the wallet derives the BIP341 message after policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTradeIntentRequest {
    pub wallet_id: crate::WalletId,
    pub signer_id: u16,
    #[serde(with = "crate::api::hex_array32")]
    pub session_id: [u8; 32],
    pub expiry: i64,
    pub trade: TradeSigningRequest,
}

/// A generic Taproot key-spend request whose digest is derived by the wallet
/// after decoding the complete unsigned transaction and ordered prevouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTransactionIntentRequest {
    pub wallet_id: crate::WalletId,
    pub signer_id: u16,
    #[serde(with = "crate::api::hex_array32")]
    pub session_id: [u8; 32],
    pub expiry: i64,
    pub transaction: TransactionReviewRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeVerification {
    pub path: catomicals_trading::TradePath,
    pub txid: String,
    pub sighash_hex: String,
    pub fee_sat: u64,
    pub spent_order_outpoint: bitcoin::OutPoint,
    pub listing_commitment_hex: String,
    pub independently_verified_by: String,
}

impl TradeVerification {
    fn from_verified(verified: &catomicals_trading::VerifiedTrade, verifier: &str) -> Self {
        Self {
            path: verified.path,
            txid: verified.txid.to_string(),
            sighash_hex: hex::encode(verified.sighash),
            fee_sat: verified.fee_sat,
            spent_order_outpoint: verified.spent_order_outpoint,
            listing_commitment_hex: hex::encode(verified.listing_commitment),
            independently_verified_by: verifier.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletNodeError {
    #[error("invalid WebAuthn origin: {0}")]
    InvalidOrigin(String),
    #[error("non-local WebAuthn origins require HTTPS")]
    InsecureRemoteOrigin,
    #[error("ceremony TTL must be positive")]
    InvalidCeremonyTtl,
    #[error("registration label and user names must be non-empty")]
    InvalidRegistrationIdentity,
    #[error("Passkey registration is locked after the first credential is enrolled")]
    RegistrationLocked,
    #[error("WebAuthn verification failed: {0}")]
    WebAuthn(String),
    #[error("ceremony does not exist or has already been consumed")]
    CeremonyNotFound,
    #[error("ceremony expired")]
    CeremonyExpired,
    #[error("credential already registered")]
    CredentialAlreadyRegistered,
    #[error("credential is not registered")]
    CredentialNotFound,
    #[error("at least one Passkey must be registered")]
    NoCredentials,
    #[error("user verification is required")]
    UserVerificationRequired,
    #[error("intent is not pending")]
    IntentNotPending,
    #[error("intent not found")]
    IntentNotFound,
    #[error("intent expired")]
    IntentExpired,
    #[error("approval ceremony is bound to a different immutable intent")]
    IntentBindingMismatch,
    #[error("this node has no FROST participant configured")]
    SignerNotConfigured,
    #[error("intent belongs to a different signer")]
    WrongSigner,
    #[error("Passkey authorization is unavailable or already consumed")]
    AuthorizationUnavailable,
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("FROST signing error: {0}")]
    Signing(String),
    #[error("a trusted active Signet node snapshot is required for trade approval")]
    TradeNodeUnavailable,
    #[error("protected trade policy rejected the raw transaction: {0}")]
    TradePolicy(String),
    #[error("protected trade seller key does not match this wallet's FROST group key")]
    TradeSignerMismatch,
    #[error("transaction review rejected the request: {0}")]
    TransactionPolicy(String),
    #[error("chat message does not exist")]
    ChatMessageNotFound,
    #[error("chat message must contain 1..={MAX_CHAT_MESSAGE_BYTES} bytes after trimming")]
    InvalidChatMessage,
    #[error("chat history reached its {MAX_CHAT_MESSAGES}-message in-memory limit")]
    ChatHistoryFull,
}

impl From<WalletError> for WalletNodeError {
    fn from(error: WalletError) -> Self {
        match error {
            WalletError::NotFound => Self::IntentNotFound,
            other => Self::Wallet(other.to_string()),
        }
    }
}

impl From<SigningError> for WalletNodeError {
    fn from(error: SigningError) -> Self {
        Self::Signing(error.to_string())
    }
}

/// A self-hosted relying party plus exactly one optional FROST participant.
pub struct WalletNodeService {
    wallet: WalletApi,
    relying_party: WebAuthnRelyingParty,
    participant: Option<LocalFrostParticipant>,
    public_key_package: Option<PublicKeyPackage>,
    min_signers: u16,
    authorizations: HashMap<IntentId, SigningAuthorization>,
    phases: HashMap<IntentId, SigningPhase>,
    trade_requests: HashMap<IntentId, TradeSigningRequest>,
    transaction_requests: HashMap<IntentId, TransactionReviewRequest>,
    chat: ChatStore,
}

impl WalletNodeService {
    pub fn new(
        config: RelyingPartyConfig,
        participant: Option<LocalFrostParticipant>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
    ) -> Result<Self, WalletNodeError> {
        let relying_party = WebAuthnRelyingParty::new(config)?;
        let signer_id = participant.as_ref().map(LocalFrostParticipant::signer_id);
        let max_signers = u16::try_from(public_key_package.verifying_shares().len())
            .map_err(|_| WalletNodeError::SignerNotConfigured)?;
        let xonly = catomicals_threshold::group_pubkey_xonly(&public_key_package)
            .map_err(|error| WalletNodeError::Signing(error.to_string()))?;
        let mut wallet = WalletApi::new();
        wallet.configure_threshold(min_signers, max_signers, xonly);
        if let Some(id) = signer_id {
            wallet.set_signers(vec![crate::SignerSnapshot {
                id,
                label: format!("local participant {id}"),
                online: true,
            }]);
        }
        Ok(Self {
            wallet,
            relying_party,
            participant,
            public_key_package: Some(public_key_package),
            min_signers,
            authorizations: HashMap::new(),
            phases: HashMap::new(),
            trade_requests: HashMap::new(),
            transaction_requests: HashMap::new(),
            chat: ChatStore::new(),
        })
    }

    pub fn without_signer(config: RelyingPartyConfig) -> Result<Self, WalletNodeError> {
        Ok(Self {
            wallet: WalletApi::new(),
            relying_party: WebAuthnRelyingParty::new(config)?,
            participant: None,
            public_key_package: None,
            min_signers: 0,
            authorizations: HashMap::new(),
            phases: HashMap::new(),
            trade_requests: HashMap::new(),
            transaction_requests: HashMap::new(),
            chat: ChatStore::new(),
        })
    }

    pub fn node_status(&self) -> WalletNodeStatus {
        WalletNodeStatus {
            network: "signet".into(),
            rp_id: self.relying_party.config().rp_id.clone(),
            rp_origin: self.relying_party.config().rp_origin.clone(),
            persistence: "memory-only; restart loses credentials, intents, and replay state".into(),
            secret_storage: "process-memory-only; no encryption or hardware isolation".into(),
            production_ready: false,
        }
    }

    pub fn set_node_snapshot(&mut self, node: Option<crate::NodeSnapshot>) {
        self.wallet.set_node_snapshot(node);
    }

    pub fn wallet_status(&self) -> WalletSnapshot {
        let mut status = self.wallet.status();
        status.credentials = self.relying_party.credential_count();
        status
    }

    pub fn signer_status(&self) -> WalletSignerStatus {
        WalletSignerStatus {
            signer_id: self
                .participant
                .as_ref()
                .map(LocalFrostParticipant::signer_id),
            configured: self.participant.is_some(),
            min_signers: self.min_signers,
            group_pubkey_xonly: self
                .public_key_package
                .as_ref()
                .and_then(|package| catomicals_threshold::group_pubkey_xonly(package).ok())
                .map(hex::encode),
            approved_actions: self.authorizations.len(),
        }
    }

    pub fn credentials(&self) -> Vec<CredentialSummary> {
        self.relying_party.credentials()
    }

    pub fn public_key_package(&self) -> &PublicKeyPackage {
        self.public_key_package
            .as_ref()
            .expect("configured service has a public key package")
    }

    pub fn create_intent(
        &mut self,
        request: CreateIntentRequest,
        now: i64,
    ) -> Result<SigningIntent, WalletNodeError> {
        if let Some(participant) = &self.participant
            && request.signer_id != participant.signer_id()
        {
            return Err(WalletNodeError::WrongSigner);
        }
        let intent = self.wallet.create_intent(request, now)?;
        self.phases.insert(intent.id, SigningPhase::PendingApproval);
        Ok(intent)
    }

    fn trading_height(&self) -> Result<u32, WalletNodeError> {
        let node = self
            .wallet
            .node_snapshot()
            .filter(|node| node.chain == "signet" && node.op_cat_active)
            .ok_or(WalletNodeError::TradeNodeUnavailable)?;
        u32::try_from(node.blocks).map_err(|_| WalletNodeError::TradeNodeUnavailable)
    }

    /// Agent-facing dry-run. This uses the agent verifier and does not create
    /// an intent or confer signing authority.
    pub fn verify_trade_for_agent(
        &self,
        request: &TradeSigningRequest,
    ) -> Result<TradeVerification, WalletNodeError> {
        let verified = AgentTradingApi::verify(request, self.trading_height()?)
            .map_err(|error| WalletNodeError::TradePolicy(error.to_string()))?;
        Ok(TradeVerification::from_verified(&verified, "agent"))
    }

    /// Wallet-facing creation path. The caller cannot choose `tx_digest`; it
    /// is derived from the independently decoded transaction and prevouts.
    pub fn create_trade_intent(
        &mut self,
        request: CreateTradeIntentRequest,
        now: i64,
    ) -> Result<SigningIntent, WalletNodeError> {
        let verified = WalletTradingApi::verify(&request.trade, self.trading_height()?)
            .map_err(|error| WalletNodeError::TradePolicy(error.to_string()))?;
        if let Some(package) = &self.public_key_package {
            let group_key = catomicals_threshold::group_pubkey_xonly(package)
                .map_err(|error| WalletNodeError::Signing(error.to_string()))?;
            if verified.seller_key.serialize() != group_key {
                return Err(WalletNodeError::TradeSignerMismatch);
            }
        }
        let intent = self.create_intent(
            CreateIntentRequest {
                wallet_id: request.wallet_id,
                signer_id: request.signer_id,
                tx_digest: verified.sighash,
                session_id: request.session_id,
                expiry: request.expiry,
            },
            now,
        )?;
        self.trade_requests.insert(intent.id, request.trade);
        Ok(intent)
    }

    pub fn trade_verification(
        &self,
        intent_id: IntentId,
    ) -> Result<TradeVerification, WalletNodeError> {
        let request = self
            .trade_requests
            .get(&intent_id)
            .ok_or(WalletNodeError::IntentNotFound)?;
        let verified = WalletTradingApi::verify(request, self.trading_height()?)
            .map_err(|error| WalletNodeError::TradePolicy(error.to_string()))?;
        let intent = self.wallet.read_intent(&intent_id)?;
        if intent.tx_digest != verified.sighash {
            return Err(WalletNodeError::IntentBindingMismatch);
        }
        Ok(TradeVerification::from_verified(&verified, "wallet"))
    }

    pub fn read_intent(&self, id: IntentId) -> Result<SigningIntent, WalletNodeError> {
        Ok(self.wallet.read_intent(&id)?)
    }

    pub fn list_intents(&self) -> Vec<SigningIntent> {
        self.wallet.list_intents()
    }

    pub fn inspect_transaction(
        &self,
        request: &TransactionReviewRequest,
    ) -> Result<TransactionReview, WalletNodeError> {
        review_transaction(request)
            .map_err(|error| WalletNodeError::TransactionPolicy(error.to_string()))
    }

    pub fn create_transaction_intent(
        &mut self,
        request: CreateTransactionIntentRequest,
        now: i64,
    ) -> Result<SigningIntent, WalletNodeError> {
        let review = self.inspect_transaction(&request.transaction)?;
        let digest = hex::decode(&review.sighash_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WalletNodeError::IntentBindingMismatch)?;
        let intent = self.create_intent(
            CreateIntentRequest {
                wallet_id: request.wallet_id,
                signer_id: request.signer_id,
                tx_digest: digest,
                session_id: request.session_id,
                expiry: request.expiry,
            },
            now,
        )?;
        self.transaction_requests
            .insert(intent.id, request.transaction);
        Ok(intent)
    }

    pub fn transaction_review(
        &self,
        intent_id: IntentId,
    ) -> Result<TransactionReview, WalletNodeError> {
        let request = self
            .transaction_requests
            .get(&intent_id)
            .ok_or(WalletNodeError::IntentNotFound)?;
        let review = self.inspect_transaction(request)?;
        let intent = self.wallet.read_intent(&intent_id)?;
        if review.sighash_hex != hex::encode(intent.tx_digest) {
            return Err(WalletNodeError::IntentBindingMismatch);
        }
        Ok(review)
    }

    fn project_chat_record(&self, record: &ChatRecord, now: i64) -> ChatMessage {
        let wallet_action = record.intent_id.and_then(|intent_id| {
            let intent = self.wallet.read_intent(&intent_id).ok()?;
            Some(ChatIntentBinding {
                intent_id,
                intent_digest_hex: hex::encode(intent.digest()),
                network: intent.network,
                action: intent.action,
                wallet_id: intent.wallet_id,
                signer_id: intent.signer_id,
                tx_digest_hex: hex::encode(intent.tx_digest),
                session_id_hex: hex::encode(intent.session_id),
                expiry: intent.expiry,
                status: intent.status,
                authorization: ChatAuthorizationState::from_intent(
                    intent.status,
                    intent.is_expired(now),
                ),
            })
        });
        ChatMessage {
            id: record.id,
            role: record.role,
            kind: record.kind,
            content: record.content.clone(),
            created_at: record.created_at,
            wallet_action,
        }
    }

    pub fn chat_state(&self, now: i64) -> ChatState {
        let messages: Vec<_> = self
            .chat
            .records()
            .iter()
            .map(|record| self.project_chat_record(record, now))
            .collect();
        let pending_wallet_actions = messages
            .iter()
            .filter_map(|message| message.wallet_action.as_ref())
            .filter(|action| action.authorization == ChatAuthorizationState::PasskeyRequired)
            .count();
        ChatState {
            messages,
            pending_wallet_actions,
        }
    }

    pub fn read_chat_message(
        &self,
        id: ChatMessageId,
        now: i64,
    ) -> Result<ChatMessage, WalletNodeError> {
        self.chat
            .get(id)
            .map(|record| self.project_chat_record(record, now))
            .ok_or(WalletNodeError::ChatMessageNotFound)
    }

    pub fn create_chat_message(
        &mut self,
        request: CreateChatMessageRequest,
        now: i64,
    ) -> Result<ChatExchange, WalletNodeError> {
        let content = request.content.trim();
        if content.is_empty() || content.len() > MAX_CHAT_MESSAGE_BYTES {
            return Err(WalletNodeError::InvalidChatMessage);
        }
        if self.chat.len() + 2 > MAX_CHAT_MESSAGES {
            return Err(WalletNodeError::ChatHistoryFull);
        }
        let intent_id = match request.wallet_action {
            Some(ChatWalletActionRequest::SignTaprootTransaction {
                wallet_id,
                signer_id,
                tx_digest,
                session_id,
                expiry,
            }) => Some(
                self.create_intent(
                    CreateIntentRequest {
                        wallet_id,
                        signer_id,
                        tx_digest,
                        session_id,
                        expiry,
                    },
                    now,
                )?
                .id,
            ),
            None => None,
        };
        let (user, wallet) = self.chat.add_exchange(content.into(), intent_id, now);
        Ok(ChatExchange {
            user_message: self.project_chat_record(&user, now),
            wallet_message: self.project_chat_record(&wallet, now),
        })
    }

    pub fn cancel_intent(
        &mut self,
        id: IntentId,
        now: i64,
    ) -> Result<SigningIntent, WalletNodeError> {
        let intent = self.wallet.cancel_intent(&id, now)?;
        self.authorizations.remove(&id);
        self.trade_requests.remove(&id);
        self.transaction_requests.remove(&id);
        self.phases.insert(
            id,
            if intent.status == IntentStatus::Expired {
                SigningPhase::Expired
            } else {
                SigningPhase::Cancelled
            },
        );
        Ok(intent)
    }

    pub fn registration_start(
        &mut self,
        request: PasskeyRegistrationStartRequest,
        now: i64,
    ) -> Result<PasskeyRegistrationStartResponse, WalletNodeError> {
        if self.relying_party.credential_count() != 0 {
            return Err(WalletNodeError::RegistrationLocked);
        }
        self.relying_party.registration_start(request, now)
    }

    pub fn registration_finish(
        &mut self,
        request: PasskeyRegistrationFinishRequest,
        now: i64,
    ) -> Result<PasskeyRegistrationFinishResponse, WalletNodeError> {
        self.relying_party.registration_finish(request, now)
    }

    pub fn approval_start(
        &mut self,
        intent_id: IntentId,
        now: i64,
    ) -> Result<ApprovalStartResponse, WalletNodeError> {
        let intent = self.wallet.read_intent(&intent_id)?;
        if self.trade_requests.contains_key(&intent_id) {
            let verified = self.trade_verification(intent_id)?;
            if verified.sighash_hex != hex::encode(intent.tx_digest) {
                return Err(WalletNodeError::IntentBindingMismatch);
            }
        }
        if self.transaction_requests.contains_key(&intent_id) {
            let review = self.transaction_review(intent_id)?;
            if review.sighash_hex != hex::encode(intent.tx_digest) {
                return Err(WalletNodeError::IntentBindingMismatch);
            }
        }
        self.relying_party.approval_start(&intent, now)
    }

    pub fn approval_finish(
        &mut self,
        intent_id: IntentId,
        request: ApprovalFinishRequest,
        now: i64,
    ) -> Result<ApprovalFinishResponse, WalletNodeError> {
        let intent = self.wallet.read_intent(&intent_id)?;
        let verified = self
            .relying_party
            .approval_finish(intent_id, &intent, request, now)?;
        let signer_id = verified.signer_id;
        let expires_at = intent.expiry;
        let authorization = self.wallet.submit_verified(&intent_id, verified, now)?;
        self.authorizations.insert(intent_id, authorization);
        self.phases.insert(intent_id, SigningPhase::Approved);
        Ok(ApprovalFinishResponse {
            intent_id,
            signer_id,
            approved: true,
            expires_at,
        })
    }

    pub fn signer_round1(
        &mut self,
        intent_id: IntentId,
        now: i64,
    ) -> Result<SigningCommitments, WalletNodeError> {
        let intent = self.wallet.read_intent(&intent_id)?;
        if intent.is_expired(now) {
            return Err(WalletNodeError::IntentExpired);
        }
        if intent.status != IntentStatus::Approved {
            return Err(WalletNodeError::IntentNotPending);
        }
        let participant = self
            .participant
            .as_mut()
            .ok_or(WalletNodeError::SignerNotConfigured)?;
        if participant.signer_id() != intent.signer_id {
            return Err(WalletNodeError::WrongSigner);
        }
        let commitments = participant.round1(intent.session_id, intent.tx_digest)?;
        self.phases.insert(intent_id, SigningPhase::RoundOneReady);
        Ok(commitments)
    }

    pub fn signer_round2(
        &mut self,
        intent_id: IntentId,
        session: &FrostSession,
        now: i64,
    ) -> Result<SignatureShare, WalletNodeError> {
        let mut authorization = self
            .authorizations
            .remove(&intent_id)
            .ok_or(WalletNodeError::AuthorizationUnavailable)?;
        let participant = self
            .participant
            .as_mut()
            .ok_or(WalletNodeError::SignerNotConfigured)?;
        let share = participant.round2(session, &mut authorization, now)?;
        self.phases.insert(intent_id, SigningPhase::ShareProduced);
        Ok(share)
    }

    pub fn signing_status(
        &self,
        intent_id: IntentId,
        now: i64,
    ) -> Result<ThresholdSigningStatus, WalletNodeError> {
        let intent = self.wallet.read_intent(&intent_id)?;
        let phase = if intent.is_expired(now) && intent.status == IntentStatus::Pending {
            SigningPhase::Expired
        } else {
            self.phases
                .get(&intent_id)
                .copied()
                .unwrap_or(match intent.status {
                    IntentStatus::Pending => SigningPhase::PendingApproval,
                    IntentStatus::Approved => SigningPhase::Approved,
                    IntentStatus::Signed => SigningPhase::Signed,
                    IntentStatus::Cancelled => SigningPhase::Cancelled,
                    IntentStatus::Expired => SigningPhase::Expired,
                })
        };
        Ok(ThresholdSigningStatus {
            intent_id,
            signer_id: intent.signer_id,
            session_id_hex: hex::encode(intent.session_id),
            message_hex: hex::encode(intent.tx_digest),
            phase,
            expires_at: intent.expiry,
        })
    }
}
