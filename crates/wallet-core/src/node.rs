//! Typed wallet-node façade. Secret-bearing values remain inside this type.

use std::collections::{HashMap, HashSet};

use catomicals_threshold::{
    FrostSession, LocalFrostParticipant, PublicKeyPackage, SignatureShare, SigningCommitments,
    SigningError,
};
use catomicals_trading::{AgentTradingApi, TradeSigningRequest, WalletTradingApi};
use serde::{Deserialize, Serialize};

use crate::{
    ApprovalCompletionState, ApprovalStartState, AuthorizationState, ChatAuthorizationState,
    ChatExchange, ChatIntentBinding, ChatMessage, ChatMessageId, ChatState,
    ChatWalletActionRequest, CreateChatMessageRequest, CreateIntentRequest, FrostNonceClaimState,
    IntentId, IntentStatus, MAX_CHAT_MESSAGE_BYTES, MAX_CHAT_MESSAGES, SigningAuthorization,
    SigningIntent, StorageDescriptor, StorageMode, WalletApi, WalletError, WalletSnapshot,
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
    pub runtime_mode: StorageMode,
    pub compatibility_entry: bool,
    pub state_schema_version: Option<i32>,
    pub recovery_epoch: Option<u64>,
    pub startup_invalidated_ceremonies: u64,
    pub durable_intents: bool,
    pub durable_passkeys: bool,
    pub durable_authorizations: bool,
    pub durable_nonce_claims: bool,
    pub durable_signer: bool,
    pub recovered_intents: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSignerStatus {
    pub signer_id: Option<u16>,
    pub configured: bool,
    pub min_signers: u16,
    pub group_pubkey_xonly: Option<String>,
    pub signet_address: Option<String>,
    pub approved_actions: usize,
    /// Durable authorization records that survived restart but cannot release
    /// a share until the signer capability is recovered explicitly.
    pub recoverable_authorizations: usize,
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
    #[error("stored WebAuthn profile does not match the configured relying party")]
    WebauthnProfileMismatch,
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
    #[error("a recovered signer requires durable single-writer authority storage")]
    DurableSignerRequiresDurableAuthority,
    #[error("intent belongs to a different signer")]
    WrongSigner,
    #[error("Passkey authorization is unavailable or already consumed")]
    AuthorizationUnavailable,
    #[error("a recovered intent cannot be approved without its original review context")]
    RecoveredIntentApprovalUnavailable,
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

/// Narrow signer boundary implemented by the encrypted local signer today and
/// by a future HSM or authenticated remote signer without giving wallet-core
/// direct access to private key material.
pub trait ThresholdSigner: Send {
    fn signer_id(&self) -> u16;

    fn label(&self) -> String {
        format!("signer {}", self.signer_id())
    }

    fn online(&self) -> bool {
        true
    }

    fn round1(
        &mut self,
        session_id: [u8; 32],
        message: [u8; 32],
    ) -> Result<SigningCommitments, SigningError>;

    fn pending_nonce_fingerprint(
        &self,
        session_id: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<[u8; 32], SigningError>;

    fn round2(
        &mut self,
        session: &FrostSession,
        authorization: &mut dyn catomicals_threshold::SigningAuthorization,
        now: i64,
    ) -> Result<SignatureShare, SigningError>;
}

impl ThresholdSigner for LocalFrostParticipant {
    fn signer_id(&self) -> u16 {
        LocalFrostParticipant::signer_id(self)
    }

    fn label(&self) -> String {
        format!("local participant {}", self.signer_id())
    }

    fn round1(
        &mut self,
        session_id: [u8; 32],
        message: [u8; 32],
    ) -> Result<SigningCommitments, SigningError> {
        LocalFrostParticipant::round1(self, session_id, message)
    }

    fn pending_nonce_fingerprint(
        &self,
        session_id: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<[u8; 32], SigningError> {
        LocalFrostParticipant::pending_nonce_fingerprint(self, session_id, message)
    }

    fn round2(
        &mut self,
        session: &FrostSession,
        authorization: &mut dyn catomicals_threshold::SigningAuthorization,
        now: i64,
    ) -> Result<SignatureShare, SigningError> {
        LocalFrostParticipant::round2(self, session, authorization, now)
    }
}

/// A self-hosted relying party plus exactly one optional FROST participant.
pub struct WalletNodeService {
    wallet: WalletApi,
    relying_party: WebAuthnRelyingParty,
    participant: Option<Box<dyn ThresholdSigner>>,
    public_key_package: Option<PublicKeyPackage>,
    min_signers: u16,
    durable_signer: bool,
    authorizations: HashMap<IntentId, SigningAuthorization>,
    authorization_records: HashMap<IntentId, AuthorizationState>,
    recovered_intents: HashSet<IntentId>,
    phases: HashMap<IntentId, SigningPhase>,
    trade_requests: HashMap<IntentId, TradeSigningRequest>,
    transaction_requests: HashMap<IntentId, TransactionReviewRequest>,
    chat: ChatStore,
}

struct RestoredAuthority {
    wallet: WalletApi,
    relying_party: WebAuthnRelyingParty,
    authorization_records: HashMap<IntentId, AuthorizationState>,
    recovered_intents: HashSet<IntentId>,
}

impl WalletNodeService {
    fn restore_authority(
        config: RelyingPartyConfig,
        store: Box<dyn crate::WalletStore>,
        now: i64,
    ) -> Result<RestoredAuthority, WalletNodeError> {
        let mut wallet = WalletApi::with_store(store);
        let wallet_id = wallet.wallet_id().unwrap_or_else(uuid::Uuid::new_v4);
        let profile = match wallet.webauthn_profile()? {
            Some(profile) => {
                if profile.wallet_id != wallet_id
                    || profile.rp_id != config.rp_id
                    || profile.rp_origin != config.rp_origin
                {
                    return Err(WalletNodeError::WebauthnProfileMismatch);
                }
                profile
            }
            None => {
                let profile = crate::WebauthnProfileState {
                    wallet_id,
                    user_id: uuid::Uuid::new_v4(),
                    rp_id: config.rp_id.clone(),
                    rp_origin: config.rp_origin.clone(),
                    record_version: 1,
                    updated_at: now,
                };
                wallet.set_webauthn_profile(profile.clone())?;
                profile
            }
        };
        let relying_party =
            WebAuthnRelyingParty::new_with_state(config, profile.user_id, wallet.passkeys()?)?;
        let authorization_records = wallet
            .available_authorizations(now)?
            .into_iter()
            .map(|record| (record.intent_id, record))
            .collect();
        let recovered_intents = wallet
            .list_intents()
            .into_iter()
            .map(|intent| intent.id)
            .collect();
        Ok(RestoredAuthority {
            wallet,
            relying_party,
            authorization_records,
            recovered_intents,
        })
    }

    pub fn new(
        config: RelyingPartyConfig,
        participant: Option<LocalFrostParticipant>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
    ) -> Result<Self, WalletNodeError> {
        Self::new_with_store(
            config,
            participant,
            public_key_package,
            min_signers,
            Box::new(crate::InMemoryWalletStore::new()),
            0,
        )
    }

    pub fn new_with_store(
        config: RelyingPartyConfig,
        participant: Option<LocalFrostParticipant>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        store: Box<dyn crate::WalletStore>,
        now: i64,
    ) -> Result<Self, WalletNodeError> {
        Self::new_with_store_capability(
            config,
            participant.map(|participant| Box::new(participant) as Box<dyn ThresholdSigner>),
            public_key_package,
            min_signers,
            store,
            now,
            false,
        )
    }

    /// Restore a signer whose private package was authenticated by a durable
    /// secret backend before entering wallet-core. This constructor is kept
    /// separate so an ordinary process-local participant is never reported as
    /// restart-safe merely because authority metadata uses SQLite.
    pub fn new_with_recovered_signer_store(
        config: RelyingPartyConfig,
        participant: LocalFrostParticipant,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        store: Box<dyn crate::WalletStore>,
        now: i64,
    ) -> Result<Self, WalletNodeError> {
        Self::new_with_store_capability(
            config,
            Some(Box::new(participant)),
            public_key_package,
            min_signers,
            store,
            now,
            true,
        )
    }

    /// Provider seam for an HSM or authenticated remote participant. The
    /// caller owns transport attestation and availability; wallet-core keeps
    /// the same Passkey, nonce, and intent binding checks around every share.
    pub fn new_with_signer_provider_store(
        config: RelyingPartyConfig,
        signer: Box<dyn ThresholdSigner>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        store: Box<dyn crate::WalletStore>,
        now: i64,
        durable_signer: bool,
    ) -> Result<Self, WalletNodeError> {
        Self::new_with_store_capability(
            config,
            Some(signer),
            public_key_package,
            min_signers,
            store,
            now,
            durable_signer,
        )
    }

    fn new_with_store_capability(
        config: RelyingPartyConfig,
        participant: Option<Box<dyn ThresholdSigner>>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        store: Box<dyn crate::WalletStore>,
        now: i64,
        durable_signer: bool,
    ) -> Result<Self, WalletNodeError> {
        let RestoredAuthority {
            mut wallet,
            relying_party,
            authorization_records,
            recovered_intents,
        } = Self::restore_authority(config, store, now)?;
        if durable_signer && wallet.storage_descriptor().mode != StorageMode::Durable {
            return Err(WalletNodeError::DurableSignerRequiresDurableAuthority);
        }
        let signer = participant
            .as_ref()
            .map(|participant| crate::SignerSnapshot {
                id: participant.signer_id(),
                label: participant.label(),
                online: participant.online(),
            });
        let max_signers = u16::try_from(public_key_package.verifying_shares().len())
            .map_err(|_| WalletNodeError::SignerNotConfigured)?;
        let xonly = catomicals_threshold::group_pubkey_xonly(&public_key_package)
            .map_err(|error| WalletNodeError::Signing(error.to_string()))?;
        wallet.configure_threshold(min_signers, max_signers, xonly);
        if let Some(signer) = signer {
            wallet.set_signers(vec![signer]);
        }
        Ok(Self {
            wallet,
            relying_party,
            participant,
            public_key_package: Some(public_key_package),
            min_signers,
            durable_signer,
            authorizations: HashMap::new(),
            authorization_records,
            recovered_intents,
            phases: HashMap::new(),
            trade_requests: HashMap::new(),
            transaction_requests: HashMap::new(),
            chat: ChatStore::new(),
        })
    }

    pub fn without_signer(config: RelyingPartyConfig) -> Result<Self, WalletNodeError> {
        Self::without_signer_with_store(config, Box::new(crate::InMemoryWalletStore::new()), 0)
    }

    pub fn without_signer_with_store(
        config: RelyingPartyConfig,
        store: Box<dyn crate::WalletStore>,
        now: i64,
    ) -> Result<Self, WalletNodeError> {
        let RestoredAuthority {
            wallet,
            relying_party,
            authorization_records,
            recovered_intents,
        } = Self::restore_authority(config, store, now)?;
        Ok(Self {
            wallet,
            relying_party,
            participant: None,
            public_key_package: None,
            min_signers: 0,
            durable_signer: false,
            authorizations: HashMap::new(),
            authorization_records,
            recovered_intents,
            phases: HashMap::new(),
            trade_requests: HashMap::new(),
            transaction_requests: HashMap::new(),
            chat: ChatStore::new(),
        })
    }

    pub fn node_status(&self) -> WalletNodeStatus {
        let storage = self.wallet.storage_descriptor();
        let durable = storage.mode == StorageMode::Durable;
        WalletNodeStatus {
            network: "signet".into(),
            rp_id: self.relying_party.config().rp_id.clone(),
            rp_origin: self.relying_party.config().rp_origin.clone(),
            persistence: if durable && self.durable_signer {
                "SQLite authority state plus restart-recoverable signer metadata".into()
            } else if durable {
                "SQLite authority state; signer capability is unavailable".into()
            } else {
                "memory-only; restart loses credentials, intents, and replay state".into()
            },
            secret_storage: if durable && self.durable_signer {
                "durable signer provider; private package is loaded into signer process memory and absent from SQLite".into()
            } else {
                "process-memory-only; no encryption or hardware isolation".into()
            },
            production_ready: false,
            runtime_mode: storage.mode,
            compatibility_entry: !durable,
            state_schema_version: storage.schema_version,
            recovery_epoch: storage.recovery_epoch,
            startup_invalidated_ceremonies: storage.startup_invalidated_ceremonies,
            durable_intents: durable,
            durable_passkeys: durable,
            durable_authorizations: durable,
            durable_nonce_claims: durable,
            durable_signer: durable && self.durable_signer,
            recovered_intents: self.recovered_intents.len(),
        }
    }

    pub fn storage_descriptor(&self) -> StorageDescriptor {
        self.wallet.storage_descriptor()
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
        let group_key = self
            .public_key_package
            .as_ref()
            .and_then(|package| catomicals_threshold::group_pubkey_xonly(package).ok());
        let signet_address = group_key.and_then(|key| {
            let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&key).ok()?;
            Some(
                bitcoin::Address::p2tr(
                    &bitcoin::secp256k1::Secp256k1::verification_only(),
                    key,
                    None,
                    bitcoin::Network::Signet,
                )
                .to_string(),
            )
        });
        WalletSignerStatus {
            signer_id: self
                .participant
                .as_ref()
                .map(|participant| participant.signer_id()),
            configured: self.participant.is_some(),
            min_signers: self.min_signers,
            group_pubkey_xonly: group_key.map(hex::encode),
            signet_address,
            approved_actions: self.authorizations.len(),
            recoverable_authorizations: self.authorization_records.len(),
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
        if self.wallet.storage_descriptor().mode == StorageMode::Durable
            && self.public_key_package.is_none()
        {
            return Err(WalletNodeError::SignerNotConfigured);
        }
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
        self.recovered_intents.remove(&id);
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
        let response = self.relying_party.registration_finish(request, now)?;
        let state = self
            .relying_party
            .passkey_state(&response.credential_id)
            .ok_or(WalletNodeError::CredentialNotFound)?;
        if let Err(error) = self.wallet.persist_passkey(state) {
            self.relying_party
                .remove_credential(&response.credential_id);
            return Err(error.into());
        }
        Ok(response)
    }

    pub fn approval_start(
        &mut self,
        intent_id: IntentId,
        now: i64,
    ) -> Result<ApprovalStartResponse, WalletNodeError> {
        if self.recovered_intents.contains(&intent_id) {
            return Err(WalletNodeError::RecoveredIntentApprovalUnavailable);
        }
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
        let credential_id = self
            .relying_party
            .primary_credential_id()
            .ok_or(WalletNodeError::NoCredentials)?;
        let response = self.relying_party.approval_start(&intent, now)?;
        if let Err(error) = self.wallet.begin_approval(ApprovalStartState {
            ceremony_id: response.ceremony_id,
            intent_id,
            credential_id,
            binding_digest: intent.digest(),
            started_at: now,
            expires_at: response.binding.expires_at,
        }) {
            self.relying_party.invalidate_approval(response.ceremony_id);
            return Err(error.into());
        }
        Ok(response)
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
        let authorization_id = uuid::Uuid::new_v4();
        let completion = ApprovalCompletionState {
            ceremony_id: verified.ceremony_id,
            intent_id,
            credential_id: verified.credential_id.clone(),
            expected_credential_record_version: verified.expected_credential_record_version,
            updated_passkey_json: verified.updated_passkey_json.clone(),
            binding_digest: intent.digest(),
            authorization_id,
            authorization_expires_at: expires_at,
            rp_id: self.relying_party.config().rp_id.clone(),
            rp_origin: self.relying_party.config().rp_origin.clone(),
            approved_at: now,
        };
        let (authorization, record) = self
            .wallet
            .submit_verified(&intent_id, &verified, completion, now)?;
        self.relying_party.commit_verified_passkey(&verified);
        self.authorizations.insert(intent_id, authorization);
        self.authorization_records.insert(intent_id, record);
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
        if !self.authorizations.contains_key(&intent_id) {
            return Err(WalletNodeError::AuthorizationUnavailable);
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
        if !self.authorizations.contains_key(&intent_id) {
            return Err(WalletNodeError::AuthorizationUnavailable);
        }
        let participant = self
            .participant
            .as_mut()
            .ok_or(WalletNodeError::SignerNotConfigured)?;
        let authorization_record = self
            .authorization_records
            .get(&intent_id)
            .cloned()
            .ok_or(WalletNodeError::AuthorizationUnavailable)?;
        let fingerprint = participant.pending_nonce_fingerprint(&session.id, &session.message)?;
        self.wallet.claim_frost_nonce(FrostNonceClaimState {
            authorization_id: authorization_record.id,
            intent_id,
            signer_id: participant.signer_id(),
            session_id: session.id,
            fingerprint,
            claimed_at: now,
        })?;
        self.authorization_records.remove(&intent_id);
        let mut authorization = self
            .authorizations
            .remove(&intent_id)
            .ok_or(WalletNodeError::AuthorizationUnavailable)?;
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
