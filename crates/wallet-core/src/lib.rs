//! Catomicals wallet core: the smallest wallet-node seam where Passkey
//! authorization gates threshold signing.
//!
//! Principles enforced here:
//! - **Passkey is authorization, never a Bitcoin signature.** A Passkey
//!   approval proves *user intent approval*; the actual Bitcoin transaction
//!   signature is produced later by the FROST threshold signers.
//! - **Signing intents are immutable and exactly bound.** The WebAuthn relying
//!   party stores the exact intent digest (wallet id, signer id, transaction
//!   digest, FROST session id, expiry, one-time nonce) beside its random,
//!   one-use assertion challenge and checks that binding at finish.
//! - **One-time.** An intent is approved at most once; an approval nonce is
//!   never reused.
//! - **Provider-neutral.** The same primitives serve human UI, Codex and DSH
//!   adapters; agents may propose intents but can never bypass Passkey or
//!   obtain FROST shares.

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as catomicals_wallet;

pub mod api;
mod bitcoin_wallet;
#[cfg(feature = "native-cbmpc")]
mod cb_mpc_chains;
#[cfg(feature = "native-cbmpc")]
mod cb_mpc_wallet;
pub mod chat;
mod chia_wallet;
mod durable_store;
mod ergo_wallet;
mod fractal_wallet;
pub mod threshold_seam {
    //! Adapter that lets a wallet-issued [`SigningAuthorization`] satisfy the
    //! signer-side authorization seam without wallet-core depending on FROST
    //! internals beyond the trait.
    pub use catomicals_threshold::{AuthorizationError, SigningAuthorization};
}

mod auth;
pub mod gate;
pub mod intent;
pub mod node;
pub mod signing_job;
pub mod signing_operation;
pub mod store;
pub mod transaction;
pub mod webauthn;

pub use api::{
    ApprovalChallenge, ApprovalState, CreateIntentRequest, CreatePersonalIntentRequest,
    IntentSnapshot, NodeSnapshot, SignerAddressSnapshot, SignerProfileStartupSnapshot,
    SignerSnapshot, ThresholdSnapshot, WalletApi, WalletError, WalletSnapshot,
};
pub use auth::b64url_encode;
#[cfg(test)]
pub(crate) use auth::{
    ApprovalError, ApprovalVerifier, CryptographicApprovalVerifier, PasskeyApproval,
    PasskeyVerifier, WebAuthnAssertion,
};
pub use bitcoin_wallet::{
    BitcoinExecutionClaim, BitcoinExecutionClaimStore, BitcoinThresholdChainSigningExecutor,
    BitcoinThresholdCoordinator,
};
pub use catomicals_trading::TradeSigningRequest;
#[cfg(feature = "native-cbmpc")]
pub use cb_mpc_chains::{
    BitcoinCashCbMpcSignatureAssembler, BsvCbMpcSignatureAssembler, KaspaCbMpcSignatureAssembler,
};
#[cfg(feature = "native-cbmpc")]
pub use cb_mpc_wallet::{
    CbMpcChainSigningExecutor, CbMpcConsensusSignatureAssembler, CbMpcWalletCoordinator,
    SigningJobRequest,
};
pub use chat::{
    ChatAuthorizationState, ChatExchange, ChatIntentBinding, ChatMessage, ChatMessageId,
    ChatMessageKind, ChatMessageRole, ChatState, ChatWalletActionRequest, CreateChatMessageRequest,
    MAX_CHAT_MESSAGE_BYTES, MAX_CHAT_MESSAGES,
};
pub use chia_wallet::{
    ChiaExecutionClaimStore, ChiaThresholdChainSigningExecutor, ChiaThresholdShareProvider,
    ChiaThresholdSpendFinalizer,
};
pub use durable_store::DurableWalletStore;
pub use ergo_wallet::{
    ErgoNonceReplayStore, ErgoThresholdChainSigningExecutor, ErgoThresholdProofAssembler,
    ErgoThresholdShareProvider, NativeErgoThresholdProofAssembler,
};
pub use fractal_wallet::{
    FractalExecutionClaimStore, FractalThresholdChainSigningExecutor, FractalThresholdCoordinator,
    FractalThresholdFinalizer, NativeFractalThresholdFinalizer,
};
pub use gate::{GateError, PersonalOperationAuthorization, SigningAuthorization};
pub use intent::{
    BitcoinNetwork, IntentId, IntentStatus, PersonalSigningPolicy, SIGNING_PROTOCOL_VERSION,
    SigningAction, SigningIntent, WalletId, intent_digest,
};
pub use node::{
    CreateTradeIntentRequest, CreateTransactionIntentRequest, SigningPhase, ThresholdSigner,
    ThresholdSigningStatus, TradeVerification, WalletNodeError, WalletNodeService,
    WalletNodeStatus, WalletSignerStatus,
};
pub use signing_job::{
    AddressBinding, ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey,
    ChainSigningExecutorRegistry, ChainSigningJobState, ChainSigningJobStatus,
    CreateChainSigningJobRequest, SignerProfile, SigningJob, SigningJobError,
    VerifiedChainSignature,
};
pub use signing_operation::{
    BeginPersonalSigningOperation, PersonalAbortDispatch, PersonalRoundOneDispatch,
    PersonalRoundTwoDispatch, PersonalSigningCoordinator, PersonalSigningError,
    PersonalSigningRecovery, PersonalSigningStore, PersonalSigningTermination,
};
pub use store::{
    ApprovalCompletionState, ApprovalStartState, AuthorizationState, FrostNonceClaimState,
    InMemoryWalletStore, PasskeyState, StorageDescriptor, StorageMode, WalletStore,
    WalletStoreError, WebauthnProfileState,
};
pub use transaction::{
    ReviewedInput, ReviewedOutput, TransactionPrevout, TransactionReview, TransactionReviewError,
    TransactionReviewRequest, TransactionWarning, inspect_transaction,
};
pub use webauthn::{
    ApprovalBinding, ApprovalFinishRequest, ApprovalFinishResponse, ApprovalStartResponse,
    CredentialSummary, PasskeyRegistrationFinishRequest, PasskeyRegistrationFinishResponse,
    PasskeyRegistrationStartRequest, PasskeyRegistrationStartResponse, RelyingPartyConfig,
};

#[cfg(test)]
#[path = "tests/authorization_seam.rs"]
mod authorization_seam_tests;

#[cfg(test)]
#[path = "tests/security_requirements.rs"]
mod security_requirements_tests;

#[cfg(test)]
#[path = "tests/trade_policy.rs"]
mod trade_policy_tests;

#[cfg(test)]
#[path = "tests/chat_wallet.rs"]
mod chat_wallet_tests;

#[cfg(test)]
#[path = "tests/transaction_review.rs"]
mod transaction_review_tests;
