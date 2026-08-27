//! Durable, single-writer storage primitives for `walletd`.
//!
//! This crate stores authority metadata and opaque secret handles. It never
//! accepts private keys, FROST shares, or signing nonces as secret values.
//!
//! The backup coordinator exports an encrypted single-wallet SQLite snapshot,
//! verifies its manifest and checksums, performs an atomic local cutover, and
//! leaves the wallet in [`RestoreState::Recovering`]. Its concrete file secret
//! backend is development-only. System keychains, HSMs, quorum-share recovery,
//! and automatic signer reactivation remain outside this crate.
//!
//! Every file-backed [`WalletStorage`] owns an exclusive adjacent
//! `.owner.lock` file lock until drop. A second `WalletStorage` writer fails
//! closed, so public API race testing belongs at the later `walletd` process
//! boundary rather than through a storage backdoor.
//!
//! Opening a database also verifies the SHA-256 checksum recorded for every
//! bundled migration and checks critical live tables, indexes, triggers, and
//! security constraints. A matching SQLite `user_version` alone is not trust.

mod backup;
mod error;
mod migrations;
mod models;
mod policy;
mod sqlite;

pub use backup::{BackupError, BackupManifest};
pub use error::StorageError;
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use models::{
    ActivationStatus, ApprovalCeremony, ApprovalDecision, ApprovalNonce, AuditActor, AuditContext,
    AuditEvent, AuthorizationRecord, CredentialMetadata, CredentialState,
    FrostNonceAuthorizationClaim, IntentAction, IntentCursor, IntentMaterial, IntentMaterialKind,
    IntentNetwork, NewApprovalCeremony, NewNonceClaim, NewPasskeyApprovalCeremony,
    NewPasskeyRecord, NewTransactionIntent, NewTransactionIntentV2, NonceClaim,
    PasskeyApprovalCompletion, PasskeyRecord, PolicyStoreOutcome, RestoreState, SecretBackend,
    SecretRef, SqliteSettings, TransactionIntent, TransactionIntentStatus, TransactionIntentV2,
    WalletMetadata, WebauthnProfile,
};
pub use sqlite::WalletStorage;

pub type Result<T> = std::result::Result<T, StorageError>;
