use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Backup(#[from] crate::BackupError),
    #[error("wallet storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite storage error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: i32, supported: i32 },
    #[error("wallet database schema integrity check failed: {reason}")]
    SchemaIntegrity { reason: &'static str },
    #[error("wallet database has not been initialized")]
    NotInitialized,
    #[error("wallet database is already initialized")]
    AlreadyInitialized,
    #[error("wallet database already has an active writer")]
    WriterAlreadyActive,
    #[error("stored value is invalid: {0}")]
    InvalidStoredValue(String),
    #[error("invalid opaque secret handle for {backend}")]
    InvalidSecretHandle { backend: &'static str },
    #[error("one-time authorization is missing, expired, invalidated, or already consumed")]
    AuthorizationUnavailable,
    #[error("approval ceremony is missing, invalidated, or already completed")]
    ApprovalCeremonyUnavailable,
    #[error("approval ceremony has expired")]
    ApprovalCeremonyExpired,
    #[error("transaction intent has expired")]
    IntentExpired,
    #[error("approval ceremony expiry exceeds transaction intent expiry")]
    ApprovalCeremonyExceedsIntentExpiry,
    #[error("authorization expiry precedes approval time")]
    AuthorizationExpiresBeforeApproval,
    #[error("authorization expiry exceeds transaction intent expiry")]
    AuthorizationExceedsIntentExpiry,
    #[error("transaction intent cannot be approved in its current state")]
    IntentNotApprovable,
    #[error("transaction intent already has a one-time authorization")]
    AuthorizationAlreadyExists,
    #[error("credential signature counter cannot decrease")]
    CredentialCounterRollback,
    #[error("stored WebAuthn profile does not match the requested relying party")]
    WebauthnProfileMismatch,
    #[error("passkey credential record version changed before the update")]
    CredentialVersionConflict,
    #[error("passkey credential is missing or cannot authenticate")]
    CredentialUnavailable,
    #[error("approval ceremony binding does not match the approved intent or credential")]
    ApprovalBindingMismatch,
    #[error("intent material does not belong to the transaction intent")]
    IntentMaterialMismatch,
    #[error("v2 transaction intent is invalid: {0}")]
    InvalidV2Intent(String),
    #[error("legacy wallet storage API cannot mutate v2 security state")]
    LegacyApiRejectedForV2,
    #[error("wallet mutations are blocked while restore state is {state}")]
    MutationBlocked { state: String },
    #[error("nonce fingerprint has already been claimed")]
    NonceAlreadyClaimed,
    #[error("stale wallet epoch: current epoch is {current}, provided epoch is {provided}")]
    StaleEpoch { current: u64, provided: u64 },
    #[error("invalid restore transition from {from} to {to}")]
    InvalidRestoreTransition { from: String, to: String },
    #[error("invalid transaction intent transition from {from} to {to}")]
    InvalidIntentTransition { from: String, to: String },
    #[error("transaction intent status or wallet epoch changed before the update")]
    IntentTransitionConflict,
}
