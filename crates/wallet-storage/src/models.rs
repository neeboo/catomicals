use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreState {
    Normal,
    Snapshotting,
    RestorePrecheck,
    Cutover,
    Recovering,
}

impl RestoreState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Snapshotting => "snapshotting",
            Self::RestorePrecheck => "restore_precheck",
            Self::Cutover => "cutover",
            Self::Recovering => "recovering",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "normal" => Some(Self::Normal),
            "snapshotting" => Some(Self::Snapshotting),
            "restore_precheck" => Some(Self::RestorePrecheck),
            "cutover" => Some(Self::Cutover),
            "recovering" => Some(Self::Recovering),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMetadata {
    pub wallet_id: Uuid,
    pub epoch: u64,
    pub restore_state: RestoreState,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSettings {
    pub foreign_keys: bool,
    pub journal_mode: String,
    pub synchronous: String,
    pub busy_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionIntentStatus {
    Pending,
    Approved,
    Signing,
    Signed,
    Cancelled,
    Expired,
    Invalidated,
}

impl TransactionIntentStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Signing => "signing",
            Self::Signed => "signed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Invalidated => "invalidated",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "signing" => Some(Self::Signing),
            "signed" => Some(Self::Signed),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            "invalidated" => Some(Self::Invalidated),
            _ => None,
        }
    }

    pub(crate) fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Cancelled | Self::Expired | Self::Invalidated
            ) | (
                Self::Approved,
                Self::Signing | Self::Cancelled | Self::Expired | Self::Invalidated
            ) | (Self::Signing, Self::Signed | Self::Invalidated)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTransactionIntent {
    pub id: Uuid,
    pub tx_digest: [u8; 32],
    pub policy_hash: [u8; 32],
    pub session_id: [u8; 32],
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionIntent {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub epoch: u64,
    pub tx_digest: [u8; 32],
    pub policy_hash: [u8; 32],
    pub session_id: [u8; 32],
    pub status: TransactionIntentStatus,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub label: String,
    pub cose_public_key: String,
    pub sign_count: u64,
    pub enrolled_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNonceClaim {
    pub fingerprint: [u8; 32],
    pub session_id: [u8; 32],
    pub claimed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceClaim {
    pub fingerprint: [u8; 32],
    pub session_id: [u8; 32],
    pub epoch: u64,
    pub claimed_at: i64,
    pub invalidated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCeremony {
    pub id: Uuid,
    pub intent_id: Uuid,
    pub epoch: u64,
    pub started_at: i64,
    pub expires_at: i64,
    pub completed_at: Option<i64>,
    pub invalidated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApprovalCeremony {
    pub id: Uuid,
    pub intent_id: Uuid,
    pub expires_at: i64,
    pub started_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub ceremony_id: Uuid,
    pub authorization_id: Uuid,
    pub binding_digest: [u8; 32],
    pub authorization_expires_at: i64,
    pub approved_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuditActor {
    #[default]
    System,
    LocalUser,
    PasskeyFingerprint([u8; 32]),
    AgentSession(Uuid),
}

impl AuditActor {
    pub(crate) fn redacted_ref(&self) -> String {
        match self {
            Self::System => "system".to_owned(),
            Self::LocalUser => "local_user".to_owned(),
            Self::PasskeyFingerprint(fingerprint) => {
                format!("passkey_sha256:{}", hex::encode(fingerprint))
            }
            Self::AgentSession(session_id) => format!("agent_session:{session_id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContext {
    pub component_version: String,
    pub node_snapshot_id: Option<String>,
    pub actor: AuditActor,
}

impl Default for AuditContext {
    fn default() -> Self {
        Self {
            component_version: env!("CARGO_PKG_VERSION").to_owned(),
            node_snapshot_id: None,
            actor: AuditActor::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    OsKeychain,
    Hsm,
    EncryptedFile,
}

impl SecretBackend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OsKeychain => "os_keychain",
            Self::Hsm => "hsm",
            Self::EncryptedFile => "encrypted_file",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "os_keychain" => Some(Self::OsKeychain),
            "hsm" => Some(Self::Hsm),
            "encrypted_file" => Some(Self::EncryptedFile),
            _ => None,
        }
    }

    pub(crate) fn required_prefix(self) -> &'static str {
        match self {
            Self::OsKeychain => "keychain://",
            Self::Hsm => "hsm://",
            Self::EncryptedFile => "encrypted-file://",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub id: Uuid,
    pub backend: SecretBackend,
    pub handle: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl SecretRef {
    pub fn new(
        id: Uuid,
        backend: SecretBackend,
        handle: impl Into<String>,
        now: i64,
    ) -> crate::Result<Self> {
        let handle = handle.into();
        if !handle.starts_with(backend.required_prefix())
            || handle.len() == backend.required_prefix().len()
        {
            return Err(crate::StorageError::InvalidSecretHandle {
                backend: backend.as_str(),
            });
        }
        Ok(Self {
            id,
            backend,
            handle,
            created_at: now,
            updated_at: now,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub wallet_id: Uuid,
    pub epoch: u64,
    pub event_type: String,
    pub subject_id: Option<String>,
    pub payload: serde_json::Value,
    pub created_at: i64,
}
