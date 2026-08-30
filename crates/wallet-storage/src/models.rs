use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStoreOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationStatus {
    Pending,
    Expired,
    InvalidatedByRecovery,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl IntentNetwork {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            "signet" => Some(Self::Signet),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentAction {
    Issue,
    Mint,
    Transfer,
    Swap,
    Spend,
}

impl IntentAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Mint => "mint",
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::Spend => "spend",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "issue" => Some(Self::Issue),
            "mint" => Some(Self::Mint),
            "transfer" => Some(Self::Transfer),
            "swap" => Some(Self::Swap),
            "spend" => Some(Self::Spend),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalNonce(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTransactionIntentV2 {
    pub id: Uuid,
    pub tx_digest: [u8; 32],
    pub policy_hash: [u8; 32],
    pub session_id: [u8; 32],
    pub network: IntentNetwork,
    pub protocol_version: u32,
    pub action: IntentAction,
    pub signer_id: String,
    pub approval_nonce: ApprovalNonce,
    pub intent_schema_version: u32,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransactionIntentV2 {
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
    pub network: IntentNetwork,
    pub protocol_version: u32,
    pub action: IntentAction,
    pub signer_id: String,
    pub approval_nonce: ApprovalNonce,
    pub intent_schema_version: u32,
    /// Material is deliberately not joined on hot list paths.
    pub material: Option<IntentMaterial>,
}

impl TransactionIntentV2 {
    pub fn cursor(&self) -> IntentCursor {
        IntentCursor {
            created_at: self.created_at,
            id: self.id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentCursor {
    pub created_at: i64,
    pub id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentMaterialKind {
    UnsignedTransaction,
    PolicyInput,
    NodeSnapshot,
}

impl IntentMaterialKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnsignedTransaction => "unsigned_transaction",
            Self::PolicyInput => "policy_input",
            Self::NodeSnapshot => "node_snapshot",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "unsigned_transaction" => Some(Self::UnsignedTransaction),
            "policy_input" => Some(Self::PolicyInput),
            "node_snapshot" => Some(Self::NodeSnapshot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntentMaterial {
    pub intent_id: Uuid,
    pub kind: IntentMaterialKind,
    pub payload_json: serde_json::Value,
    pub payload_hash: [u8; 32],
    pub node_snapshot_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Active,
    LegacyUnusable,
    Disabled,
}

impl CredentialState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::LegacyUnusable => "legacy_unusable",
            Self::Disabled => "disabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "legacy_unusable" => Some(Self::LegacyUnusable),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnProfile {
    pub wallet_id: Uuid,
    pub user_id: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub record_version: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskeyRecord {
    pub credential_id: String,
    pub label: String,
    pub passkey_json: String,
    pub format: String,
    pub credential_state: CredentialState,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    pub credential_id: String,
    pub wallet_id: Uuid,
    pub label: String,
    pub passkey_json: String,
    pub format: String,
    pub record_version: u64,
    pub credential_state: CredentialState,
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
pub struct NewPasskeyApprovalCeremony {
    pub id: Uuid,
    pub intent_id: Uuid,
    pub credential_id: String,
    pub binding_digest: [u8; 32],
    pub started_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyApprovalCompletion {
    pub ceremony_id: Uuid,
    pub intent_id: Uuid,
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
pub struct AuthorizationRecord {
    pub id: Uuid,
    pub intent_id: Uuid,
    pub epoch: u64,
    pub binding_digest: [u8; 32],
    pub expires_at: i64,
    pub issued_at: i64,
    pub consumed_at: Option<i64>,
    pub invalidated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostNonceAuthorizationClaim {
    pub authorization_id: Uuid,
    pub intent_id: Uuid,
    pub signer_id: String,
    pub session_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub claimed_at: i64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalSigningOperationStatus {
    CollectingCommitments,
    CollectingShares,
    Finalized,
    Aborted,
    Expired,
    Failed,
}

impl PersonalSigningOperationStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CollectingCommitments => "collecting_commitments",
            Self::CollectingShares => "collecting_shares",
            Self::Finalized => "finalized",
            Self::Aborted => "aborted",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "collecting_commitments" => Some(Self::CollectingCommitments),
            "collecting_shares" => Some(Self::CollectingShares),
            "finalized" => Some(Self::Finalized),
            "aborted" => Some(Self::Aborted),
            "expired" => Some(Self::Expired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Aborted | Self::Expired | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalSigningRound {
    Commitment,
    SignatureShare,
}

impl PersonalSigningRound {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Commitment => "commitment",
            Self::SignatureShare => "signature_share",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "commitment" => Some(Self::Commitment),
            "signature_share" => Some(Self::SignatureShare),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPersonalSigningOperation {
    pub operation_id: Uuid,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub intent_id: Uuid,
    pub session_id: [u8; 32],
    pub taproot_sighash: [u8; 32],
    pub policy_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub group_pubkey_xonly: [u8; 32],
    pub profile_binding_digest: [u8; 32],
    pub operation_binding_digest: [u8; 32],
    pub allowed_participants: [u16; 3],
    pub selected_participants: [u16; 2],
    pub threshold: u16,
    pub max_signers: u16,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalSigningOperation {
    pub operation_id: Uuid,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    pub intent_id: Uuid,
    pub session_id: [u8; 32],
    pub taproot_sighash: [u8; 32],
    pub policy_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub group_pubkey_xonly: [u8; 32],
    pub profile_binding_digest: [u8; 32],
    pub operation_binding_digest: [u8; 32],
    pub allowed_participants: [u16; 3],
    pub selected_participants: [u16; 2],
    pub threshold: u16,
    pub max_signers: u16,
    pub status: PersonalSigningOperationStatus,
    pub signing_package: Option<Vec<u8>>,
    pub final_signature: Option<[u8; 64]>,
    pub terminal_reason: Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalSigningReceipt {
    pub operation_id: Uuid,
    pub signer_id: u16,
    pub round: PersonalSigningRound,
    pub device_id: Uuid,
    pub device_generation: u64,
    pub request_binding_digest: [u8; 32],
    /// Public FROST commitment or signature share bytes.
    pub payload: Vec<u8>,
    pub received_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSignerProfile {
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub signing_suite_id: catomicals_signing_domain::SigningSuiteId,
    pub backend_requirement: catomicals_signing_domain::SignerBackendRequirement,
    pub signer_set_id: String,
    pub authorization_signer_id: String,
    pub signer_epoch: u64,
    pub threshold: u16,
    pub max_signers: u16,
    pub verification_key: Vec<u8>,
    pub secret_ref_id: Uuid,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerProfileRecord {
    pub profile_id: Uuid,
    pub wallet_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub signing_suite_id: catomicals_signing_domain::SigningSuiteId,
    pub backend_requirement: catomicals_signing_domain::SignerBackendRequirement,
    pub signer_set_id: String,
    pub authorization_signer_id: String,
    pub signer_epoch: u64,
    pub threshold: u16,
    pub max_signers: u16,
    pub verification_key: Vec<u8>,
    pub secret_ref_id: Uuid,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAddressBinding {
    pub binding_id: Uuid,
    pub profile_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub address: String,
    pub verification_key_digest: [u8; 32],
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSignerCatalogEntry {
    pub secret_ref: SecretRef,
    pub profile: NewSignerProfile,
    pub address_bindings: Vec<NewAddressBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCatalogInstallOutcome {
    Installed,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAddressBinding {
    pub binding_id: Uuid,
    pub profile_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub address: String,
    pub verification_key_digest: [u8; 32],
    pub created_at: i64,
}

/// Public signer metadata required to reconstruct chain-signing executors at
/// wallet startup. `secret_ref` is an opaque backend handle; it is never key
/// material, a threshold share, or a signing nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerProfileInventoryRecord {
    pub profile: SignerProfileRecord,
    pub secret_ref: String,
    pub address_bindings: Vec<StoredAddressBinding>,
}

/// One-time durable claim made immediately before a chain threshold executor
/// contacts any signer. Only public binding digests are persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainExecutorClaim {
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub signing_suite_id: catomicals_signing_domain::SigningSuiteId,
    pub backend_requirement: catomicals_signing_domain::SignerBackendRequirement,
    pub session_id: [u8; 32],
    pub review_domain_digest: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub operation_binding_digest: [u8; 32],
    pub claimed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningJobStatus {
    Prepared,
    Signing,
    Finalized,
    Aborted,
    Expired,
    Failed,
}

impl SigningJobStatus {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "prepared" => Some(Self::Prepared),
            "signing" => Some(Self::Signing),
            "finalized" => Some(Self::Finalized),
            "aborted" => Some(Self::Aborted),
            "expired" => Some(Self::Expired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSigningJob {
    pub job_id: Uuid,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub intent_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub signing_suite_id: catomicals_signing_domain::SigningSuiteId,
    pub backend_requirement: catomicals_signing_domain::SignerBackendRequirement,
    pub review_schema_version: u16,
    pub review_artifact: catomicals_chain_domain::ReviewArtifact,
    pub review_digest: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub selected_parties: [String; 2],
    pub receiver: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSigningJob {
    pub job_id: Uuid,
    pub wallet_id: Uuid,
    pub profile_id: Uuid,
    pub intent_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub signing_suite_id: catomicals_signing_domain::SigningSuiteId,
    pub backend_requirement: catomicals_signing_domain::SignerBackendRequirement,
    pub review_schema_version: u16,
    pub review_artifact: catomicals_chain_domain::ReviewArtifact,
    pub review_digest: [u8; 32],
    pub signing_message_digest: [u8; 32],
    pub policy_snapshot_digest: [u8; 32],
    pub chain_snapshot_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub selected_parties: [String; 2],
    pub receiver: String,
    pub operation_binding_digest: Option<[u8; 32]>,
    pub status: SigningJobStatus,
    pub final_signature: Option<Vec<u8>>,
    pub terminal_reason: Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}
