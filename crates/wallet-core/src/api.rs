//! Provider-neutral wallet primitives.
//!
//! This is the single surface that human UI, Codex and DeepSeek adapters use.
//! Every operation is expressed in plain serde JSON types; there is no
//! harness-specific coupling in wallet-core (see `docs/adapters.md`).
//!
//! Capability parity: agents and UI can both create/read/cancel intents and
//! read status. Approval submission belongs to [`crate::WalletNodeService`],
//! which owns the complete WebAuthn relying-party ceremony and does not accept
//! caller-supplied verifiers.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
use crate::auth::{CryptographicApprovalVerifier, PasskeyApproval};
use crate::covhub::{CovhubBinding, CovhubIntentStatus, CovhubSigningIntent};
use crate::gate::{AuthorizationGate, GateError, SigningAuthorization};
use crate::intent::{
    BitcoinNetwork, IntentId, IntentStatus, SIGNING_PROTOCOL_VERSION, SigningAction, SigningIntent,
    WalletId,
};
use crate::store::{
    ApprovalCompletionState, ApprovalStartState, AuthorizationState, FrostNonceClaimState,
    InMemoryWalletStore, PasskeyState, StorageDescriptor, WalletStore, WalletStoreError,
    WebauthnProfileState,
};
use crate::webauthn::VerifiedPasskeyApproval;

/// Snapshot of node connectivity as reported by `catomicals-node-client`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub subversion: String,
    pub op_cat_active: bool,
}

/// Threshold wallet status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSnapshot {
    pub configured: bool,
    pub min_signers: u16,
    pub max_signers: u16,
    /// BIP340 X-only group public key (hex), when configured.
    pub group_pubkey_xonly: Option<String>,
}

/// One signer of the threshold set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSnapshot {
    pub id: u16,
    pub label: String,
    pub online: bool,
}

/// An intent as presented in status/listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSnapshot {
    pub id: IntentId,
    pub signer_id: u16,
    pub tx_digest_hex: String,
    pub session_id_hex: String,
    pub status: IntentStatus,
    pub expiry: i64,
    pub approved: bool,
}

/// Public address metadata attached to a signer profile at wallet startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerAddressSnapshot {
    pub binding_id: Uuid,
    pub chain_scope: catomicals_chain_domain::ChainScope,
    pub address: String,
    pub verification_key_digest_hex: String,
}

/// Public signer configuration used to register chain executors after a
/// restart. `secret_ref` is an opaque backend handle; it does not contain a
/// private key, threshold share, or nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerProfileStartupSnapshot {
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
    pub verification_key_hex: String,
    pub secret_ref: String,
    pub address_bindings: Vec<SignerAddressSnapshot>,
}

impl From<&SigningIntent> for IntentSnapshot {
    fn from(i: &SigningIntent) -> Self {
        Self {
            id: i.id,
            signer_id: i.signer_id,
            tx_digest_hex: hex::encode(i.tx_digest),
            session_id_hex: hex::encode(i.session_id),
            status: i.status,
            expiry: i.expiry,
            approved: matches!(
                i.status,
                IntentStatus::Approved | IntentStatus::Signing | IntentStatus::Signed
            ),
        }
    }
}

/// Full wallet status for the first screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub node: Option<NodeSnapshot>,
    pub threshold: ThresholdSnapshot,
    pub signers: Vec<SignerSnapshot>,
    pub pending_approvals: Vec<IntentSnapshot>,
    pub recent_intents: Vec<IntentSnapshot>,
    pub credentials: usize,
}

/// Request to create a signing intent. Agents may propose intents; approval is
/// always gated by Passkey afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateIntentRequest {
    pub wallet_id: WalletId,
    pub signer_id: u16,
    #[serde(with = "hex_array32")]
    pub tx_digest: [u8; 32],
    #[serde(with = "hex_array32")]
    pub session_id: [u8; 32],
    pub expiry: i64,
}

/// Group-bound personal 2-of-3 intent. Participant selection happens later
/// inside the allowed group and is never represented as one authorized share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePersonalIntentRequest {
    pub wallet_id: WalletId,
    #[serde(with = "hex_array32")]
    pub tx_digest: [u8; 32],
    #[serde(with = "hex_array32")]
    pub session_id: [u8; 32],
    pub expiry: i64,
    pub policy: crate::intent::PersonalSigningPolicy,
}

/// The challenge the human must approve: the intent digest, base64url encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub intent_id: IntentId,
    #[serde(with = "hex_array32")]
    pub challenge: [u8; 32],
    pub challenge_b64url: String,
    pub expires_at: i64,
}

/// Readable approval state for an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalState {
    pub intent_id: IntentId,
    pub status: IntentStatus,
    pub approved: bool,
    pub challenge_issued: bool,
}

/// API-level errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletError {
    #[error("intent not found")]
    NotFound,
    #[error("gate rejected: {0}")]
    Gate(#[from] GateError),
    #[error("intent already approved")]
    AlreadyApproved,
    #[error("intent is not pending")]
    NotPending,
    #[error("signer id must be in 1..=65535")]
    InvalidSignerId,
    #[error("expiry must be in the future")]
    InvalidExpiry,
    #[error("personal signing policy must describe the canonical 2-of-3 group")]
    InvalidPersonalSigningPolicy,
    #[error("{0}")]
    Store(#[from] crate::WalletStoreError),
}

/// The provider-neutral wallet node façade.
///
/// Raw verifier injection is intentionally not part of the public API. The
/// following structural-only verifier must never be able to reach the signing
/// authorization gate from an embedding crate:
///
/// ```compile_fail
/// use catomicals_wallet::{
///     ApprovalError, ApprovalVerifier, CryptographicApprovalVerifier, IntentId,
///     PasskeyApproval, WalletApi,
/// };
///
/// struct StructuralOnly;
///
/// impl ApprovalVerifier for StructuralOnly {
///     fn verify(
///         &self,
///         challenge: &[u8; 32],
///         approval: &PasskeyApproval,
///     ) -> Result<(), ApprovalError> {
///         (challenge == &approval.intent_digest)
///             .then_some(())
///             .ok_or(ApprovalError::ChallengeMismatch)
///     }
/// }
///
/// impl CryptographicApprovalVerifier for StructuralOnly {}
///
/// fn bypass(
///     api: &mut WalletApi,
///     intent_id: &IntentId,
///     approval: PasskeyApproval,
/// ) {
///     let _ = api.submit_signing(intent_id, approval, &StructuralOnly, 0);
/// }
/// ```
pub struct WalletApi {
    store: Box<dyn WalletStore>,
    gate: AuthorizationGate,
    node: Option<NodeSnapshot>,
    threshold: ThresholdSnapshot,
    signers: Vec<SignerSnapshot>,
    rng: rand::rngs::OsRng,
}

impl core::fmt::Debug for WalletApi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WalletApi")
            .field("storage", &self.store.descriptor())
            .field("node", &self.node)
            .field("threshold", &self.threshold)
            .field("signers", &self.signers)
            .finish_non_exhaustive()
    }
}

impl Default for WalletApi {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletApi {
    pub fn new() -> Self {
        Self::with_store(Box::new(InMemoryWalletStore::new()))
    }

    pub fn with_store(store: Box<dyn WalletStore>) -> Self {
        Self {
            store,
            gate: AuthorizationGate::new(),
            node: None,
            threshold: ThresholdSnapshot {
                configured: false,
                min_signers: 0,
                max_signers: 0,
                group_pubkey_xonly: None,
            },
            signers: Vec::new(),
            rng: rand::rngs::OsRng,
        }
    }

    pub fn storage_descriptor(&self) -> StorageDescriptor {
        self.store.descriptor()
    }

    pub fn wallet_id(&self) -> Option<Uuid> {
        self.store.wallet_id()
    }

    pub(crate) fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletError> {
        Ok(self.store.webauthn_profile()?)
    }

    pub(crate) fn set_webauthn_profile(
        &mut self,
        profile: WebauthnProfileState,
    ) -> Result<(), WalletError> {
        Ok(self.store.set_webauthn_profile(profile)?)
    }

    pub(crate) fn passkeys(&self) -> Result<Vec<PasskeyState>, WalletError> {
        Ok(self.store.list_passkeys()?)
    }

    pub(crate) fn persist_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletError> {
        Ok(self.store.insert_passkey(passkey)?)
    }

    pub(crate) fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletError> {
        Ok(self.store.begin_approval(state)?)
    }

    pub(crate) fn available_authorizations(
        &self,
        now: i64,
    ) -> Result<Vec<AuthorizationState>, WalletError> {
        Ok(self.store.available_authorizations(now)?)
    }

    pub(crate) fn claim_frost_nonce(
        &mut self,
        claim: FrostNonceClaimState,
    ) -> Result<(), WalletError> {
        Ok(self.store.claim_frost_nonce(claim)?)
    }

    pub(crate) fn create_chain_signing_job(
        &mut self,
        request: crate::CreateChainSigningJobRequest,
        now: i64,
    ) -> Result<crate::ChainSigningJobState, WalletError> {
        Ok(self.store.create_chain_signing_job(request, now)?)
    }

    pub(crate) fn chain_signing_job(
        &self,
        job_id: Uuid,
    ) -> Result<Option<crate::ChainSigningJobState>, WalletError> {
        Ok(self.store.chain_signing_job(job_id)?)
    }

    pub(crate) fn chain_signing_execution(
        &self,
        job_id: Uuid,
    ) -> Result<Option<crate::ChainSigningExecution>, WalletError> {
        Ok(self.store.chain_signing_execution(job_id)?)
    }

    pub(crate) fn claim_chain_executor(
        &mut self,
        execution: &crate::ChainSigningExecution,
        now: i64,
    ) -> Result<(), WalletError> {
        Ok(self.store.claim_chain_executor(execution, now)?)
    }

    pub(crate) fn finalize_chain_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        final_signature: Vec<u8>,
        now: i64,
    ) -> Result<(), WalletError> {
        Ok(self.store.finalize_chain_signing_job(
            job_id,
            operation_binding_digest,
            final_signature,
            now,
        )?)
    }

    pub(crate) fn terminate_chain_signing_job(
        &mut self,
        job_id: Uuid,
        operation_binding_digest: [u8; 32],
        status: crate::ChainSigningJobStatus,
        reason: String,
        now: i64,
    ) -> Result<(), WalletError> {
        Ok(self.store.terminate_chain_signing_job(
            job_id,
            operation_binding_digest,
            status,
            reason,
            now,
        )?)
    }

    // ---- administration -------------------------------------------------

    pub fn set_node_snapshot(&mut self, node: Option<NodeSnapshot>) {
        self.node = node;
    }

    pub fn node_snapshot(&self) -> Option<&NodeSnapshot> {
        self.node.as_ref()
    }

    pub fn configure_threshold(&mut self, min_signers: u16, max_signers: u16, xonly: [u8; 32]) {
        self.threshold = ThresholdSnapshot {
            configured: true,
            min_signers,
            max_signers,
            group_pubkey_xonly: Some(hex::encode(xonly)),
        };
    }

    pub fn set_signers(&mut self, signers: Vec<SignerSnapshot>) {
        self.signers = signers;
    }

    pub fn enroll_credential(
        &mut self,
        label: &str,
        cose_public_key: Option<String>,
        now: i64,
    ) -> Result<String, WalletError> {
        let mut rng = rand::rngs::OsRng;
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        let credential_id = crate::auth::b64url_encode(&raw);
        self.store.insert_passkey(PasskeyState {
            credential_id: credential_id.clone(),
            label: label.to_owned(),
            passkey_json: serde_json::json!({"cose_public_key": cose_public_key}).to_string(),
            format: "compatibility-public-key-metadata-v1".to_owned(),
            record_version: 1,
            enrolled_at: now,
        })?;
        Ok(credential_id)
    }

    // ---- status ---------------------------------------------------------

    pub fn status(&self) -> WalletSnapshot {
        let all = self.store.list_intents();
        let mut intents: Vec<IntentSnapshot> = all.iter().map(IntentSnapshot::from).collect();
        intents.sort_by_key(|i| i.expiry);
        let pending: Vec<IntentSnapshot> = intents
            .iter()
            .filter(|i| i.status == IntentStatus::Pending && i.expiry > 0)
            .cloned()
            .collect();
        WalletSnapshot {
            node: self.node.clone(),
            threshold: self.threshold.clone(),
            signers: self.signers.clone(),
            pending_approvals: pending,
            recent_intents: intents,
            credentials: self
                .store
                .list_passkeys()
                .map_or(0, |records| records.len()),
        }
    }

    // ---- intents ----------------------------------------------------------

    pub fn create_intent(
        &mut self,
        req: CreateIntentRequest,
        now: i64,
    ) -> Result<SigningIntent, WalletError> {
        if req.signer_id == 0 {
            return Err(WalletError::InvalidSignerId);
        }
        if req.expiry <= now {
            return Err(WalletError::InvalidExpiry);
        }
        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);
        let intent = SigningIntent {
            id: Uuid::new_v4(),
            network: BitcoinNetwork::Signet,
            protocol_version: SIGNING_PROTOCOL_VERSION,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: req.wallet_id,
            signer_id: req.signer_id,
            personal_signing_policy: None,
            tx_digest: req.tx_digest,
            session_id: req.session_id,
            expiry: req.expiry,
            nonce,
            covhub: None,
            status: IntentStatus::Pending,
            created_at: now,
        };
        self.store.insert_intent(intent.clone())?;
        Ok(intent)
    }

    pub fn create_personal_intent(
        &mut self,
        req: CreatePersonalIntentRequest,
        now: i64,
    ) -> Result<SigningIntent, WalletError> {
        if req.expiry <= now {
            return Err(WalletError::InvalidExpiry);
        }
        if req.policy.signer_epoch == 0
            || req.policy.allowed_participants != [1, 2, 3]
            || req.policy.threshold != 2
            || req.policy.group_pubkey_xonly == [0; 32]
            || req.policy.policy_digest == [0; 32]
            || req.policy.chain_snapshot_digest == [0; 32]
        {
            return Err(WalletError::InvalidPersonalSigningPolicy);
        }
        let mut nonce = [0_u8; 32];
        self.rng.fill_bytes(&mut nonce);
        let intent = SigningIntent {
            id: Uuid::new_v4(),
            network: BitcoinNetwork::Signet,
            protocol_version: SIGNING_PROTOCOL_VERSION,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: req.wallet_id,
            signer_id: 0,
            personal_signing_policy: Some(req.policy),
            tx_digest: req.tx_digest,
            session_id: req.session_id,
            expiry: req.expiry,
            nonce,
            covhub: None,
            status: IntentStatus::Pending,
            created_at: now,
        };
        self.store.insert_intent(intent.clone())?;
        Ok(intent)
    }

    /// Persist a chain-neutral CovHub pending intent in the durable wallet
    /// intent store.
    ///
    /// The wallet only accepts a `Pending` CovHub intent whose expiry is in
    /// the future and whose profile exists in this wallet. The agent never
    /// supplies an approval, Passkey assertion, signer secret, nonce, or
    /// broadcast instruction; the wallet mints the one-time approval nonce
    /// and derives the durable `SigningIntent` record from the already
    /// re-run local chain review. The Passkey challenge for the persisted
    /// intent is exactly the CovHub intent digest.
    pub fn create_covhub_intent(
        &mut self,
        covhub: CovhubSigningIntent,
        now: i64,
    ) -> Result<SigningIntent, WalletError> {
        if covhub.status != CovhubIntentStatus::Pending {
            return Err(WalletError::NotPending);
        }
        if covhub.expires_at <= now {
            return Err(WalletError::InvalidExpiry);
        }
        let profiles = self.store.signer_profiles()?;
        let profile = profiles
            .iter()
            .find(|(profile, _)| profile.profile_id == covhub.profile_id)
            .map(|(profile, _)| profile)
            .ok_or(WalletError::NotFound)?;
        if profile.chain_scope != covhub.chain_scope {
            return Err(WalletError::Store(WalletStoreError::new(
                "covhub intent profile chain scope mismatch",
            )));
        }
        if let Some(wallet_id) = self.wallet_id()
            && wallet_id != profile.wallet_id
        {
            return Err(WalletError::Store(WalletStoreError::new(
                "covhub intent profile belongs to a different wallet",
            )));
        }
        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);
        // Narrow explicit representation: a CovHub-backed intent never claims
        // a Bitcoin Signet taproot authority in its legacy container fields.
        // The native `chain_scope` on the immutable CovHub binding is the sole
        // chain authority, regardless of which chain the intent targets.
        let intent = SigningIntent {
            id: covhub.intent_id,
            network: BitcoinNetwork::CovhubDelegated,
            protocol_version: SIGNING_PROTOCOL_VERSION,
            action: SigningAction::CovhubDelegated,
            wallet_id: profile.wallet_id,
            signer_id: participant_id(&profile.authorization_signer_id),
            personal_signing_policy: None,
            tx_digest: covhub.signing_message_digest,
            session_id: covhub.session_id,
            expiry: covhub.expires_at,
            nonce,
            covhub: Some(CovhubBinding::from_covhub_intent(&covhub)),
            status: IntentStatus::Pending,
            created_at: covhub.created_at,
        };
        self.store.insert_intent(intent.clone())?;
        Ok(intent)
    }

    pub fn read_intent(&self, id: &IntentId) -> Result<SigningIntent, WalletError> {
        self.store.get_intent(id).ok_or(WalletError::NotFound)
    }

    pub fn list_intents(&self) -> Vec<SigningIntent> {
        self.store.list_intents()
    }

    pub fn cancel_intent(&mut self, id: &IntentId, now: i64) -> Result<SigningIntent, WalletError> {
        let intent = self.read_intent(id)?;
        match intent.status {
            IntentStatus::Pending => {
                let mut intent = intent;
                if intent.is_expired(now) {
                    intent.status = IntentStatus::Expired;
                } else {
                    intent.status = IntentStatus::Cancelled;
                }
                self.store.update_intent(intent.clone(), now)?;
                Ok(intent)
            }
            IntentStatus::Expired => Ok(intent),
            _ => Err(WalletError::NotPending), // approved intents cannot be cancelled
        }
    }

    // ---- approval ---------------------------------------------------------

    /// Issue the approval challenge for a pending intent. The challenge IS the
    /// intent digest: approving it authorizes this exact intent and nothing
    /// else.
    pub fn approval_challenge(
        &self,
        id: &IntentId,
        now: i64,
    ) -> Result<ApprovalChallenge, WalletError> {
        let intent = self.read_intent(id)?;
        if intent.status != IntentStatus::Pending {
            return Err(WalletError::NotPending);
        }
        if intent.is_expired(now) {
            return Err(WalletError::Gate(GateError::Expired));
        }
        let challenge = intent.digest();
        Ok(ApprovalChallenge {
            intent_id: id.to_owned(),
            challenge,
            challenge_b64url: crate::auth::b64url_encode(&challenge),
            expires_at: intent.expiry,
        })
    }

    pub fn read_approval(&self, id: &IntentId) -> Result<ApprovalState, WalletError> {
        let intent = self.read_intent(id)?;
        Ok(ApprovalState {
            intent_id: id.to_owned(),
            status: intent.status,
            approved: matches!(
                intent.status,
                IntentStatus::Approved | IntentStatus::Signing | IntentStatus::Signed
            ),
            challenge_issued: true,
        })
    }

    // ---- signing submission -------------------------------------------------

    /// Submit a Passkey approval. On success the intent moves to `Approved`
    /// and a one-time [`SigningAuthorization`] bound to the exact intent is
    /// returned. The FROST signer consumes it via
    /// `catomicals_threshold::sign_share`.
    #[cfg(test)]
    pub(crate) fn submit_signing(
        &mut self,
        id: &IntentId,
        approval: PasskeyApproval,
        verifier: &dyn CryptographicApprovalVerifier,
        now: i64,
    ) -> Result<SigningAuthorization, WalletError> {
        let intent = self.read_intent(id)?;
        if matches!(
            intent.status,
            IntentStatus::Approved | IntentStatus::Signing | IntentStatus::Signed
        ) {
            return Err(WalletError::AlreadyApproved);
        }
        let auth = self.gate.authorize(&intent, &approval, verifier, now)?;
        let mut intent = intent;
        intent.status = IntentStatus::Approved;
        self.store.update_intent(intent, now)?;
        Ok(auth)
    }

    pub(crate) fn submit_verified(
        &mut self,
        id: &IntentId,
        approval: &VerifiedPasskeyApproval,
        completion: ApprovalCompletionState,
        now: i64,
    ) -> Result<(SigningAuthorization, AuthorizationState), WalletError> {
        let intent = self.read_intent(id)?;
        if approval.intent_id != intent.id
            || approval.signer_id != intent.signer_id
            || approval.session_id != intent.session_id
            || approval.message != intent.tx_digest
            || approval.expires_at > intent.expiry
        {
            return Err(WalletError::Gate(GateError::ApprovalMismatch));
        }
        if matches!(
            intent.status,
            IntentStatus::Approved | IntentStatus::Signing | IntentStatus::Signed
        ) {
            return Err(WalletError::AlreadyApproved);
        }
        let auth = self
            .gate
            .authorize_verified(&intent, &approval.intent_digest, now)?;
        let persisted = self.store.complete_approval(completion)?;
        Ok((auth, persisted))
    }

    /// Mark an intent signed after the threshold signature completed.
    pub fn credentials_snapshot(&self) -> Result<Vec<PasskeyState>, WalletError> {
        Ok(self.store.list_passkeys()?)
    }

    /// Deterministic, wallet-scoped signer inventory for production startup.
    /// The result is safe to serialize because it contains public keys and an
    /// opaque secret backend reference only.
    pub fn signer_profiles_snapshot(
        &self,
    ) -> Result<Vec<SignerProfileStartupSnapshot>, WalletError> {
        Ok(self
            .store
            .signer_profiles()?
            .into_iter()
            .map(|(profile, address_bindings)| SignerProfileStartupSnapshot {
                profile_id: profile.profile_id,
                wallet_id: profile.wallet_id,
                chain_scope: profile.chain_scope,
                signing_suite_id: profile.signing_suite_id,
                backend_requirement: profile.backend_requirement,
                signer_set_id: profile.signer_set_id,
                authorization_signer_id: profile.authorization_signer_id,
                signer_epoch: profile.signer_epoch,
                threshold: profile.threshold,
                max_signers: profile.max_signers,
                verification_key_hex: hex::encode(profile.verification_key),
                secret_ref: profile.secret_ref,
                address_bindings: address_bindings
                    .into_iter()
                    .map(|binding| SignerAddressSnapshot {
                        binding_id: binding.binding_id(),
                        chain_scope: binding.chain_scope(),
                        address: binding.address().to_owned(),
                        verification_key_digest_hex: hex::encode(binding.verification_key_digest()),
                    })
                    .collect(),
            })
            .collect())
    }

    pub fn mark_signed(&mut self, id: &IntentId, now: i64) -> Result<(), WalletError> {
        let intent = self.read_intent(id)?;
        let mut intent = intent;
        intent.status = IntentStatus::Signed;
        self.store.update_intent(intent, now)?;
        Ok(())
    }
}

// serde helpers for [u8; 32] as lowercase hex
pub mod hex_array32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod personal_intent_tests {
    use super::*;
    use catomicals_threshold::{PersonalSignerProfile, run_local_dkg};

    #[test]
    fn personal_intent_uses_group_authorization_instead_of_one_participant() {
        let wallet_id = Uuid::from_bytes([0x61; 16]);
        let profile = PersonalSignerProfile::bootstrap(
            Uuid::from_bytes([0x62; 16]),
            wallet_id,
            Uuid::from_bytes([0x63; 16]),
            1,
            run_local_dkg(3, 2).unwrap(),
        )
        .unwrap()
        .profile;
        let mut api = WalletApi::new();
        let intent = api
            .create_personal_intent(
                CreatePersonalIntentRequest {
                    wallet_id,
                    tx_digest: [0x64; 32],
                    session_id: [0x65; 32],
                    expiry: 200,
                    policy: crate::PersonalSigningPolicy::from_profile(
                        &profile, [0x66; 32], [0x67; 32],
                    ),
                },
                100,
            )
            .unwrap();

        assert_eq!(intent.signer_id, 0);
        assert_eq!(
            intent.personal_signing_policy,
            Some(crate::PersonalSigningPolicy::from_profile(
                &profile, [0x66; 32], [0x67; 32],
            ))
        );
    }
}

/// Derive the durable wallet-intent participant label for a signer profile.
/// CovHub intents are chain-scoped and never run the legacy FROST round flow,
/// so the label is a stable shim derived from the wallet-owned profile; the
/// chain-neutral CovHub binding (not this label) is what the human approves.
fn participant_id(authorization_signer_id: &str) -> u16 {
    authorization_signer_id
        .rsplit(['-', ':', '/'])
        .next()
        .and_then(|suffix| suffix.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}
