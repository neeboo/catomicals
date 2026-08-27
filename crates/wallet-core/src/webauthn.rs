//! Complete self-hosted WebAuthn relying-party ceremonies.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};

use crate::{IntentId, IntentStatus, PasskeyState, SigningIntent};

const PASSKEY_FORMAT: &str = "webauthn-rs-passkey-json-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelyingPartyConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
    pub ceremony_ttl_seconds: i64,
}

impl Default for RelyingPartyConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".into(),
            rp_origin: "http://localhost:5173".into(),
            rp_name: "Catomicals local wallet".into(),
            ceremony_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRegistrationStartRequest {
    pub label: String,
    pub user_name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationStartResponse {
    pub ceremony_id: Uuid,
    pub public_key: CreationChallengeResponse,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationFinishRequest {
    pub ceremony_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRegistrationFinishResponse {
    pub credential_id: String,
    pub label: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBinding {
    pub intent_id: IntentId,
    pub intent_digest_hex: String,
    pub signer_id: u16,
    pub session_id_hex: String,
    pub message_hex: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStartResponse {
    pub ceremony_id: Uuid,
    pub public_key: RequestChallengeResponse,
    pub binding: ApprovalBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalFinishRequest {
    pub ceremony_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFinishResponse {
    pub intent_id: IntentId,
    pub signer_id: u16,
    pub approved: bool,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub credential_id: String,
    pub label: String,
    pub registered_at: i64,
}

#[derive(Clone)]
struct StoredCredential {
    label: String,
    registered_at: i64,
    record_version: u64,
    passkey: Passkey,
}

struct RegistrationCeremony {
    label: String,
    expires_at: i64,
    state: PasskeyRegistration,
}

struct ApprovalCeremony {
    binding: ApprovalBinding,
    intent_digest: [u8; 32],
    session_id: [u8; 32],
    message: [u8; 32],
    state: PasskeyAuthentication,
}

/// Capability produced only after full WebAuthn verification. It is crate
/// private so API adapters cannot manufacture approval.
pub(crate) struct VerifiedPasskeyApproval {
    pub(crate) ceremony_id: Uuid,
    pub(crate) intent_id: IntentId,
    pub(crate) intent_digest: [u8; 32],
    pub(crate) signer_id: u16,
    pub(crate) session_id: [u8; 32],
    pub(crate) message: [u8; 32],
    pub(crate) expires_at: i64,
    pub(crate) credential_id: String,
    pub(crate) expected_credential_record_version: u64,
    pub(crate) updated_passkey_json: String,
    updated_passkey: Passkey,
}

pub struct WebAuthnRelyingParty {
    config: RelyingPartyConfig,
    webauthn: Webauthn,
    user_id: Uuid,
    credentials: HashMap<String, StoredCredential>,
    registrations: HashMap<Uuid, RegistrationCeremony>,
    approvals: HashMap<Uuid, ApprovalCeremony>,
}

impl core::fmt::Debug for WebAuthnRelyingParty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebAuthnRelyingParty")
            .field("config", &self.config)
            .field("credentials", &self.credentials.len())
            .field("registrations", &self.registrations.len())
            .field("approvals", &self.approvals.len())
            .finish()
    }
}

impl WebAuthnRelyingParty {
    pub fn new(config: RelyingPartyConfig) -> Result<Self, crate::WalletNodeError> {
        Self::new_with_state(config, Uuid::new_v4(), Vec::new())
    }

    pub(crate) fn new_with_state(
        config: RelyingPartyConfig,
        user_id: Uuid,
        passkeys: Vec<PasskeyState>,
    ) -> Result<Self, crate::WalletNodeError> {
        if config.ceremony_ttl_seconds <= 0 {
            return Err(crate::WalletNodeError::InvalidCeremonyTtl);
        }
        let origin = Url::parse(&config.rp_origin)
            .map_err(|error| crate::WalletNodeError::InvalidOrigin(error.to_string()))?;
        let host = origin
            .host_str()
            .ok_or_else(|| crate::WalletNodeError::InvalidOrigin("origin has no host".into()))?;
        let local = host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1";
        if !local && origin.scheme() != "https" {
            return Err(crate::WalletNodeError::InsecureRemoteOrigin);
        }
        if origin.scheme() != "https" && !(local && origin.scheme() == "http") {
            return Err(crate::WalletNodeError::InvalidOrigin(
                "origin must be HTTPS, except localhost development".into(),
            ));
        }
        let builder = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?
            .rp_name(&config.rp_name)
            .timeout(Duration::from_secs(
                u64::try_from(config.ceremony_ttl_seconds)
                    .map_err(|_| crate::WalletNodeError::InvalidCeremonyTtl)?,
            ));
        let webauthn = builder
            .build()
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
        let mut credentials = HashMap::new();
        for record in passkeys {
            if record.format != PASSKEY_FORMAT || record.record_version == 0 {
                return Err(crate::WalletNodeError::CredentialNotFound);
            }
            let passkey: Passkey = serde_json::from_str(&record.passkey_json)
                .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
            if crate::auth::b64url_encode(passkey.cred_id().as_slice()) != record.credential_id {
                return Err(crate::WalletNodeError::CredentialNotFound);
            }
            credentials.insert(
                record.credential_id,
                StoredCredential {
                    label: record.label,
                    registered_at: record.enrolled_at,
                    record_version: record.record_version,
                    passkey,
                },
            );
        }
        Ok(Self {
            config,
            webauthn,
            user_id,
            credentials,
            registrations: HashMap::new(),
            approvals: HashMap::new(),
        })
    }

    pub fn config(&self) -> &RelyingPartyConfig {
        &self.config
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    pub(crate) fn primary_credential_id(&self) -> Option<String> {
        self.credentials.keys().next().cloned()
    }

    pub(crate) fn passkey_state(&self, credential_id: &str) -> Option<PasskeyState> {
        let stored = self.credentials.get(credential_id)?;
        Some(PasskeyState {
            credential_id: credential_id.to_owned(),
            label: stored.label.clone(),
            passkey_json: serde_json::to_string(&stored.passkey).ok()?,
            format: PASSKEY_FORMAT.to_owned(),
            record_version: stored.record_version,
            enrolled_at: stored.registered_at,
        })
    }

    pub(crate) fn remove_credential(&mut self, credential_id: &str) {
        self.credentials.remove(credential_id);
    }

    pub(crate) fn invalidate_approval(&mut self, ceremony_id: Uuid) {
        self.approvals.remove(&ceremony_id);
    }

    pub(crate) fn commit_verified_passkey(&mut self, approval: &VerifiedPasskeyApproval) {
        if let Some(stored) = self.credentials.get_mut(&approval.credential_id) {
            stored.passkey = approval.updated_passkey.clone();
            stored.record_version = stored.record_version.saturating_add(1);
        }
    }

    pub fn credentials(&self) -> Vec<CredentialSummary> {
        let mut credentials: Vec<_> = self
            .credentials
            .iter()
            .map(|(id, stored)| CredentialSummary {
                credential_id: id.clone(),
                label: stored.label.clone(),
                registered_at: stored.registered_at,
            })
            .collect();
        credentials.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
        credentials
    }

    pub fn registration_start(
        &mut self,
        request: PasskeyRegistrationStartRequest,
        now: i64,
    ) -> Result<PasskeyRegistrationStartResponse, crate::WalletNodeError> {
        if request.label.trim().is_empty()
            || request.user_name.trim().is_empty()
            || request.display_name.trim().is_empty()
        {
            return Err(crate::WalletNodeError::InvalidRegistrationIdentity);
        }
        let excluded = if self.credentials.is_empty() {
            None
        } else {
            Some(
                self.credentials
                    .values()
                    .map(|stored| stored.passkey.cred_id().clone())
                    .collect(),
            )
        };
        let (public_key, state) = self
            .webauthn
            .start_passkey_registration(
                self.user_id,
                &request.user_name,
                &request.display_name,
                excluded,
            )
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
        let ceremony_id = Uuid::new_v4();
        let expires_at = now.saturating_add(self.config.ceremony_ttl_seconds);
        self.registrations.insert(
            ceremony_id,
            RegistrationCeremony {
                label: request.label,
                expires_at,
                state,
            },
        );
        Ok(PasskeyRegistrationStartResponse {
            ceremony_id,
            public_key,
            expires_at,
        })
    }

    pub fn registration_finish(
        &mut self,
        request: PasskeyRegistrationFinishRequest,
        now: i64,
    ) -> Result<PasskeyRegistrationFinishResponse, crate::WalletNodeError> {
        let ceremony = self
            .registrations
            .remove(&request.ceremony_id)
            .ok_or(crate::WalletNodeError::CeremonyNotFound)?;
        if !self.credentials.is_empty() {
            return Err(crate::WalletNodeError::RegistrationLocked);
        }
        if now > ceremony.expires_at {
            return Err(crate::WalletNodeError::CeremonyExpired);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(&request.credential, &ceremony.state)
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
        let credential_id = crate::auth::b64url_encode(passkey.cred_id().as_slice());
        if self.credentials.contains_key(&credential_id) {
            return Err(crate::WalletNodeError::CredentialAlreadyRegistered);
        }
        self.credentials.insert(
            credential_id.clone(),
            StoredCredential {
                label: ceremony.label.clone(),
                registered_at: now,
                record_version: 1,
                passkey,
            },
        );
        Ok(PasskeyRegistrationFinishResponse {
            credential_id,
            label: ceremony.label,
            registered_at: now,
        })
    }

    pub fn approval_start(
        &mut self,
        intent: &SigningIntent,
        now: i64,
    ) -> Result<ApprovalStartResponse, crate::WalletNodeError> {
        if intent.status != IntentStatus::Pending {
            return Err(crate::WalletNodeError::IntentNotPending);
        }
        if intent.is_expired(now) {
            return Err(crate::WalletNodeError::IntentExpired);
        }
        if self.credentials.is_empty() {
            return Err(crate::WalletNodeError::NoCredentials);
        }
        let passkeys: Vec<_> = self
            .credentials
            .values()
            .map(|stored| stored.passkey.clone())
            .collect();
        let (public_key, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
        let ceremony_id = Uuid::new_v4();
        let ceremony_expiry = now.saturating_add(self.config.ceremony_ttl_seconds);
        let expires_at = intent.expiry.min(ceremony_expiry);
        let digest = intent.digest();
        let binding = ApprovalBinding {
            intent_id: intent.id,
            intent_digest_hex: hex::encode(digest),
            signer_id: intent.signer_id,
            session_id_hex: hex::encode(intent.session_id),
            message_hex: hex::encode(intent.tx_digest),
            expires_at,
        };
        self.approvals.insert(
            ceremony_id,
            ApprovalCeremony {
                binding: binding.clone(),
                intent_digest: digest,
                session_id: intent.session_id,
                message: intent.tx_digest,
                state,
            },
        );
        Ok(ApprovalStartResponse {
            ceremony_id,
            public_key,
            binding,
        })
    }

    pub(crate) fn approval_finish(
        &mut self,
        requested_intent_id: IntentId,
        current_intent: &SigningIntent,
        request: ApprovalFinishRequest,
        now: i64,
    ) -> Result<VerifiedPasskeyApproval, crate::WalletNodeError> {
        let ceremony = self
            .approvals
            .remove(&request.ceremony_id)
            .ok_or(crate::WalletNodeError::CeremonyNotFound)?;
        if now > ceremony.binding.expires_at {
            return Err(crate::WalletNodeError::CeremonyExpired);
        }
        if requested_intent_id != ceremony.binding.intent_id
            || current_intent.id != ceremony.binding.intent_id
            || current_intent.digest() != ceremony.intent_digest
            || current_intent.signer_id != ceremony.binding.signer_id
            || current_intent.session_id != ceremony.session_id
            || current_intent.tx_digest != ceremony.message
        {
            return Err(crate::WalletNodeError::IntentBindingMismatch);
        }
        if current_intent.status != IntentStatus::Pending {
            return Err(crate::WalletNodeError::IntentNotPending);
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(&request.credential, &ceremony.state)
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;
        if !result.user_verified() {
            return Err(crate::WalletNodeError::UserVerificationRequired);
        }
        let id = crate::auth::b64url_encode(result.cred_id().as_slice());
        let stored = self
            .credentials
            .get(&id)
            .ok_or(crate::WalletNodeError::CredentialNotFound)?;
        let mut updated_passkey = stored.passkey.clone();
        updated_passkey
            .update_credential(&result)
            .ok_or(crate::WalletNodeError::CredentialNotFound)?;
        let updated_passkey_json = serde_json::to_string(&updated_passkey)
            .map_err(|error| crate::WalletNodeError::WebAuthn(error.to_string()))?;

        Ok(VerifiedPasskeyApproval {
            ceremony_id: request.ceremony_id,
            intent_id: current_intent.id,
            intent_digest: ceremony.intent_digest,
            signer_id: current_intent.signer_id,
            session_id: ceremony.session_id,
            message: ceremony.message,
            expires_at: ceremony.binding.expires_at,
            credential_id: id,
            expected_credential_record_version: stored.record_version,
            updated_passkey_json,
            updated_passkey,
        })
    }
}
