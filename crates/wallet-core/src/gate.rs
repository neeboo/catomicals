//! The authorization gate: Passkey approval -> one-time signing authorization.
//!
//! Production authorization accepts only the crate-private capability created
//! by the complete WebAuthn ceremony. A separate test-only path exercises the
//! same exact-binding rules with injected verifiers and refuses unless:
//! unless:
//! 1. the intent is `Pending` and unexpired,
//! 2. the Passkey approval's digest equals the intent digest,
//! 3. the test verifier accepts the approval,
//! 4. the one-time nonce has never been seen before.
//!
//! The resulting [`SigningAuthorization`] binds wallet id, signer id,
//! transaction digest, FROST session id, expiry and nonce — and may be
//! consumed exactly once by the FROST signer. It never contains key material.

#[cfg(test)]
use crate::auth::{CryptographicApprovalVerifier, PasskeyApproval};
use crate::intent::{
    BitcoinNetwork, IntentId, IntentStatus, SIGNING_PROTOCOL_VERSION, SigningAction, SigningIntent,
    WalletId,
};
use rand::RngCore;

/// Errors from the authorization gate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error("intent is not pending (status = {0:?})")]
    NotPending(IntentStatus),
    #[error("intent has expired")]
    Expired,
    #[error("approval does not match this intent")]
    ApprovalMismatch,
    #[cfg(test)]
    #[error("approval rejected: {0}")]
    ApprovalRejected(crate::auth::ApprovalError),
    #[error("one-time nonce was already used")]
    NonceReused,
    #[error("unsupported signing intent protocol version {0}")]
    UnsupportedProtocolVersion(u16),
}

/// The one-time token a signer share must present.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningAuthorization {
    pub token: [u8; 32],
    pub intent_id: IntentId,
    pub network: BitcoinNetwork,
    pub protocol_version: u16,
    pub action: SigningAction,
    pub wallet_id: WalletId,
    pub signer_id: u16,
    pub tx_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub nonce: [u8; 32],
    pub expiry: i64,
    pub issued_at: i64,
    consumed: bool,
}

impl core::fmt::Debug for SigningAuthorization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningAuthorization")
            .field("token", &"<redacted>")
            .field("intent_id", &self.intent_id)
            .field("network", &self.network)
            .field("protocol_version", &self.protocol_version)
            .field("action", &self.action)
            .field("wallet_id", &self.wallet_id)
            .field("signer_id", &self.signer_id)
            .field("tx_digest", &hex::encode(self.tx_digest))
            .field("session_id", &hex::encode(self.session_id))
            .field("nonce", &"<redacted>")
            .field("expiry", &self.expiry)
            .field("issued_at", &self.issued_at)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl SigningAuthorization {
    fn new(intent: &SigningIntent, issued_at: i64, rng: &mut impl RngCore) -> Self {
        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);
        Self {
            token,
            intent_id: intent.id,
            network: intent.network,
            protocol_version: intent.protocol_version,
            action: intent.action,
            wallet_id: intent.wallet_id,
            signer_id: intent.signer_id,
            tx_digest: intent.tx_digest,
            session_id: intent.session_id,
            nonce: intent.nonce,
            expiry: intent.expiry,
            issued_at,
            consumed: false,
        }
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

impl crate::threshold_seam::SigningAuthorization for SigningAuthorization {
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        now: i64,
    ) -> Result<(), crate::threshold_seam::AuthorizationError> {
        use crate::threshold_seam::AuthorizationError as E;
        if self.consumed {
            return Err(E::AlreadyConsumed);
        }
        if &self.session_id != session_id {
            return Err(E::WrongSession);
        }
        if &self.tx_digest != message {
            return Err(E::WrongMessage);
        }
        if self.signer_id != signer_id {
            return Err(E::WrongSigner);
        }
        if now > self.expiry {
            return Err(E::Expired);
        }
        self.consumed = true;
        Ok(())
    }
}

/// Issues one-time, exact-bound signing authorizations.
#[derive(Debug, Default)]
pub struct AuthorizationGate {
    used_nonces: std::collections::HashSet<[u8; 32]>,
    rng: rand::rngs::OsRng,
}

impl AuthorizationGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_nonce_been_used(&self, nonce: &[u8; 32]) -> bool {
        self.used_nonces.contains(nonce)
    }

    /// Authorize an intent given a Passkey approval.
    #[cfg(test)]
    pub(crate) fn authorize(
        &mut self,
        intent: &SigningIntent,
        approval: &PasskeyApproval,
        verifier: &dyn CryptographicApprovalVerifier,
        now: i64,
    ) -> Result<SigningAuthorization, GateError> {
        if intent.status != IntentStatus::Pending {
            return Err(GateError::NotPending(intent.status));
        }
        if intent.protocol_version != SIGNING_PROTOCOL_VERSION {
            return Err(GateError::UnsupportedProtocolVersion(
                intent.protocol_version,
            ));
        }
        if intent.is_expired(now) {
            return Err(GateError::Expired);
        }
        if approval.intent_digest != intent.digest() {
            return Err(GateError::ApprovalMismatch);
        }
        verifier
            .verify(&intent.digest(), approval)
            .map_err(GateError::ApprovalRejected)?;
        if !self.used_nonces.insert(intent.nonce) {
            return Err(GateError::NonceReused);
        }
        Ok(SigningAuthorization::new(intent, now, &mut self.rng))
    }

    /// Issue an authorization after the crate-private WebAuthn relying party
    /// has produced a verified capability. This is not visible to API users.
    pub(crate) fn authorize_verified(
        &mut self,
        intent: &SigningIntent,
        intent_digest: &[u8; 32],
        now: i64,
    ) -> Result<SigningAuthorization, GateError> {
        if intent.status != IntentStatus::Pending {
            return Err(GateError::NotPending(intent.status));
        }
        if intent.protocol_version != SIGNING_PROTOCOL_VERSION {
            return Err(GateError::UnsupportedProtocolVersion(
                intent.protocol_version,
            ));
        }
        if intent.is_expired(now) {
            return Err(GateError::Expired);
        }
        if &intent.digest() != intent_digest {
            return Err(GateError::ApprovalMismatch);
        }
        if !self.used_nonces.insert(intent.nonce) {
            return Err(GateError::NonceReused);
        }
        Ok(SigningAuthorization::new(intent, now, &mut self.rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        ApprovalError, ApprovalVerifier, CryptographicApprovalVerifier, PasskeyApproval,
        StructuralVerifier, WebAuthnAssertion, b64url_encode, make_client_data,
    };
    use uuid::Uuid;

    struct TestCryptographicVerifier;

    impl ApprovalVerifier for TestCryptographicVerifier {
        fn verify(
            &self,
            challenge: &[u8; 32],
            approval: &PasskeyApproval,
        ) -> Result<(), ApprovalError> {
            StructuralVerifier.verify(challenge, approval)
        }
    }

    impl CryptographicApprovalVerifier for TestCryptographicVerifier {}

    fn intent(now: i64) -> SigningIntent {
        SigningIntent {
            id: Uuid::new_v4(),
            network: BitcoinNetwork::Signet,
            protocol_version: SIGNING_PROTOCOL_VERSION,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: Uuid::new_v4(),
            signer_id: 1,
            tx_digest: [0x11; 32],
            session_id: [0x22; 32],
            expiry: now + 3600,
            nonce: [0x33; 32],
            status: IntentStatus::Pending,
            created_at: now,
        }
    }

    fn approval_for(intent: &SigningIntent) -> PasskeyApproval {
        let digest = intent.digest();
        let b64 = b64url_encode(&digest);
        PasskeyApproval {
            intent_digest: digest,
            assertion: WebAuthnAssertion {
                credential_id: "cred-1".into(),
                authenticator_data: b64url_encode(&[1u8; 37]),
                client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
                signature: b64url_encode(&[2u8; 64]),
            },
        }
    }

    #[test]
    fn authorize_issues_bound_token() {
        let now = 1_700_000_000;
        let i = intent(now);
        let mut gate = AuthorizationGate::new();
        let auth = gate
            .authorize(&i, &approval_for(&i), &TestCryptographicVerifier, now)
            .unwrap();
        assert_eq!(auth.intent_id, i.id);
        assert_eq!(auth.signer_id, 1);
        assert_eq!(auth.tx_digest, i.tx_digest);
        assert_eq!(auth.session_id, i.session_id);
        assert_eq!(auth.nonce, i.nonce);
        assert!(!auth.is_consumed());
    }

    #[test]
    fn nonce_is_one_time_globally() {
        let now = 1_700_000_000;
        let i = intent(now);
        let mut gate = AuthorizationGate::new();
        assert!(
            gate.authorize(&i, &approval_for(&i), &TestCryptographicVerifier, now)
                .is_ok()
        );
        // A second intent reusing the same nonce must fail.
        let mut i2 = intent(now);
        i2.nonce = i.nonce;
        assert_eq!(
            gate.authorize(&i2, &approval_for(&i2), &TestCryptographicVerifier, now,),
            Err(GateError::NonceReused)
        );
    }

    #[test]
    fn expired_intent_rejected() {
        let now = 1_700_000_000;
        let i = intent(now - 7200); // expired
        let mut gate = AuthorizationGate::new();
        assert_eq!(
            gate.authorize(&i, &approval_for(&i), &TestCryptographicVerifier, now,),
            Err(GateError::Expired)
        );
    }

    #[test]
    fn wrong_approval_digest_rejected() {
        let now = 1_700_000_000;
        let i = intent(now);
        let mut bad = approval_for(&i);
        bad.intent_digest[0] ^= 1;
        let mut gate = AuthorizationGate::new();
        assert_eq!(
            gate.authorize(&i, &bad, &TestCryptographicVerifier, now),
            Err(GateError::ApprovalMismatch)
        );
    }

    #[test]
    fn already_approved_intent_rejected() {
        let now = 1_700_000_000;
        let mut i = intent(now);
        i.status = IntentStatus::Approved;
        let mut gate = AuthorizationGate::new();
        assert_eq!(
            gate.authorize(&i, &approval_for(&i), &TestCryptographicVerifier, now,),
            Err(GateError::NotPending(IntentStatus::Approved))
        );
    }
}
