//! Nonce reuse protection for FROST signing.
//!
//! FROST is unforgeable only while each participant's per-message nonces are
//! used for exactly one signing session. If a signer reuses nonces across two
//! different messages the resulting shares can leak the signing share. The
//! [`NonceGuard`] is the smallest mechanical defense: it records every
//! (nonce, session) association and rejects a second use of the same nonces in
//! a different session.

use std::collections::HashMap;

use frost_secp256k1_tr::round1::SigningNonces;
use sha2::{Digest, Sha256};

/// Error returned when a nonce is reused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceReuseError {
    #[error("nonces were already used for session {0:?}")]
    ReusedInOtherSession([u8; 32]),
    #[error("nonces were already used for this same session")]
    ReusedInSameSession,
}

/// Tracks which signing nonces have already been claimed for a session.
#[derive(Debug, Default)]
pub struct NonceGuard {
    /// nonce fingerprint -> session id
    claims: HashMap<[u8; 32], [u8; 32]>,
}

impl NonceGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fingerprint of a participant's signing nonces (session-independent).
    pub fn fingerprint(participant_id: u16, nonces: &SigningNonces) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"catomicals-frost-nonce-v1");
        hasher.update(participant_id.to_be_bytes());
        // Serialization is deterministic for these nonces.
        hasher.update(nonces.serialize().expect("nonce serialization"));
        hasher.finalize().into()
    }

    /// Claim `nonces` for `session_id`. Rejects reuse across sessions and
    /// double-claims within the same session.
    pub fn claim(
        &mut self,
        participant_id: u16,
        nonces: &SigningNonces,
        session_id: &[u8; 32],
    ) -> Result<(), NonceReuseError> {
        self.claim_fingerprint(Self::fingerprint(participant_id, nonces), session_id)
    }

    /// Lower-level claim used for unit tests and nonce fingerprint tracking.
    pub fn claim_fingerprint(
        &mut self,
        fingerprint: [u8; 32],
        session_id: &[u8; 32],
    ) -> Result<(), NonceReuseError> {
        match self.claims.get(&fingerprint) {
            None => {
                self.claims.insert(fingerprint, *session_id);
                Ok(())
            }
            Some(prior) if prior == session_id => Err(NonceReuseError::ReusedInSameSession),
            Some(prior) => Err(NonceReuseError::ReusedInOtherSession(*prior)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_nonce_fingerprint_rejected_across_sessions() {
        let mut guard = NonceGuard::new();
        let fp = [7u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(guard.claim_fingerprint(fp, &a), Ok(()));
        assert_eq!(
            guard.claim_fingerprint(fp, &b),
            Err(NonceReuseError::ReusedInOtherSession(a))
        );
    }

    #[test]
    fn same_nonce_fingerprint_in_same_session_rejected() {
        let mut guard = NonceGuard::new();
        let fp = [9u8; 32];
        let a = [3u8; 32];
        assert_eq!(guard.claim_fingerprint(fp, &a), Ok(()));
        assert_eq!(
            guard.claim_fingerprint(fp, &a),
            Err(NonceReuseError::ReusedInSameSession)
        );
    }

    #[test]
    fn distinct_nonces_are_claimable() {
        let mut guard = NonceGuard::new();
        let a = [1u8; 32];
        assert_eq!(guard.claim_fingerprint([1u8; 32], &a), Ok(()));
        assert_eq!(guard.claim_fingerprint([2u8; 32], &a), Ok(()));
    }
}
