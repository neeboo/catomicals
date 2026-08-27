//! Passkey authorization: proving user approval for an exact signing intent.
//!
//! The wallet node treats a WebAuthn assertion as an *approval* of the
//! challenge it was produced for. That challenge is the intent digest, so a
//! valid approval proves the human approved this exact intent. Passkey is
//! authorization only; it is never interpreted as a Bitcoin transaction
//! signature.
//!
//! This module contains a package-internal legacy seam used to test exact
//! authorization binding. Production approval is performed by
//! [`crate::webauthn::WebAuthnRelyingParty`], which owns the complete ceremony
//! and does not accept caller-supplied verification callbacks.

use base64::Engine;
#[cfg(test)]
use serde::{Deserialize, Serialize};

/// A WebAuthn assertion as transmitted by the browser.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    /// base64url credential id.
    pub credential_id: String,
    /// base64url authenticator data.
    pub authenticator_data: String,
    /// base64url client data JSON.
    pub client_data_json: String,
    /// base64url assertion signature.
    pub signature: String,
}

/// A Passkey approval of an intent digest.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyApproval {
    /// The intent digest this approval authorizes (== the challenge).
    pub intent_digest: [u8; 32],
    pub assertion: WebAuthnAssertion,
}

/// Errors from approval verification.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval was created for a different intent digest")]
    ChallengeMismatch,
    #[error("client data is not a WebAuthn get (approval) operation")]
    NotApprovalOperation,
    #[error("client data JSON could not be parsed: {0}")]
    MalformedClientData(String),
    #[error("approval credential {0} is not enrolled with this wallet")]
    UnknownCredential(String),
    #[error("cryptographic assertion verification failed")]
    AssertionVerificationFailed,
}

/// Verifies that a Passkey approval authorizes an exact challenge.
#[cfg(test)]
pub trait ApprovalVerifier {
    fn verify(&self, challenge: &[u8; 32], approval: &PasskeyApproval)
    -> Result<(), ApprovalError>;
}

/// Legacy unit-test marker for a verifier that stands in for complete
/// cryptographic WebAuthn RP verification.
#[cfg(test)]
pub trait CryptographicApprovalVerifier: ApprovalVerifier {}

/// Checks the binding that the wallet node controls: challenge equality,
/// and operation type. It is deliberately test/dev-only and does not implement
/// [`CryptographicApprovalVerifier`].
#[cfg(test)]
pub struct StructuralVerifier;

#[cfg(test)]
impl ApprovalVerifier for StructuralVerifier {
    fn verify(
        &self,
        challenge: &[u8; 32],
        approval: &PasskeyApproval,
    ) -> Result<(), ApprovalError> {
        verify_structure(challenge, approval)
    }
}

#[cfg(test)]
fn verify_structure(challenge: &[u8; 32], approval: &PasskeyApproval) -> Result<(), ApprovalError> {
    if &approval.intent_digest != challenge {
        return Err(ApprovalError::ChallengeMismatch);
    }
    let client = client_data(&approval.assertion.client_data_json)?;
    if client.r#type != "webauthn.get" {
        return Err(ApprovalError::NotApprovalOperation);
    }
    let challenge_b64 = b64url_decode(&client.challenge)
        .ok_or_else(|| ApprovalError::MalformedClientData("challenge".into()))?;
    if challenge_b64.as_slice() != challenge {
        return Err(ApprovalError::ChallengeMismatch);
    }
    Ok(())
}

/// A verifier that additionally checks credential enrollment against the
/// wallet's credential registry.
#[cfg(test)]
pub struct PasskeyVerifier<'a> {
    pub credentials: &'a dyn Fn(&str) -> bool,
    /// Complete WebAuthn RP verification supplied by the embedding service.
    pub verify_assertion: &'a dyn Fn(&WebAuthnAssertion) -> Result<(), ApprovalError>,
}

#[cfg(test)]
impl ApprovalVerifier for PasskeyVerifier<'_> {
    fn verify(
        &self,
        challenge: &[u8; 32],
        approval: &PasskeyApproval,
    ) -> Result<(), ApprovalError> {
        verify_structure(challenge, approval)?;
        if !(self.credentials)(&approval.assertion.credential_id) {
            return Err(ApprovalError::UnknownCredential(
                approval.assertion.credential_id.clone(),
            ));
        }
        (self.verify_assertion)(&approval.assertion)?;
        Ok(())
    }
}

#[cfg(test)]
impl CryptographicApprovalVerifier for PasskeyVerifier<'_> {}

/// Decode the WebAuthn client data JSON.
#[cfg(test)]
fn client_data(b64url: &str) -> Result<ClientData, ApprovalError> {
    let bytes = b64url_decode(b64url)
        .ok_or_else(|| ApprovalError::MalformedClientData("base64url".into()))?;
    serde_json::from_slice(&bytes).map_err(|e| ApprovalError::MalformedClientData(e.to_string()))
}

#[cfg(test)]
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    r#type: String,
    challenge: String,
}

/// base64url decode without padding.
#[cfg(test)]
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Encode bytes as unpadded base64url (used by the API/CLI).
pub fn b64url_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a canonical client-data JSON for a challenge (used by dev tooling and
/// tests to construct well-formed approvals).
#[cfg(test)]
pub fn make_client_data(challenge_b64url: &str) -> String {
    serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": "http://localhost:5173",
        "crossOrigin": false,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_verifier_binds_exact_challenge() {
        let challenge = [0x42u8; 32];
        let b64 = b64url_encode(&challenge);
        let approval = PasskeyApproval {
            intent_digest: challenge,
            assertion: WebAuthnAssertion {
                credential_id: "cred-1".into(),
                authenticator_data: b64url_encode(&[1u8; 37]),
                client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
                signature: b64url_encode(&[2u8; 64]),
            },
        };
        assert_eq!(StructuralVerifier.verify(&challenge, &approval), Ok(()));
    }

    #[test]
    fn structural_verifier_rejects_wrong_challenge() {
        let challenge = [0x42u8; 32];
        let other = [0x43u8; 32];
        let b64 = b64url_encode(&challenge);
        let approval = PasskeyApproval {
            intent_digest: other, // intent digest field disagrees
            assertion: WebAuthnAssertion {
                credential_id: "cred-1".into(),
                authenticator_data: b64url_encode(&[1u8; 37]),
                client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
                signature: b64url_encode(&[2u8; 64]),
            },
        };
        assert_eq!(
            StructuralVerifier.verify(&challenge, &approval),
            Err(ApprovalError::ChallengeMismatch)
        );
    }

    #[test]
    fn passkey_verifier_checks_enrollment() {
        let challenge = [0x42u8; 32];
        let b64 = b64url_encode(&challenge);
        let approval = PasskeyApproval {
            intent_digest: challenge,
            assertion: WebAuthnAssertion {
                credential_id: "cred-1".into(),
                authenticator_data: b64url_encode(&[1u8; 37]),
                client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
                signature: b64url_encode(&[2u8; 64]),
            },
        };
        let verifier = PasskeyVerifier {
            credentials: &|id| id == "cred-1",
            verify_assertion: &|_| Ok(()),
        };
        assert_eq!(verifier.verify(&challenge, &approval), Ok(()));
        let verifier2 = PasskeyVerifier {
            credentials: &|_| false,
            verify_assertion: &|_| Ok(()),
        };
        assert_eq!(
            verifier2.verify(&challenge, &approval),
            Err(ApprovalError::UnknownCredential("cred-1".into()))
        );
    }

    #[test]
    fn passkey_verifier_requires_cryptographic_assertion_verification() {
        let challenge = [0x42u8; 32];
        let b64 = b64url_encode(&challenge);
        let approval = PasskeyApproval {
            intent_digest: challenge,
            assertion: WebAuthnAssertion {
                credential_id: "cred-1".into(),
                authenticator_data: b64url_encode(&[1u8; 37]),
                client_data_json: b64url_encode(make_client_data(&b64).as_bytes()),
                signature: b64url_encode(&[2u8; 64]),
            },
        };
        let verifier = PasskeyVerifier {
            credentials: &|_| true,
            verify_assertion: &|_| Err(ApprovalError::AssertionVerificationFailed),
        };
        assert_eq!(
            verifier.verify(&challenge, &approval),
            Err(ApprovalError::AssertionVerificationFailed)
        );
    }
}
