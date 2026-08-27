//! FROST signing sessions: the authorization seam plus round orchestration.
//!
//! A [`FrostSession`] is fully determined by its id, the BIP340 message digest
//! and the set of signing commitments. A signer share may only participate via
//! [`sign_share`], which requires a one-time, intent-bound
//! [`SigningAuthorization`] covering the exact session and message, plus a
//! [`crate::NonceGuard`] claim proving the nonces have not been reused.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier, Signature,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
};

use crate::nonce_guard::{NonceGuard, NonceReuseError};

/// Re-exported frost aggregation (used by tests and the CLI).
pub use frost_secp256k1_tr::aggregate;

/// A threshold signing session over a single BIP340 message digest.
#[derive(Debug, Clone)]
pub struct FrostSession {
    /// Opaque session identifier (binds to a wallet signing intent).
    pub id: [u8; 32],
    /// The exact 32-byte BIP340 message digest to be signed.
    pub message: [u8; 32],
    /// Minimum number of signers required.
    pub min_signers: u16,
    /// Round-one signing commitments from the participating signers.
    pub signing_package: frost_secp256k1_tr::SigningPackage,
    /// Public key package (group key + verifying shares).
    pub public_key_package: PublicKeyPackage,
}

/// Build a signing session from participant commitments.
pub fn build_session(
    id: [u8; 32],
    message: [u8; 32],
    min_signers: u16,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    public_key_package: PublicKeyPackage,
) -> FrostSession {
    let signing_package = frost_secp256k1_tr::SigningPackage::new(commitments, &message);
    FrostSession {
        id,
        message,
        min_signers,
        signing_package,
        public_key_package,
    }
}

/// Authorization errors a signer share must clear before participating.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("authorization token has already been consumed")]
    AlreadyConsumed,
    #[error("authorization token is bound to a different FROST session")]
    WrongSession,
    #[error("authorization token is bound to a different message digest")]
    WrongMessage,
    #[error("authorization token is bound to a different signer id")]
    WrongSigner,
    #[error("authorization has expired")]
    Expired,
}

/// The one-time, exact-binding authorization a signer must present.
///
/// Implemented by the wallet node (Passkey-approved signing intents). The
/// signer share refuses to participate unless the token covers the exact
/// session id, message digest and signer id, is unexpired, and is consumed.
pub trait SigningAuthorization {
    /// Validate the token against this exact session and consume it (one-time).
    fn authorize(
        &mut self,
        session_id: &[u8; 32],
        message: &[u8; 32],
        signer_id: u16,
        now: i64,
    ) -> Result<(), AuthorizationError>;
}

/// Produce a signature share for `signer_id` in `session`.
///
/// The share is only ever produced after:
/// 1. `authorization.authorize(...)` succeeds (Passkey-approved, exact-bound,
///    one-time token), and
/// 2. `nonce_guard.claim(...)` succeeds (these nonces were not used before).
pub fn sign_share(
    session: &FrostSession,
    signer_id: u16,
    nonces: &SigningNonces,
    key_package: &KeyPackage,
    nonce_guard: &mut NonceGuard,
    authorization: &mut dyn SigningAuthorization,
    now: i64,
) -> Result<SignatureShare, SigningError> {
    authorization.authorize(&session.id, &session.message, signer_id, now)?;
    nonce_guard.claim(signer_id, nonces, &session.id)?;
    // Defensive: the presented key package must actually belong to the signer.
    let expected = Identifier::try_from(signer_id).map_err(SigningError::from)?;
    if key_package.identifier() != &expected {
        return Err(SigningError::KeyPackageSignerMismatch);
    }
    Ok(round2::sign(&session.signing_package, nonces, key_package)?)
}

/// Aggregate signature shares into a BIP340/Taproot-compatible signature and
/// verify it against the group public key.
pub fn aggregate_and_verify(
    session: &FrostSession,
    shares: &BTreeMap<Identifier, SignatureShare>,
) -> Result<Signature, SigningError> {
    let signature = aggregate(
        &session.signing_package,
        shares,
        &session.public_key_package,
    )?;
    verify_signature(session, &signature)?;
    Ok(signature)
}

/// Verify a signature against the session's group public key and message.
pub fn verify_signature(session: &FrostSession, signature: &Signature) -> Result<(), SigningError> {
    session
        .public_key_package
        .verifying_key()
        .verify(&session.message, signature)
        .map_err(SigningError::from)
}

/// Serialize a BIP340 signature as the 64-byte `R || s` encoding.
pub fn signature_to_bytes(signature: &Signature) -> Result<[u8; 64], SigningError> {
    let bytes = signature.serialize()?;
    if bytes.len() != 64 {
        return Err(SigningError::UnexpectedSignatureLength(bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Error type for signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("authorization rejected: {0}")]
    Authorization(#[from] AuthorizationError),
    #[error("nonce guard rejected: {0}")]
    NonceReuse(#[from] NonceReuseError),
    #[error("frost error: {0}")]
    Frost(#[from] frost_secp256k1_tr::Error),
    #[error("key package does not belong to the declared signer id")]
    KeyPackageSignerMismatch,
    #[error("round one already exists for this session")]
    RoundOneAlreadyExists,
    #[error("no round-one nonces exist for this session")]
    RoundOneNotFound,
    #[error("round-two session/message/commitment does not match round one")]
    RoundBindingMismatch,
    #[error("unexpected signature length {0} (expected 64)")]
    UnexpectedSignatureLength(usize),
}
