//! Catomicals threshold signing over `frost-secp256k1-tr`.
//!
//! Demonstrates a threshold BIP340/Taproot-compatible Schnorr signature using
//! the Zcash Foundation FROST implementation, and defines the *smallest*
//! authorization seam a signer share must clear before it may participate:
//! a one-time, intent-bound [`SigningAuthorization`].
//!
//! Security posture:
//! - This crate never persists key material.
//! - `frost-secp256k1-tr` has not been independently audited for Catomicals'
//!   production use; see `docs/security.md`. Mainnet is disabled.
//! - A signer share MUST NOT be used unless the authorization token binds the
//!   exact `FrostSession` id and BIP340 message digest, is unexpired, and is
//!   consumed exactly once.

#![forbid(unsafe_code)]

pub mod dkg;
pub mod nonce_guard;
pub mod orchestrator;
pub mod participant;
pub mod provider;
pub mod session;

pub use dkg::{LocalDkgOutput, run_local_dkg};
pub use frost_secp256k1_tr::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare,
};
pub use nonce_guard::{NonceGuard, NonceReuseError};
pub use orchestrator::{
    AuditEvent, AuditEventKind, BoundParticipant, OrchestrationError, SessionPhase,
    ThresholdSessionMachine,
};
pub use participant::{CoordinatorError, FrostCoordinator, LocalFrostParticipant};
pub use provider::{
    DeviceHealth, DeviceRegistrationChallenge, DeviceRegistrationProof, DeviceStatus,
    FrostSignerBackend, GuardedSignerProvider, HsmSignerAdapter, LocalEncryptedFrostBackend,
    MemoryProviderReplayStore, ProviderError, ProviderIdentity, ProviderReplayStore,
    ProviderRequestAuthorizer, ProviderRound, SIGNER_PROVIDER_PROTOCOL_VERSION, SignerAbortRequest,
    SignerDeviceRecord, SignerDeviceRegistry, SignerProvider, SignerProviderKind,
    SignerRequestContext, SignerRoundOneRequest, SignerRoundOneResponse, SignerRoundTwoRequest,
    SignerRoundTwoResponse,
};
pub use session::{
    AuthorizationError, FrostSession, SigningAuthorization, SigningError, aggregate_and_verify,
    build_session, sign_share, signature_to_bytes, verify_signature,
};

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier,
    keys::{IdentifierList, SecretShare, generate_with_dealer},
};
use rand::rngs::OsRng;

/// Default threshold wallet shape: 2-of-3.
pub const DEFAULT_MAX_SIGNERS: u16 = 3;
pub const DEFAULT_MIN_SIGNERS: u16 = 2;

/// Result of a trusted-dealer key generation.
pub struct ThresholdKeygen {
    /// Number of total signers.
    pub max_signers: u16,
    /// Number of signers required to produce a signature.
    pub min_signers: u16,
    /// One `SecretShare` per participant (dealer output).
    pub shares: BTreeMap<Identifier, SecretShare>,
    /// Public package containing verifying shares and the group public key.
    pub public_key_package: PublicKeyPackage,
}

impl core::fmt::Debug for ThresholdKeygen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThresholdKeygen")
            .field("max_signers", &self.max_signers)
            .field("min_signers", &self.min_signers)
            .field("shares", &format_args!("<{} redacted>", self.shares.len()))
            .field("public_key_package", &self.public_key_package)
            .finish()
    }
}

/// Generate a `t-of-n` FROST key set using a trusted dealer.
///
/// # Test only
///
/// This remains for compatibility with foundation tests. Applications must use
/// DKG because a trusted dealer can reconstruct the group secret.
pub fn generate_threshold(
    max_signers: u16,
    min_signers: u16,
) -> Result<ThresholdKeygen, frost_secp256k1_tr::Error> {
    let (shares, public_key_package) =
        generate_with_dealer(max_signers, min_signers, IdentifierList::Default, OsRng)?;
    Ok(ThresholdKeygen {
        max_signers,
        min_signers,
        shares,
        public_key_package,
    })
}

/// Serialize the group public key as a BIP340 X-only 32-byte array.
///
/// `frost-secp256k1-tr` serializes elements as 33-byte SEC1 compressed points;
/// the BIP340 X-only encoding is the X coordinate (the trailing 32 bytes).
pub fn group_pubkey_xonly(
    public_key_package: &PublicKeyPackage,
) -> Result<[u8; 32], frost_secp256k1_tr::Error> {
    let bytes = public_key_package.verifying_key().serialize()?;
    let xonly = match bytes.len() {
        32 => &bytes[..],
        33 => &bytes[1..],
        _ => return Err(frost_secp256k1_tr::Error::MalformedIdentifier),
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(xonly);
    Ok(out)
}

/// Derive a participant `Identifier` from a `u16` signer id (1-based).
pub fn participant_identifier(id: u16) -> Result<Identifier, frost_secp256k1_tr::Error> {
    Identifier::try_from(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::keys::KeyPackage;

    #[test]
    fn keygen_produces_expected_shapes() {
        let kg = generate_threshold(3, 2).expect("keygen");
        assert_eq!(kg.shares.len(), 3);
        let xonly = group_pubkey_xonly(&kg.public_key_package).expect("xonly");
        assert_eq!(xonly.len(), 32);
        // A public key package is not a secret: 32-byte X-only key is printable.
        assert_ne!(xonly, [0u8; 32]);
        let _ =
            KeyPackage::try_from(kg.shares.values().next().unwrap().clone()).expect("keypackage");
    }
}
