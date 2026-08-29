//! Immutable signing intents.
//!
//! A [`SigningIntent`] is the smallest unit of *what* the user is being asked
//! to approve. Every field below is bound into the intent digest; nothing about
//! the signing request can be swapped after the challenge is issued.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Canonical signing-intent protocol version.
pub const SIGNING_PROTOCOL_VERSION: u16 = 1;

/// The only Bitcoin network authorized by this foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Signet,
}

impl BitcoinNetwork {
    fn canonical_name(self) -> &'static [u8] {
        match self {
            Self::Signet => b"signet",
        }
    }
}

/// The exact operation approved by a signing intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAction {
    SignTaprootTransaction,
}

impl SigningAction {
    fn canonical_name(self) -> &'static [u8] {
        match self {
            Self::SignTaprootTransaction => b"sign_taproot_transaction",
        }
    }
}

/// A wallet identifier (opaque to the signer).
pub type WalletId = Uuid;
/// A signing intent identifier.
pub type IntentId = Uuid;

/// Public group policy approved by Passkey before a personal 2-of-3
/// operation may select one of its permitted participant pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalSigningPolicy {
    pub profile_id: Uuid,
    pub signer_set_id: Uuid,
    pub signer_epoch: u64,
    #[serde(with = "crate::api::hex_array32")]
    pub group_pubkey_xonly: [u8; 32],
    pub allowed_participants: [u16; 3],
    pub threshold: u16,
    #[serde(with = "crate::api::hex_array32")]
    pub policy_digest: [u8; 32],
    #[serde(with = "crate::api::hex_array32")]
    pub chain_snapshot_digest: [u8; 32],
}

impl PersonalSigningPolicy {
    pub fn from_profile(
        profile: &catomicals_threshold::PersonalSignerProfile,
        policy_digest: [u8; 32],
        chain_snapshot_digest: [u8; 32],
    ) -> Self {
        Self {
            profile_id: profile.profile_id(),
            signer_set_id: profile.signer_set_id(),
            signer_epoch: profile.signer_epoch(),
            group_pubkey_xonly: profile.group_pubkey_xonly(),
            allowed_participants: [1, 2, 3],
            threshold: profile.min_signers(),
            policy_digest,
            chain_snapshot_digest,
        }
    }
}

/// Lifecycle of a signing intent. Only `Pending` intents may be approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Pending,
    Approved,
    Signing,
    Cancelled,
    Expired,
    Signed,
}

/// The exact, immutable request a Passkey approval authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningIntent {
    pub id: IntentId,
    pub network: BitcoinNetwork,
    pub protocol_version: u16,
    pub action: SigningAction,
    pub wallet_id: WalletId,
    /// FROST participant identifier (1-based) whose share will participate.
    /// Zero denotes a group authorization and requires `personal_signing_policy`.
    pub signer_id: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_signing_policy: Option<PersonalSigningPolicy>,
    /// Exact transaction digest (32 bytes) to be signed.
    #[serde(with = "crate::api::hex_array32")]
    pub tx_digest: [u8; 32],
    /// FROST session id (32 bytes, opaque to the wallet).
    #[serde(with = "crate::api::hex_array32")]
    pub session_id: [u8; 32],
    /// Unix seconds after which the intent may not be approved.
    pub expiry: i64,
    /// One-time approval nonce.
    #[serde(with = "crate::api::hex_array32")]
    pub nonce: [u8; 32],
    pub status: IntentStatus,
    pub created_at: i64,
}

impl SigningIntent {
    /// Canonical encoding of the immutable intent fields.
    ///
    /// `status`/`created_at` are deliberately excluded: they are lifecycle
    /// metadata, not part of what the user approves.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"catomicals/signing-intent\0");
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(self.network.canonical_name());
        out.push(0);
        out.extend_from_slice(self.action.canonical_name());
        out.push(0);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(self.wallet_id.as_bytes());
        out.extend_from_slice(&self.signer_id.to_be_bytes());
        if let Some(policy) = &self.personal_signing_policy {
            out.extend_from_slice(b"personal-2of3\0");
            out.extend_from_slice(policy.profile_id.as_bytes());
            out.extend_from_slice(policy.signer_set_id.as_bytes());
            out.extend_from_slice(&policy.signer_epoch.to_be_bytes());
            out.extend_from_slice(&policy.group_pubkey_xonly);
            for signer_id in policy.allowed_participants {
                out.extend_from_slice(&signer_id.to_be_bytes());
            }
            out.extend_from_slice(&policy.threshold.to_be_bytes());
            out.extend_from_slice(&policy.policy_digest);
            out.extend_from_slice(&policy.chain_snapshot_digest);
        }
        out.extend_from_slice(&self.tx_digest);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// SHA-256 digest of the immutable intent. This is the approval challenge.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expiry
    }
}

/// Compute the intent digest for an intent with the given identity fields
/// (used for test vectors and the CLI).
pub fn intent_digest(intent: &SigningIntent) -> [u8; 32] {
    intent.digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SigningIntent {
        SigningIntent {
            id: Uuid::from_bytes([0x0a; 16]),
            network: BitcoinNetwork::Signet,
            protocol_version: SIGNING_PROTOCOL_VERSION,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: Uuid::from_bytes([0x0b; 16]),
            signer_id: 1,
            personal_signing_policy: None,
            tx_digest: [0x11; 32],
            session_id: [0x22; 32],
            expiry: 2_000_000_000,
            nonce: [0x33; 32],
            status: IntentStatus::Pending,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn digest_is_stable_and_immutable_fields_bound() {
        let a = sample();
        let b = sample();
        // Same immutable fields -> same digest even though status differs.
        assert_eq!(a.digest(), b.digest());
        let mut c = sample();
        c.status = IntentStatus::Approved; // lifecycle metadata not part of digest
        assert_eq!(a.digest(), c.digest());
        let mut d = sample();
        d.tx_digest[0] ^= 1;
        assert_ne!(a.digest(), d.digest());
        let mut e = sample();
        e.nonce[0] ^= 1;
        assert_ne!(a.digest(), e.digest());
        let mut f = sample();
        f.signer_id = 2;
        assert_ne!(a.digest(), f.digest());
        let mut g = sample();
        g.wallet_id = Uuid::from_bytes([0x0c; 16]);
        assert_ne!(a.digest(), g.digest());
        let mut h = sample();
        h.session_id[0] ^= 1;
        assert_ne!(a.digest(), h.digest());
        let mut j = sample();
        j.expiry += 1;
        assert_ne!(a.digest(), j.digest());
        let mut k = sample();
        k.protocol_version += 1;
        assert_ne!(a.digest(), k.digest());
    }

    #[test]
    fn signing_is_a_distinct_public_lifecycle_state() {
        let mut intent = sample();
        intent.status = IntentStatus::Signing;
        assert_eq!(
            serde_json::to_string(&intent.status).unwrap(),
            r#""signing""#
        );
        assert_eq!(
            serde_json::from_str::<IntentStatus>(r#""signing""#).unwrap(),
            IntentStatus::Signing
        );
    }

    #[test]
    fn canonical_intent_explicitly_binds_signet_version_and_action() {
        let bytes = sample().canonical_bytes();
        assert!(bytes.starts_with(b"catomicals/signing-intent\0"));
        assert!(bytes.windows(b"signet".len()).any(|w| w == b"signet"));
        assert!(
            bytes
                .windows(b"sign_taproot_transaction".len())
                .any(|w| w == b"sign_taproot_transaction")
        );
    }

    #[test]
    fn expiry_is_checked() {
        let i = sample();
        assert!(!i.is_expired(1_700_000_000));
        assert!(i.is_expired(2_000_000_001));
    }

    #[test]
    fn personal_signing_policy_is_bound_into_the_passkey_challenge() {
        let mut intent = sample();
        let legacy_digest = intent.digest();
        intent.personal_signing_policy = Some(PersonalSigningPolicy {
            profile_id: Uuid::from_bytes([0x41; 16]),
            signer_set_id: Uuid::from_bytes([0x42; 16]),
            signer_epoch: 7,
            group_pubkey_xonly: [0x43; 32],
            allowed_participants: [1, 2, 3],
            threshold: 2,
            policy_digest: [0x44; 32],
            chain_snapshot_digest: [0x45; 32],
        });
        assert_ne!(intent.digest(), legacy_digest);

        let digest = intent.digest();
        intent
            .personal_signing_policy
            .as_mut()
            .unwrap()
            .signer_epoch += 1;
        assert_ne!(intent.digest(), digest);

        intent
            .personal_signing_policy
            .as_mut()
            .unwrap()
            .signer_epoch -= 1;
        let digest = intent.digest();
        intent
            .personal_signing_policy
            .as_mut()
            .unwrap()
            .policy_digest[0] ^= 1;
        assert_ne!(intent.digest(), digest);
    }
}
