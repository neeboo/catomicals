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

/// The only Bitcoin network this foundation authorizes through the legacy
/// FROST signer path.
///
/// `CovhubDelegated` is a narrow, explicit placeholder carried by a
/// CovHub-backed intent: the legacy container field no longer claims to be a
/// Bitcoin Signet network. Approval and execution authority for a CovHub
/// intent comes exclusively from the native `ChainScope`/`CovhubBinding`; this
/// variant grants nothing and is never consulted for chain routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Signet,
    /// Narrow marker for a CovHub-backed intent. The chain authority is the
    /// binding's native `chain_scope`; the legacy field is authority-inert.
    CovhubDelegated,
}

impl BitcoinNetwork {
    fn canonical_name(self) -> &'static [u8] {
        match self {
            Self::Signet => b"signet",
            Self::CovhubDelegated => b"covhub_delegated",
        }
    }
}

/// The exact operation approved by a signing intent.
///
/// `CovhubDelegated` is the narrow placeholder counterpart of
/// [`BitcoinNetwork::CovhubDelegated`] for a CovHub-backed intent; it does not
/// describe a taproot spend and grants no legacy authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAction {
    SignTaprootTransaction,
    CovhubDelegated,
}

impl SigningAction {
    fn canonical_name(self) -> &'static [u8] {
        match self {
            Self::SignTaprootTransaction => b"sign_taproot_transaction",
            Self::CovhubDelegated => b"covhub_delegated",
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
    /// Narrow, versioned, chain-neutral CovHub binding. When present this
    /// intent is a persisted CovHub pending intent: the wallet `SigningIntent`
    /// record is the durable container and lifecycle authority, while the
    /// binding carries the exact proposal, chain scope, and locally recomputed
    /// review that the human must approve. It is never set by an agent; the
    /// wallet derives it from its own re-run of the chain review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covhub: Option<crate::covhub::CovhubBinding>,
}

impl SigningIntent {
    /// Canonical encoding of the immutable intent fields.
    ///
    /// `status`/`created_at` are deliberately excluded: they are lifecycle
    /// metadata, not part of what the user approves.
    ///
    /// For a CovHub-bound intent the canonical form is the chain-neutral
    /// CovHub canonical encoding, so the Passkey approval challenge is exactly
    /// the CovHub intent digest (see `crate::covhub::covhub_canonical_bytes`).
    /// Legacy wallet intents keep their historical encoding byte-for-byte.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        if let Some(binding) = &self.covhub {
            return crate::covhub::covhub_canonical_bytes(
                binding.version,
                &self.id,
                &binding.proposal_id,
                &binding.proposal_digest,
                &binding.canvas_digest,
                &binding.code_confirmation_digest,
                &binding.chain_scope,
                &binding.review_digest,
                &binding.signing_message_digest,
                &self.session_id,
                &binding.profile_id,
                self.expiry,
            );
        }
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

    /// The chain scope that authoritatively governs any chain signing
    /// operation created from this intent. A CovHub-backed intent returns its
    /// chain-neutral native scope from the immutable CovHub binding; legacy
    /// intents return `None`.
    ///
    /// A CovHub-backed intent carries the narrow [`BitcoinNetwork::CovhubDelegated`]
    /// / [`SigningAction::CovhubDelegated`] markers in its legacy container
    /// fields: the fields never claim to authorize a Bitcoin Signet taproot
    /// spend and are never used as chain-routing or authorization inputs. The
    /// binding's native scope is the sole chain authority, so e.g. a Kaspa
    /// Testnet11 intent is never represented as a Bitcoin Signet intent.
    pub fn authoritative_chain_scope(&self) -> Option<catomicals_chain_domain::ChainScope> {
        self.covhub.as_ref().map(|binding| binding.chain_scope)
    }

    /// Whether the legacy `network`/`action` container fields are consistent
    /// with the CovHub representation invariant: a CovHub-backed intent must
    /// carry the narrow delegated markers (never the Bitcoin Signet/taproot
    /// pair), and a legacy intent never carries the delegated markers. The
    /// wallet enforces this at intent creation and again before a chain
    /// signing job is created, so a stale or hostile Signet placeholder on a
    /// CovHub intent fails closed.
    pub fn covhub_legacy_fields_are_delegated(&self) -> bool {
        match &self.covhub {
            Some(_) => {
                self.network == BitcoinNetwork::CovhubDelegated
                    && self.action == SigningAction::CovhubDelegated
            }
            None => {
                self.network != BitcoinNetwork::CovhubDelegated
                    && self.action != SigningAction::CovhubDelegated
            }
        }
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
            covhub: None,
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
