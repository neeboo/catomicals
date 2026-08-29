//! Authenticated, standalone recovery bundles for personal participant 3.
//!
//! Recovery bundles deliberately contain exactly one FROST participant. They
//! are independent from wallet database backups so a single backup artifact
//! cannot silently collect a signing quorum.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use catomicals_threshold::{PersonalParticipantSecretPackage, PersonalSignerProfile};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const RECOVERY_BUNDLE_FORMAT_VERSION: u16 = 1;
pub const RECOVERY_BUNDLE_MAX_BYTES: usize = 128 * 1024;
pub const RECOVERY_KDF_MEMORY_KIB: u32 = 64 * 1024;
pub const RECOVERY_KDF_PASSES: u32 = 3;
pub const RECOVERY_KDF_LANES: u32 = 4;
pub const RECOVERY_KDF_OUTPUT_LEN: usize = 32;

const RECOVERY_KEY_BYTES: usize = 32;
const RECOVERY_SALT_BYTES: usize = 16;
const RECOVERY_NONCE_BYTES: usize = 24;
const PARTICIPANT_ID: u16 = 3;
const KDF_ALGORITHM: &str = "argon2id-v1.3";
const ENCRYPTION_SUITE: &str = "xchacha20-poly1305+argon2id";
const AAD_DOMAIN: &[u8] = b"catomicals/participant3-recovery-bundle/v1\0";
const WRAPPED_DEK_PURPOSE: &[u8] = b"wrapped-dek\0";
const PAYLOAD_PURPOSE: &[u8] = b"participant-package\0";
const CHECKSUM_DOMAIN: &[u8] = b"catomicals/participant3-recovery-checksum/v1\0";

/// A random recovery secret used only to derive the bundle wrapping key.
pub struct RecoveryKey(Zeroizing<[u8; RECOVERY_KEY_BYTES]>);

impl RecoveryKey {
    #[must_use]
    fn generate() -> Self {
        let mut bytes = [0_u8; RECOVERY_KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; RECOVERY_KEY_BYTES]> {
        Zeroizing::new(*self.0)
    }

    fn expose(&self) -> &[u8; RECOVERY_KEY_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RecoveryKey").field(&"<redacted>").finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryKdf {
    algorithm: String,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    output_len: usize,
    salt: [u8; RECOVERY_SALT_BYTES],
}

impl RecoveryKdf {
    fn secure_random() -> Self {
        let mut salt = [0_u8; RECOVERY_SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: KDF_ALGORITHM.to_owned(),
            memory_kib: RECOVERY_KDF_MEMORY_KIB,
            passes: RECOVERY_KDF_PASSES,
            lanes: RECOVERY_KDF_LANES,
            output_len: RECOVERY_KDF_OUTPUT_LEN,
            salt,
        }
    }

    fn validate(&self) -> Result<(), RecoveryBundleError> {
        // Version 1 accepts one audited cost profile. Higher values belong in
        // a future format version; accepting arbitrary costs from an
        // untrusted bundle would create a memory/CPU denial-of-service path.
        if self.algorithm != KDF_ALGORITHM
            || self.memory_kib != RECOVERY_KDF_MEMORY_KIB
            || self.passes != RECOVERY_KDF_PASSES
            || self.lanes != RECOVERY_KDF_LANES
            || self.output_len != RECOVERY_KDF_OUTPUT_LEN
        {
            return Err(RecoveryBundleError::WeakKdfParameters);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBundle {
    format_version: u16,
    encryption_suite: String,
    bundle_id: Uuid,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    participant_id: u16,
    group_pubkey_xonly: [u8; 32],
    profile_binding_digest: [u8; 32],
    kdf: RecoveryKdf,
    wrapped_dek_nonce: [u8; RECOVERY_NONCE_BYTES],
    wrapped_dek: Vec<u8>,
    payload_nonce: [u8; RECOVERY_NONCE_BYTES],
    payload_ciphertext: Vec<u8>,
    checksum: [u8; 32],
}

impl core::fmt::Debug for RecoveryBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryBundle")
            .field("format_version", &self.format_version)
            .field("encryption_suite", &self.encryption_suite)
            .field("bundle_id", &self.bundle_id)
            .field("profile_id", &self.profile_id)
            .field("wallet_id", &self.wallet_id)
            .field("signer_set_id", &self.signer_set_id)
            .field("signer_epoch", &self.signer_epoch)
            .field("participant_id", &self.participant_id)
            .field("group_pubkey_xonly", &self.group_pubkey_xonly)
            .field("profile_binding_digest", &self.profile_binding_digest)
            .field("kdf", &self.kdf)
            .field("wrapped_dek_nonce", &"<redacted>")
            .field("wrapped_dek", &"<redacted>")
            .field("payload_nonce", &"<redacted>")
            .field("payload_ciphertext", &"<redacted>")
            .field("checksum", &self.checksum)
            .finish()
    }
}

#[derive(Serialize)]
struct AadRef<'a> {
    format_version: u16,
    encryption_suite: &'a str,
    bundle_id: Uuid,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    participant_id: u16,
    group_pubkey_xonly: [u8; 32],
    profile_binding_digest: [u8; 32],
    kdf: &'a RecoveryKdf,
}

#[derive(Serialize)]
struct ChecksumRef<'a> {
    aad: AadRef<'a>,
    wrapped_dek_nonce: [u8; RECOVERY_NONCE_BYTES],
    wrapped_dek: &'a [u8],
    payload_nonce: [u8; RECOVERY_NONCE_BYTES],
    payload_ciphertext: &'a [u8],
}

impl RecoveryBundle {
    pub fn seal(
        participant: PersonalParticipantSecretPackage,
        profile: &PersonalSignerProfile,
    ) -> Result<(Self, RecoveryKey), RecoveryBundleError> {
        if participant.signer_id() != PARTICIPANT_ID {
            return Err(RecoveryBundleError::WrongParticipant);
        }
        participant
            .validate(profile)
            .map_err(|_| RecoveryBundleError::ProfileMismatch)?;
        let plaintext = participant
            .to_bytes()
            .map_err(|_| RecoveryBundleError::InvalidSecretPackage)?;
        // The caller cannot choose a weak or repeated recovery secret. The
        // imported-key constructor remains available only for opening an
        // already-created bundle.
        let recovery_key = RecoveryKey::generate();

        let mut bundle_id_bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bundle_id_bytes);
        let bundle_id = Uuid::from_bytes(bundle_id_bytes);
        let kdf = RecoveryKdf::secure_random();
        let mut bundle = Self {
            format_version: RECOVERY_BUNDLE_FORMAT_VERSION,
            encryption_suite: ENCRYPTION_SUITE.to_owned(),
            bundle_id,
            profile_id: profile.profile_id(),
            wallet_id: profile.wallet_id(),
            signer_set_id: profile.signer_set_id(),
            signer_epoch: profile.signer_epoch(),
            participant_id: PARTICIPANT_ID,
            group_pubkey_xonly: profile.group_pubkey_xonly(),
            profile_binding_digest: profile.binding_digest(),
            kdf,
            wrapped_dek_nonce: random_array(),
            wrapped_dek: Vec::new(),
            payload_nonce: random_array(),
            payload_ciphertext: Vec::new(),
            checksum: [0_u8; 32],
        };
        bundle.kdf.validate()?;

        let kek = derive_kek(&recovery_key, &bundle.kdf)?;
        let mut dek = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(dek.as_mut());
        let dek_cipher = XChaCha20Poly1305::new_from_slice(dek.as_ref())
            .map_err(|_| RecoveryBundleError::Cryptography)?;
        let kek_cipher = XChaCha20Poly1305::new_from_slice(kek.as_ref())
            .map_err(|_| RecoveryBundleError::Cryptography)?;

        let payload_aad = bundle.aad_bytes(PAYLOAD_PURPOSE)?;
        bundle.payload_ciphertext = dek_cipher
            .encrypt(
                XNonce::from_slice(&bundle.payload_nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &payload_aad,
                },
            )
            .map_err(|_| RecoveryBundleError::Cryptography)?;
        let wrapped_dek_aad = bundle.aad_bytes(WRAPPED_DEK_PURPOSE)?;
        bundle.wrapped_dek = kek_cipher
            .encrypt(
                XNonce::from_slice(&bundle.wrapped_dek_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &wrapped_dek_aad,
                },
            )
            .map_err(|_| RecoveryBundleError::Cryptography)?;
        bundle.checksum = bundle.compute_checksum()?;
        bundle.validate_wire()?;
        Ok((bundle, recovery_key))
    }

    pub fn open(
        &self,
        recovery_key: &RecoveryKey,
        profile: &PersonalSignerProfile,
    ) -> Result<PersonalParticipantSecretPackage, RecoveryBundleError> {
        self.validate_wire()?;
        self.verify_checksum()?;
        self.validate_profile(profile)?;

        let kek = derive_kek(recovery_key, &self.kdf)?;
        let kek_cipher = XChaCha20Poly1305::new_from_slice(kek.as_ref())
            .map_err(|_| RecoveryBundleError::Cryptography)?;
        let wrapped_dek_aad = self.aad_bytes(WRAPPED_DEK_PURPOSE)?;
        let mut opened_dek = Zeroizing::new(
            kek_cipher
                .decrypt(
                    XNonce::from_slice(&self.wrapped_dek_nonce),
                    Payload {
                        msg: &self.wrapped_dek,
                        aad: &wrapped_dek_aad,
                    },
                )
                .map_err(|_| RecoveryBundleError::AuthenticationFailed)?,
        );
        if opened_dek.len() != 32 {
            return Err(RecoveryBundleError::AuthenticationFailed);
        }
        let payload_cipher = XChaCha20Poly1305::new_from_slice(&opened_dek)
            .map_err(|_| RecoveryBundleError::AuthenticationFailed)?;
        let payload_aad = self.aad_bytes(PAYLOAD_PURPOSE)?;
        let mut plaintext = Zeroizing::new(
            payload_cipher
                .decrypt(
                    XNonce::from_slice(&self.payload_nonce),
                    Payload {
                        msg: &self.payload_ciphertext,
                        aad: &payload_aad,
                    },
                )
                .map_err(|_| RecoveryBundleError::AuthenticationFailed)?,
        );
        opened_dek.zeroize();
        let package = PersonalParticipantSecretPackage::from_bytes(&plaintext, profile)
            .map_err(|_| RecoveryBundleError::InvalidSecretPackage)?;
        plaintext.zeroize();
        if package.signer_id() != PARTICIPANT_ID {
            return Err(RecoveryBundleError::WrongParticipant);
        }
        package
            .validate(profile)
            .map_err(|_| RecoveryBundleError::InvalidSecretPackage)?;
        Ok(package)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryBundleError> {
        self.validate_wire()?;
        self.verify_checksum()?;
        let bytes = serde_json::to_vec(self).map_err(|_| RecoveryBundleError::InvalidEncoding)?;
        if bytes.len() > RECOVERY_BUNDLE_MAX_BYTES {
            return Err(RecoveryBundleError::BundleTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryBundleError> {
        if bytes.len() > RECOVERY_BUNDLE_MAX_BYTES {
            return Err(RecoveryBundleError::BundleTooLarge);
        }
        let bundle: Self =
            serde_json::from_slice(bytes).map_err(|_| RecoveryBundleError::InvalidEncoding)?;
        bundle.validate_wire()?;
        bundle.verify_checksum()?;
        Ok(bundle)
    }

    pub fn verify_checksum(&self) -> Result<(), RecoveryBundleError> {
        if self.compute_checksum()? != self.checksum {
            return Err(RecoveryBundleError::ChecksumMismatch);
        }
        Ok(())
    }

    fn validate_wire(&self) -> Result<(), RecoveryBundleError> {
        if self.format_version != RECOVERY_BUNDLE_FORMAT_VERSION {
            return Err(RecoveryBundleError::UnsupportedVersion);
        }
        if self.encryption_suite != ENCRYPTION_SUITE {
            return Err(RecoveryBundleError::UnsupportedEncryptionSuite);
        }
        if self.participant_id != PARTICIPANT_ID {
            return Err(RecoveryBundleError::WrongParticipant);
        }
        if self.signer_epoch == 0 {
            return Err(RecoveryBundleError::ProfileMismatch);
        }
        self.kdf.validate()?;
        if self.wrapped_dek.len() != 48
            || self.payload_ciphertext.len() < 16
            || self.payload_ciphertext.len() > RECOVERY_BUNDLE_MAX_BYTES
        {
            return Err(RecoveryBundleError::InvalidEncoding);
        }
        Ok(())
    }

    fn validate_profile(&self, profile: &PersonalSignerProfile) -> Result<(), RecoveryBundleError> {
        if self.profile_id != profile.profile_id()
            || self.wallet_id != profile.wallet_id()
            || self.signer_set_id != profile.signer_set_id()
            || self.signer_epoch != profile.signer_epoch()
            || self.group_pubkey_xonly != profile.group_pubkey_xonly()
            || self.profile_binding_digest != profile.binding_digest()
            || profile
                .participants()
                .iter()
                .all(|participant| participant.signer_id != PARTICIPANT_ID)
        {
            return Err(RecoveryBundleError::ProfileMismatch);
        }
        Ok(())
    }

    fn aad(&self) -> AadRef<'_> {
        AadRef {
            format_version: self.format_version,
            encryption_suite: &self.encryption_suite,
            bundle_id: self.bundle_id,
            profile_id: self.profile_id,
            wallet_id: self.wallet_id,
            signer_set_id: self.signer_set_id,
            signer_epoch: self.signer_epoch,
            participant_id: self.participant_id,
            group_pubkey_xonly: self.group_pubkey_xonly,
            profile_binding_digest: self.profile_binding_digest,
            kdf: &self.kdf,
        }
    }

    fn aad_bytes(&self, purpose: &[u8]) -> Result<Vec<u8>, RecoveryBundleError> {
        let encoded =
            serde_json::to_vec(&self.aad()).map_err(|_| RecoveryBundleError::InvalidEncoding)?;
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + purpose.len() + encoded.len());
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(purpose);
        aad.extend_from_slice(&encoded);
        Ok(aad)
    }

    fn compute_checksum(&self) -> Result<[u8; 32], RecoveryBundleError> {
        let material = ChecksumRef {
            aad: self.aad(),
            wrapped_dek_nonce: self.wrapped_dek_nonce,
            wrapped_dek: &self.wrapped_dek,
            payload_nonce: self.payload_nonce,
            payload_ciphertext: &self.payload_ciphertext,
        };
        let encoded =
            serde_json::to_vec(&material).map_err(|_| RecoveryBundleError::InvalidEncoding)?;
        let mut hasher = Sha256::new();
        hasher.update(CHECKSUM_DOMAIN);
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    #[must_use]
    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub fn participant_id(&self) -> u16 {
        self.participant_id
    }

    #[must_use]
    pub fn profile_id(&self) -> Uuid {
        self.profile_id
    }

    #[must_use]
    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }

    #[must_use]
    pub fn signer_set_id(&self) -> Uuid {
        self.signer_set_id
    }

    #[must_use]
    pub fn signer_epoch(&self) -> u64 {
        self.signer_epoch
    }

    #[must_use]
    pub fn group_pubkey_xonly(&self) -> [u8; 32] {
        self.group_pubkey_xonly
    }

    #[must_use]
    pub fn profile_binding_digest(&self) -> [u8; 32] {
        self.profile_binding_digest
    }

    #[must_use]
    pub fn kdf_memory_kib(&self) -> u32 {
        self.kdf.memory_kib
    }

    #[must_use]
    pub fn kdf_passes(&self) -> u32 {
        self.kdf.passes
    }

    #[must_use]
    pub fn kdf_lanes(&self) -> u32 {
        self.kdf.lanes
    }

    #[must_use]
    pub fn kdf_output_len(&self) -> usize {
        self.kdf.output_len
    }
}

fn derive_kek(
    recovery_key: &RecoveryKey,
    kdf: &RecoveryKdf,
) -> Result<Zeroizing<[u8; 32]>, RecoveryBundleError> {
    kdf.validate()?;
    let params = Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(kdf.output_len))
        .map_err(|_| RecoveryBundleError::WeakKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(recovery_key.expose(), &kdf.salt, output.as_mut())
        .map_err(|_| RecoveryBundleError::Cryptography)?;
    Ok(output)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut output = [0_u8; N];
    OsRng.fill_bytes(&mut output);
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryBundleError {
    #[error("recovery bundle format version is unsupported")]
    UnsupportedVersion,
    #[error("recovery bundle encryption suite is unsupported")]
    UnsupportedEncryptionSuite,
    #[error("recovery bundle must contain personal participant 3")]
    WrongParticipant,
    #[error("recovery bundle does not match the supplied personal signer profile")]
    ProfileMismatch,
    #[error("recovery bundle KDF parameters are below the security floor")]
    WeakKdfParameters,
    #[error("recovery bundle exceeds its size limit")]
    BundleTooLarge,
    #[error("recovery bundle encoding is invalid")]
    InvalidEncoding,
    #[error("recovery bundle copy checksum does not match")]
    ChecksumMismatch,
    #[error("recovery bundle authentication failed")]
    AuthenticationFailed,
    #[error("recovered participant package is invalid")]
    InvalidSecretPackage,
    #[error("recovery bundle cryptography failed")]
    Cryptography,
}

#[cfg(test)]
mod tests {
    use catomicals_threshold::{PersonalSignerProfile, run_local_dkg};
    use uuid::Uuid;

    use super::*;

    fn fixture() -> (PersonalSignerProfile, PersonalParticipantSecretPackage) {
        let mut bootstrap = PersonalSignerProfile::bootstrap(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            9,
            run_local_dkg(3, 2).unwrap(),
        )
        .unwrap();
        let participant = bootstrap.secret_packages.remove(&3).unwrap();
        (bootstrap.profile, participant)
    }

    #[test]
    fn aad_authenticates_bundle_id_and_kdf_salt_even_with_recomputed_checksum() {
        let (profile, participant) = fixture();
        let (bundle, key) = RecoveryBundle::seal(participant, &profile).unwrap();

        let mut changed_id = bundle.clone();
        changed_id.bundle_id = Uuid::from_bytes([0x55; 16]);
        changed_id.checksum = changed_id.compute_checksum().unwrap();
        assert!(matches!(
            changed_id.open(&key, &profile),
            Err(RecoveryBundleError::AuthenticationFailed)
        ));

        let mut changed_salt = bundle;
        changed_salt.kdf.salt[0] ^= 1;
        changed_salt.checksum = changed_salt.compute_checksum().unwrap();
        assert!(matches!(
            changed_salt.open(&key, &profile),
            Err(RecoveryBundleError::AuthenticationFailed)
        ));
    }

    #[test]
    fn profile_identity_epoch_and_participant_tampering_fail_after_checksum_recompute() {
        let (profile, participant) = fixture();
        let (bundle, key) = RecoveryBundle::seal(participant, &profile).unwrap();

        let mut changed_profile = bundle.clone();
        changed_profile.profile_id = Uuid::from_bytes([0x66; 16]);
        changed_profile.checksum = changed_profile.compute_checksum().unwrap();
        assert!(matches!(
            changed_profile.open(&key, &profile),
            Err(RecoveryBundleError::ProfileMismatch)
        ));

        let mut changed_wallet = bundle.clone();
        changed_wallet.wallet_id = Uuid::from_bytes([0x67; 16]);
        changed_wallet.checksum = changed_wallet.compute_checksum().unwrap();
        assert!(matches!(
            changed_wallet.open(&key, &profile),
            Err(RecoveryBundleError::ProfileMismatch)
        ));

        let mut changed_signer_set = bundle.clone();
        changed_signer_set.signer_set_id = Uuid::from_bytes([0x68; 16]);
        changed_signer_set.checksum = changed_signer_set.compute_checksum().unwrap();
        assert!(matches!(
            changed_signer_set.open(&key, &profile),
            Err(RecoveryBundleError::ProfileMismatch)
        ));

        let mut changed_epoch = bundle.clone();
        changed_epoch.signer_epoch += 1;
        changed_epoch.checksum = changed_epoch.compute_checksum().unwrap();
        assert!(matches!(
            changed_epoch.open(&key, &profile),
            Err(RecoveryBundleError::ProfileMismatch)
        ));

        let mut changed_participant = bundle;
        changed_participant.participant_id = 2;
        changed_participant.checksum = changed_participant.compute_checksum().unwrap();
        assert!(matches!(
            changed_participant.open(&key, &profile),
            Err(RecoveryBundleError::WrongParticipant)
        ));
    }
}
