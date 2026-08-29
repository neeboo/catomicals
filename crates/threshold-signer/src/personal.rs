//! Versioned package contract for a personal 2-of-3 signer set.
//!
//! This module deliberately stops at an in-memory package boundary. Storage,
//! device wrapping, 1Password access and transport belong to application
//! layers. A [`PersonalParticipantSecretPackage`] can be wrapped there without
//! exposing its FROST key package through `Debug` or an unbounded encoder.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    LocalDkgOutput, LocalFrostParticipant, NonceGuard, group_pubkey_xonly, participant_identifier,
};

pub const PERSONAL_PROFILE_FORMAT_VERSION: u16 = 1;
pub const PERSONAL_SECRET_PACKAGE_FORMAT_VERSION: u16 = 1;
pub const PERSONAL_PROFILE_MAX_BYTES: usize = 64 * 1024;
pub const PERSONAL_SECRET_PACKAGE_MAX_BYTES: usize = 64 * 1024;

const PERSONAL_MIN_SIGNERS: u16 = 2;
const PERSONAL_MAX_SIGNERS: u16 = 3;
const PROFILE_BINDING_DOMAIN: &[u8] = b"catomicals/personal-signer-profile/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalParticipantRole {
    WalletNode,
    DesktopOnePassword,
    PhoneRecovery,
}

impl PersonalParticipantRole {
    fn for_signer(signer_id: u16) -> Result<Self, PersonalProfileError> {
        match signer_id {
            1 => Ok(Self::WalletNode),
            2 => Ok(Self::DesktopOnePassword),
            3 => Ok(Self::PhoneRecovery),
            _ => Err(PersonalProfileError::InvalidParticipantInventory),
        }
    }

    fn binding_tag(self) -> u8 {
        match self {
            Self::WalletNode => 1,
            Self::DesktopOnePassword => 2,
            Self::PhoneRecovery => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalParticipantDescriptor {
    pub signer_id: u16,
    pub role: PersonalParticipantRole,
    pub identifier_hex: String,
    pub verifying_share_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalSignerProfile {
    format_version: u16,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: [u8; 32],
    public_key_package: Vec<u8>,
    participants: Vec<PersonalParticipantDescriptor>,
}

pub struct PersonalSignerBootstrap {
    pub profile: PersonalSignerProfile,
    pub secret_packages: BTreeMap<u16, PersonalParticipantSecretPackage>,
}

impl core::fmt::Debug for PersonalSignerBootstrap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersonalSignerBootstrap")
            .field("profile", &self.profile)
            .field(
                "secret_packages",
                &format_args!("<{} redacted packages>", self.secret_packages.len()),
            )
            .finish()
    }
}

pub struct PersonalParticipantSecretPackage {
    format_version: u16,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    signer_id: u16,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: [u8; 32],
    profile_binding_digest: [u8; 32],
    key_package: Zeroizing<Vec<u8>>,
}

/// A validated, short-lived FROST key package.
///
/// The inner key cannot be extracted directly. Consumers move it into a
/// [`LocalFrostParticipant`], whose drop implementation also erases the key.
/// Dropping this wrapper before consumption erases the key here.
pub struct OpenedPersonalKeyPackage {
    signer_id: u16,
    key_package: Option<KeyPackage>,
}

impl core::fmt::Debug for OpenedPersonalKeyPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedPersonalKeyPackage")
            .field("signer_id", &self.signer_id)
            .field("key_package", &"<redacted>")
            .finish()
    }
}

impl Drop for OpenedPersonalKeyPackage {
    fn drop(&mut self) {
        if let Some(key_package) = self.key_package.as_mut() {
            key_package.zeroize();
        }
    }
}

impl OpenedPersonalKeyPackage {
    pub fn signer_id(&self) -> u16 {
        self.signer_id
    }

    pub fn into_participant(
        mut self,
        nonce_guard: NonceGuard,
    ) -> Result<LocalFrostParticipant, PersonalProfileError> {
        let key_package = self
            .key_package
            .take()
            .ok_or(PersonalProfileError::InvalidKeyPackage)?;
        LocalFrostParticipant::new(self.signer_id, key_package, nonce_guard)
            .map_err(|_| PersonalProfileError::InvalidKeyPackage)
    }
}

impl core::fmt::Debug for PersonalParticipantSecretPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersonalParticipantSecretPackage")
            .field("format_version", &self.format_version)
            .field("profile_id", &self.profile_id)
            .field("wallet_id", &self.wallet_id)
            .field("signer_set_id", &self.signer_set_id)
            .field("signer_epoch", &self.signer_epoch)
            .field("signer_id", &self.signer_id)
            .field("min_signers", &self.min_signers)
            .field("max_signers", &self.max_signers)
            .field("group_pubkey_xonly", &self.group_pubkey_xonly)
            .field("profile_binding_digest", &self.profile_binding_digest)
            .field("key_package", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SecretPackageRef<'a> {
    format_version: u16,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    signer_id: u16,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: [u8; 32],
    profile_binding_digest: [u8; 32],
    key_package: &'a [u8],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPackageOwned {
    format_version: u16,
    profile_id: Uuid,
    wallet_id: Uuid,
    signer_set_id: Uuid,
    signer_epoch: u64,
    signer_id: u16,
    min_signers: u16,
    max_signers: u16,
    group_pubkey_xonly: [u8; 32],
    profile_binding_digest: [u8; 32],
    key_package: Vec<u8>,
}

impl Drop for SecretPackageOwned {
    fn drop(&mut self) {
        self.key_package.zeroize();
    }
}

impl PersonalSignerProfile {
    pub fn bootstrap(
        profile_id: Uuid,
        wallet_id: Uuid,
        signer_set_id: Uuid,
        signer_epoch: u64,
        dkg: LocalDkgOutput,
    ) -> Result<PersonalSignerBootstrap, PersonalProfileError> {
        let LocalDkgOutput {
            min_signers,
            max_signers,
            mut key_packages,
            public_key_package: dkg_public_key_package,
        } = dkg;
        if signer_epoch == 0 {
            zeroize_key_packages(&mut key_packages);
            return Err(PersonalProfileError::InvalidEpoch);
        }
        if min_signers != PERSONAL_MIN_SIGNERS
            || max_signers != PERSONAL_MAX_SIGNERS
            || key_packages.len() != usize::from(PERSONAL_MAX_SIGNERS)
        {
            zeroize_key_packages(&mut key_packages);
            return Err(PersonalProfileError::InvalidThreshold);
        }

        let public_key_package = match dkg_public_key_package.serialize() {
            Ok(package) => package,
            Err(_) => {
                zeroize_key_packages(&mut key_packages);
                return Err(PersonalProfileError::InvalidPublicPackage);
            }
        };
        let group_pubkey_xonly = match group_pubkey_xonly(&dkg_public_key_package) {
            Ok(group) => group,
            Err(_) => {
                zeroize_key_packages(&mut key_packages);
                return Err(PersonalProfileError::InvalidPublicPackage);
            }
        };
        let participants = match participant_descriptors(&dkg_public_key_package) {
            Ok(participants) => participants,
            Err(error) => {
                zeroize_key_packages(&mut key_packages);
                return Err(error);
            }
        };
        let profile = Self {
            format_version: PERSONAL_PROFILE_FORMAT_VERSION,
            profile_id,
            wallet_id,
            signer_set_id,
            signer_epoch,
            min_signers,
            max_signers,
            group_pubkey_xonly,
            public_key_package,
            participants,
        };
        if let Err(error) = profile.validate() {
            zeroize_key_packages(&mut key_packages);
            return Err(error);
        }
        let profile_binding_digest = profile.binding_digest();

        let mut secret_packages = BTreeMap::new();
        for signer_id in 1..=PERSONAL_MAX_SIGNERS {
            let identifier = match participant_identifier(signer_id) {
                Ok(identifier) => identifier,
                Err(_) => {
                    zeroize_key_packages(&mut key_packages);
                    return Err(PersonalProfileError::InvalidParticipantInventory);
                }
            };
            let key_package = match key_packages.remove(&identifier) {
                Some(key_package) => key_package,
                None => {
                    zeroize_key_packages(&mut key_packages);
                    return Err(PersonalProfileError::InvalidParticipantInventory);
                }
            };
            let key_package = match validate_serialize_and_zeroize_key_package(
                key_package,
                signer_id,
                &profile,
            ) {
                Ok(key_package) => key_package,
                Err(error) => {
                    zeroize_key_packages(&mut key_packages);
                    return Err(error);
                }
            };
            let package = PersonalParticipantSecretPackage {
                format_version: PERSONAL_SECRET_PACKAGE_FORMAT_VERSION,
                profile_id,
                wallet_id,
                signer_set_id,
                signer_epoch,
                signer_id,
                min_signers: profile.min_signers,
                max_signers: profile.max_signers,
                group_pubkey_xonly,
                profile_binding_digest,
                key_package,
            };
            secret_packages.insert(signer_id, package);
        }
        if !key_packages.is_empty() {
            zeroize_key_packages(&mut key_packages);
            return Err(PersonalProfileError::InvalidParticipantInventory);
        }

        Ok(PersonalSignerBootstrap {
            profile,
            secret_packages,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PersonalProfileError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| PersonalProfileError::Encoding)?;
        if bytes.len() > PERSONAL_PROFILE_MAX_BYTES {
            return Err(PersonalProfileError::PackageTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PersonalProfileError> {
        if bytes.len() > PERSONAL_PROFILE_MAX_BYTES {
            return Err(PersonalProfileError::PackageTooLarge);
        }
        let profile: Self =
            serde_json::from_slice(bytes).map_err(|_| PersonalProfileError::Encoding)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_BINDING_DOMAIN);
        hasher.update(self.format_version.to_be_bytes());
        hasher.update(self.profile_id.as_bytes());
        hasher.update(self.wallet_id.as_bytes());
        hasher.update(self.signer_set_id.as_bytes());
        hasher.update(self.signer_epoch.to_be_bytes());
        hasher.update(self.min_signers.to_be_bytes());
        hasher.update(self.max_signers.to_be_bytes());
        hasher.update(self.group_pubkey_xonly);
        update_len_prefixed(&mut hasher, &self.public_key_package);
        hasher.update((self.participants.len() as u64).to_be_bytes());
        for participant in &self.participants {
            hasher.update(participant.signer_id.to_be_bytes());
            hasher.update([participant.role.binding_tag()]);
            update_len_prefixed(&mut hasher, participant.identifier_hex.as_bytes());
            hasher.update(participant.verifying_share_digest);
        }
        hasher.finalize().into()
    }

    pub fn public_key_package(&self) -> Result<PublicKeyPackage, PersonalProfileError> {
        PublicKeyPackage::deserialize(&self.public_key_package)
            .map_err(|_| PersonalProfileError::InvalidPublicPackage)
    }

    pub fn profile_id(&self) -> Uuid {
        self.profile_id
    }

    pub fn wallet_id(&self) -> Uuid {
        self.wallet_id
    }

    pub fn signer_set_id(&self) -> Uuid {
        self.signer_set_id
    }

    pub fn signer_epoch(&self) -> u64 {
        self.signer_epoch
    }

    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }

    pub fn group_pubkey_xonly(&self) -> [u8; 32] {
        self.group_pubkey_xonly
    }

    pub fn participants(&self) -> &[PersonalParticipantDescriptor] {
        &self.participants
    }

    fn validate(&self) -> Result<(), PersonalProfileError> {
        if self.format_version != PERSONAL_PROFILE_FORMAT_VERSION {
            return Err(PersonalProfileError::UnsupportedVersion);
        }
        if self.signer_epoch == 0 {
            return Err(PersonalProfileError::InvalidEpoch);
        }
        if self.min_signers != PERSONAL_MIN_SIGNERS || self.max_signers != PERSONAL_MAX_SIGNERS {
            return Err(PersonalProfileError::InvalidThreshold);
        }
        if self.public_key_package.len() > PERSONAL_PROFILE_MAX_BYTES {
            return Err(PersonalProfileError::PackageTooLarge);
        }
        let public = self.public_key_package()?;
        if public.verifying_shares().len() != usize::from(self.max_signers)
            || group_pubkey_xonly(&public)
                .map_err(|_| PersonalProfileError::InvalidPublicPackage)?
                != self.group_pubkey_xonly
        {
            return Err(PersonalProfileError::InvalidPublicPackage);
        }
        let expected = participant_descriptors(&public)?;
        if expected != self.participants {
            return Err(PersonalProfileError::InvalidParticipantInventory);
        }
        Ok(())
    }
}

impl PersonalParticipantSecretPackage {
    pub fn signer_id(&self) -> u16 {
        self.signer_id
    }

    pub fn profile_binding_digest(&self) -> [u8; 32] {
        self.profile_binding_digest
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, PersonalProfileError> {
        let wire = SecretPackageRef {
            format_version: self.format_version,
            profile_id: self.profile_id,
            wallet_id: self.wallet_id,
            signer_set_id: self.signer_set_id,
            signer_epoch: self.signer_epoch,
            signer_id: self.signer_id,
            min_signers: self.min_signers,
            max_signers: self.max_signers,
            group_pubkey_xonly: self.group_pubkey_xonly,
            profile_binding_digest: self.profile_binding_digest,
            key_package: &self.key_package,
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| PersonalProfileError::Encoding)?);
        if bytes.len() > PERSONAL_SECRET_PACKAGE_MAX_BYTES {
            return Err(PersonalProfileError::PackageTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(
        bytes: &[u8],
        profile: &PersonalSignerProfile,
    ) -> Result<Self, PersonalProfileError> {
        if bytes.len() > PERSONAL_SECRET_PACKAGE_MAX_BYTES {
            return Err(PersonalProfileError::PackageTooLarge);
        }
        let mut wire: SecretPackageOwned =
            serde_json::from_slice(bytes).map_err(|_| PersonalProfileError::Encoding)?;
        if wire.format_version != PERSONAL_SECRET_PACKAGE_FORMAT_VERSION {
            return Err(PersonalProfileError::UnsupportedVersion);
        }
        if wire.signer_epoch == 0 {
            return Err(PersonalProfileError::InvalidEpoch);
        }
        if wire.min_signers != PERSONAL_MIN_SIGNERS || wire.max_signers != PERSONAL_MAX_SIGNERS {
            return Err(PersonalProfileError::InvalidThreshold);
        }
        if !(1..=PERSONAL_MAX_SIGNERS).contains(&wire.signer_id) {
            return Err(PersonalProfileError::ParticipantMismatch);
        }
        let package = Self {
            format_version: wire.format_version,
            profile_id: wire.profile_id,
            wallet_id: wire.wallet_id,
            signer_set_id: wire.signer_set_id,
            signer_epoch: wire.signer_epoch,
            signer_id: wire.signer_id,
            min_signers: wire.min_signers,
            max_signers: wire.max_signers,
            group_pubkey_xonly: wire.group_pubkey_xonly,
            profile_binding_digest: wire.profile_binding_digest,
            key_package: Zeroizing::new(core::mem::take(&mut wire.key_package)),
        };
        package.open(profile)?;
        Ok(package)
    }

    pub fn validate(&self, profile: &PersonalSignerProfile) -> Result<(), PersonalProfileError> {
        self.open(profile).map(drop)
    }

    pub fn open(
        &self,
        profile: &PersonalSignerProfile,
    ) -> Result<OpenedPersonalKeyPackage, PersonalProfileError> {
        profile.validate()?;
        if self.format_version != PERSONAL_SECRET_PACKAGE_FORMAT_VERSION {
            return Err(PersonalProfileError::UnsupportedVersion);
        }
        if self.profile_id != profile.profile_id
            || self.wallet_id != profile.wallet_id
            || self.signer_set_id != profile.signer_set_id
            || self.signer_epoch != profile.signer_epoch
            || self.min_signers != profile.min_signers
            || self.max_signers != profile.max_signers
            || self.group_pubkey_xonly != profile.group_pubkey_xonly
            || self.profile_binding_digest != profile.binding_digest()
        {
            return Err(PersonalProfileError::ProfileBindingMismatch);
        }
        let identifier = participant_identifier(self.signer_id)
            .map_err(|_| PersonalProfileError::ParticipantMismatch)?;
        if profile
            .participants
            .iter()
            .all(|participant| participant.signer_id != self.signer_id)
        {
            return Err(PersonalProfileError::ParticipantMismatch);
        }
        let mut key_package = KeyPackage::deserialize(&self.key_package)
            .map_err(|_| PersonalProfileError::InvalidKeyPackage)?;
        if validate_key_package(&key_package, identifier, profile).is_err() {
            key_package.zeroize();
            return Err(PersonalProfileError::KeyPackageMismatch);
        }
        Ok(OpenedPersonalKeyPackage {
            signer_id: self.signer_id,
            key_package: Some(key_package),
        })
    }
}

fn validate_serialize_and_zeroize_key_package(
    mut key_package: KeyPackage,
    signer_id: u16,
    profile: &PersonalSignerProfile,
) -> Result<Zeroizing<Vec<u8>>, PersonalProfileError> {
    let result = participant_identifier(signer_id)
        .map_err(|_| PersonalProfileError::ParticipantMismatch)
        .and_then(|identifier| validate_key_package(&key_package, identifier, profile))
        .and_then(|()| {
            key_package
                .serialize()
                .map(Zeroizing::new)
                .map_err(|_| PersonalProfileError::InvalidKeyPackage)
        });
    key_package.zeroize();
    result
}

fn zeroize_key_packages(key_packages: &mut BTreeMap<Identifier, KeyPackage>) {
    for key_package in key_packages.values_mut() {
        key_package.zeroize();
    }
    key_packages.clear();
}

fn validate_key_package(
    key_package: &KeyPackage,
    identifier: Identifier,
    profile: &PersonalSignerProfile,
) -> Result<(), PersonalProfileError> {
    let public = profile.public_key_package()?;
    if key_package.identifier() != &identifier
        || *key_package.min_signers() != profile.min_signers
        || key_package.verifying_key() != public.verifying_key()
        || public.verifying_shares().get(&identifier) != Some(key_package.verifying_share())
    {
        return Err(PersonalProfileError::KeyPackageMismatch);
    }
    Ok(())
}

fn participant_descriptors(
    public: &PublicKeyPackage,
) -> Result<Vec<PersonalParticipantDescriptor>, PersonalProfileError> {
    if public.verifying_shares().len() != usize::from(PERSONAL_MAX_SIGNERS) {
        return Err(PersonalProfileError::InvalidParticipantInventory);
    }
    let mut participants = Vec::with_capacity(usize::from(PERSONAL_MAX_SIGNERS));
    for signer_id in 1..=PERSONAL_MAX_SIGNERS {
        let identifier = participant_identifier(signer_id)
            .map_err(|_| PersonalProfileError::InvalidParticipantInventory)?;
        let verifying_share = public
            .verifying_shares()
            .get(&identifier)
            .ok_or(PersonalProfileError::InvalidParticipantInventory)?;
        let verifying_share = verifying_share
            .serialize()
            .map_err(|_| PersonalProfileError::InvalidPublicPackage)?;
        participants.push(PersonalParticipantDescriptor {
            signer_id,
            role: PersonalParticipantRole::for_signer(signer_id)?,
            identifier_hex: hex::encode(identifier.serialize()),
            verifying_share_digest: Sha256::digest(verifying_share).into(),
        });
    }
    Ok(participants)
}

fn update_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PersonalProfileError {
    #[error("personal signer package version is unsupported")]
    UnsupportedVersion,
    #[error("personal signer epoch is invalid")]
    InvalidEpoch,
    #[error("personal signer profile must be 2-of-3")]
    InvalidThreshold,
    #[error("personal signer participant inventory is invalid")]
    InvalidParticipantInventory,
    #[error("personal signer public package is invalid")]
    InvalidPublicPackage,
    #[error("personal signer key package is invalid")]
    InvalidKeyPackage,
    #[error("personal signer package exceeds its size limit")]
    PackageTooLarge,
    #[error("personal signer package encoding is invalid")]
    Encoding,
    #[error("participant package belongs to a different public profile")]
    ProfileBindingMismatch,
    #[error("participant package signer identity is invalid")]
    ParticipantMismatch,
    #[error("participant key package does not match the public profile")]
    KeyPackageMismatch,
}
