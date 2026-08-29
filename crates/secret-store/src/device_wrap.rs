use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInPlace, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::SecretValue;

const DEVICE_WRAPPED_PACKAGE_VERSION: u16 = 1;
const DEVICE_WRAPPED_PACKAGE_DOMAIN: &[u8] = b"catomicals/device-wrapped-package/v1\0";
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_WRAPPED_DEK_BYTES: usize = 16 * 1024;
const MAX_ENCODED_PACKAGE_BYTES: usize = 128 * 1024;
const DEK_BYTES: usize = 32;
const PAYLOAD_NONCE_BYTES: usize = 24;
const AEAD_TAG_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyProvider {
    MacosSecureEnclaveP256,
    IosSecureEnclaveP256,
    AndroidStrongboxP256,
}

impl DeviceKeyProvider {
    fn aad_tag(self) -> u8 {
        match self {
            Self::MacosSecureEnclaveP256 => 1,
            Self::IosSecureEnclaveP256 => 2,
            Self::AndroidStrongboxP256 => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyWrapAlgorithm {
    AppleEciesCofactorX963Sha256AesGcm,
    AndroidEciesHkdfSha256AesGcm,
}

impl DeviceKeyWrapAlgorithm {
    fn aad_tag(self) -> u8 {
        match self {
            Self::AppleEciesCofactorX963Sha256AesGcm => 1,
            Self::AndroidEciesHkdfSha256AesGcm => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceWrapBinding {
    provider: DeviceKeyProvider,
    algorithm: DeviceKeyWrapAlgorithm,
    key_id: String,
    profile_digest: [u8; 32],
    signer_id: u16,
    epoch: u64,
    device_generation: u64,
}

impl fmt::Debug for DeviceWrapBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceWrapBinding")
            .field("provider", &self.provider)
            .field("algorithm", &self.algorithm)
            .field("key_id", &"[REDACTED]")
            .field("profile_digest", &"[REDACTED]")
            .field("signer_id", &self.signer_id)
            .field("epoch", &self.epoch)
            .field("device_generation", &self.device_generation)
            .finish()
    }
}

impl DeviceWrapBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: DeviceKeyProvider,
        algorithm: DeviceKeyWrapAlgorithm,
        key_id: impl Into<String>,
        profile_digest: [u8; 32],
        signer_id: u16,
        epoch: u64,
        device_generation: u64,
    ) -> Result<Self, DeviceWrapError> {
        let binding = Self {
            provider,
            algorithm,
            key_id: key_id.into(),
            profile_digest,
            signer_id,
            epoch,
            device_generation,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn provider(&self) -> DeviceKeyProvider {
        self.provider
    }

    pub fn algorithm(&self) -> DeviceKeyWrapAlgorithm {
        self.algorithm
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    pub fn signer_id(&self) -> u16 {
        self.signer_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn device_generation(&self) -> u64 {
        self.device_generation
    }

    fn validate(&self) -> Result<(), DeviceWrapError> {
        if self.key_id.is_empty()
            || self.key_id.len() > MAX_KEY_ID_BYTES
            || self.key_id.chars().any(char::is_control)
        {
            return Err(DeviceWrapError::InvalidBinding);
        }
        if self.signer_id == 0 || self.epoch == 0 || self.device_generation == 0 {
            return Err(DeviceWrapError::InvalidBinding);
        }
        Ok(())
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(96 + self.key_id.len());
        aad.extend_from_slice(DEVICE_WRAPPED_PACKAGE_DOMAIN);
        aad.extend_from_slice(&DEVICE_WRAPPED_PACKAGE_VERSION.to_be_bytes());
        aad.push(self.provider.aad_tag());
        aad.push(self.algorithm.aad_tag());
        aad.extend_from_slice(&(self.key_id.len() as u16).to_be_bytes());
        aad.extend_from_slice(self.key_id.as_bytes());
        aad.extend_from_slice(&self.profile_digest);
        aad.extend_from_slice(&self.signer_id.to_be_bytes());
        aad.extend_from_slice(&self.epoch.to_be_bytes());
        aad.extend_from_slice(&self.device_generation.to_be_bytes());
        aad
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceKeyProtectionError {
    #[error("device key protection is unsupported on this platform")]
    Unsupported,
    #[error("device key is unavailable")]
    KeyUnavailable,
    #[error("device key authorization was cancelled")]
    AuthorizationCancelled,
    #[error("device key operation failed")]
    OperationFailed,
}

pub trait DeviceKeyProtector: Send + Sync {
    fn provider(&self) -> DeviceKeyProvider;
    fn algorithm(&self) -> DeviceKeyWrapAlgorithm;
    fn key_id(&self) -> &str;
    fn wrap_dek(&self, dek: SecretValue) -> Result<Vec<u8>, DeviceKeyProtectionError>;
    fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceWrapError {
    #[error("device wrap binding is invalid")]
    InvalidBinding,
    #[error("device wrap binding does not match the expected participant")]
    BindingMismatch,
    #[error("participant package exceeds the device wrapping size limit")]
    PlaintextTooLarge,
    #[error("device wrapped package exceeds its size limit")]
    PackageTooLarge,
    #[error("device wrapped package encoding is invalid")]
    InvalidEncoding,
    #[error("device wrapped package version is unsupported")]
    UnsupportedVersion,
    #[error("device key protector does not match the package binding")]
    ProtectorMismatch,
    #[error("device key protection failed")]
    KeyProtectionFailed,
    #[error("device wrapped package failed authentication")]
    AuthenticationFailed,
}

pub struct DeviceWrappedPackageV1 {
    binding: DeviceWrapBinding,
    payload_nonce: [u8; PAYLOAD_NONCE_BYTES],
    ciphertext: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

impl fmt::Debug for DeviceWrappedPackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceWrappedPackageV1([REDACTED])")
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceWrappedPackageRef<'a> {
    version: u16,
    provider: DeviceKeyProvider,
    algorithm: DeviceKeyWrapAlgorithm,
    key_id: &'a str,
    profile_digest: [u8; 32],
    signer_id: u16,
    epoch: u64,
    device_generation: u64,
    payload_nonce: String,
    ciphertext: String,
    wrapped_dek: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceWrappedPackageOwned {
    version: u16,
    provider: DeviceKeyProvider,
    algorithm: DeviceKeyWrapAlgorithm,
    key_id: String,
    profile_digest: [u8; 32],
    signer_id: u16,
    epoch: u64,
    device_generation: u64,
    payload_nonce: String,
    ciphertext: String,
    wrapped_dek: String,
}

impl DeviceWrappedPackageV1 {
    pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;

    pub fn seal(
        plaintext: SecretValue,
        binding: DeviceWrapBinding,
        protector: &dyn DeviceKeyProtector,
    ) -> Result<Self, DeviceWrapError> {
        binding.validate()?;
        validate_protector(&binding, protector)?;
        if plaintext.expose().len() > Self::MAX_PLAINTEXT_BYTES {
            return Err(DeviceWrapError::PlaintextTooLarge);
        }

        let mut dek = Zeroizing::new(vec![0u8; DEK_BYTES]);
        OsRng.fill_bytes(dek.as_mut_slice());
        let mut payload_nonce = [0u8; PAYLOAD_NONCE_BYTES];
        OsRng.fill_bytes(&mut payload_nonce);
        let aad = binding.aad();
        let ciphertext = XChaCha20Poly1305::new_from_slice(dek.as_slice())
            .map_err(|_| DeviceWrapError::AuthenticationFailed)?
            .encrypt(
                &XNonce::from(payload_nonce),
                Payload {
                    msg: plaintext.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| DeviceWrapError::AuthenticationFailed)?;

        let wrapped_dek = protector
            .wrap_dek(SecretValue::new(core::mem::take(&mut *dek)))
            .map_err(|_| DeviceWrapError::KeyProtectionFailed)?;
        if wrapped_dek.is_empty() || wrapped_dek.len() > MAX_WRAPPED_DEK_BYTES {
            return Err(DeviceWrapError::KeyProtectionFailed);
        }
        Ok(Self {
            binding,
            payload_nonce,
            ciphertext,
            wrapped_dek,
        })
    }

    pub fn binding(&self) -> &DeviceWrapBinding {
        &self.binding
    }

    pub fn open(
        &self,
        expected: &DeviceWrapBinding,
        protector: &dyn DeviceKeyProtector,
    ) -> Result<SecretValue, DeviceWrapError> {
        self.validate()?;
        expected.validate()?;
        if &self.binding != expected {
            return Err(DeviceWrapError::BindingMismatch);
        }
        validate_protector(expected, protector)?;
        let dek = protector
            .unwrap_dek(&self.wrapped_dek)
            .map_err(|_| DeviceWrapError::KeyProtectionFailed)?;
        if dek.expose().len() != DEK_BYTES {
            return Err(DeviceWrapError::KeyProtectionFailed);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(dek.expose())
            .map_err(|_| DeviceWrapError::AuthenticationFailed)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        cipher
            .decrypt_in_place(
                &XNonce::from(self.payload_nonce),
                &expected.aad(),
                &mut *plaintext,
            )
            .map_err(|_| DeviceWrapError::AuthenticationFailed)?;
        Ok(SecretValue::new(core::mem::take(&mut *plaintext)))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DeviceWrapError> {
        self.validate()?;
        let wire = DeviceWrappedPackageRef {
            version: DEVICE_WRAPPED_PACKAGE_VERSION,
            provider: self.binding.provider,
            algorithm: self.binding.algorithm,
            key_id: &self.binding.key_id,
            profile_digest: self.binding.profile_digest,
            signer_id: self.binding.signer_id,
            epoch: self.binding.epoch,
            device_generation: self.binding.device_generation,
            payload_nonce: STANDARD_NO_PAD.encode(self.payload_nonce),
            ciphertext: STANDARD_NO_PAD.encode(&self.ciphertext),
            wrapped_dek: STANDARD_NO_PAD.encode(&self.wrapped_dek),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| DeviceWrapError::InvalidEncoding)?;
        if bytes.len() > MAX_ENCODED_PACKAGE_BYTES {
            return Err(DeviceWrapError::PackageTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceWrapError> {
        if bytes.len() > MAX_ENCODED_PACKAGE_BYTES {
            return Err(DeviceWrapError::PackageTooLarge);
        }
        let wire: DeviceWrappedPackageOwned =
            serde_json::from_slice(bytes).map_err(|_| DeviceWrapError::InvalidEncoding)?;
        if wire.version != DEVICE_WRAPPED_PACKAGE_VERSION {
            return Err(DeviceWrapError::UnsupportedVersion);
        }
        let binding = DeviceWrapBinding::new(
            wire.provider,
            wire.algorithm,
            wire.key_id,
            wire.profile_digest,
            wire.signer_id,
            wire.epoch,
            wire.device_generation,
        )?;
        let nonce = STANDARD_NO_PAD
            .decode(wire.payload_nonce)
            .map_err(|_| DeviceWrapError::InvalidEncoding)?;
        let payload_nonce: [u8; PAYLOAD_NONCE_BYTES] = nonce
            .try_into()
            .map_err(|_| DeviceWrapError::InvalidEncoding)?;
        let ciphertext = STANDARD_NO_PAD
            .decode(wire.ciphertext)
            .map_err(|_| DeviceWrapError::InvalidEncoding)?;
        let wrapped_dek = STANDARD_NO_PAD
            .decode(wire.wrapped_dek)
            .map_err(|_| DeviceWrapError::InvalidEncoding)?;
        let package = Self {
            binding,
            payload_nonce,
            ciphertext,
            wrapped_dek,
        };
        package.validate()?;
        Ok(package)
    }

    fn validate(&self) -> Result<(), DeviceWrapError> {
        self.binding.validate()?;
        if self.ciphertext.len() < AEAD_TAG_BYTES
            || self.ciphertext.len() > Self::MAX_PLAINTEXT_BYTES + AEAD_TAG_BYTES
            || self.wrapped_dek.is_empty()
            || self.wrapped_dek.len() > MAX_WRAPPED_DEK_BYTES
        {
            return Err(DeviceWrapError::InvalidEncoding);
        }
        Ok(())
    }
}

fn validate_protector(
    binding: &DeviceWrapBinding,
    protector: &dyn DeviceKeyProtector,
) -> Result<(), DeviceWrapError> {
    if binding.provider != protector.provider()
        || binding.algorithm != protector.algorithm()
        || binding.key_id != protector.key_id()
    {
        return Err(DeviceWrapError::ProtectorMismatch);
    }
    Ok(())
}
