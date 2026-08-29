use core::fmt;

use core_foundation::{
    base::{CFType, TCFType, ToVoid},
    number::CFNumber,
    string::CFString,
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};
use security_framework_sys::{
    access_control::{kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence},
    base::errSecItemNotFound,
    item::{
        kSecAttrAccessControl, kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits,
        kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave,
    },
};

use crate::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    SecretValue,
};

const DEK_BYTES: usize = 32;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_WRAPPED_DEK_BYTES: usize = 16 * 1024;
const KEY_SIZE_BITS: u32 = 256;
const ERR_SEC_USER_CANCELED: isize = -128;

/// A non-exportable P-256 key in the macOS Secure Enclave.
///
/// Creation uses the Data Protection Keychain and binds private-key use to
/// `AccessibleWhenUnlockedThisDeviceOnly`, user presence and private-key use.
/// The host must be codesigned with the appropriate keychain access-group
/// entitlement. There is no software-key fallback.
pub struct MacosSecureEnclaveProtector {
    key_id: String,
    private_key: SecKey,
    public_key: SecKey,
}

impl fmt::Debug for MacosSecureEnclaveProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSecureEnclaveProtector")
            .field("key_id", &"[REDACTED]")
            .field("provider", &DeviceKeyProvider::MacosSecureEnclaveP256)
            .finish_non_exhaustive()
    }
}

impl MacosSecureEnclaveProtector {
    pub fn create(key_id: impl Into<String>) -> Result<Self, DeviceKeyProtectionError> {
        let key_id = validate_key_id(key_id.into())?;
        match Self::open(&key_id) {
            Ok(_) => return Err(DeviceKeyProtectionError::KeyAlreadyExists),
            Err(DeviceKeyProtectionError::KeyUnavailable) => {}
            Err(error) => return Err(error),
        }

        let access_control = required_access_control()?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(KEY_SIZE_BITS)
            .set_label(&key_id)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access_control);
        let private_key =
            SecKey::new(&options).map_err(|error| map_key_operation_error_code(error.code()))?;
        Self::from_private_key(key_id, private_key)
    }

    pub fn open(key_id: impl Into<String>) -> Result<Self, DeviceKeyProtectionError> {
        let key_id = validate_key_id(key_id.into())?;
        let result = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .label(&key_id)
            .ignore_legacy_keychains()
            .load_refs(true)
            .limit(2)
            .search();
        let results = match result {
            Ok(results) => results,
            Err(error) if error.code() == errSecItemNotFound => {
                return Err(DeviceKeyProtectionError::KeyUnavailable);
            }
            Err(error) => {
                return Err(map_key_operation_error_code(error.code() as isize));
            }
        };
        let mut keys = results.into_iter().filter_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        });
        let private_key = keys
            .next()
            .ok_or(DeviceKeyProtectionError::KeyUnavailable)?;
        if keys.next().is_some() {
            return Err(DeviceKeyProtectionError::OperationFailed);
        }
        Self::from_private_key(key_id, private_key)
    }

    fn from_private_key(
        key_id: String,
        private_key: SecKey,
    ) -> Result<Self, DeviceKeyProtectionError> {
        require_secure_enclave_key(&private_key)?;
        let public_key = private_key
            .public_key()
            .ok_or(DeviceKeyProtectionError::OperationFailed)?;
        Ok(Self {
            key_id,
            private_key,
            public_key,
        })
    }
}

fn require_secure_enclave_key(key: &SecKey) -> Result<(), DeviceKeyProtectionError> {
    let attributes = key.attributes();
    let token = string_attribute(&attributes, unsafe { kSecAttrTokenID.to_void() })?;
    let secure_enclave = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
    let key_class = string_attribute(&attributes, unsafe { kSecAttrKeyClass.to_void() })?;
    let private_key_class = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate) };
    let key_type = string_attribute(&attributes, unsafe { kSecAttrKeyType.to_void() })?;
    let ec_sec_prime_random =
        unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
    let key_size = number_attribute(&attributes, unsafe { kSecAttrKeySizeInBits.to_void() })?;
    let access_control = cf_attribute(&attributes, unsafe { kSecAttrAccessControl.to_void() })?;
    if token != secure_enclave
        || key_class != private_key_class
        || key_type != ec_sec_prime_random
        || key_size != i64::from(KEY_SIZE_BITS)
        || key.external_representation().is_some()
    {
        return Err(DeviceKeyProtectionError::PolicyMismatch);
    }
    validate_access_control_policy(&access_control)
}

fn string_attribute(
    attributes: &core_foundation::dictionary::CFDictionary,
    key: *const core::ffi::c_void,
) -> Result<CFString, DeviceKeyProtectionError> {
    let value = cf_attribute(attributes, key)?;
    if !value.instance_of::<CFString>() {
        return Err(DeviceKeyProtectionError::PolicyMismatch);
    }
    Ok(unsafe { CFString::wrap_under_get_rule(value.as_CFTypeRef().cast()) })
}

fn number_attribute(
    attributes: &core_foundation::dictionary::CFDictionary,
    key: *const core::ffi::c_void,
) -> Result<i64, DeviceKeyProtectionError> {
    let value = cf_attribute(attributes, key)?;
    if !value.instance_of::<CFNumber>() {
        return Err(DeviceKeyProtectionError::PolicyMismatch);
    }
    unsafe { CFNumber::wrap_under_get_rule(value.as_CFTypeRef().cast()) }
        .to_i64()
        .ok_or(DeviceKeyProtectionError::PolicyMismatch)
}

fn cf_attribute(
    attributes: &core_foundation::dictionary::CFDictionary,
    key: *const core::ffi::c_void,
) -> Result<CFType, DeviceKeyProtectionError> {
    attributes
        .find(key)
        .map(|value| unsafe { CFType::wrap_under_get_rule(value.cast()) })
        .ok_or(DeviceKeyProtectionError::PolicyMismatch)
}

fn required_access_control() -> Result<SecAccessControl, DeviceKeyProtectionError> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence | kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|error| map_key_operation_error_code(error.code() as isize))
}

fn validate_access_control_policy(actual: &CFType) -> Result<(), DeviceKeyProtectionError> {
    let expected = required_access_control()?.as_CFType();
    if actual != &expected {
        return Err(DeviceKeyProtectionError::PolicyMismatch);
    }
    Ok(())
}

fn map_key_operation_error_code(code: isize) -> DeviceKeyProtectionError {
    if code == ERR_SEC_USER_CANCELED {
        DeviceKeyProtectionError::AuthorizationCancelled
    } else {
        DeviceKeyProtectionError::OperationFailed
    }
}

impl DeviceKeyProtector for MacosSecureEnclaveProtector {
    fn provider(&self) -> DeviceKeyProvider {
        DeviceKeyProvider::MacosSecureEnclaveP256
    }

    fn algorithm(&self) -> DeviceKeyWrapAlgorithm {
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_dek(&self, dek: SecretValue) -> Result<Vec<u8>, DeviceKeyProtectionError> {
        if dek.expose().len() != DEK_BYTES {
            return Err(DeviceKeyProtectionError::OperationFailed);
        }
        let wrapped = self
            .public_key
            .encrypt_data(
                Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                dek.expose(),
            )
            .map_err(|error| map_key_operation_error_code(error.code()))?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_DEK_BYTES {
            return Err(DeviceKeyProtectionError::OperationFailed);
        }
        Ok(wrapped)
    }

    fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError> {
        if wrapped_dek.is_empty() || wrapped_dek.len() > MAX_WRAPPED_DEK_BYTES {
            return Err(DeviceKeyProtectionError::OperationFailed);
        }
        let dek = SecretValue::new(
            self.private_key
                .decrypt_data(
                    Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                    wrapped_dek,
                )
                .map_err(|error| map_key_operation_error_code(error.code()))?,
        );
        if dek.expose().len() != DEK_BYTES {
            return Err(DeviceKeyProtectionError::OperationFailed);
        }
        Ok(dek)
    }
}

fn validate_key_id(key_id: String) -> Result<String, DeviceKeyProtectionError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES || key_id.chars().any(char::is_control)
    {
        return Err(DeviceKeyProtectionError::OperationFailed);
    }
    Ok(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_user_cancellation_without_exposing_provider_details() {
        assert_eq!(
            map_key_operation_error_code(-128),
            DeviceKeyProtectionError::AuthorizationCancelled
        );
        assert_eq!(
            map_key_operation_error_code(-50),
            DeviceKeyProtectionError::OperationFailed
        );
        assert_eq!(
            DeviceKeyProtectionError::KeyAlreadyExists.to_string(),
            "device key already exists"
        );
        assert_eq!(
            DeviceKeyProtectionError::PolicyMismatch.to_string(),
            "device key policy does not match the required protection"
        );

        let first = required_access_control()
            .expect("construct required access control")
            .as_CFType();
        let second = required_access_control()
            .expect("construct the same access control")
            .as_CFType();
        assert_eq!(first, second, "CFEqual must compare the policy contract");
    }

    #[test]
    fn rejects_each_weakened_access_control_policy() {
        let missing_user_presence = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .expect("construct policy without user presence")
        .as_CFType();
        let missing_private_key_usage = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlUserPresence,
        )
        .expect("construct policy without private-key usage")
        .as_CFType();
        let migratable_when_unlocked = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            kSecAccessControlUserPresence | kSecAccessControlPrivateKeyUsage,
        )
        .expect("construct policy without this-device-only protection")
        .as_CFType();

        for weakened in [
            missing_user_presence,
            missing_private_key_usage,
            migratable_when_unlocked,
        ] {
            assert_eq!(
                validate_access_control_policy(&weakened),
                Err(DeviceKeyProtectionError::PolicyMismatch)
            );
        }
    }
}
