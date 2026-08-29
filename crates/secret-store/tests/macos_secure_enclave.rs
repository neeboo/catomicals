#![cfg(target_os = "macos")]

use catomicals_secret_store::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    MacosSecureEnclaveProtector, SecretValue,
};
use uuid::Uuid;

#[test]
#[ignore = "requires a codesigned host with Data Protection Keychain entitlements and user presence"]
fn secure_enclave_wraps_and_unwraps_a_dek() {
    let key_id = format!("catomicals.test.{}", Uuid::new_v4());
    let protector = MacosSecureEnclaveProtector::create(&key_id)
        .expect("create user-presence Secure Enclave key");
    assert_eq!(
        MacosSecureEnclaveProtector::create(&key_id)
            .expect_err("same device key id must not be replaced"),
        DeviceKeyProtectionError::KeyAlreadyExists
    );
    assert_eq!(
        protector.provider(),
        DeviceKeyProvider::MacosSecureEnclaveP256
    );
    assert_eq!(
        protector.algorithm(),
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm
    );

    let wrapped = protector
        .wrap_dek(SecretValue::new(vec![0x5a; 32]))
        .expect("wrap DEK with public key");
    let opened = protector
        .unwrap_dek(&wrapped)
        .expect("authorize and unwrap with Secure Enclave private key");
    assert_eq!(opened.expose(), &[0x5a; 32]);

    let reopened = MacosSecureEnclaveProtector::open(&key_id)
        .expect("open the same key from the Data Protection Keychain");
    let opened = reopened
        .unwrap_dek(&wrapped)
        .expect("unwrap with reopened Secure Enclave key");
    assert_eq!(opened.expose(), &[0x5a; 32]);
}
