#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use catomicals_secret_store::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    DeviceWrapBinding, DeviceWrappedPackageV1, SecretValue,
};
use catomicals_threshold::{PersonalSignerProfile, run_local_dkg};
use tempfile::TempDir;
use uuid::Uuid;

const DEVICE_GENERATION: u64 = 7;

struct IntegrationFakeProtector(String);

impl DeviceKeyProtector for IntegrationFakeProtector {
    fn provider(&self) -> DeviceKeyProvider {
        DeviceKeyProvider::MacosSecureEnclaveP256
    }

    fn algorithm(&self) -> DeviceKeyWrapAlgorithm {
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm
    }

    fn key_id(&self) -> &str {
        &self.0
    }

    fn wrap_dek(&self, dek: SecretValue) -> Result<Vec<u8>, DeviceKeyProtectionError> {
        Ok(dek.expose().iter().map(|byte| byte ^ 0x5a).collect())
    }

    fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError> {
        Ok(SecretValue::new(
            wrapped_dek.iter().map(|byte| byte ^ 0x5a).collect(),
        ))
    }
}

#[cfg(target_os = "macos")]
#[test]
fn production_cli_rejects_noninteractive_op_token_without_leaking_configuration() {
    let temp = TempDir::new().expect("temporary directory");
    let profile = PersonalSignerProfile::bootstrap(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        run_local_dkg(3, 2).expect("2-of-3 DKG"),
    )
    .expect("personal profile")
    .profile;
    let profile_path = temp.path().join("private-profile-name.json");
    write_private(&profile_path, &profile.to_bytes().expect("profile bytes"));
    let unused_payload = temp.path().join("unused-payload");
    write_private(&unused_payload, b"dW51c2Vk");
    let fake_op = fake_op_executable(temp.path(), &unused_payload);
    let config_path = temp.path().join("private-config-name.json");
    let secret_reference = "op://Private/private-item/private-field";
    let key_id = "private-key-label";
    let config = serde_json::json!({
        "format_version": 2,
        "protocol_profile": "frost-secp256k1-tr-v1",
        "chain_scope": {"schema_version": 1, "chain": "bitcoin", "network": "bitcoin.signet"},
        "signing_suite_id": "btc.bip340.frost-secp256k1-tr.v1",
        "listen_addr": "127.0.0.1:0",
        "profile_path": profile_path,
        "onepassword_executable": fake_op,
        "wrapped_package_reference": secret_reference,
        "device_key_id": key_id,
        "server_cert_path": temp.path().join("unused-server-cert"),
        "server_key_path": temp.path().join("unused-server-key"),
        "client_ca_cert_path": temp.path().join("unused-client-ca"),
        "coordinator_spki_sha256_hex": hex::encode([0x11; 32]),
        "device_id": Uuid::new_v4(),
        "device_generation": DEVICE_GENERATION,
        "round_timeout_ms": 1000,
        "session_timeout_ms": 10000,
        "max_frame_bytes": 65536,
        "max_connections": 1
    });
    write_private(
        &config_path,
        &serde_json::to_vec(&config).expect("config JSON"),
    );
    let token = "must-not-be-cleared-or-printed";
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["signer", "serve", "--config"])
        .arg(&config_path)
        .env("OP_SERVICE_ACCOUNT_TOKEN", token)
        .output()
        .expect("run production CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("1Password signer package is unavailable"));
    for sensitive in [
        config_path.to_string_lossy().as_ref(),
        profile_path.to_string_lossy().as_ref(),
        secret_reference,
        key_id,
        token,
    ] {
        assert!(!stderr.contains(sensitive));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn production_cli_rejects_non_private_config_without_echoing_its_path() {
    let temp = TempDir::new().expect("temporary directory");
    let config_path = temp.path().join("unsafe-private-config-name.json");
    fs::write(&config_path, b"{}").expect("config fixture");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))
        .expect("unsafe fixture mode");
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["signer", "serve", "--config"])
        .arg(&config_path)
        .output()
        .expect("run production CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("private signer file permissions are unsafe"));
    assert!(!stderr.contains(config_path.to_string_lossy().as_ref()));
}

#[cfg(target_os = "macos")]
#[test]
fn production_binary_does_not_compile_the_test_protector_entry() {
    let temp = TempDir::new().expect("temporary directory");
    let mut bootstrap = PersonalSignerProfile::bootstrap(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        run_local_dkg(3, 2).expect("2-of-3 DKG"),
    )
    .expect("personal profile");
    let profile = bootstrap.profile;
    let share_two = bootstrap.secret_packages.remove(&2).expect("desktop share");
    let profile_path = temp.path().join("profile.json");
    write_private(&profile_path, &profile.to_bytes().expect("profile bytes"));
    let key_id = format!("catomicals-test-absent-{}", Uuid::new_v4());
    let binding = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        key_id.clone(),
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        DEVICE_GENERATION,
    )
    .expect("binding");
    let wrapped = DeviceWrappedPackageV1::seal(
        SecretValue::new(share_two.to_bytes().expect("share bytes").to_vec()),
        binding,
        &IntegrationFakeProtector(key_id.clone()),
    )
    .expect("wrapped share");
    let payload = temp.path().join("payload");
    write_private(
        &payload,
        STANDARD
            .encode(wrapped.to_bytes().expect("wrapped bytes"))
            .as_bytes(),
    );
    let fake_op = fake_op_executable(temp.path(), &payload);
    let config_path = temp.path().join("config.json");
    write_private(
        &config_path,
        &serde_json::to_vec(&serde_json::json!({
            "format_version": 2,
            "protocol_profile": "frost-secp256k1-tr-v1",
            "chain_scope": {"schema_version": 1, "chain": "bitcoin", "network": "bitcoin.signet"},
            "signing_suite_id": "btc.bip340.frost-secp256k1-tr.v1",
            "listen_addr": "127.0.0.1:0",
            "profile_path": profile_path,
            "onepassword_executable": fake_op,
            "wrapped_package_reference": "op://Private/Catomicals/package",
            "device_key_id": key_id,
            "server_cert_path": temp.path().join("unused-server-cert"),
            "server_key_path": temp.path().join("unused-server-key"),
            "client_ca_cert_path": temp.path().join("unused-client-ca"),
            "coordinator_spki_sha256_hex": hex::encode([0x11; 32]),
            "device_id": Uuid::new_v4(),
            "device_generation": DEVICE_GENERATION,
            "round_timeout_ms": 1000,
            "session_timeout_ms": 10000,
            "max_frame_bytes": 65536,
            "max_connections": 1
        }))
        .expect("config"),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["signer", "serve", "--config"])
        .arg(config_path)
        .env(
            "CATOMICALS_TEST_ONLY_DEVICE_PROTECTOR",
            "explicit-unit-test-only",
        )
        .output()
        .expect("run production binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("signed helper")
            || stderr.contains("device signer package could not be opened")
    );
    assert!(!stderr.contains("signer certificate is unavailable"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn production_signer_fails_closed_off_macos() {
    let output = Command::new(env!("CARGO_BIN_EXE_catomicals"))
        .args(["signer", "serve", "--config", "/tmp/never-read.json"])
        .output()
        .expect("run CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported on this platform"));
    assert!(!stderr.contains("never-read.json"));
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private permissions");
}

fn fake_op_executable(root: &Path, payload: &Path) -> PathBuf {
    let script = root.join("op");
    let payload = payload
        .to_str()
        .expect("UTF-8 fixture path")
        .replace('\'', "'\\''");
    fs::write(&script, format!("#!/bin/sh\nexec /bin/cat '{payload}'\n")).expect("fake op script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("fake op executable");
    script
}
