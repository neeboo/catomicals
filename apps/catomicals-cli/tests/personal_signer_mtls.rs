#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use catomicals_secret_store::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    DeviceWrapBinding, DeviceWrappedPackageV1, OnePasswordWrappedPackageLoader, SecretValue,
};
use catomicals_signer_transport::{
    MtlsSignerClient, MtlsSignerServer, RemoteSignerProvider, TransportError, TransportLimits,
    WireErrorCode, certificate_spki_sha256, private_ca_client_config, private_ca_server_config,
};
use catomicals_threshold::{
    AuthorizationError, GuardedSignerProvider, LocalEncryptedFrostBackend, NonceGuard,
    PersonalParticipantSecretPackage, PersonalSignerProfile, ProviderError, ProviderIdentity,
    ProviderRequestAuthorizer, ProviderRound, SIGNER_PROVIDER_PROTOCOL_VERSION,
    SignerRequestContext, SignerRoundOneRequest, SignerRoundTwoRequest, SigningAuthorization,
    aggregate_and_verify, build_session, participant_identifier, run_local_dkg,
};
use frost_secp256k1_tr::{round1::SigningCommitments, round2::SignatureShare};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tokio::{net::TcpListener, runtime::Builder, sync::watch};
use uuid::Uuid;

const CHILD_ENV: &str = "CATOMICALS_TEST_PERSONAL_SIGNER_CHILD";
const OP_REFERENCE: &str = "op://Private/Catomicals/package";
const TEST_KEY_ID: &str = "catomicals-test-device-key";
const DEVICE_GENERATION: u64 = 7;
const POLICY_DIGEST: [u8; 32] = [0x49; 32];

struct FakeDeviceProtector {
    key_id: String,
}

impl FakeDeviceProtector {
    fn new() -> Self {
        Self {
            key_id: TEST_KEY_ID.to_owned(),
        }
    }
}

impl DeviceKeyProtector for FakeDeviceProtector {
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
        Ok(dek.expose().iter().map(|byte| byte ^ 0xa5).collect())
    }

    fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError> {
        Ok(SecretValue::new(
            wrapped_dek.iter().map(|byte| byte ^ 0xa5).collect(),
        ))
    }
}

struct ExactPersonalAuthorizer {
    identity: ProviderIdentity,
}

impl ProviderRequestAuthorizer for ExactPersonalAuthorizer {
    fn authorize(
        &mut self,
        context: &SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        if context.wallet_id != self.identity.wallet_id
            || context.signer_set_id != self.identity.signer_set_id
            || context.signer_epoch != self.identity.signer_epoch
            || context.signer_id != self.identity.signer_id
            || context.device_id != self.identity.device_id
            || context.device_generation != self.identity.device_generation
            || context.group_pubkey_xonly != self.identity.group_pubkey_xonly
            || context.verifying_share_digest != self.identity.verifying_share_digest
            || context.min_signers != 2
            || context.max_signers != 3
            || context.policy_digest != POLICY_DIGEST
        {
            return Err(ProviderError::IdentityDrift);
        }
        Ok(())
    }
}

struct AllowLocalShare;

impl SigningAuthorization for AllowLocalShare {
    fn authorize(
        &mut self,
        _session_id: &[u8; 32],
        _message: &[u8; 32],
        signer_id: u16,
        _now: i64,
    ) -> Result<(), AuthorizationError> {
        (signer_id == 1)
            .then_some(())
            .ok_or(AuthorizationError::WrongSigner)
    }
}

struct TestPki {
    ca: Certificate,
    ca_key: KeyPair,
    signer: Certificate,
    signer_key: KeyPair,
    coordinator: Certificate,
    coordinator_key: KeyPair,
}

impl TestPki {
    fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("CA key");
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let (signer, signer_key) = leaf(
            "signer.local",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (coordinator, coordinator_key) = leaf(
            "coordinator.local",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        Self {
            ca,
            ca_key,
            signer,
            signer_key,
            coordinator,
            coordinator_key,
        }
    }

    fn ca_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca.der().to_vec())
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn personal_share_one_and_remote_share_two_complete_bip340_with_phone_offline() {
    let temp = TempDir::new().expect("temporary directory");
    let pki = TestPki::new();
    let _keep_ca_key_alive = &pki.ca_key;
    let mut bootstrap = PersonalSignerProfile::bootstrap(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
        run_local_dkg(3, 2).expect("2-of-3 DKG"),
    )
    .expect("personal profile");
    let profile = bootstrap.profile;
    let profile_path = temp.path().join("profile.json");
    write_private(&profile_path, &profile.to_bytes().expect("profile bytes"));

    let share_one_package = bootstrap
        .secret_packages
        .remove(&1)
        .expect("wallet-node share");
    let share_two_package = bootstrap.secret_packages.remove(&2).expect("desktop share");
    assert!(
        bootstrap.secret_packages.contains_key(&3),
        "phone stays offline"
    );

    let binding = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        TEST_KEY_ID,
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        DEVICE_GENERATION,
    )
    .expect("device binding");
    let wrapped = DeviceWrappedPackageV1::seal(
        SecretValue::new(share_two_package.to_bytes().expect("share bytes").to_vec()),
        binding,
        &FakeDeviceProtector::new(),
    )
    .expect("wrap share two");
    let wrong_binding = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        TEST_KEY_ID,
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        DEVICE_GENERATION + 1,
    )
    .expect("wrong device binding fixture");
    assert!(
        wrapped
            .open(&wrong_binding, &FakeDeviceProtector::new())
            .is_err()
    );
    let payload_path = temp.path().join("wrapped-package.txt");
    write_private(
        &payload_path,
        STANDARD
            .encode(wrapped.to_bytes().expect("wrapped bytes"))
            .as_bytes(),
    );
    let fake_op = fake_op_executable(temp.path(), &payload_path);

    let ca_path = temp.path().join("ca.der");
    let signer_cert_path = temp.path().join("signer.der");
    let signer_key_path = temp.path().join("signer-key.der");
    write_private(&ca_path, pki.ca.der().as_ref());
    write_private(&signer_cert_path, pki.signer.der().as_ref());
    write_private(&signer_key_path, &pki.signer_key.serialize_der());
    let ready_path = temp.path().join("ready");
    let address = reserve_loopback_address();
    let device_id = Uuid::new_v4();

    let child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--ignored",
            "--exact",
            "child_remote_signer_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_ENV, "1")
        .env("CATOMICALS_TEST_PROFILE", &profile_path)
        .env("CATOMICALS_TEST_FAKE_OP", &fake_op)
        .env("CATOMICALS_TEST_CA", &ca_path)
        .env("CATOMICALS_TEST_SIGNER_CERT", &signer_cert_path)
        .env("CATOMICALS_TEST_SIGNER_KEY", &signer_key_path)
        .env("CATOMICALS_TEST_READY", &ready_path)
        .env("CATOMICALS_TEST_ADDR", address.to_string())
        .env("CATOMICALS_TEST_DEVICE_ID", device_id.to_string())
        .env(
            "CATOMICALS_TEST_COORDINATOR_PIN",
            hex::encode(
                certificate_spki_sha256(pki.coordinator.der().as_ref()).expect("coordinator pin"),
            ),
        )
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn remote signer process");
    let _child = ChildGuard(child);
    wait_until_ready(&ready_path);

    let remote_identity = identity(&profile, 2, device_id, DEVICE_GENERATION);
    let client = MtlsSignerClient::new(
        private_ca_client_config(
            pki.ca_der(),
            vec![CertificateDer::from(pki.coordinator.der().to_vec())],
            PrivatePkcs8KeyDer::from(pki.coordinator_key.serialize_der()).into(),
        )
        .expect("client TLS"),
        "signer.local",
        certificate_spki_sha256(pki.signer.der().as_ref()).expect("signer pin"),
        TransportLimits::default(),
    );
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let remote = RemoteSignerProvider::new(remote_identity.clone(), address, client);
        assert!(remote.health().await.expect("remote health").online);

        let session_id = [0x45; 32];
        let message = [0x46; 32];
        let mut context = signer_context(&remote_identity, session_id, message, [0x51; 32]);
        context.signer_epoch += 1;
        assert!(matches!(
            remote.round_one(SignerRoundOneRequest { context }).await,
            Err(TransportError::Remote(WireErrorCode::IdentityDrift))
        ));

        let context = signer_context(&remote_identity, session_id, message, [0x52; 32]);
        let remote_round_one = remote
            .round_one(SignerRoundOneRequest {
                context: context.clone(),
            })
            .await
            .expect("remote round one");
        let remote_commitment = SigningCommitments::deserialize(
            &hex::decode(remote_round_one.commitment_hex).expect("commitment hex"),
        )
        .expect("remote commitment");

        let mut share_one = share_one_package
            .open(&profile)
            .expect("open share one")
            .into_participant(NonceGuard::new())
            .expect("wallet participant");
        let local_commitment = share_one
            .round1(session_id, message)
            .expect("local round one");
        let session = build_session(
            session_id,
            message,
            2,
            BTreeMap::from([
                (
                    participant_identifier(1).expect("share one id"),
                    local_commitment,
                ),
                (
                    participant_identifier(2).expect("share two id"),
                    remote_commitment,
                ),
            ]),
            profile.public_key_package().expect("public package"),
        );
        let mut round_two_context = context;
        round_two_context.request_nonce = [0x53; 32];
        let remote_round_two = remote
            .round_two(SignerRoundTwoRequest {
                context: round_two_context,
                signing_package_hex: hex::encode(
                    session
                        .signing_package
                        .serialize()
                        .expect("signing package"),
                ),
            })
            .await
            .expect("remote round two");
        let remote_share = SignatureShare::deserialize(
            &hex::decode(remote_round_two.signature_share_hex).expect("share hex"),
        )
        .expect("remote share");
        let local_share = share_one
            .round2(&session, &mut AllowLocalShare, 1)
            .expect("local round two");
        aggregate_and_verify(
            &session,
            &BTreeMap::from([
                (
                    participant_identifier(1).expect("share one id"),
                    local_share,
                ),
                (
                    participant_identifier(2).expect("share two id"),
                    remote_share,
                ),
            ]),
        )
        .expect("valid BIP340 aggregate");
    });
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
        "format_version": 1,
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
        "io_timeout_ms": 1000,
        "max_frame_bytes": 65536,
        "max_connections": 4
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

#[test]
#[ignore = "spawned only by the parent integration test"]
fn child_remote_signer_process() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    run_child_signer();
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

fn run_child_signer() {
    let profile_bytes = fs::read(required_path("CATOMICALS_TEST_PROFILE")).expect("read profile");
    let profile = PersonalSignerProfile::from_bytes(&profile_bytes).expect("valid profile");
    let loader = OnePasswordWrappedPackageLoader::new(
        required_path("CATOMICALS_TEST_FAKE_OP"),
        OP_REFERENCE,
        Duration::from_secs(5),
    )
    .expect("fake op loader");
    let loaded = loader.load().expect("load wrapped share from fake op");
    let wrapped = DeviceWrappedPackageV1::from_bytes(loaded.expose()).expect("wrapped share");
    let expected = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        TEST_KEY_ID,
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        DEVICE_GENERATION,
    )
    .expect("expected binding");
    assert_eq!(wrapped.binding(), &expected);
    let opened = wrapped
        .open(&expected, &FakeDeviceProtector::new())
        .expect("open device wrapper");
    let package = PersonalParticipantSecretPackage::from_bytes(opened.expose(), &profile)
        .expect("profile-bound share");
    assert_eq!(package.signer_id(), 2);
    let participant = package
        .open(&profile)
        .expect("open share two")
        .into_participant(NonceGuard::new())
        .expect("desktop participant");
    let device_id = Uuid::parse_str(
        &std::env::var("CATOMICALS_TEST_DEVICE_ID").expect("device id environment"),
    )
    .expect("device id");
    let identity = identity(&profile, 2, device_id, DEVICE_GENERATION);
    let backend = LocalEncryptedFrostBackend::new(
        participant,
        profile.public_key_package().expect("public package"),
        ExactPersonalAuthorizer {
            identity: identity.clone(),
        },
    );
    let provider = GuardedSignerProvider::new(identity, backend);

    let ca = CertificateDer::from(fs::read(required_path("CATOMICALS_TEST_CA")).expect("CA"));
    let signer_cert = CertificateDer::from(
        fs::read(required_path("CATOMICALS_TEST_SIGNER_CERT")).expect("signer certificate"),
    );
    let signer_key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(
        fs::read(required_path("CATOMICALS_TEST_SIGNER_KEY")).expect("signer key"),
    )
    .into();
    let coordinator_pin: [u8; 32] =
        hex::decode(std::env::var("CATOMICALS_TEST_COORDINATOR_PIN").expect("coordinator pin"))
            .expect("pin hex")
            .try_into()
            .expect("pin length");
    let server = MtlsSignerServer::new(
        provider,
        private_ca_server_config(ca, vec![signer_cert], signer_key).expect("server TLS"),
        coordinator_pin,
        TransportLimits::default(),
    );
    let address: SocketAddr = std::env::var("CATOMICALS_TEST_ADDR")
        .expect("address")
        .parse()
        .expect("socket address");
    let ready = required_path("CATOMICALS_TEST_READY");
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("child runtime")
        .block_on(async move {
            let listener = TcpListener::bind(address).await.expect("child listener");
            fs::write(ready, b"ready").expect("ready marker");
            let (_shutdown, receiver) = watch::channel(false);
            server
                .serve(listener, receiver)
                .await
                .expect("serve signer");
        });
}

fn identity(
    profile: &PersonalSignerProfile,
    signer_id: u16,
    device_id: Uuid,
    device_generation: u64,
) -> ProviderIdentity {
    let descriptor = profile
        .participants()
        .iter()
        .find(|participant| participant.signer_id == signer_id)
        .expect("participant descriptor");
    ProviderIdentity {
        wallet_id: profile.wallet_id(),
        signer_set_id: profile.signer_set_id(),
        signer_epoch: profile.signer_epoch(),
        signer_id,
        device_id,
        device_generation,
        group_pubkey_xonly: profile.group_pubkey_xonly(),
        verifying_share_digest: descriptor.verifying_share_digest,
    }
}

fn signer_context(
    identity: &ProviderIdentity,
    session_id: [u8; 32],
    message: [u8; 32],
    request_nonce: [u8; 32],
) -> SignerRequestContext {
    SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: identity.wallet_id,
        signer_set_id: identity.signer_set_id,
        signer_epoch: identity.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id: Uuid::new_v4(),
        intent_id: Uuid::new_v4(),
        session_id,
        taproot_sighash: message,
        policy_digest: POLICY_DIGEST,
        group_pubkey_xonly: identity.group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: 2,
        max_signers: 3,
        chain_snapshot_digest: [0x50; 32],
        request_nonce,
        expires_at: i64::MAX,
    }
}

fn leaf(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().expect("leaf key");
    let certificate = params
        .signed_by(&key, ca, ca_key)
        .expect("leaf certificate");
    (certificate, key)
}

fn reserve_loopback_address() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve port");
    listener.local_addr().expect("reserved address")
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
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n[ \"$1\" = \"read\" ] || exit 2\n[ \"$2\" = \"{OP_REFERENCE}\" ] || exit 3\nexec /bin/cat '{payload}'\n"
        ),
    )
    .expect("fake op script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("fake op executable");
    script
}

fn wait_until_ready(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "remote signer did not become ready"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}
