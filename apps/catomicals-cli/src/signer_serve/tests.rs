use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead as _, BufReader},
    net::{SocketAddr, TcpListener as StdTcpListener},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use catomicals_secret_store::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    DeviceWrapBinding, DeviceWrappedPackageV1, SecretValue,
};
use catomicals_signer_transport::{
    MtlsSignerClient, RemoteSignerProvider, TransportError, TransportLimits, WireErrorCode,
    certificate_spki_sha256, private_ca_client_config,
};
use catomicals_threshold::{
    AuthorizationError, NonceGuard, PersonalSignerProfile, ProviderIdentity,
    SIGNER_PROVIDER_PROTOCOL_VERSION, SignerRequestContext, SignerRoundOneRequest,
    SignerRoundTwoRequest, SigningAuthorization, aggregate_and_verify, build_session,
    participant_identifier, run_local_dkg,
};
use clap::Parser as _;
use frost_secp256k1_tr::{round1::SigningCommitments, round2::SignatureShare};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::runtime::Builder;
use uuid::Uuid;

use super::{
    FROST_SIGNING_ROUNDS, SignerProtocolProfile, TEST_PROTECTOR_ENV, TEST_PROTECTOR_VALUE,
    read_config,
};

const CHILD_ENV: &str = "CATOMICALS_TEST_PERSONAL_SIGNER_CLI_CHILD";
const OP_REFERENCE: &str = "op://Private/Catomicals/package";
const TEST_KEY_ID: &str = "catomicals-test-device-key";
const DEVICE_GENERATION: u64 = 7;
const POLICY_DIGEST: [u8; 32] = [0x49; 32];

#[test]
fn signer_config_keeps_frost_rounds_fixed_and_loads_runtime_timeouts() {
    let temp = TempDir::new().expect("temporary directory");
    let config_path = temp.path().join("signer-config.json");
    write_private(
        &config_path,
        &serde_json::to_vec(&signer_config_value(temp.path())).expect("signer config"),
    );

    let config = read_config(&config_path).expect("valid signer config");

    assert_eq!(
        config.protocol_profile,
        SignerProtocolProfile::FrostSecp256k1TrV1
    );
    assert_eq!(FROST_SIGNING_ROUNDS, 2);
    assert_eq!(config.round_timeout_ms, 1_500);
    assert_eq!(config.session_timeout_ms, 10_000);
}

#[test]
fn signer_config_rejects_a_round_count_override_and_impossible_timeout_budget() {
    let temp = TempDir::new().expect("temporary directory");
    let config_path = temp.path().join("signer-config.json");
    let mut configured_rounds = signer_config_value(temp.path());
    configured_rounds["signing_rounds"] = serde_json::json!(3);
    write_private(
        &config_path,
        &serde_json::to_vec(&configured_rounds).expect("signer config"),
    );
    assert!(read_config(&config_path).is_err());

    let mut impossible_budget = signer_config_value(temp.path());
    impossible_budget["session_timeout_ms"] = serde_json::json!(2_999);
    write_private(
        &config_path,
        &serde_json::to_vec(&impossible_budget).expect("signer config"),
    );
    assert!(read_config(&config_path).is_err());
}

fn signer_config_value(root: &Path) -> serde_json::Value {
    serde_json::json!({
        "format_version": 2,
        "protocol_profile": "frost-secp256k1-tr-v1",
        "listen_addr": "127.0.0.1:18789",
        "profile_path": root.join("profile.json"),
        "onepassword_executable": root.join("op"),
        "wrapped_package_reference": OP_REFERENCE,
        "device_key_id": TEST_KEY_ID,
        "server_cert_path": root.join("signer.der"),
        "server_key_path": root.join("signer-key.der"),
        "client_ca_cert_path": root.join("ca.der"),
        "coordinator_spki_sha256_hex": "11".repeat(32),
        "device_id": Uuid::new_v4(),
        "device_generation": DEVICE_GENERATION,
        "round_timeout_ms": 1_500,
        "session_timeout_ms": 10_000,
        "max_frame_bytes": 65_536,
        "max_connections": 1
    })
}

struct FakeDeviceProtector {
    key_id: String,
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

pub(super) fn open_test_protector(key_id: &str) -> anyhow::Result<Box<dyn DeviceKeyProtector>> {
    if key_id != TEST_KEY_ID {
        anyhow::bail!("test device key mismatch");
    }
    Ok(Box::new(FakeDeviceProtector {
        key_id: key_id.to_owned(),
    }))
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

#[derive(Debug, Deserialize)]
struct ObservedStatus {
    event: String,
    state: String,
    signer_id: u16,
    signer_set_id: Uuid,
    epoch: u64,
    device_generation: u64,
    online: bool,
    protocol_profile: SignerProtocolProfile,
    signing_rounds: u8,
}

#[test]
fn cli_serve_loads_share_two_and_completes_bip340_with_share_one() {
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
    let share_one_package = bootstrap
        .secret_packages
        .remove(&1)
        .expect("wallet-node share");
    let share_two_package = bootstrap.secret_packages.remove(&2).expect("desktop share");
    assert!(
        bootstrap.secret_packages.contains_key(&3),
        "phone share remains offline"
    );

    let profile_path = temp.path().join("profile.json");
    write_private(&profile_path, &profile.to_bytes().expect("profile bytes"));
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
        &FakeDeviceProtector {
            key_id: TEST_KEY_ID.to_owned(),
        },
    )
    .expect("device-wrapped share two");
    let wrong_binding = DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        TEST_KEY_ID,
        profile.binding_digest(),
        2,
        profile.signer_epoch(),
        DEVICE_GENERATION + 1,
    )
    .expect("wrong binding fixture");
    assert!(
        wrapped
            .open(
                &wrong_binding,
                &FakeDeviceProtector {
                    key_id: TEST_KEY_ID.to_owned(),
                }
            )
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
    let address = reserve_loopback_address();
    let device_id = Uuid::new_v4();
    let config_path = temp.path().join("signer-config.json");
    write_private(
        &config_path,
        &serde_json::to_vec(&serde_json::json!({
            "format_version": 2,
            "protocol_profile": "frost-secp256k1-tr-v1",
            "listen_addr": address,
            "profile_path": profile_path,
            "onepassword_executable": fake_op,
            "wrapped_package_reference": OP_REFERENCE,
            "device_key_id": TEST_KEY_ID,
            "server_cert_path": signer_cert_path,
            "server_key_path": signer_key_path,
            "client_ca_cert_path": ca_path,
            "coordinator_spki_sha256_hex": hex::encode(
                certificate_spki_sha256(pki.coordinator.der().as_ref())
                    .expect("coordinator pin")
            ),
            "device_id": device_id,
            "device_generation": DEVICE_GENERATION,
            "round_timeout_ms": 5000,
            "session_timeout_ms": 30000,
            "max_frame_bytes": 65536,
            "max_connections": 1
        }))
        .expect("signer config"),
    );

    let mut child = Command::new(std::env::current_exe().expect("unit test executable"))
        .args([
            "--ignored",
            "--exact",
            "signer_serve::tests::child_cli_signer_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_ENV, "1")
        .env("CATOMICALS_TEST_SIGNER_CONFIG", &config_path)
        .env(TEST_PROTECTOR_ENV, TEST_PROTECTOR_VALUE)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn CLI signer process");
    let stdout = child.stdout.take().expect("child stdout");
    let _child = ChildGuard(child);
    let status_line = wait_for_status(stdout);
    let json_start = status_line.find('{').expect("status JSON start");
    let status: ObservedStatus =
        serde_json::from_str(&status_line[json_start..]).expect("structured status");
    assert_eq!(status.event, "personal_signer_status");
    assert_eq!(status.state, "ready");
    assert_eq!(status.signer_id, 2);
    assert_eq!(status.signer_set_id, profile.signer_set_id());
    assert_eq!(status.epoch, profile.signer_epoch());
    assert_eq!(status.device_generation, DEVICE_GENERATION);
    assert!(status.online);
    assert_eq!(
        status.protocol_profile,
        SignerProtocolProfile::FrostSecp256k1TrV1
    );
    assert_eq!(status.signing_rounds, FROST_SIGNING_ROUNDS);
    for sensitive in [
        config_path.to_string_lossy().as_ref(),
        OP_REFERENCE,
        TEST_KEY_ID,
    ] {
        assert!(!status_line.contains(sensitive));
    }

    let remote_identity = identity(&profile, device_id);
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
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async move {
            let remote = RemoteSignerProvider::new(remote_identity.clone(), address, client);
            assert!(remote.health().await.expect("remote health").online);

            let session_id = [0x45; 32];
            let message = [0x46; 32];
            let mut wrong_context =
                signer_context(&remote_identity, session_id, message, [0x51; 32]);
            wrong_context.signer_epoch += 1;
            assert!(matches!(
                remote
                    .round_one(SignerRoundOneRequest {
                        context: wrong_context
                    })
                    .await,
                Err(TransportError::Remote(WireErrorCode::IdentityDrift))
            ));

            let context = signer_context(&remote_identity, session_id, message, [0x52; 32]);
            let response = remote
                .round_one(SignerRoundOneRequest {
                    context: context.clone(),
                })
                .await
                .expect("remote round one");
            let remote_commitment = SigningCommitments::deserialize(
                &hex::decode(response.commitment_hex).expect("commitment hex"),
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
            let response = remote
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
                &hex::decode(response.signature_share_hex).expect("share hex"),
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

#[test]
#[ignore = "spawned only by the parent CLI integration test"]
fn child_cli_signer_process() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let config = required_path("CATOMICALS_TEST_SIGNER_CONFIG");
    let cli = crate::Cli::try_parse_from([
        "catomicals",
        "signer",
        "serve",
        "--config",
        config.to_str().expect("UTF-8 config path"),
    ])
    .expect("parse catomicals signer serve command");
    crate::execute(cli).expect("run catomicals signer serve command");
}

fn identity(profile: &PersonalSignerProfile, device_id: Uuid) -> ProviderIdentity {
    let descriptor = profile
        .participants()
        .iter()
        .find(|participant| participant.signer_id == 2)
        .expect("desktop participant");
    ProviderIdentity {
        wallet_id: profile.wallet_id(),
        signer_set_id: profile.signer_set_id(),
        signer_epoch: profile.signer_epoch(),
        signer_id: 2,
        device_id,
        device_generation: DEVICE_GENERATION,
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
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64
            + 20,
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

fn wait_for_status(stdout: impl std::io::Read + Send + 'static) -> String {
    let (sender, receiver) = mpsc::sync_channel(8);
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let line = receiver
            .recv_timeout(remaining)
            .expect("CLI signer did not emit ready status");
        if line.contains("{\"event\":\"personal_signer_status\"") {
            return line;
        }
    }
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}
