use catomicals_signer_transport::{
    MtlsSignerClient, MtlsSignerServer, RemoteSignerProvider, TransportError, TransportLimits,
    WireRequest, WireResponse, certificate_spki_sha256, private_ca_client_config,
    private_ca_server_config,
};
use catomicals_threshold::{
    DeviceHealth, GuardedSignerProvider, LocalEncryptedFrostBackend, LocalFrostParticipant,
    NonceGuard, ProviderError, ProviderIdentity, ProviderRequestAuthorizer, ProviderRound,
    SIGNER_PROVIDER_PROTOCOL_VERSION, SignerAbortRequest, SignerProvider, SignerProviderKind,
    SignerRequestContext, SignerRoundOneRequest, SignerRoundOneResponse, SignerRoundTwoRequest,
    SignerRoundTwoResponse, build_session, group_pubkey_xonly, participant_identifier,
    run_local_dkg,
};
use frost_secp256k1_tr::{round1::SigningCommitments, round2::SignatureShare};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    version::TLS13,
};
use tokio::{net::TcpListener, sync::watch};
use uuid::Uuid;

use sha2::{Digest, Sha256};

#[test]
fn wire_protocol_rejects_unknown_top_level_fields() {
    let value = serde_json::json!({"method": "health", "unexpected": true});
    assert!(serde_json::from_value::<WireRequest>(value).is_err());
}

struct TestProvider {
    identity: ProviderIdentity,
}

impl SignerProvider for TestProvider {
    fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    fn kind(&self) -> SignerProviderKind {
        SignerProviderKind::LocalEncrypted
    }

    fn health(&mut self, now: i64) -> DeviceHealth {
        DeviceHealth {
            online: true,
            checked_at: Some(now),
            last_success_at: Some(now),
            last_error_code: None,
        }
    }

    fn round_one(
        &mut self,
        _request: SignerRoundOneRequest,
        _now: i64,
    ) -> Result<SignerRoundOneResponse, ProviderError> {
        Err(ProviderError::BackendUnavailable)
    }

    fn round_two(
        &mut self,
        _request: SignerRoundTwoRequest,
        _now: i64,
    ) -> Result<SignerRoundTwoResponse, ProviderError> {
        Err(ProviderError::BackendUnavailable)
    }

    fn abort(&mut self, _request: SignerAbortRequest, _now: i64) -> Result<(), ProviderError> {
        Err(ProviderError::BackendUnavailable)
    }
}

struct TestPki {
    ca: Certificate,
    ca_key: KeyPair,
    signer: Certificate,
    signer_key: KeyPair,
    coordinator: Certificate,
    coordinator_key: KeyPair,
    rogue: Certificate,
    rogue_key: KeyPair,
}

impl TestPki {
    fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
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
        let (rogue, rogue_key) = leaf(
            "rogue.local",
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
            rogue,
            rogue_key,
        }
    }

    fn ca_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca.der().to_vec())
    }
}

fn leaf(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, ca, ca_key).unwrap();
    (certificate, key)
}

fn cert_chain(certificate: &Certificate) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(certificate.der().to_vec())]
}

fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(key.serialize_der()).into()
}

async fn start_server(
    pki: &TestPki,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), TransportError>>,
) {
    let server_config = private_ca_server_config(
        pki.ca_der(),
        cert_chain(&pki.signer),
        private_key(&pki.signer_key),
    )
    .unwrap();
    let coordinator_pin = certificate_spki_sha256(pki.coordinator.der().as_ref()).unwrap();
    let provider = TestProvider {
        identity: ProviderIdentity {
            wallet_id: Uuid::from_bytes([1; 16]),
            signer_set_id: Uuid::from_bytes([2; 16]),
            signer_epoch: 1,
            signer_id: 2,
            device_id: Uuid::from_bytes([3; 16]),
            device_generation: 1,
            group_pubkey_xonly: [4; 32],
            verifying_share_digest: [5; 32],
        },
    };
    let server = MtlsSignerServer::new(
        provider,
        server_config,
        coordinator_pin,
        TransportLimits::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(server.serve(listener, receiver));
    (address, shutdown, task)
}

#[tokio::test]
async fn private_ca_and_both_spki_pins_are_required() {
    let pki = TestPki::new();
    let _keep_ca_key_alive = &pki.ca_key;
    let (address, shutdown, server) = start_server(&pki).await;
    let signer_pin = certificate_spki_sha256(pki.signer.der().as_ref()).unwrap();
    let good_client = MtlsSignerClient::new(
        private_ca_client_config(
            pki.ca_der(),
            cert_chain(&pki.coordinator),
            private_key(&pki.coordinator_key),
        )
        .unwrap(),
        "signer.local",
        signer_pin,
        TransportLimits::default(),
    );
    let response = good_client
        .request(address, &WireRequest::Health)
        .await
        .unwrap();
    assert!(matches!(
        response,
        WireResponse::Health(DeviceHealth { online: true, .. })
    ));

    let wrong_server_pin = MtlsSignerClient::new(
        private_ca_client_config(
            pki.ca_der(),
            cert_chain(&pki.coordinator),
            private_key(&pki.coordinator_key),
        )
        .unwrap(),
        "signer.local",
        [0x77; 32],
        TransportLimits::default(),
    );
    assert!(matches!(
        wrong_server_pin
            .request(address, &WireRequest::Health)
            .await,
        Err(TransportError::PeerPinMismatch)
    ));

    let rogue_client = MtlsSignerClient::new(
        private_ca_client_config(
            pki.ca_der(),
            cert_chain(&pki.rogue),
            private_key(&pki.rogue_key),
        )
        .unwrap(),
        "signer.local",
        signer_pin,
        TransportLimits {
            io_timeout: std::time::Duration::from_secs(1),
            ..TransportLimits::default()
        },
    );
    assert!(
        rogue_client
            .request(address, &WireRequest::Health)
            .await
            .is_err()
    );

    shutdown.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn client_certificate_is_mandatory_even_with_a_valid_private_ca() {
    let pki = TestPki::new();
    let (address, shutdown, server) = start_server(&pki).await;
    let signer_pin = certificate_spki_sha256(pki.signer.der().as_ref()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der()).unwrap();
    let mut anonymous_config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    anonymous_config.alpn_protocols = vec![b"catomicals-signer/1".to_vec()];
    let anonymous = MtlsSignerClient::new(
        anonymous_config,
        "signer.local",
        signer_pin,
        TransportLimits {
            io_timeout: std::time::Duration::from_secs(1),
            ..TransportLimits::default()
        },
    );
    assert!(
        anonymous
            .request(address, &WireRequest::Health)
            .await
            .is_err()
    );

    shutdown.send(true).unwrap();
    server.await.unwrap().unwrap();
}

struct AllowExactPolicy;

impl ProviderRequestAuthorizer for AllowExactPolicy {
    fn authorize(
        &mut self,
        context: &SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        (context.policy_digest == [0x49; 32])
            .then_some(())
            .ok_or(ProviderError::IdentityDrift)
    }
}

#[tokio::test]
async fn real_frost_share_crosses_mtls_without_exposing_the_key_or_broadcasting() {
    let pki = TestPki::new();
    let generated = run_local_dkg(3, 2).unwrap();
    let identifier = participant_identifier(2).unwrap();
    let participant = LocalFrostParticipant::new(
        2,
        generated.key_packages[&identifier].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let identity = ProviderIdentity {
        wallet_id: Uuid::from_bytes([0x41; 16]),
        signer_set_id: Uuid::from_bytes([0x42; 16]),
        signer_epoch: 1,
        signer_id: 2,
        device_id: Uuid::from_bytes([0x43; 16]),
        device_generation: 1,
        group_pubkey_xonly: group_pubkey_xonly(&generated.public_key_package).unwrap(),
        verifying_share_digest: Sha256::digest(
            generated.public_key_package.verifying_shares()[&identifier]
                .serialize()
                .unwrap(),
        )
        .into(),
    };
    let backend = LocalEncryptedFrostBackend::new(
        participant,
        generated.public_key_package.clone(),
        AllowExactPolicy,
    );
    let provider = GuardedSignerProvider::new(identity.clone(), backend);
    let server_config = private_ca_server_config(
        pki.ca_der(),
        cert_chain(&pki.signer),
        private_key(&pki.signer_key),
    )
    .unwrap();
    let server = MtlsSignerServer::new(
        provider,
        server_config,
        certificate_spki_sha256(pki.coordinator.der().as_ref()).unwrap(),
        TransportLimits::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let server_task = tokio::spawn(server.serve(listener, receiver));
    let client = MtlsSignerClient::new(
        private_ca_client_config(
            pki.ca_der(),
            cert_chain(&pki.coordinator),
            private_key(&pki.coordinator_key),
        )
        .unwrap(),
        "signer.local",
        certificate_spki_sha256(pki.signer.der().as_ref()).unwrap(),
        TransportLimits::default(),
    );
    let remote = RemoteSignerProvider::new(identity.clone(), address, client);
    assert!(remote.health().await.unwrap().online);

    let operation_id = Uuid::from_bytes([0x44; 16]);
    let session_id = [0x45; 32];
    let message = [0x46; 32];
    let base = SignerRequestContext {
        protocol_version: SIGNER_PROVIDER_PROTOCOL_VERSION,
        wallet_id: identity.wallet_id,
        signer_set_id: identity.signer_set_id,
        signer_epoch: identity.signer_epoch,
        signer_id: identity.signer_id,
        device_id: identity.device_id,
        device_generation: identity.device_generation,
        operation_id,
        intent_id: Uuid::from_bytes([0x47; 16]),
        session_id,
        taproot_sighash: message,
        policy_digest: [0x49; 32],
        group_pubkey_xonly: identity.group_pubkey_xonly,
        verifying_share_digest: identity.verifying_share_digest,
        min_signers: 2,
        max_signers: 3,
        chain_snapshot_digest: [0x50; 32],
        request_nonce: [0x51; 32],
        expires_at: i64::MAX,
    };
    let response = remote
        .round_one(SignerRoundOneRequest {
            context: base.clone(),
        })
        .await
        .unwrap();
    let remote_commitment =
        SigningCommitments::deserialize(&hex::decode(response.commitment_hex).unwrap()).unwrap();
    let mut other = LocalFrostParticipant::new(
        1,
        generated.key_packages[&participant_identifier(1).unwrap()].clone(),
        NonceGuard::new(),
    )
    .unwrap();
    let other_commitment = other.round1(session_id, message).unwrap();
    let session = build_session(
        session_id,
        message,
        2,
        std::collections::BTreeMap::from([
            (participant_identifier(1).unwrap(), other_commitment),
            (identifier, remote_commitment),
        ]),
        generated.public_key_package.clone(),
    );
    let mut round_two_context = base;
    round_two_context.request_nonce = [0x52; 32];
    let response = remote
        .round_two(SignerRoundTwoRequest {
            context: round_two_context,
            signing_package_hex: hex::encode(session.signing_package.serialize().unwrap()),
        })
        .await
        .unwrap();
    let share =
        SignatureShare::deserialize(&hex::decode(response.signature_share_hex).unwrap()).unwrap();
    frost_core::verify_signature_share(
        identifier,
        &generated.public_key_package.verifying_shares()[&identifier],
        &share,
        &session.signing_package,
        generated.public_key_package.verifying_key(),
    )
    .unwrap();

    shutdown.send(true).unwrap();
    server_task.await.unwrap().unwrap();
}
