use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use catomicals_chain_chia::{
    ChiaAdapterError, ChiaCoin, ChiaPushReview, ChiaRuntimeAdapter, ChiaSpendOutput,
    ThresholdBlsDealerKeyKind, ThresholdChiaSpend, dealer_split_threshold_secret_2_of_3,
    standard_threshold_puzzle_hash,
};
use catomicals_chain_domain::{ChainNetwork, ChainScope, ChiaNetwork};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

const MAINNET_ADDITIONAL_DATA: &str =
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb";

fn mainnet_scope() -> ChainScope {
    ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Mainnet))
}

fn finalized_fixture() -> (
    catomicals_chain_chia::ThresholdBlsDealerOutput,
    Vec<u8>,
    ChiaPushReview,
) {
    let scope = mainnet_scope();
    let dealer = dealer_split_threshold_secret_2_of_3(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        [0x2a; 32],
        [0x31; 32],
    )
    .unwrap();
    let puzzle_hash =
        standard_threshold_puzzle_hash(dealer.commitment().group_public_key()).unwrap();
    let coin = ChiaCoin::new([0x44; 32].into(), puzzle_hash.into(), 2_000_000);
    let output =
        ChiaSpendOutput::new([0x55; 32], 1_900_000).with_memos(vec![b"reviewed memo".to_vec()]);
    let spend = ThresholdChiaSpend::standard(
        scope,
        coin,
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        dealer.commitment().clone(),
        vec![output.clone()],
    )
    .unwrap();
    let first = spend.sign_share(&dealer.shares()[0]).unwrap();
    let third = spend.sign_share(&dealer.shares()[2]).unwrap();
    let finalized = spend.finalize(&[first, third]).unwrap();
    let bytes = finalized.to_bytes().unwrap();
    let review = ChiaPushReview {
        scope,
        bundle_id: finalized.bundle_id(),
        coin_id: spend.coin_id(),
        outputs: vec![output],
    };
    (dealer, bytes, review)
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    body: String,
}

fn mock_rpc(
    responses: Vec<(&'static str, Duration)>,
) -> (
    String,
    Arc<Mutex<Vec<RecordedRequest>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let handle = thread::spawn(move || {
        for (response, delay) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end;
            loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    header_end = index + 4;
                    break;
                }
            }
            let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .or_else(|| line.strip_prefix("Content-Length: "))
                })
                .unwrap()
                .trim()
                .parse::<usize>()
                .unwrap();
            while bytes.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            }
            let request_line = headers.lines().next().unwrap();
            let path = request_line.split_whitespace().nth(1).unwrap().to_owned();
            let body =
                String::from_utf8(bytes[header_end..header_end + content_length].to_vec()).unwrap();
            recorded
                .lock()
                .unwrap()
                .push(RecordedRequest { path, body });
            thread::sleep(delay);
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (format!("http://{address}/"), requests, handle)
}

struct TestPki {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    client: Certificate,
    client_key: KeyPair,
    rogue_ca: Certificate,
}

impl TestPki {
    fn new() -> Self {
        let (ca, ca_key) = certificate_authority();
        let (server, server_key) = signed_leaf(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client, client_key) = signed_leaf(
            "wallet.local",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        let (rogue_ca, _) = certificate_authority();
        Self {
            ca,
            server,
            server_key,
            client,
            client_key,
            rogue_ca,
        }
    }

    fn client_identity_pem(&self) -> Vec<u8> {
        format!("{}{}", self.client.pem(), self.client_key.serialize_pem()).into_bytes()
    }

    fn ca_pem(&self) -> Vec<u8> {
        self.ca.pem().into_bytes()
    }

    fn rogue_ca_pem(&self) -> Vec<u8> {
        self.rogue_ca.pem().into_bytes()
    }

    fn server_config(&self) -> ServerConfig {
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(self.ca.der().to_vec()))
            .unwrap();
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(self.server.der().to_vec())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.server_key.serialize_der())),
            )
            .unwrap()
    }
}

fn certificate_authority() -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (certificate, key)
}

fn signed_leaf(
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

fn mock_mtls_rpc(
    config: ServerConfig,
    responses: Vec<String>,
) -> (String, thread::JoinHandle<Vec<bool>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(config);
    let handle = thread::spawn(move || {
        let mut handshakes = Vec::new();
        for response in responses {
            let (tcp, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(config.clone()).unwrap();
            let mut stream = StreamOwned::new(connection, tcp);
            let request = read_http_request(&mut stream);
            handshakes.push(request.is_ok());
            if request.is_err() {
                continue;
            }
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        }
        handshakes
    });
    (format!("https://localhost:{}/", address.port()), handle)
}

fn read_http_request(stream: &mut impl Read) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS peer closed before request",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        })
        .unwrap_or("0")
        .trim()
        .parse::<usize>()
        .unwrap();
    while bytes.len() < header_end + length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS peer closed before request body",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(())
}

#[test]
fn runtime_constructors_make_local_http_and_private_mtls_explicit() {
    assert!(matches!(
        ChiaRuntimeAdapter::new_loopback_http(
            mainnet_scope(),
            "https://rpc.example.com:8555/",
            Duration::from_secs(1),
        ),
        Err(ChiaAdapterError::ChiaRpcMutualTlsRequired)
    ));
    assert!(matches!(
        ChiaRuntimeAdapter::new_loopback_http(
            mainnet_scope(),
            "http://rpc.example.com:8555/",
            Duration::from_secs(1),
        ),
        Err(ChiaAdapterError::InsecureChiaRpcEndpoint)
    ));
    assert!(matches!(
        ChiaRuntimeAdapter::new_private_mtls(
            mainnet_scope(),
            "https://rpc.example.com:8555/",
            Duration::from_secs(1),
            &[],
            &[],
        ),
        Err(ChiaAdapterError::ChiaRpcMutualTlsRequired)
    ));
}

#[tokio::test]
async fn private_mtls_completes_real_tls_handshakes_and_pushes() {
    let pki = TestPki::new();
    let (dealer, bytes, review) = finalized_fixture();
    let responses = vec![
        r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#.to_owned(),
        format!(r#"{{"success":true,"additional_data":"{MAINNET_ADDITIONAL_DATA}"}}"#),
        r#"{"success":true,"status":"SUCCESS"}"#.to_owned(),
    ];
    let (endpoint, server) = mock_mtls_rpc(pki.server_config(), responses);
    let runtime = ChiaRuntimeAdapter::new_private_mtls(
        mainnet_scope(),
        &endpoint,
        Duration::from_secs(2),
        &pki.client_identity_pem(),
        &pki.ca_pem(),
    )
    .unwrap();
    let receipt = runtime
        .push_tx(
            &bytes,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            dealer.commitment(),
            &review,
        )
        .await
        .unwrap();
    assert_eq!(receipt.status, "SUCCESS");
    assert_eq!(server.join().unwrap(), [true, true, true]);
}

#[tokio::test]
async fn private_mtls_rejects_wrong_ca_and_missing_client_certificate() {
    let pki = TestPki::new();
    let (dealer, bytes, review) = finalized_fixture();
    let (endpoint, server) = mock_mtls_rpc(
        pki.server_config(),
        vec![r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#.to_owned()],
    );
    let wrong_ca = ChiaRuntimeAdapter::new_private_mtls(
        mainnet_scope(),
        &endpoint,
        Duration::from_secs(1),
        &pki.client_identity_pem(),
        &pki.rogue_ca_pem(),
    )
    .unwrap();
    assert!(matches!(
        wrong_ca
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaRpcRequest(_))
    ));
    assert_eq!(server.join().unwrap(), [false]);

    let pki = TestPki::new();
    let (endpoint, server) =
        mock_mtls_rpc(pki.server_config(), vec![r#"{"success":true}"#.to_owned()]);
    let ca = reqwest::Certificate::from_pem(&pki.ca_pem()).unwrap();
    let anonymous = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .build()
        .unwrap();
    assert!(
        anonymous
            .post(format!("{endpoint}get_network_info"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .is_err()
    );
    assert_eq!(server.join().unwrap(), [false]);
}

#[tokio::test]
async fn push_tx_verifies_review_network_and_domain_before_strict_success() {
    let (dealer, bytes, review) = finalized_fixture();
    let (endpoint, requests, server) = mock_rpc(vec![
        (
            r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#,
            Duration::ZERO,
        ),
        (
            Box::leak(
                format!(r#"{{"success":true,"additional_data":"{MAINNET_ADDITIONAL_DATA}"}}"#)
                    .into_boxed_str(),
            ),
            Duration::ZERO,
        ),
        (r#"{"success":true,"status":"SUCCESS"}"#, Duration::ZERO),
    ]);
    let runtime =
        ChiaRuntimeAdapter::new_loopback_http(mainnet_scope(), &endpoint, Duration::from_secs(2))
            .unwrap();

    let receipt = runtime
        .push_tx(
            &bytes,
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            dealer.commitment(),
            &review,
        )
        .await
        .unwrap();
    server.join().unwrap();
    assert_eq!(receipt.bundle_id, review.bundle_id);
    assert_eq!(receipt.status, "SUCCESS");
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/get_network_info",
            "/get_aggsig_additional_data",
            "/push_tx"
        ]
    );
    assert_eq!(requests[0].body, "{}");
    let push: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
    assert!(push["spend_bundle"]["coin_spends"].is_array());
    assert!(
        push["spend_bundle"]["aggregated_signature"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
}

#[tokio::test]
async fn review_drift_fails_before_contacting_rpc() {
    let (dealer, bytes, mut review) = finalized_fixture();
    review.outputs[0].amount -= 1;
    let runtime = ChiaRuntimeAdapter::new_loopback_http(
        mainnet_scope(),
        "http://127.0.0.1:1/",
        Duration::from_millis(50),
    )
    .unwrap();
    assert!(matches!(
        runtime
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaSpendReviewMismatch)
    ));
}

#[tokio::test]
async fn wrong_network_and_domain_stop_before_push() {
    let (dealer, bytes, review) = finalized_fixture();
    let (endpoint, requests, server) = mock_rpc(vec![(
        r#"{"success":true,"network_name":"testnet11","network_prefix":"txch"}"#,
        Duration::ZERO,
    )]);
    let runtime =
        ChiaRuntimeAdapter::new_loopback_http(mainnet_scope(), &endpoint, Duration::from_secs(2))
            .unwrap();
    assert!(matches!(
        runtime
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaRpcNetworkMismatch { .. })
    ));
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);

    let (endpoint, requests, server) = mock_rpc(vec![
        (
            r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#,
            Duration::ZERO,
        ),
        (
            r#"{"success":true,"additional_data":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            Duration::ZERO,
        ),
    ]);
    let runtime =
        ChiaRuntimeAdapter::new_loopback_http(mainnet_scope(), &endpoint, Duration::from_secs(2))
            .unwrap();
    assert!(matches!(
        runtime
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaRpcAdditionalDataMismatch)
    ));
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn timeout_and_non_success_mempool_status_fail_closed() {
    let (dealer, bytes, review) = finalized_fixture();
    let (endpoint, _requests, server) = mock_rpc(vec![(
        r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#,
        Duration::from_millis(150),
    )]);
    let runtime = ChiaRuntimeAdapter::new_loopback_http(
        mainnet_scope(),
        &endpoint,
        Duration::from_millis(30),
    )
    .unwrap();
    assert!(matches!(
        runtime
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaRpcRequest(_))
    ));
    server.join().unwrap();

    let (endpoint, _requests, server) = mock_rpc(vec![
        (
            r#"{"success":true,"network_name":"mainnet","network_prefix":"xch"}"#,
            Duration::ZERO,
        ),
        (
            Box::leak(
                format!(r#"{{"success":true,"additional_data":"{MAINNET_ADDITIONAL_DATA}"}}"#)
                    .into_boxed_str(),
            ),
            Duration::ZERO,
        ),
        (r#"{"success":true,"status":"PENDING"}"#, Duration::ZERO),
    ]);
    let runtime =
        ChiaRuntimeAdapter::new_loopback_http(mainnet_scope(), &endpoint, Duration::from_secs(2))
            .unwrap();
    assert!(matches!(
        runtime
            .push_tx(
                &bytes,
                ThresholdBlsDealerKeyKind::FinalSigningKey,
                dealer.commitment(),
                &review,
            )
            .await,
        Err(ChiaAdapterError::ChiaRpcRejected(status)) if status == "PENDING"
    ));
    server.join().unwrap();
}
