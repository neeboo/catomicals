//! Private-CA mTLS transport for a Catomicals remote FROST signer.
//!
//! TLS verifies the configured private certificate authority. The transport
//! then pins the authenticated leaf certificate's SPKI digest, so a different
//! certificate issued by the same CA cannot silently assume the coordinator or
//! signer role. The application protocol is one bounded, length-prefixed JSON
//! request per TLS connection.

#![forbid(unsafe_code)]

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use catomicals_threshold::{
    DeviceHealth, ProviderError, ProviderIdentity, SignerAbortRequest, SignerProvider,
    SignerRequestContext, SignerRoundOneRequest, SignerRoundOneResponse, SignerRoundTwoRequest,
    SignerRoundTwoResponse,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    version::TLS13,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::parse_x509_certificate;

const PROTOCOL_ALPN: &[u8] = b"catomicals-signer/1";
const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WireRequest {
    Health,
    RoundOne(SignerRoundOneRequest),
    RoundTwo(SignerRoundTwoRequest),
    Abort(SignerAbortRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WireResponse {
    Health(DeviceHealth),
    RoundOne(SignerRoundOneResponse),
    RoundTwo(SignerRoundTwoResponse),
    Ack,
    Error { code: WireErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    Unconfigured,
    Revoked,
    IdentityDrift,
    Expired,
    Replay,
    InvalidRequest,
    RoundBindingMismatch,
    BackendUnavailable,
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("transport frame is too large")]
    FrameTooLarge,
    #[error("transport JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("authenticated peer public key does not match the configured pin")]
    PeerPinMismatch,
    #[error("authenticated peer did not present exactly one usable leaf certificate")]
    MissingPeerCertificate,
    #[error("transport operation timed out")]
    Timeout,
    #[error("signer worker failed")]
    Worker,
    #[error("remote signer rejected request: {0:?}")]
    Remote(WireErrorCode),
}

#[derive(Debug, Clone, Copy)]
pub struct TransportLimits {
    pub io_timeout: Duration,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(10),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

pub fn private_ca_server_config(
    client_ca: CertificateDer<'static>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TransportError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(client_ca)
        .map_err(|error| TransportError::Tls(rustls::Error::General(error.to_string())))?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| TransportError::Tls(rustls::Error::General(error.to_string())))?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)?;
    config.alpn_protocols = vec![PROTOCOL_ALPN.to_vec()];
    Ok(config)
}

pub fn private_ca_client_config(
    server_ca: CertificateDer<'static>,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, TransportError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(server_ca)
        .map_err(|error| TransportError::Tls(rustls::Error::General(error.to_string())))?;
    let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(certificate_chain, private_key)?;
    config.alpn_protocols = vec![PROTOCOL_ALPN.to_vec()];
    Ok(config)
}

pub fn certificate_spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32], TransportError> {
    let (_, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| TransportError::MissingPeerCertificate)?;
    Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}

pub struct MtlsSignerServer<P> {
    provider: Arc<Mutex<P>>,
    acceptor: TlsAcceptor,
    coordinator_spki_sha256: [u8; 32],
    limits: TransportLimits,
}

impl<P: SignerProvider + 'static> MtlsSignerServer<P> {
    pub fn new(
        provider: P,
        tls_config: ServerConfig,
        coordinator_spki_sha256: [u8; 32],
        limits: TransportLimits,
    ) -> Self {
        Self {
            provider: Arc::new(Mutex::new(provider)),
            acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            coordinator_spki_sha256,
            limits,
        }
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), TransportError> {
        let permits = Arc::new(Semaphore::new(self.limits.max_connections.max(1)));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let permit = permits.clone().acquire_owned().await.map_err(|_| TransportError::Worker)?;
                    let provider = self.provider.clone();
                    let acceptor = self.acceptor.clone();
                    let pin = self.coordinator_spki_sha256;
                    let limits = self.limits;
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = handle_connection(provider, acceptor, pin, limits, stream).await;
                    });
                }
            }
        }
    }
}

async fn handle_connection<P: SignerProvider + 'static>(
    provider: Arc<Mutex<P>>,
    acceptor: TlsAcceptor,
    coordinator_spki_sha256: [u8; 32],
    limits: TransportLimits,
    stream: TcpStream,
) -> Result<(), TransportError> {
    let mut stream = timeout(limits.io_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| TransportError::Timeout)??;
    let peer_certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(TransportError::MissingPeerCertificate)?;
    if certificate_spki_sha256(peer_certificate.as_ref())? != coordinator_spki_sha256 {
        return Err(TransportError::PeerPinMismatch);
    }
    let request: WireRequest = read_frame(&mut stream, limits).await?;
    let now = unix_timestamp();
    let response = task::spawn_blocking(move || {
        let mut provider = provider.lock().map_err(|_| TransportError::Worker)?;
        Ok::<_, TransportError>(dispatch(&mut *provider, request, now))
    })
    .await
    .map_err(|_| TransportError::Worker)??;
    write_frame(&mut stream, &response, limits).await?;
    timeout(limits.io_timeout, stream.shutdown())
        .await
        .map_err(|_| TransportError::Timeout)??;
    Ok(())
}

fn dispatch(provider: &mut dyn SignerProvider, request: WireRequest, now: i64) -> WireResponse {
    let result = match request {
        WireRequest::Health => return WireResponse::Health(provider.health(now)),
        WireRequest::RoundOne(request) => {
            provider.round_one(request, now).map(WireResponse::RoundOne)
        }
        WireRequest::RoundTwo(request) => {
            provider.round_two(request, now).map(WireResponse::RoundTwo)
        }
        WireRequest::Abort(request) => provider.abort(request, now).map(|()| WireResponse::Ack),
    };
    result.unwrap_or_else(|error| WireResponse::Error {
        code: provider_error_code(&error),
    })
}

fn provider_error_code(error: &ProviderError) -> WireErrorCode {
    match error {
        ProviderError::Unconfigured => WireErrorCode::Unconfigured,
        ProviderError::Revoked => WireErrorCode::Revoked,
        ProviderError::IdentityDrift
        | ProviderError::WrongSignerSet
        | ProviderError::SpkiMismatch => WireErrorCode::IdentityDrift,
        ProviderError::Expired | ProviderError::SessionLifetimeExceeded => WireErrorCode::Expired,
        ProviderError::Replay => WireErrorCode::Replay,
        ProviderError::RoundBindingMismatch => WireErrorCode::RoundBindingMismatch,
        ProviderError::BackendUnavailable => WireErrorCode::BackendUnavailable,
        ProviderError::InvalidChallenge
        | ProviderError::InvalidProof
        | ProviderError::RotationAuthorizationRequired
        | ProviderError::InvalidProvider
        | ProviderError::InvalidEncoding
        | ProviderError::UnknownParticipant => WireErrorCode::InvalidRequest,
    }
}

#[derive(Clone)]
pub struct MtlsSignerClient {
    connector: TlsConnector,
    server_name: String,
    signer_spki_sha256: [u8; 32],
    limits: TransportLimits,
}

impl MtlsSignerClient {
    pub fn new(
        tls_config: ClientConfig,
        server_name: impl Into<String>,
        signer_spki_sha256: [u8; 32],
        limits: TransportLimits,
    ) -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(tls_config)),
            server_name: server_name.into(),
            signer_spki_sha256,
            limits,
        }
    }

    pub async fn request(
        &self,
        address: SocketAddr,
        request: &WireRequest,
    ) -> Result<WireResponse, TransportError> {
        let tcp = timeout(self.limits.io_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::MissingPeerCertificate)?;
        let mut stream = timeout(self.limits.io_timeout, self.connector.connect(name, tcp))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let peer_certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(TransportError::MissingPeerCertificate)?;
        if certificate_spki_sha256(peer_certificate.as_ref())? != self.signer_spki_sha256 {
            return Err(TransportError::PeerPinMismatch);
        }
        write_frame(&mut stream, request, self.limits).await?;
        let response: WireResponse = read_frame(&mut stream, self.limits).await?;
        if let WireResponse::Error { code } = response {
            return Err(TransportError::Remote(code));
        }
        Ok(response)
    }
}

/// Coordinator-side remote signer provider. The address, signer identity,
/// private CA and both certificate pins are fixed when constructed; callers
/// cannot redirect one signing request to a different network endpoint.
#[derive(Clone)]
pub struct RemoteSignerProvider {
    identity: ProviderIdentity,
    address: SocketAddr,
    client: MtlsSignerClient,
}

impl RemoteSignerProvider {
    pub fn new(identity: ProviderIdentity, address: SocketAddr, client: MtlsSignerClient) -> Self {
        Self {
            identity,
            address,
            client,
        }
    }

    pub fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    pub async fn health(&self) -> Result<DeviceHealth, TransportError> {
        match self
            .client
            .request(self.address, &WireRequest::Health)
            .await?
        {
            WireResponse::Health(health) => Ok(health),
            _ => Err(TransportError::Worker),
        }
    }

    pub async fn round_one(
        &self,
        request: SignerRoundOneRequest,
    ) -> Result<SignerRoundOneResponse, TransportError> {
        self.ensure_identity(&request.context)?;
        match self
            .client
            .request(self.address, &WireRequest::RoundOne(request))
            .await?
        {
            WireResponse::RoundOne(response) => Ok(response),
            _ => Err(TransportError::Worker),
        }
    }

    pub async fn round_two(
        &self,
        request: SignerRoundTwoRequest,
    ) -> Result<SignerRoundTwoResponse, TransportError> {
        self.ensure_identity(&request.context)?;
        match self
            .client
            .request(self.address, &WireRequest::RoundTwo(request))
            .await?
        {
            WireResponse::RoundTwo(response) => Ok(response),
            _ => Err(TransportError::Worker),
        }
    }

    pub async fn abort(&self, request: SignerAbortRequest) -> Result<(), TransportError> {
        self.ensure_identity(&request.context)?;
        match self
            .client
            .request(self.address, &WireRequest::Abort(request))
            .await?
        {
            WireResponse::Ack => Ok(()),
            _ => Err(TransportError::Worker),
        }
    }

    fn ensure_identity(&self, context: &SignerRequestContext) -> Result<(), TransportError> {
        if context.wallet_id != self.identity.wallet_id
            || context.signer_set_id != self.identity.signer_set_id
            || context.signer_epoch != self.identity.signer_epoch
            || context.signer_id != self.identity.signer_id
            || context.device_id != self.identity.device_id
            || context.device_generation != self.identity.device_generation
            || context.group_pubkey_xonly != self.identity.group_pubkey_xonly
            || context.verifying_share_digest != self.identity.verifying_share_digest
        {
            return Err(TransportError::Remote(WireErrorCode::IdentityDrift));
        }
        Ok(())
    }
}

async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    limits: TransportLimits,
) -> Result<T, TransportError> {
    let length = timeout(limits.io_timeout, stream.read_u32())
        .await
        .map_err(|_| TransportError::Timeout)?? as usize;
    if length == 0 || length > limits.max_frame_bytes {
        return Err(TransportError::FrameTooLarge);
    }
    let mut bytes = vec![0u8; length];
    timeout(limits.io_timeout, stream.read_exact(&mut bytes))
        .await
        .map_err(|_| TransportError::Timeout)??;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn write_frame<T: Serialize>(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    value: &T,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > limits.max_frame_bytes {
        return Err(TransportError::FrameTooLarge);
    }
    timeout(limits.io_timeout, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| TransportError::Timeout)??;
    Ok(())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
