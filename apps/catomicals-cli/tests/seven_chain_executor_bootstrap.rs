#![cfg(unix)]

#[path = "../src/cbmpc_executor_factory.rs"]
#[allow(dead_code)]
mod cbmpc_executor_factory;
#[path = "../src/chia_ergo_executor_factory.rs"]
#[allow(dead_code)]
mod chia_ergo_executor_factory;
#[path = "../src/frost_executor_factory.rs"]
#[allow(dead_code)]
mod frost_executor_factory;
#[path = "../src/multichain_wallet.rs"]
mod multichain_wallet;
#[path = "../src/wallet_executor_bootstrap.rs"]
mod wallet_executor_bootstrap;

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use catomicals_cb_mpc_signer::{
    CbMpcError, CbMpcRuntimeLimits, CbMpcShareProtector, CbMpcSignerSet, PartyId,
    SecretShareMaterial, SessionTransport, TransportFailure, generate_native_provider_2_of_3,
};
use catomicals_chain_chia::{
    ThresholdBlsDealerKeyKind, dealer_split_threshold_secret_2_of_3 as chia_dealer_split,
};
use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainId, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
use catomicals_chain_ergo::dealer_split_threshold_secret_2_of_3 as ergo_dealer_split;
use catomicals_secret_store::{FileSecretBackend, RuntimeProfile, SecretBackend, SecretValue};
use catomicals_signer_transport::certificate_spki_sha256;
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    ProviderIdentity, group_pubkey_xonly, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    ChainSigningExecutor, RelyingPartyConfig, SignerProfileStartupSnapshot, WalletNodeService,
};
use cbmpc_executor_factory::{
    CB_MPC_MANIFEST_VERSION, CB_MPC_PROTOCOL_STAGES, CB_MPC_TLS_IDENTITY_VERSION,
    CbMpcExecutorManifestV1, CbMpcFactoryError, CbMpcProductionExecutorBuilder, CbMpcSignerRefV1,
    CbMpcTlsIdentityRefsV1, OpaqueSecretResolver,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use chia_ergo_executor_factory::{
    ThresholdSecretResolver, ThresholdShareReference, chia_ergo_startup_builders,
    encode_chia_threshold_manifest, encode_ergo_threshold_manifest,
};
use frost_executor_factory::{
    FrostOnlineSignerV1, FrostProviderKindV1, FrostProviderSecretV1, FrostSignerManifestSource,
    FrostSignerManifestV1, FrostStartupExecutorBuilder, SecretBackedFrostProviderLoader,
    SharedFrostProviderRegistry,
};
use rand::{RngCore, rngs::OsRng};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wallet_executor_bootstrap::{
    ExecutorFactoryError, ExecutorRegistrationState, StartupExecutorBuilder,
    WalletSnapshotProfileInventory, bootstrap_wallet_executors, snapshot_backed_factories,
};

const WALLET_ID: Uuid = Uuid::from_bytes([0x11; 16]);
const SIGNER_SET_ID: &str = "personal-seven-chain-2-of-3";
const SIGNER_EPOCH: u64 = 1;
const SHARE_ENVELOPE_VERSION: u8 = 1;
const SHARE_AAD_DOMAIN: &[u8] = b"catomicals.cb-mpc.share-envelope.v1\0";

#[derive(Default)]
struct SecretMap(Mutex<HashMap<String, Vec<u8>>>);

impl SecretMap {
    fn insert(&self, reference: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.0
            .lock()
            .unwrap()
            .insert(reference.into(), bytes.into());
    }
}

impl OpaqueSecretResolver for SecretMap {
    fn resolve(&self, reference: &str) -> Result<SecretValue, CbMpcFactoryError> {
        self.0
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .map(SecretValue::new)
            .ok_or(CbMpcFactoryError::SecretUnavailable)
    }
}

impl ThresholdSecretResolver for SecretMap {
    fn resolve(&self, reference: &str) -> Result<SecretValue, String> {
        self.0
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .map(SecretValue::new)
            .ok_or_else(|| format!("missing secret: {reference}"))
    }
}

struct ManifestMap(HashMap<String, Vec<u8>>);

impl FrostSignerManifestSource for ManifestMap {
    fn load(&self, secret_ref: &str) -> Result<Vec<u8>, String> {
        self.0
            .get(secret_ref)
            .cloned()
            .ok_or_else(|| format!("missing manifest: {secret_ref}"))
    }
}

struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    available: Condvar,
}

impl Queue {
    fn new() -> Self {
        Self {
            frames: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
        }
    }
}

struct MemoryNetwork {
    queues: Vec<Vec<Queue>>,
}

impl MemoryNetwork {
    fn new(party_count: usize) -> Arc<Self> {
        Arc::new(Self {
            queues: (0..party_count)
                .map(|_| (0..party_count).map(|_| Queue::new()).collect())
                .collect(),
        })
    }

    fn transport(self: &Arc<Self>, self_index: usize) -> MemoryTransport {
        MemoryTransport {
            network: Arc::clone(self),
            self_index,
        }
    }
}

struct MemoryTransport {
    network: Arc<MemoryNetwork>,
    self_index: usize,
}

impl SessionTransport for MemoryTransport {
    fn send(
        &self,
        receiver: usize,
        frame: &[u8],
        _deadline: Instant,
    ) -> Result<(), TransportFailure> {
        let queue = self
            .network
            .queues
            .get(receiver)
            .and_then(|senders| senders.get(self.self_index))
            .ok_or(TransportFailure::Terminated)?;
        queue.frames.lock().unwrap().push_back(frame.to_vec());
        queue.available.notify_one();
        Ok(())
    }

    fn receive(&self, sender: usize, deadline: Instant) -> Result<Vec<u8>, TransportFailure> {
        let queue = self
            .network
            .queues
            .get(self.self_index)
            .and_then(|senders| senders.get(sender))
            .ok_or(TransportFailure::Terminated)?;
        let mut frames = queue.frames.lock().unwrap();
        loop {
            if let Some(frame) = frames.pop_front() {
                return Ok(frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TransportFailure::Timeout);
            }
            let (next, timeout) = queue
                .available
                .wait_timeout(frames, deadline - now)
                .unwrap();
            frames = next;
            if timeout.timed_out() && frames.is_empty() {
                return Err(TransportFailure::Timeout);
            }
        }
    }
}

struct ProductionCbMpcAdapter(CbMpcProductionExecutorBuilder);

impl StartupExecutorBuilder for ProductionCbMpcAdapter {
    fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
        self.0.build(snapshot).map_err(|error| match error {
            CbMpcFactoryError::UnsupportedSuite => ExecutorFactoryError::UnsupportedProfile,
            CbMpcFactoryError::ManifestInvalid
            | CbMpcFactoryError::ManifestBindingMismatch
            | CbMpcFactoryError::TlsIdentityInvalid => ExecutorFactoryError::InvalidConfiguration,
            CbMpcFactoryError::SecretUnavailable
            | CbMpcFactoryError::ShareUnavailable
            | CbMpcFactoryError::TransportUnavailable
            | CbMpcFactoryError::ClaimStoreUnavailable
            | CbMpcFactoryError::RuntimeUnavailable => ExecutorFactoryError::ProviderUnavailable,
        })
    }
}

struct ProductionEnvelope {
    key: [u8; 32],
    binding: [u8; 32],
}

impl CbMpcShareProtector for ProductionEnvelope {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, CbMpcError> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = SHARE_AAD_DOMAIN.to_vec();
        aad.extend_from_slice(&self.binding);
        let ciphertext = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| CbMpcError::ShareMismatch)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| CbMpcError::ShareMismatch)?;
        let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        envelope.push(SHARE_ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn open(&self, _sealed: &[u8]) -> Result<SecretShareMaterial, CbMpcError> {
        Err(CbMpcError::ShareMismatch)
    }
}

fn snapshot(
    discriminator: u8,
    network: ChainNetwork,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
    verification_key: &[u8],
    secret_ref: impl Into<String>,
) -> SignerProfileStartupSnapshot {
    SignerProfileStartupSnapshot {
        profile_id: Uuid::from_bytes([discriminator; 16]),
        wallet_id: WALLET_ID,
        chain_scope: ChainScope::for_network(network),
        signing_suite_id: suite,
        backend_requirement: backend,
        signer_set_id: SIGNER_SET_ID.to_owned(),
        authorization_signer_id: "passkey:owner".to_owned(),
        signer_epoch: SIGNER_EPOCH,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(verification_key),
        secret_ref: secret_ref.into(),
        address_bindings: Vec::new(),
    }
}

fn frost_material() -> (
    Vec<SignerProfileStartupSnapshot>,
    Box<dyn StartupExecutorBuilder>,
    tempfile::TempDir,
) {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let public = dkg.public_key_package.clone();
    let group_key = group_pubkey_xonly(&public).unwrap();
    let signer_set_id =
        Uuid::parse_str(SIGNER_SET_ID).unwrap_or_else(|_| Uuid::from_bytes([0x19; 16]));
    let secret_directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let backend = Arc::new(
        FileSecretBackend::open(secret_directory.path(), RuntimeProfile::Development).unwrap(),
    );
    let mut descriptors = Vec::new();
    for signer_id in [1_u16, 2] {
        let identifier = participant_identifier(signer_id).unwrap();
        let verifying_share_digest: [u8; 32] = Sha256::digest(
            public
                .verifying_shares()
                .get(&identifier)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .into();
        let identity = ProviderIdentity {
            wallet_id: WALLET_ID,
            signer_set_id,
            signer_epoch: SIGNER_EPOCH,
            signer_id,
            device_id: Uuid::from_bytes([0x20 + signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        let provider_ref = backend
            .put_raw(SecretValue::new(
                serde_json::to_vec(&FrostProviderSecretV1::local_encrypted(
                    dkg.key_packages
                        .remove(&identifier)
                        .unwrap()
                        .serialize()
                        .unwrap(),
                ))
                .unwrap(),
            ))
            .unwrap();
        descriptors.push(FrostOnlineSignerV1::from_identity(
            provider_ref,
            FrostProviderKindV1::LocalEncrypted,
            &identity,
            None,
        ));
    }
    let descriptors: [FrostOnlineSignerV1; 2] = descriptors.try_into().unwrap();
    let bitcoin_ref = "encrypted-file://manifests/bitcoin.json".to_owned();
    let fractal_ref = "encrypted-file://manifests/fractal.json".to_owned();
    let mut bitcoin = snapshot(
        0x31,
        ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        &group_key,
        bitcoin_ref.clone(),
    );
    let mut fractal = snapshot(
        0x34,
        ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet),
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        SignerBackendRequirement::FrostSecp256k1Tr,
        &group_key,
        fractal_ref.clone(),
    );
    bitcoin.signer_set_id = signer_set_id.to_string();
    fractal.signer_set_id = signer_set_id.to_string();
    let manifests = HashMap::from([
        (
            bitcoin_ref,
            serde_json::to_vec(&FrostSignerManifestV1::new(
                bitcoin.profile_id,
                WALLET_ID,
                bitcoin.chain_scope,
                bitcoin.signing_suite_id,
                signer_set_id,
                SIGNER_EPOCH,
                public.serialize().unwrap(),
                descriptors.clone(),
            ))
            .unwrap(),
        ),
        (
            fractal_ref,
            serde_json::to_vec(&FrostSignerManifestV1::new(
                fractal.profile_id,
                WALLET_ID,
                fractal.chain_scope,
                fractal.signing_suite_id,
                signer_set_id,
                SIGNER_EPOCH,
                public.serialize().unwrap(),
                descriptors,
            ))
            .unwrap(),
        ),
    ]);
    let loader = Arc::new(SecretBackedFrostProviderLoader::new(
        backend as Arc<dyn SecretBackend>,
    ));
    let builder = FrostStartupExecutorBuilder::with_loader(
        Box::new(ManifestMap(manifests)),
        SharedFrostProviderRegistry::new(),
        loader,
    );
    (
        [bitcoin, fractal].into(),
        Box::new(builder),
        secret_directory,
    )
}

fn cbmpc_material() -> (
    Vec<SignerProfileStartupSnapshot>,
    Arc<SecretMap>,
    Box<dyn StartupExecutorBuilder>,
    tempfile::TempDir,
) {
    let parties = ["desktop", "mobile-backup", "onepassword"]
        .map(|party| PartyId::new(party).unwrap())
        .to_vec();
    let signer_set = CbMpcSignerSet::new(SIGNER_SET_ID, SIGNER_EPOCH, 2, parties).unwrap();
    let network = MemoryNetwork::new(3);
    let transports = [
        network.transport(0),
        network.transport(1),
        network.transport(2),
    ];
    let limits = CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(90),
        4 * 1024 * 1024,
    )
    .unwrap();
    let providers = generate_native_provider_2_of_3(
        &signer_set,
        [&transports[0], &transports[1], &transports[2]],
        limits,
        &catomicals_cb_mpc_signer::CbMpcCancellation::new(),
    )
    .unwrap();
    let group_key = providers[0].group_public_key();
    let resolver = Arc::new(SecretMap::default());
    let tls_refs = install_tls_secrets();
    let cases = [
        (
            0x32,
            ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            "bitcoin-cash",
        ),
        (
            0x33,
            ChainNetwork::Bsv(BsvNetwork::Testnet),
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            "bsv",
        ),
        (
            0x35,
            ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
            SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
            "kaspa",
        ),
    ];
    let mut snapshots = Vec::new();
    for (discriminator, network, suite, name) in cases {
        let manifest_ref = format!("test://manifest/{name}");
        let snapshot = snapshot(
            discriminator,
            network,
            suite,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
            &group_key,
            manifest_ref.clone(),
        );
        let signers = [
            CbMpcSignerRefV1 {
                party_id: "desktop".to_owned(),
                device_ref: "device://desktop".to_owned(),
                sealed_share_ref: format!("test://share/{name}/desktop"),
                protector_key_ref: format!("test://key/{name}/desktop"),
                endpoint_ref: "unix://cbmpc/desktop".to_owned(),
                tls_identity_ref: "test://tls/server".to_owned(),
            },
            CbMpcSignerRefV1 {
                party_id: "mobile-backup".to_owned(),
                device_ref: "device://mobile-backup".to_owned(),
                sealed_share_ref: format!("test://share/{name}/mobile-backup"),
                protector_key_ref: format!("test://key/{name}/mobile-backup"),
                endpoint_ref: "unix://cbmpc/mobile-backup".to_owned(),
                tls_identity_ref: "test://tls/client".to_owned(),
            },
        ];
        let manifest = CbMpcExecutorManifestV1 {
            format_version: CB_MPC_MANIFEST_VERSION,
            wallet_id: WALLET_ID,
            profile_id: snapshot.profile_id,
            chain_scope: snapshot.chain_scope,
            signing_suite_id: snapshot.signing_suite_id,
            signer_set_id: SIGNER_SET_ID.to_owned(),
            signer_epoch: SIGNER_EPOCH,
            protocol_stages: CB_MPC_PROTOCOL_STAGES,
            all_parties: [
                "desktop".to_owned(),
                "mobile-backup".to_owned(),
                "onepassword".to_owned(),
            ],
            active_signers: signers.clone(),
            recovery_signer: None,
            receiver: "desktop".to_owned(),
        };
        manifest.validate_for(&snapshot).unwrap();
        resolver.insert(manifest_ref, serde_json::to_vec(&manifest).unwrap());
        for (provider, signer) in providers[..2].iter().zip(signers.iter()) {
            let key = [discriminator.wrapping_add(signer.party_id.len() as u8); 32];
            let binding = share_binding(&snapshot, &manifest, signer);
            let sealed = provider
                .seal_for_persistence(&ProductionEnvelope { key, binding })
                .unwrap();
            resolver.insert(&signer.protector_key_ref, key);
            resolver.insert(&signer.sealed_share_ref, sealed);
        }
        snapshots.push(snapshot);
    }
    for (reference, bytes) in tls_refs {
        resolver.insert(reference, bytes);
    }
    let claim_root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(claim_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let builder = CbMpcProductionExecutorBuilder::new(
        Arc::clone(&resolver) as Arc<dyn OpaqueSecretResolver>,
        claim_root.path().canonicalize().unwrap(),
    )
    .unwrap();
    (
        snapshots,
        resolver,
        Box::new(ProductionCbMpcAdapter(builder)),
        claim_root,
    )
}

fn share_binding(
    snapshot: &SignerProfileStartupSnapshot,
    manifest: &CbMpcExecutorManifestV1,
    signer: &CbMpcSignerRefV1,
) -> [u8; 32] {
    #[derive(Serialize)]
    struct Binding<'a> {
        wallet_id: Uuid,
        profile_id: Uuid,
        chain_scope: ChainScope,
        signing_suite_id: SigningSuiteId,
        signer_set_id: &'a str,
        signer_epoch: u64,
        party_id: &'a str,
        device_ref: &'a str,
        endpoint_ref: &'a str,
    }
    Sha256::digest(
        serde_jcs::to_vec(&Binding {
            wallet_id: snapshot.wallet_id,
            profile_id: snapshot.profile_id,
            chain_scope: snapshot.chain_scope,
            signing_suite_id: snapshot.signing_suite_id,
            signer_set_id: &manifest.signer_set_id,
            signer_epoch: manifest.signer_epoch,
            party_id: &signer.party_id,
            device_ref: &signer.device_ref,
            endpoint_ref: &signer.endpoint_ref,
        })
        .unwrap(),
    )
    .into()
}

fn install_tls_secrets() -> Vec<(String, Vec<u8>)> {
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let (server, server_key) = tls_leaf(
        "cbmpc.local",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let (client, client_key) = tls_leaf(
        "cbmpc-client.local",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    let server_pin = certificate_spki_sha256(server.der().as_ref()).unwrap();
    let client_pin = certificate_spki_sha256(client.der().as_ref()).unwrap();
    let server_refs = CbMpcTlsIdentityRefsV1 {
        format_version: CB_MPC_TLS_IDENTITY_VERSION,
        certificate_der_ref: "test://tls/server-cert".to_owned(),
        private_key_pkcs8_der_ref: "test://tls/server-key".to_owned(),
        peer_ca_certificate_der_ref: "test://tls/ca".to_owned(),
        peer_spki_sha256_ref: "test://tls/client-pin".to_owned(),
    };
    let client_refs = CbMpcTlsIdentityRefsV1 {
        format_version: CB_MPC_TLS_IDENTITY_VERSION,
        certificate_der_ref: "test://tls/client-cert".to_owned(),
        private_key_pkcs8_der_ref: "test://tls/client-key".to_owned(),
        peer_ca_certificate_der_ref: "test://tls/ca".to_owned(),
        peer_spki_sha256_ref: "test://tls/server-pin".to_owned(),
    };
    vec![
        (
            "test://tls/server".to_owned(),
            serde_json::to_vec(&server_refs).unwrap(),
        ),
        (
            "test://tls/client".to_owned(),
            serde_json::to_vec(&client_refs).unwrap(),
        ),
        ("test://tls/ca".to_owned(), ca.der().to_vec()),
        ("test://tls/server-cert".to_owned(), server.der().to_vec()),
        (
            "test://tls/server-key".to_owned(),
            server_key.serialize_der(),
        ),
        ("test://tls/client-pin".to_owned(), client_pin.to_vec()),
        ("test://tls/client-cert".to_owned(), client.der().to_vec()),
        (
            "test://tls/client-key".to_owned(),
            client_key.serialize_der(),
        ),
        ("test://tls/server-pin".to_owned(), server_pin.to_vec()),
    ]
}

fn tls_leaf(
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

fn chia_ergo_material(
    resolver: &Arc<SecretMap>,
) -> (Vec<SignerProfileStartupSnapshot>, tempfile::TempDir) {
    let chia = chia_dealer_split(
        ThresholdBlsDealerKeyKind::FinalSigningKey,
        [0x61; 32],
        [0x62; 32],
    )
    .unwrap();
    let chia_snapshot = snapshot(
        0x36,
        ChainNetwork::Chia(ChiaNetwork::Testnet11),
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        &chia.commitment().group_public_key(),
        "test://manifest/chia",
    );
    let chia_refs = [
        ThresholdShareReference::new(1, "test://share/chia/1").unwrap(),
        ThresholdShareReference::new(3, "test://share/chia/3").unwrap(),
    ];
    let chia_manifest = encode_chia_threshold_manifest(
        &chia_snapshot,
        chia.commitment().coefficient_public_key(),
        chia_refs,
    )
    .unwrap();
    resolver.insert(&chia_snapshot.secret_ref, chia_manifest.expose().to_vec());
    resolver.insert(
        "test://share/chia/1",
        chia.shares()[0].export_for_provisioning().to_vec(),
    );
    resolver.insert(
        "test://share/chia/3",
        chia.shares()[2].export_for_provisioning().to_vec(),
    );

    let mut first = [0_u8; 32];
    first[31] = 5;
    let mut second = [0_u8; 32];
    second[31] = 7;
    let ergo = ergo_dealer_split(first, second).unwrap();
    let ergo_snapshot = snapshot(
        0x37,
        ChainNetwork::Ergo(ErgoNetwork::Testnet),
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        &ergo.commitment().group_public_key(),
        "test://manifest/ergo",
    );
    let ergo_refs = [
        ThresholdShareReference::new(1, "test://share/ergo/1").unwrap(),
        ThresholdShareReference::new(2, "test://share/ergo/2").unwrap(),
    ];
    let ergo_manifest = encode_ergo_threshold_manifest(
        &ergo_snapshot,
        ergo.commitment().coefficient_public_key(),
        ergo_refs,
    )
    .unwrap();
    resolver.insert(&ergo_snapshot.secret_ref, ergo_manifest.expose().to_vec());
    resolver.insert(
        "test://share/ergo/1",
        ergo.shares()[0].export_for_provisioning().to_vec(),
    );
    resolver.insert(
        "test://share/ergo/2",
        ergo.shares()[1].export_for_provisioning().to_vec(),
    );
    let replay_root = tempfile::tempdir().unwrap();
    ([chia_snapshot, ergo_snapshot].into(), replay_root)
}

#[test]
fn seven_real_chain_manifests_and_secret_providers_register_ready() {
    let (frost_snapshots, frost_builder, _frost_secrets) = frost_material();
    let (cbmpc_snapshots, resolver, cbmpc_builder, _claim_root) = cbmpc_material();
    let (threshold_snapshots, replay_root) = chia_ergo_material(&resolver);
    let mut snapshots = Vec::new();
    snapshots.extend(frost_snapshots);
    snapshots.extend(cbmpc_snapshots);
    snapshots.extend(threshold_snapshots);

    let mut builders = vec![
        (SignerBackendRequirement::FrostSecp256k1Tr, frost_builder),
        (SignerBackendRequirement::CbMpcThresholdEcdsa, cbmpc_builder),
    ];
    builders.extend(
        chia_ergo_startup_builders(
            Arc::clone(&resolver) as Arc<dyn ThresholdSecretResolver>,
            replay_root.path(),
        )
        .unwrap(),
    );
    let factories = snapshot_backed_factories(&snapshots, builders).unwrap();
    let inventory = WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(snapshots));
    let mut wallet = WalletNodeService::without_signer(RelyingPartyConfig::default()).unwrap();
    let mut surface = multichain_wallet::MultiChainWalletSurface::seven_chain_defaults();

    let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &factories);

    assert_eq!(report.inventory_error_code, None);
    assert_eq!(report.registrations.len(), 7, "{report:?}");
    assert!(
        report.registrations.iter().all(|registration| {
            registration.state == ExecutorRegistrationState::Registered
                && registration.error_code.is_none()
        }),
        "{report:?}"
    );
    let status = surface.status();
    assert_eq!(status.chains.len(), 7);
    assert!(status.chains.iter().all(|chain| {
        chain.ready_for_signing
            && chain.backend.state == multichain_wallet::BackendRuntimeState::Ready
            && chain.signer_profile.is_some()
    }));
    assert_eq!(
        status
            .chains
            .iter()
            .map(|chain| chain.chain_scope.chain)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ChainId::Bitcoin,
            ChainId::BitcoinCash,
            ChainId::Bsv,
            ChainId::FractalBitcoin,
            ChainId::Kaspa,
            ChainId::Chia,
            ChainId::Ergo,
        ])
    );
}
