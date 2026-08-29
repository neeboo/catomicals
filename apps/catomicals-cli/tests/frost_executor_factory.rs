#[path = "../src/frost_executor_factory.rs"]
mod frost_executor_factory;
#[path = "../src/multichain_wallet.rs"]
mod multichain_wallet;
#[path = "../src/wallet_executor_bootstrap.rs"]
mod wallet_executor_bootstrap;

use std::sync::Arc;

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash, sighash::TapSighashType, transaction,
};
use catomicals_chain_bitcoin::{
    BitcoinChainSuite, TaprootKeySpendRequest, TaprootReviewMaterial,
    derive_p2tr_output_key_address,
};
use catomicals_chain_domain::{
    BitcoinNetwork, ChainNetwork, ChainScope, ChainSuite, FractalBitcoinNetwork,
};
use catomicals_secret_store::{FileSecretBackend, RuntimeProfile, SecretBackend, SecretValue};
use catomicals_signer_transport::{
    MtlsSignerServer, TransportLimits, certificate_spki_sha256, private_ca_server_config,
};
use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    GuardedSignerProvider, LocalEncryptedFrostBackend, NonceGuard, ProviderError, ProviderIdentity,
    ProviderRequestAuthorizer, ProviderRound, SignerRequestContext, group_pubkey_xonly,
    participant_identifier, run_local_dkg,
};
use catomicals_wallet::{ChainSigningExecution, SignerProfileStartupSnapshot, SigningJob};
use frost_executor_factory::{
    FrostOnlineSignerV1, FrostProviderKindV1, FrostProviderSecretV1, FrostSignerManifestSource,
    FrostSignerManifestV1, FrostStartupExecutorBuilder, SecretBackedFrostProviderLoader,
    SharedFrostProviderRegistry,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::watch};
use uuid::Uuid;
use wallet_executor_bootstrap::StartupExecutorBuilder;

#[derive(Clone)]
struct BytesSource(Arc<Vec<u8>>);

impl FrostSignerManifestSource for BytesSource {
    fn load(&self, _secret_ref: &str) -> Result<Vec<u8>, String> {
        Ok(self.0.as_ref().clone())
    }
}

struct Allow;

impl ProviderRequestAuthorizer for Allow {
    fn authorize(
        &mut self,
        _context: &SignerRequestContext,
        _round: ProviderRound,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn certificate_leaf(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut parameters = CertificateParams::new(vec![name.to_owned()]).unwrap();
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = parameters.signed_by(&key, ca, ca_key).unwrap();
    (certificate, key)
}

async fn start_remote_signer<P: catomicals_threshold::SignerProvider + 'static>(
    provider: P,
    ca: &Certificate,
    signer_certificate: &Certificate,
    signer_key: &KeyPair,
    coordinator_pin: [u8; 32],
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), catomicals_signer_transport::TransportError>>,
) {
    let server_config = private_ca_server_config(
        CertificateDer::from(ca.der().to_vec()),
        vec![CertificateDer::from(signer_certificate.der().to_vec())],
        PrivatePkcs8KeyDer::from(signer_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let server = MtlsSignerServer::new(
        provider,
        server_config,
        coordinator_pin,
        TransportLimits::default(),
    );
    let task = tokio::spawn(server.serve(listener, receiver));
    (address, shutdown, task)
}

fn unsigned_transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([42; 32]), 1),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    }
}

#[test]
fn bitcoin_factory_runs_real_two_provider_frost_and_verifies_the_chain_signature() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let wallet_id = Uuid::from_bytes([0x11; 16]);
    let profile_id = Uuid::from_bytes([0x12; 16]);
    let signer_set_id = Uuid::from_bytes([0x13; 16]);
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let public = dkg.public_key_package.clone();
    let group_key = group_pubkey_xonly(&public).unwrap();
    let xonly = bitcoin::XOnlyPublicKey::from_slice(&group_key).unwrap();
    let secret_directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            secret_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let backend = Arc::new(
        FileSecretBackend::open(secret_directory.path(), RuntimeProfile::Development).unwrap(),
    );
    let mut signers = Vec::new();
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
            wallet_id,
            signer_set_id,
            signer_epoch: 7,
            signer_id,
            device_id: Uuid::from_bytes([0x20 + signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        let key_package = dkg.key_packages.remove(&identifier).unwrap();
        let provider_ref = backend
            .put_raw(SecretValue::new(
                serde_json::to_vec(&FrostProviderSecretV1::local_encrypted(
                    key_package.serialize().unwrap(),
                ))
                .unwrap(),
            ))
            .unwrap();
        signers.push(FrostOnlineSignerV1::from_identity(
            provider_ref,
            FrostProviderKindV1::LocalEncrypted,
            &identity,
            None,
        ));
    }
    let manifest = FrostSignerManifestV1::new(
        profile_id,
        wallet_id,
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        signer_set_id,
        7,
        public.serialize().unwrap(),
        signers.try_into().unwrap(),
    );
    let source = BytesSource(Arc::new(serde_json::to_vec(&manifest).unwrap()));
    let snapshot = SignerProfileStartupSnapshot {
        profile_id,
        wallet_id,
        chain_scope: scope,
        signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
        signer_set_id: signer_set_id.to_string(),
        authorization_signer_id: "passkey:owner".into(),
        signer_epoch: 7,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(group_key),
        secret_ref: "encrypted-file://manifests/bitcoin.json".into(),
        address_bindings: Vec::new(),
    };
    let loader = Arc::new(SecretBackedFrostProviderLoader::new(
        backend as Arc<dyn SecretBackend>,
    ));
    let builder = FrostStartupExecutorBuilder::with_loader(
        Box::new(source),
        SharedFrostProviderRegistry::new(),
        loader,
    );
    let executor = builder.build(&snapshot).unwrap();

    let address = derive_p2tr_output_key_address(scope, xonly).unwrap();
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Default,
    )
    .unwrap();
    let suite = BitcoinChainSuite::new(scope, xonly).unwrap();
    let material = TaprootReviewMaterial::from_request(&request)
        .unwrap()
        .encode()
        .unwrap();
    let review = suite.review_transaction(&material).unwrap();
    let review_binding = ReviewBinding::new(
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        signer_set_id.to_string(),
        7,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();
    let execution = ChainSigningExecution {
        job: SigningJob {
            job_id: Uuid::from_bytes([0x31; 16]),
            intent_id: Uuid::from_bytes([0x32; 16]),
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            review,
            review_binding,
            policy_snapshot_digest: [0x41; 32],
            chain_snapshot_digest: [0x42; 32],
            online_parties: ["wallet".into(), "desktop".into()],
            receiver: "wallet".into(),
            session_id: [0x43; 32],
            expires_at: 1_900_000_100,
            created_at: 1_900_000_000,
        },
        operation_binding_digest: [0x44; 32],
    };
    executor.execute(&execution, 1_900_000_001).unwrap();
}

#[test]
fn manifest_profile_epoch_or_group_key_drift_is_rejected_before_provider_use() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let wallet_id = Uuid::from_bytes([0x51; 16]);
    let profile_id = Uuid::from_bytes([0x52; 16]);
    let signer_set_id = Uuid::from_bytes([0x53; 16]);
    let dkg = run_local_dkg(3, 2).unwrap();
    let group_key = group_pubkey_xonly(&dkg.public_key_package).unwrap();
    let descriptors = [1_u16, 2].map(|signer_id| {
        let identifier = participant_identifier(signer_id).unwrap();
        let verifying_share_digest: [u8; 32] = Sha256::digest(
            dkg.public_key_package
                .verifying_shares()
                .get(&identifier)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .into();
        let identity = ProviderIdentity {
            wallet_id,
            signer_set_id,
            signer_epoch: 8,
            signer_id,
            device_id: Uuid::from_bytes([0x60 + signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        FrostOnlineSignerV1::from_identity(
            format!("local-encrypted://drift-{signer_id}"),
            FrostProviderKindV1::LocalEncrypted,
            &identity,
            None,
        )
    });
    let manifest = FrostSignerManifestV1::new(
        profile_id,
        wallet_id,
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        signer_set_id,
        8,
        dkg.public_key_package.serialize().unwrap(),
        descriptors,
    );
    let source = BytesSource(Arc::new(serde_json::to_vec(&manifest).unwrap()));
    let builder =
        FrostStartupExecutorBuilder::new(Box::new(source), SharedFrostProviderRegistry::new());
    let snapshot = SignerProfileStartupSnapshot {
        profile_id,
        wallet_id,
        chain_scope: scope,
        signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
        signer_set_id: signer_set_id.to_string(),
        authorization_signer_id: "passkey:owner".into(),
        signer_epoch: 7,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(group_key),
        secret_ref: "encrypted-file://manifests/drift.json".into(),
        address_bindings: Vec::new(),
    };
    assert!(builder.build(&snapshot).is_err());

    let mut profile_drift = snapshot.clone();
    profile_drift.signer_epoch = 8;
    profile_drift.profile_id = Uuid::from_bytes([0x54; 16]);
    assert!(builder.build(&profile_drift).is_err());

    let mut group_key_drift = snapshot;
    group_key_drift.signer_epoch = 8;
    group_key_drift.verification_key_hex = hex::encode([0x99; 32]);
    assert!(builder.build(&group_key_drift).is_err());
}

#[test]
fn fractal_factory_constructs_an_exact_executor_from_real_local_providers() {
    let scope =
        ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet));
    let wallet_id = Uuid::from_bytes([0x71; 16]);
    let profile_id = Uuid::from_bytes([0x72; 16]);
    let signer_set_id = Uuid::from_bytes([0x73; 16]);
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let public = dkg.public_key_package.clone();
    let group_key = group_pubkey_xonly(&public).unwrap();
    let registry = SharedFrostProviderRegistry::new();
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
            wallet_id,
            signer_set_id,
            signer_epoch: 9,
            signer_id,
            device_id: Uuid::from_bytes([0x80 + signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        let participant = catomicals_threshold::LocalFrostParticipant::new(
            signer_id,
            dkg.key_packages.remove(&identifier).unwrap(),
            NonceGuard::new(),
        )
        .unwrap();
        let provider = GuardedSignerProvider::new(
            identity.clone(),
            LocalEncryptedFrostBackend::new(participant, public.clone(), Allow),
        );
        let provider_ref = format!("local-encrypted://fractal-{signer_id}");
        registry
            .register(provider_ref.clone(), Box::new(provider), None)
            .unwrap();
        descriptors.push(FrostOnlineSignerV1::from_identity(
            provider_ref,
            FrostProviderKindV1::LocalEncrypted,
            &identity,
            None,
        ));
    }
    let manifest = FrostSignerManifestV1::new(
        profile_id,
        wallet_id,
        scope,
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        signer_set_id,
        9,
        public.serialize().unwrap(),
        descriptors.try_into().unwrap(),
    );
    let builder = FrostStartupExecutorBuilder::new(
        Box::new(BytesSource(Arc::new(
            serde_json::to_vec(&manifest).unwrap(),
        ))),
        registry,
    );
    let snapshot = SignerProfileStartupSnapshot {
        profile_id,
        wallet_id,
        chain_scope: scope,
        signing_suite_id: SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
        signer_set_id: signer_set_id.to_string(),
        authorization_signer_id: "passkey:owner".into(),
        signer_epoch: 9,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(group_key),
        secret_ref: "encrypted-file://manifests/fractal.json".into(),
        address_bindings: Vec::new(),
    };
    let executor = builder.build(&snapshot).unwrap();
    let key = executor.key();
    assert_eq!(key.profile_id, profile_id);
    assert_eq!(
        key.signing_suite_id,
        SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1
    );
}

#[test]
fn lazy_secret_loader_signs_with_two_distinct_remote_mtls_shares() {
    let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
    let wallet_id = Uuid::from_bytes([0xa1; 16]);
    let profile_id = Uuid::from_bytes([0xa2; 16]);
    let signer_set_id = Uuid::from_bytes([0xa3; 16]);
    let dkg = run_local_dkg(3, 2).unwrap();
    let public = dkg.public_key_package.clone();
    let group_key = group_pubkey_xonly(&public).unwrap();

    let mut ca_parameters = CertificateParams::new(Vec::new()).unwrap();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_parameters.self_signed(&ca_key).unwrap();
    let (coordinator_certificate, coordinator_key) = certificate_leaf(
        "coordinator.local",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    let coordinator_pin = certificate_spki_sha256(coordinator_certificate.der().as_ref()).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let secret_directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            secret_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let backend = Arc::new(
        FileSecretBackend::open(secret_directory.path(), RuntimeProfile::Development).unwrap(),
    );
    let ca_ref = backend
        .put_raw(SecretValue::new(ca.der().to_vec()))
        .unwrap();
    let coordinator_certificate_ref = backend
        .put_raw(SecretValue::new(coordinator_certificate.der().to_vec()))
        .unwrap();
    let coordinator_key_ref = backend
        .put_raw(SecretValue::new(coordinator_key.serialize_der()))
        .unwrap();

    let mut descriptors = Vec::new();
    let mut servers = Vec::new();
    for signer_id in [1_u16, 2] {
        let identifier = participant_identifier(signer_id).unwrap();
        let verifying_share_digest: [u8; 32] =
            Sha256::digest(public.verifying_shares()[&identifier].serialize().unwrap()).into();
        let identity = ProviderIdentity {
            wallet_id,
            signer_set_id,
            signer_epoch: 11,
            signer_id,
            device_id: Uuid::from_bytes([0xb0 + signer_id as u8; 16]),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        let participant = catomicals_threshold::LocalFrostParticipant::new(
            signer_id,
            dkg.key_packages[&identifier].clone(),
            NonceGuard::new(),
        )
        .unwrap();
        let provider = GuardedSignerProvider::new(
            identity.clone(),
            LocalEncryptedFrostBackend::new(participant, public.clone(), Allow),
        );
        let server_name = format!("signer-{signer_id}.local");
        let (server_certificate, server_key) = certificate_leaf(
            &server_name,
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let server_pin = certificate_spki_sha256(server_certificate.der().as_ref()).unwrap();
        let (address, shutdown, task) = runtime.block_on(start_remote_signer(
            provider,
            &ca,
            &server_certificate,
            &server_key,
            coordinator_pin,
        ));
        servers.push((shutdown, task));
        let encrypted_configuration = FrostProviderSecretV1::remote_mtls(
            address.to_string(),
            server_name,
            ca_ref.clone(),
            vec![coordinator_certificate_ref.clone()],
            coordinator_key_ref.clone(),
        );
        let provider_ref = backend
            .put_raw(SecretValue::new(
                serde_json::to_vec(&encrypted_configuration).unwrap(),
            ))
            .unwrap();
        descriptors.push(FrostOnlineSignerV1::from_identity(
            provider_ref,
            FrostProviderKindV1::RemoteMtls,
            &identity,
            Some(server_pin),
        ));
    }
    assert_ne!(descriptors[0].provider_ref, descriptors[1].provider_ref);
    assert_ne!(
        descriptors[0].verifying_share_digest_hex,
        descriptors[1].verifying_share_digest_hex
    );

    let manifest = FrostSignerManifestV1::new(
        profile_id,
        wallet_id,
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        signer_set_id,
        11,
        public.serialize().unwrap(),
        descriptors.try_into().unwrap(),
    );
    let serialized_manifest = serde_json::to_vec(&manifest).unwrap();
    assert!(!String::from_utf8_lossy(&serialized_manifest).contains("PRIVATE KEY"));
    let secret_backend: Arc<dyn SecretBackend> = backend;
    let loader = Arc::new(SecretBackedFrostProviderLoader::new(Arc::clone(
        &secret_backend,
    )));
    let builder = FrostStartupExecutorBuilder::with_loader(
        Box::new(BytesSource(Arc::new(serialized_manifest))),
        SharedFrostProviderRegistry::new(),
        loader,
    );
    let snapshot = SignerProfileStartupSnapshot {
        profile_id,
        wallet_id,
        chain_scope: scope,
        signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
        signer_set_id: signer_set_id.to_string(),
        authorization_signer_id: "passkey:owner".into(),
        signer_epoch: 11,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(group_key),
        secret_ref: "encrypted-file://manifests/remote.json".into(),
        address_bindings: Vec::new(),
    };
    let executor = builder.build(&snapshot).unwrap();
    let xonly = bitcoin::XOnlyPublicKey::from_slice(&group_key).unwrap();
    let address = derive_p2tr_output_key_address(scope, xonly).unwrap();
    let request = TaprootKeySpendRequest::new(
        scope,
        unsigned_transaction(),
        vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        }],
        0,
        TapSighashType::Default,
    )
    .unwrap();
    let suite = BitcoinChainSuite::new(scope, xonly).unwrap();
    let material = TaprootReviewMaterial::from_request(&request)
        .unwrap()
        .encode()
        .unwrap();
    let review = suite.review_transaction(&material).unwrap();
    let review_binding = ReviewBinding::new(
        scope,
        SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        signer_set_id.to_string(),
        11,
        review.schema_version,
        review.review_digest,
    )
    .unwrap();
    let execution = ChainSigningExecution {
        job: SigningJob {
            job_id: Uuid::from_bytes([0xc1; 16]),
            intent_id: Uuid::from_bytes([0xc2; 16]),
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            review,
            review_binding,
            policy_snapshot_digest: [0xc3; 32],
            chain_snapshot_digest: [0xc4; 32],
            online_parties: ["remote-1".into(), "remote-2".into()],
            receiver: "wallet".into(),
            session_id: [0xc5; 32],
            expires_at: 1_900_000_100,
            created_at: 1_900_000_000,
        },
        operation_binding_digest: [0xc6; 32],
    };
    executor.execute(&execution, 1_900_000_001).unwrap();

    let mut wrong_pin_manifest = manifest;
    wrong_pin_manifest.online_signers[0].mtls_spki_sha256_hex = Some(hex::encode([0xff; 32]));
    let wrong_pin_builder = FrostStartupExecutorBuilder::with_loader(
        Box::new(BytesSource(Arc::new(
            serde_json::to_vec(&wrong_pin_manifest).unwrap(),
        ))),
        SharedFrostProviderRegistry::new(),
        Arc::new(SecretBackedFrostProviderLoader::new(secret_backend)),
    );
    let wrong_pin_executor = wrong_pin_builder.build(&snapshot).unwrap();
    assert!(
        wrong_pin_executor
            .execute(&execution, 1_900_000_001)
            .is_err()
    );

    runtime.block_on(async move {
        for (shutdown, task) in servers {
            shutdown.send(true).unwrap();
            task.await.unwrap().unwrap();
        }
    });
}
