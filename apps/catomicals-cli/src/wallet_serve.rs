//! Typed HTTP adapter for the self-hosted wallet node.

#[cfg(unix)]
#[allow(dead_code)] // Optional 1Password provisioning is outside wallet startup.
#[path = "cbmpc_executor_factory.rs"]
mod cbmpc_executor_factory;
#[allow(dead_code)] // Manifest encoders are used by provisioning tools.
#[path = "chia_ergo_executor_factory.rs"]
mod chia_ergo_executor_factory;
#[allow(dead_code)] // Remote provider registration is exercised by integration tests.
#[path = "frost_executor_factory.rs"]
mod frost_executor_factory;
#[path = "multichain_wallet.rs"]
mod multichain_wallet;
#[path = "wallet_chain_provision.rs"]
pub(crate) mod wallet_chain_provision;
#[path = "wallet_executor_bootstrap.rs"]
mod wallet_executor_bootstrap;

use std::{
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};

use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    ApprovalFinishRequest, CreateChainSigningJobRequest, CreateChatMessageRequest,
    CreateIntentRequest, CreateTradeIntentRequest, CreateTransactionIntentRequest,
    PasskeyRegistrationFinishRequest, PasskeyRegistrationStartRequest, RelyingPartyConfig,
    TradeSigningRequest, TransactionReviewRequest, WalletNodeError, WalletNodeService, WalletStore,
};
use catomicals_wallet_storage::RestoreState;
use serde::Serialize;
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::wallet::ServeArgs;

const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
const NODE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const HTTP_WORKER_COUNT: usize = 8;
const HTTP_REQUEST_QUEUE_CAPACITY: usize = 64;

pub fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let addr = args.addr.clone();
    if !is_loopback_bind(&addr) && !args.allow_non_loopback_bind {
        anyhow::bail!(
            "wallet server bind `{addr}` is not loopback; pass --allow-non-loopback-bind behind an HTTPS reverse proxy"
        );
    }

    let config = RelyingPartyConfig {
        rp_id: args.rp_id.clone(),
        rp_origin: args.rp_origin.clone(),
        rp_name: args.rp_name.clone(),
        ceremony_ttl_seconds: args.ceremony_ttl_seconds,
    };
    let now = unix_time();
    let (mut api, signer_lease) = if let Some(data_dir) = &args.data_dir {
        let wallet_id = uuid::Uuid::parse_str(&args.wallet_id)
            .map_err(|error| anyhow::anyhow!("invalid --wallet-id: {error}"))?;
        let store = crate::walletd::open_authority(data_dir, wallet_id, now)?;
        let authority_wallet_id = store
            .wallet_id()
            .ok_or_else(|| anyhow::anyhow!("durable wallet authority is not initialized"))?;
        let signer = open_durable_signer(
            data_dir,
            authority_wallet_id,
            args.signer_id,
            now,
            store.restore_state()?,
        )?;
        let min_signers = signer.min_signers();
        let (participant, public_key_package, _audit, lease) = signer.into_runtime_parts();
        (
            WalletNodeService::new_with_recovered_signer_store(
                config,
                participant,
                public_key_package,
                min_signers,
                Box::new(store),
                now,
            )?,
            Some(lease),
        )
    } else {
        let mut dkg = run_local_dkg(3, 2).map_err(|error| anyhow::anyhow!("local DKG: {error}"))?;
        let key_package = dkg
            .key_packages
            .remove(&participant_identifier(args.signer_id)?)
            .ok_or_else(|| anyhow::anyhow!("signer id must be in 1..=3"))?;
        let participant =
            LocalFrostParticipant::new(args.signer_id, key_package, NonceGuard::new())?;
        (
            WalletNodeService::new(config, Some(participant), dkg.public_key_package, 2)?,
            None,
        )
    };
    if let Some(node) = crate::wallet::probe_node_public(&args.node) {
        api.set_node_snapshot(Some(node));
    }

    let server = Server::http(&addr).map_err(|error| anyhow::anyhow!("binding {addr}: {error}"))?;
    let mut multichain_surface = multichain_wallet::MultiChainWalletSurface::seven_chain_defaults();
    let startup_snapshots = api.signer_profiles_snapshot();
    let (profile_inventory, executor_factories) = match startup_snapshots {
        Ok(snapshots) => {
            let inventory =
                wallet_executor_bootstrap::WalletSnapshotProfileInventory::from_wallet_snapshot(
                    Ok(snapshots.clone()),
                );
            let builders = match args.data_dir.as_deref() {
                Some(data_dir) => startup_executor_builders(
                    data_dir,
                    &snapshots,
                    args.allow_self_hosted_development_secrets,
                )?,
                None => Vec::new(),
            };
            let factories =
                wallet_executor_bootstrap::snapshot_backed_factories(&snapshots, builders)
                    .map_err(|_| {
                        anyhow::anyhow!("wallet executor factory configuration is invalid")
                    })?;
            (inventory, factories)
        }
        Err(error) => (
            wallet_executor_bootstrap::WalletSnapshotProfileInventory::from_wallet_snapshot(Err(
                error,
            )),
            Vec::new(),
        ),
    };
    let _bootstrap_report = wallet_executor_bootstrap::bootstrap_wallet_executors(
        &mut api,
        &mut multichain_surface,
        &profile_inventory,
        &executor_factories,
    );
    let state = Arc::new(Mutex::new(api));
    let multichain = Arc::new(Mutex::new(multichain_surface));
    spawn_node_refresh(Arc::clone(&state), args.node.clone())?;
    let cors = args.cors_origin.clone();

    println!("catomicals wallet server on http://{addr}");
    println!("  WebAuthn RP: {} at {}", args.rp_id, args.rp_origin);
    println!("  CORS origin: {cors}");
    if args.data_dir.is_some() {
        println!("  authority state: durable SQLite (schema checked; single writer)");
        println!("  signer: one recovered local participant");
        if args.allow_self_hosted_development_secrets {
            println!("  secret backend: self-hosted development");
        } else {
            println!("  secret backend: production resolver");
        }
    } else {
        println!(
            "  signer: {} (ephemeral local DKG; development only)",
            args.signer_id
        );
        println!("  persistence and secret storage: process memory only");
    }
    println!("  node RPC is never exposed by this service");

    let (request_tx, request_rx) =
        std::sync::mpsc::sync_channel::<Request>(HTTP_REQUEST_QUEUE_CAPACITY);
    let request_rx = Arc::new(Mutex::new(request_rx));
    let mut workers = Vec::with_capacity(HTTP_WORKER_COUNT);
    for worker_id in 0..HTTP_WORKER_COUNT {
        let request_rx = Arc::clone(&request_rx);
        let state = Arc::clone(&state);
        let multichain = Arc::clone(&multichain);
        let cors = cors.clone();
        workers.push(
            std::thread::Builder::new()
                .name(format!("catomicals-wallet-http-{worker_id}"))
                .spawn(move || {
                    loop {
                        let request = match request_rx.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(request) = request else {
                            return;
                        };
                        let _ = handle(&state, &multichain, &cors, request);
                    }
                })
                .map_err(|error| anyhow::anyhow!("starting wallet HTTP worker: {error}"))?,
        );
    }
    for request in server.incoming_requests() {
        if request_tx.send(request).is_err() {
            break;
        }
    }
    drop(request_tx);
    for worker in workers {
        let _ = worker.join();
    }
    drop(signer_lease);
    Ok(())
}

pub(super) fn startup_executor_builders(
    data_dir: &std::path::Path,
    snapshots: &[catomicals_wallet::SignerProfileStartupSnapshot],
    allow_self_hosted_development_secrets: bool,
) -> anyhow::Result<
    Vec<(
        catomicals_signing_domain::SignerBackendRequirement,
        Box<dyn wallet_executor_bootstrap::StartupExecutorBuilder>,
    )>,
> {
    use std::sync::Arc;

    use catomicals_secret_store::{SecretBackend, SecretBackendFactory};
    use catomicals_signing_domain::SignerBackendRequirement;

    if snapshots.is_empty() {
        return Ok(Vec::new());
    }
    let root = std::fs::canonicalize(data_dir)
        .map_err(|_| anyhow::anyhow!("wallet executor data directory is unavailable"))?;
    let manifest_root = root.join("executor-manifests");
    let secret_root = root.join("executor-secrets");
    let claims_root = root.join("executor-claims");
    ensure_private_executor_directory(&manifest_root)?;
    ensure_private_executor_directory(&claims_root)?;

    let mut builders: Vec<(
        SignerBackendRequirement,
        Box<dyn wallet_executor_bootstrap::StartupExecutorBuilder>,
    )> = Vec::new();

    let needs_frost = snapshots
        .iter()
        .any(|snapshot| snapshot.backend_requirement == SignerBackendRequirement::FrostSecp256k1Tr);
    let needs_threshold_secret_backend = snapshots.iter().any(|snapshot| {
        matches!(
            snapshot.backend_requirement,
            SignerBackendRequirement::CbMpcThresholdEcdsa
                | SignerBackendRequirement::ChiaBlsAugThreshold2of3
                | SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
        )
    });
    let secret_backend: Option<Arc<dyn SecretBackend>> =
        if needs_frost || needs_threshold_secret_backend {
            let factory = if allow_self_hosted_development_secrets {
                SecretBackendFactory::self_hosted_development(&secret_root)
            } else {
                SecretBackendFactory::production()
            };
            Some(
                factory
                    .resolve()
                    .map_err(|_| anyhow::anyhow!("executor secret backend is unavailable"))?,
            )
        } else {
            None
        };

    if needs_frost {
        let source = frost_executor_factory::FileFrostSignerManifestSource::new(&manifest_root)
            .map_err(|_| anyhow::anyhow!("FROST executor manifest store is unavailable"))?;
        let loader: Arc<dyn frost_executor_factory::FrostSignerProviderLoader> = Arc::new(
            frost_executor_factory::SecretBackedFrostProviderLoader::new(Arc::clone(
                secret_backend
                    .as_ref()
                    .expect("FROST startup requires a secret backend"),
            )),
        );
        builders.push((
            SignerBackendRequirement::FrostSecp256k1Tr,
            Box::new(
                frost_executor_factory::FrostStartupExecutorBuilder::with_loader(
                    Box::new(source),
                    frost_executor_factory::SharedFrostProviderRegistry::new(),
                    loader,
                ),
            ),
        ));
    }

    if needs_threshold_secret_backend {
        let backend = Arc::clone(
            secret_backend
                .as_ref()
                .expect("threshold startup requires a secret backend"),
        );

        #[cfg(unix)]
        if snapshots.iter().any(|snapshot| {
            snapshot.backend_requirement == SignerBackendRequirement::CbMpcThresholdEcdsa
        }) {
            let cb_mpc_claims = claims_root.join("cb-mpc");
            ensure_private_executor_directory(&cb_mpc_claims)?;
            let resolver: Arc<dyn cbmpc_executor_factory::OpaqueSecretResolver> = Arc::new(
                cbmpc_executor_factory::SecretBackendResolver::new(Arc::clone(&backend)),
            );
            let builder = cbmpc_executor_factory::cb_mpc_executor_builder(resolver, cb_mpc_claims)
                .map_err(|_| anyhow::anyhow!("CB-MPC executor runtime is unavailable"))?;
            builders.push((
                SignerBackendRequirement::CbMpcThresholdEcdsa,
                Box::new(CbMpcStartupBuilderAdapter(builder)),
            ));
        }

        if snapshots.iter().any(|snapshot| {
            matches!(
                snapshot.backend_requirement,
                SignerBackendRequirement::ChiaBlsAugThreshold2of3
                    | SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3
            )
        }) {
            let threshold_claims = claims_root.join("threshold");
            ensure_private_executor_directory(&threshold_claims)?;
            let resolver: Arc<dyn chia_ergo_executor_factory::ThresholdSecretResolver> =
                Arc::new(chia_ergo_executor_factory::SecretBackendThresholdResolver::new(backend));
            builders.extend(
                chia_ergo_executor_factory::chia_ergo_startup_builders(resolver, &threshold_claims)
                    .map_err(|_| anyhow::anyhow!("threshold executor runtime is unavailable"))?,
            );
        }
    }

    Ok(builders)
}

#[cfg(unix)]
struct CbMpcStartupBuilderAdapter(cbmpc_executor_factory::CbMpcProductionExecutorBuilder);

#[cfg(unix)]
impl wallet_executor_bootstrap::StartupExecutorBuilder for CbMpcStartupBuilderAdapter {
    fn build(
        &self,
        snapshot: &catomicals_wallet::SignerProfileStartupSnapshot,
    ) -> Result<
        Box<dyn catomicals_wallet::ChainSigningExecutor>,
        wallet_executor_bootstrap::ExecutorFactoryError,
    > {
        self.0.build(snapshot).map_err(|error| match error {
            cbmpc_executor_factory::CbMpcFactoryError::UnsupportedSuite => {
                wallet_executor_bootstrap::ExecutorFactoryError::UnsupportedProfile
            }
            cbmpc_executor_factory::CbMpcFactoryError::ManifestInvalid
            | cbmpc_executor_factory::CbMpcFactoryError::ManifestBindingMismatch
            | cbmpc_executor_factory::CbMpcFactoryError::TlsIdentityInvalid => {
                wallet_executor_bootstrap::ExecutorFactoryError::InvalidConfiguration
            }
            cbmpc_executor_factory::CbMpcFactoryError::SecretUnavailable
            | cbmpc_executor_factory::CbMpcFactoryError::ShareUnavailable
            | cbmpc_executor_factory::CbMpcFactoryError::TransportUnavailable
            | cbmpc_executor_factory::CbMpcFactoryError::ClaimStoreUnavailable
            | cbmpc_executor_factory::CbMpcFactoryError::RuntimeUnavailable => {
                wallet_executor_bootstrap::ExecutorFactoryError::ProviderUnavailable
            }
        })
    }
}

pub(super) fn ensure_private_executor_directory(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("executor state path is not a private directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            anyhow::bail!("executor state directory permissions are invalid");
        }
    }
    Ok(())
}

fn open_durable_signer(
    data_dir: &std::path::Path,
    wallet_id: uuid::Uuid,
    signer_id: u16,
    now: i64,
    restore_state: RestoreState,
) -> anyhow::Result<crate::persistent_signer::PersistentSigner> {
    if restore_state == RestoreState::Normal {
        crate::persistent_signer::PersistentSigner::open_or_initialize(
            data_dir, wallet_id, signer_id, now,
        )
    } else {
        crate::persistent_signer::PersistentSigner::open_existing(
            data_dir, wallet_id, signer_id,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "wallet authority is in {restore_state:?}; refusing to initialize a replacement signer: {error:#}"
            )
        })
    }
}

fn update_node_snapshot(
    state: &Mutex<WalletNodeService>,
    snapshot: Option<catomicals_wallet::NodeSnapshot>,
) {
    if let Ok(mut api) = state.lock() {
        api.set_node_snapshot(snapshot);
    }
}

fn spawn_node_refresh(
    state: Arc<Mutex<WalletNodeService>>,
    node: crate::NodeArgs,
) -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("catomicals-node-refresh".into())
        .spawn(move || {
            loop {
                std::thread::sleep(NODE_REFRESH_INTERVAL);
                update_node_snapshot(&state, crate::wallet::probe_node_public(&node));
            }
        })
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("starting node refresh worker: {error}"))
}

fn is_loopback_bind(addr: &str) -> bool {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost") && port.parse::<u16>().is_ok()
}

fn handle(
    state: &Mutex<WalletNodeService>,
    multichain: &Mutex<multichain_wallet::MultiChainWalletSurface>,
    cors: &str,
    mut request: Request,
) -> std::io::Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let result = if method == Method::Options {
        JsonResponse {
            status: 204,
            body: String::new(),
        }
    } else {
        match read_json_body(request.as_reader()) {
            Ok(body) => {
                dispatch_json_with_multichain(state, multichain, &method, &url, &body, unix_time())
            }
            Err(response) => response,
        }
    };
    respond(cors, request, result)
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod production_factory_tests {
    use super::*;
    use catomicals_chain_domain::{
        BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainId, ChainNetwork, ChainScope,
        ChiaNetwork, ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
    };
    use catomicals_secret_store::{FileSecretBackend, RuntimeProfile, SecretBackend, SecretValue};
    use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
    use catomicals_threshold::{
        ProviderIdentity, group_pubkey_xonly, participant_identifier, run_local_dkg,
    };
    use catomicals_wallet::SignerProfileStartupSnapshot;
    use sha2::{Digest, Sha256};

    fn startup_snapshot(
        discriminator: u8,
        network: ChainNetwork,
        suite: SigningSuiteId,
        backend: SignerBackendRequirement,
    ) -> SignerProfileStartupSnapshot {
        SignerProfileStartupSnapshot {
            profile_id: uuid::Uuid::from_bytes([discriminator; 16]),
            wallet_id: uuid::Uuid::from_bytes([0x71; 16]),
            chain_scope: ChainScope::for_network(network),
            signing_suite_id: suite,
            backend_requirement: backend,
            signer_set_id: uuid::Uuid::from_bytes([0x72; 16]).to_string(),
            authorization_signer_id: "passkey:owner".to_owned(),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
            verification_key_hex: "02".repeat(48),
            secret_ref: format!(
                "encrypted-file://{}",
                uuid::Uuid::from_bytes([discriminator.wrapping_add(0x20); 16])
            ),
            address_bindings: Vec::new(),
        }
    }

    fn seven_snapshots() -> Vec<SignerProfileStartupSnapshot> {
        vec![
            startup_snapshot(
                1,
                ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
                SigningSuiteId::BITCOIN_BIP340_FROST_V1,
                SignerBackendRequirement::FrostSecp256k1Tr,
            ),
            startup_snapshot(
                2,
                ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
                SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
            ),
            startup_snapshot(
                3,
                ChainNetwork::Bsv(BsvNetwork::Testnet),
                SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
            ),
            startup_snapshot(
                4,
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet),
                SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
                SignerBackendRequirement::FrostSecp256k1Tr,
            ),
            startup_snapshot(
                5,
                ChainNetwork::Kaspa(KaspaNetwork::Testnet11),
                SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
                SignerBackendRequirement::CbMpcThresholdEcdsa,
            ),
            startup_snapshot(
                6,
                ChainNetwork::Chia(ChiaNetwork::Testnet11),
                SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
                SignerBackendRequirement::ChiaBlsAugThreshold2of3,
            ),
            startup_snapshot(
                7,
                ChainNetwork::Ergo(ErgoNetwork::Testnet),
                SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
                SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
            ),
        ]
    }

    fn provision_local_frost_profile(
        directory: &std::path::Path,
        discriminator: u8,
        network: ChainNetwork,
        suite: SigningSuiteId,
    ) -> SignerProfileStartupSnapshot {
        let wallet_id = uuid::Uuid::from_bytes([0x71; 16]);
        let profile_id = uuid::Uuid::from_bytes([discriminator; 16]);
        let signer_set_id = uuid::Uuid::from_bytes([discriminator.wrapping_add(0x40); 16]);
        let signer_epoch = u64::from(discriminator);
        let scope = ChainScope::for_network(network);
        let mut dkg = run_local_dkg(3, 2).unwrap();
        let public = dkg.public_key_package.clone();
        let group_key = group_pubkey_xonly(&public).unwrap();
        let secret_root = directory.join("executor-secrets");
        let backend = FileSecretBackend::open(&secret_root, RuntimeProfile::Development).unwrap();
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
                signer_epoch,
                signer_id,
                device_id: uuid::Uuid::from_bytes(
                    [discriminator.wrapping_add(signer_id as u8); 16],
                ),
                device_generation: 1,
                group_pubkey_xonly: group_key,
                verifying_share_digest,
            };
            let key_package = dkg.key_packages.remove(&identifier).unwrap();
            let provider_secret = frost_executor_factory::FrostProviderSecretV1::local_encrypted(
                key_package.serialize().unwrap(),
            );
            let provider_ref = backend
                .put_raw(SecretValue::new(
                    serde_json::to_vec(&provider_secret).unwrap(),
                ))
                .unwrap();
            descriptors.push(frost_executor_factory::FrostOnlineSignerV1::from_identity(
                provider_ref,
                frost_executor_factory::FrostProviderKindV1::LocalEncrypted,
                &identity,
                None,
            ));
        }
        let manifest = frost_executor_factory::FrostSignerManifestV1::new(
            profile_id,
            wallet_id,
            scope,
            suite,
            signer_set_id,
            signer_epoch,
            public.serialize().unwrap(),
            descriptors.try_into().unwrap(),
        );
        let manifest_root = directory.join("executor-manifests");
        ensure_private_executor_directory(&manifest_root).unwrap();
        let manifest_name = format!("frost-{discriminator}.json");
        let manifest_path = manifest_root.join(&manifest_name);
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        SignerProfileStartupSnapshot {
            profile_id,
            wallet_id,
            chain_scope: scope,
            signing_suite_id: suite,
            backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
            signer_set_id: signer_set_id.to_string(),
            authorization_signer_id: "passkey:owner".to_owned(),
            signer_epoch,
            threshold: 2,
            max_signers: 3,
            verification_key_hex: hex::encode(group_key),
            secret_ref: format!("encrypted-file://{manifest_name}"),
            address_bindings: Vec::new(),
        }
    }

    #[test]
    fn self_hosted_startup_registers_real_bitcoin_and_fractal_frost_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let snapshots = vec![
            provision_local_frost_profile(
                directory.path(),
                0x11,
                ChainNetwork::Bitcoin(BitcoinNetwork::Signet),
                SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            ),
            provision_local_frost_profile(
                directory.path(),
                0x12,
                ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet),
                SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
            ),
        ];
        let builders = startup_executor_builders(directory.path(), &snapshots, true).unwrap();
        let factories =
            wallet_executor_bootstrap::snapshot_backed_factories(&snapshots, builders).unwrap();
        let inventory =
            wallet_executor_bootstrap::WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(
                snapshots,
            ));
        let mut wallet = WalletNodeService::without_signer(RelyingPartyConfig::default()).unwrap();
        let mut surface = multichain_wallet::MultiChainWalletSurface::seven_chain_defaults();

        let report = wallet_executor_bootstrap::bootstrap_wallet_executors(
            &mut wallet,
            &mut surface,
            &inventory,
            &factories,
        );

        assert_eq!(report.registrations.len(), 2);
        assert!(report.registrations.iter().all(|registration| {
            registration.state == wallet_executor_bootstrap::ExecutorRegistrationState::Registered
                && registration.error_code.is_none()
        }));
        let status = surface.status();
        for chain_id in [ChainId::Bitcoin, ChainId::FractalBitcoin] {
            let chain = status
                .chains
                .iter()
                .find(|chain| chain.chain_scope.chain == chain_id)
                .unwrap();
            assert!(chain.ready_for_signing);
            assert_eq!(
                chain.backend.state,
                multichain_wallet::BackendRuntimeState::Ready
            );
            assert!(chain.backend.error_code.is_none());
        }
    }

    #[test]
    fn self_hosted_startup_routes_all_seven_profiles_through_real_backend_builders() {
        let directory = tempfile::tempdir().unwrap();
        let snapshots = seven_snapshots();
        let builders = startup_executor_builders(directory.path(), &snapshots, true).unwrap();
        assert_eq!(builders.len(), 4);
        let factories =
            wallet_executor_bootstrap::snapshot_backed_factories(&snapshots, builders).unwrap();
        let inventory =
            wallet_executor_bootstrap::WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(
                snapshots,
            ));
        let mut wallet = WalletNodeService::without_signer(RelyingPartyConfig::default()).unwrap();
        let mut surface = multichain_wallet::MultiChainWalletSurface::seven_chain_defaults();

        let report = wallet_executor_bootstrap::bootstrap_wallet_executors(
            &mut wallet,
            &mut surface,
            &inventory,
            &factories,
        );

        assert_eq!(report.registrations.len(), 7);
        assert!(report.registrations.iter().all(|registration| {
            registration.state == wallet_executor_bootstrap::ExecutorRegistrationState::Failed
                && registration.error_code == Some("executor-provider-unavailable")
        }));
        assert!(surface.status().chains.iter().all(|chain| {
            !chain.ready_for_signing
                && chain.backend.error_code == Some("executor-provider-unavailable")
        }));
    }

    #[test]
    fn production_startup_fails_closed_without_a_production_secret_resolver() {
        let directory = tempfile::tempdir().unwrap();
        let snapshots = seven_snapshots();

        let error = match startup_executor_builders(directory.path(), &snapshots, false) {
            Ok(_) => panic!("production startup must require an injected secure backend"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "executor secret backend is unavailable");
        assert!(!directory.path().join("executor-secrets").exists());
    }
}

struct JsonResponse {
    status: u16,
    body: String,
}

fn read_json_body(mut reader: impl Read) -> Result<String, JsonResponse> {
    let mut bytes = Vec::with_capacity(4096);
    reader
        .by_ref()
        .take((MAX_HTTP_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            json_response(
                400,
                &json!({"error": {"code": "request_body_unreadable", "message": error.to_string()}}),
            )
        })?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err(json_response(
            413,
            &json!({"error": {
                "code": "request_body_too_large",
                "message": format!("request body exceeds {MAX_HTTP_BODY_BYTES} bytes")
            }}),
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_json", "message": error.to_string()}}),
        )
    })
}

fn json_response(status: u16, value: &impl Serialize) -> JsonResponse {
    JsonResponse {
        status,
        body: serde_json::to_string(value).unwrap_or_else(|_| {
            r#"{"error":{"code":"serialization","message":"response serialization failed"}}"#.into()
        }),
    }
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, JsonResponse> {
    serde_json::from_str(body).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_json", "message": error.to_string()}}),
        )
    })
}

fn parse_id(value: &str) -> Result<uuid::Uuid, JsonResponse> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_intent_id", "message": error.to_string()}}),
        )
    })
}

fn parse_chat_message_id(value: &str) -> Result<uuid::Uuid, JsonResponse> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_chat_message_id", "message": error.to_string()}}),
        )
    })
}

fn parse_signing_job_id(value: &str) -> Result<uuid::Uuid, JsonResponse> {
    uuid::Uuid::parse_str(value).map_err(|error| {
        json_response(
            400,
            &json!({"error": {"code": "invalid_signing_job_id", "message": error.to_string()}}),
        )
    })
}

fn node_error(error: WalletNodeError) -> JsonResponse {
    let (status, code) = match error {
        WalletNodeError::IntentNotFound => (404, "intent_not_found"),
        WalletNodeError::ChatMessageNotFound => (404, "chat_message_not_found"),
        WalletNodeError::CeremonyNotFound => (409, "ceremony_consumed_or_missing"),
        WalletNodeError::NoCredentials => (409, "passkey_required"),
        WalletNodeError::IntentNotPending
        | WalletNodeError::IntentExpired
        | WalletNodeError::IntentBindingMismatch
        | WalletNodeError::AuthorizationUnavailable
        | WalletNodeError::RecoveredIntentApprovalUnavailable
        | WalletNodeError::CeremonyExpired
        | WalletNodeError::CredentialAlreadyRegistered => (409, "state_conflict"),
        WalletNodeError::WebAuthn(_) | WalletNodeError::UserVerificationRequired => {
            (401, "webauthn_rejected")
        }
        WalletNodeError::TradeNodeUnavailable => (503, "trade_node_unavailable"),
        WalletNodeError::TradePolicy(_) => (422, "trade_policy_rejected"),
        WalletNodeError::TransactionPolicy(_) => (422, "transaction_policy_rejected"),
        WalletNodeError::InvalidChatMessage => (422, "invalid_chat_message"),
        WalletNodeError::ChatHistoryFull => (429, "chat_history_full"),
        _ => (400, "invalid_request"),
    };
    json_response(
        status,
        &json!({"error": {"code": code, "message": error.to_string()}}),
    )
}

fn chain_execution_error(error: WalletNodeError) -> JsonResponse {
    match error {
        WalletNodeError::IntentNotFound => json_response(
            404,
            &json!({"error": {"code": "signing_job_not_found", "message": "signing job not found"}}),
        ),
        WalletNodeError::SignerNotConfigured => json_response(
            503,
            &json!({"error": {"code": "signing_executor_unavailable", "message": error.to_string()}}),
        ),
        WalletNodeError::IntentExpired => json_response(
            409,
            &json!({"error": {"code": "signing_job_expired", "message": error.to_string()}}),
        ),
        WalletNodeError::ChainSigning(_) => json_response(
            422,
            &json!({"error": {"code": "chain_signing_failed", "message": error.to_string()}}),
        ),
        other => node_error(other),
    }
}

#[cfg(test)]
fn dispatch_json(
    state: &Mutex<WalletNodeService>,
    method: &Method,
    url: &str,
    body: &str,
    now: i64,
) -> JsonResponse {
    let multichain = Mutex::new(multichain_wallet::MultiChainWalletSurface::seven_chain_defaults());
    dispatch_json_with_multichain(state, &multichain, method, url, body, now)
}

fn dispatch_json_with_multichain(
    state: &Mutex<WalletNodeService>,
    multichain: &Mutex<multichain_wallet::MultiChainWalletSurface>,
    method: &Method,
    url: &str,
    body: &str,
    now: i64,
) -> JsonResponse {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    if let (&Method::Post, ["api", "v1", "signing", "jobs", job_id, "execute"]) =
        (method, segments.as_slice())
    {
        let job_id = match parse_signing_job_id(job_id) {
            Ok(job_id) => job_id,
            Err(response) => return response,
        };
        let claimed = {
            let mut api = match state.lock() {
                Ok(api) => api,
                Err(_) => {
                    return json_response(
                        500,
                        &json!({"error": {"code": "state_poisoned", "message": "wallet state unavailable"}}),
                    );
                }
            };
            match api.claim_chain_signing_job_execution(job_id, now) {
                Ok(claimed) => claimed,
                Err(error) => return chain_execution_error(error),
            }
        };

        // Provider/network work deliberately runs without the global wallet
        // mutex. The durable one-time claim above is already committed.
        let execution_result = claimed.execute(now);

        let mut api = match state.lock() {
            Ok(api) => api,
            Err(_) => {
                return json_response(
                    500,
                    &json!({"error": {"code": "state_poisoned", "message": "wallet state unavailable"}}),
                );
            }
        };
        return match api.complete_claimed_chain_signing_job(&claimed, execution_result, now) {
            Ok(value) => json_response(200, &value),
            Err(error) => chain_execution_error(error),
        };
    }

    let mut api = match state.lock() {
        Ok(api) => api,
        Err(_) => {
            return json_response(
                500,
                &json!({"error": {"code": "state_poisoned", "message": "wallet state unavailable"}}),
            );
        }
    };
    let result: Result<(u16, serde_json::Value), JsonResponse> = match (method, segments.as_slice())
    {
        (&Method::Get, ["api", "v1", "chains", "status"]) => {
            let chains = match multichain.lock() {
                Ok(chains) => chains,
                Err(_) => {
                    return json_response(
                        500,
                        &json!({"error": {"code": "chain_state_poisoned", "message": "chain runtime state unavailable"}}),
                    );
                }
            };
            return json_response(200, &chains.status());
        }
        (&Method::Get, ["api", "v1", "chains", "config"]) => {
            let chains = match multichain.lock() {
                Ok(chains) => chains,
                Err(_) => {
                    return json_response(
                        500,
                        &json!({"error": {"code": "chain_state_poisoned", "message": "chain runtime state unavailable"}}),
                    );
                }
            };
            return json_response(200, &chains.configuration());
        }
        (&Method::Post, ["api", "v1", "chains", "config"]) => {
            let request = match parse_body::<multichain_wallet::ConfigureChainRequest>(body) {
                Ok(request) => request,
                Err(response) => return response,
            };
            let mut chains = match multichain.lock() {
                Ok(chains) => chains,
                Err(_) => {
                    return json_response(
                        500,
                        &json!({"error": {"code": "chain_state_poisoned", "message": "chain runtime state unavailable"}}),
                    );
                }
            };
            return match chains.configure(request) {
                Ok(status) => json_response(200, &status),
                Err(error) => json_response(
                    422,
                    &json!({"error": {"code": error.code(), "message": error.to_string()}}),
                ),
            };
        }
        (&Method::Post, ["api", "v1", "signing", "jobs"]) => {
            parse_body::<CreateChainSigningJobRequest>(body)
                .and_then(|request| {
                    api.create_chain_signing_job(request, now)
                        .map_err(node_error)
                })
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "signing", "jobs", job_id]) => {
            parse_signing_job_id(job_id)
                .and_then(|job_id| {
                    api.chain_signing_job(job_id, now).map_err(|error| {
                        if error == WalletNodeError::IntentNotFound {
                            json_response(
                                404,
                                &json!({"error": {"code": "signing_job_not_found", "message": "signing job not found"}}),
                            )
                        } else {
                            node_error(error)
                        }
                    })
                })
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "node", "status"]) => {
            return json_response(200, &api.node_status());
        }
        (&Method::Get, ["api", "v1", "wallet", "status"]) | (&Method::Get, ["api", "status"]) => {
            return json_response(200, &api.wallet_status());
        }
        (&Method::Get, ["api", "v1", "signer", "status"]) => {
            return json_response(200, &api.signer_status());
        }
        (&Method::Get, ["api", "v1", "webauthn", "credentials"]) => {
            return json_response(200, &api.credentials());
        }
        (&Method::Get, ["api", "v1", "intents"]) => {
            return json_response(200, &api.list_intents());
        }
        (&Method::Get, ["api", "v1", "chat", "state"]) => {
            return json_response(200, &api.chat_state(now));
        }
        (&Method::Post, ["api", "v1", "chat", "messages"]) => {
            parse_body::<CreateChatMessageRequest>(body)
                .and_then(|request| api.create_chat_message(request, now).map_err(node_error))
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "chat", "messages", id]) => parse_chat_message_id(id)
            .and_then(|id| api.read_chat_message(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "transactions", "inspect"]) => {
            parse_body::<TransactionReviewRequest>(body)
                .and_then(|request| api.inspect_transaction(&request).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "transactions", "intents"]) => {
            parse_body::<CreateTransactionIntentRequest>(body)
                .and_then(|request| {
                    api.create_transaction_intent(request, now)
                        .map_err(node_error)
                })
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "transactions", "intents", id]) => parse_id(id)
            .and_then(|id| api.transaction_review(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "trades", "verify"]) => {
            parse_body::<TradeSigningRequest>(body)
                .and_then(|request| api.verify_trade_for_agent(&request).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "trades", "intents"]) => {
            parse_body::<CreateTradeIntentRequest>(body)
                .and_then(|request| api.create_trade_intent(request, now).map_err(node_error))
                .map(|value| (201, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Get, ["api", "v1", "trades", "intents", id]) => parse_id(id)
            .and_then(|id| api.trade_verification(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents"]) => parse_body::<CreateIntentRequest>(body)
            .and_then(|request| api.create_intent(request, now).map_err(node_error))
            .map(|value| (201, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Get, ["api", "v1", "intents", id]) => parse_id(id)
            .and_then(|id| api.read_intent(id).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents", id, "cancel"]) => parse_id(id)
            .and_then(|id| api.cancel_intent(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "webauthn", "register", "start"]) => {
            parse_body::<PasskeyRegistrationStartRequest>(body)
                .and_then(|request| api.registration_start(request, now).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "webauthn", "register", "finish"]) => {
            parse_body::<PasskeyRegistrationFinishRequest>(body)
                .and_then(|request| api.registration_finish(request, now).map_err(node_error))
                .map(|value| (200, serde_json::to_value(value).unwrap_or_default()))
        }
        (&Method::Post, ["api", "v1", "intents", id, "approve", "start"]) => parse_id(id)
            .and_then(|id| api.approval_start(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Post, ["api", "v1", "intents", id, "approve", "finish"]) => parse_id(id)
            .and_then(|id| {
                parse_body::<ApprovalFinishRequest>(body)
                    .and_then(|request| api.approval_finish(id, request, now).map_err(node_error))
            })
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        (&Method::Get, ["api", "v1", "signing", id, "status"]) => parse_id(id)
            .and_then(|id| api.signing_status(id, now).map_err(node_error))
            .map(|value| (200, serde_json::to_value(value).unwrap_or_default())),
        _ => {
            return json_response(
                404,
                &json!({"error": {"code": "route_not_found", "message": "not found"}}),
            );
        }
    };

    match result {
        Ok((status, value)) => json_response(status, &value),
        Err(response) => response,
    }
}

fn respond(cors: &str, request: Request, result: JsonResponse) -> std::io::Result<()> {
    let mut response =
        Response::from_string(result.body).with_status_code(StatusCode(result.status));
    response
        .add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    response.add_header(
        Header::from_bytes(&b"Access-Control-Allow-Origin"[..], cors.as_bytes()).unwrap(),
    );
    response.add_header(
        Header::from_bytes(
            &b"Access-Control-Allow-Methods"[..],
            &b"GET, POST, OPTIONS"[..],
        )
        .unwrap(),
    );
    response.add_header(
        Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap(),
    );
    request.respond(response)
}

#[cfg(test)]
mod typed_route_tests {
    use super::*;
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, absolute,
        consensus::encode::serialize_hex,
        hashes::Hash,
        secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
        transaction,
    };
    use catomicals_chain_domain::{
        BitcoinNetwork, ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ReviewArtifact,
        ReviewContractError,
    };
    use catomicals_signing_domain::{ReviewBinding, SignerBackendRequirement, SigningSuiteId};
    use catomicals_threshold::{
        LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
    };
    use catomicals_wallet::{
        ApprovalCompletionState, ApprovalStartState, AuthorizationState,
        BitcoinNetwork as WalletBitcoinNetwork, ChainSigningExecution, ChainSigningExecutor,
        ChainSigningExecutorKey, ChainSigningJobState, ChainSigningJobStatus,
        CreateChainSigningJobRequest, CreateIntentRequest, FrostNonceClaimState,
        InMemoryWalletStore, IntentStatus, PasskeyState, RelyingPartyConfig, SigningAction,
        SigningIntent, SigningJob, SigningJobError, StorageDescriptor, VerifiedChainSignature,
        WalletNodeService, WalletStore, WalletStoreError, WebauthnProfileState,
    };
    use std::sync::mpsc;
    use uuid::Uuid;

    #[test]
    fn recovery_state_never_creates_a_replacement_signer() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_id = Uuid::from_bytes([0x28; 16]);

        let error = open_durable_signer(
            directory.path(),
            wallet_id,
            1,
            1_800_000_000,
            RestoreState::Recovering,
        )
        .unwrap_err();

        assert!(error.to_string().contains("refusing to initialize"));
        assert!(!directory.path().join("signer.json").exists());
        assert!(!directory.path().join("signer-secrets").exists());
    }

    fn service() -> Mutex<WalletNodeService> {
        let mut dkg = run_local_dkg(3, 2).unwrap();
        let participant = LocalFrostParticipant::new(
            1,
            dkg.key_packages
                .remove(&participant_identifier(1).unwrap())
                .unwrap(),
            NonceGuard::new(),
        )
        .unwrap();
        Mutex::new(
            WalletNodeService::new(
                RelyingPartyConfig::default(),
                Some(participant),
                dkg.public_key_package,
                2,
            )
            .unwrap(),
        )
    }

    fn multichain_service() -> Mutex<multichain_wallet::MultiChainWalletSurface> {
        Mutex::new(multichain_wallet::MultiChainWalletSurface::seven_chain_defaults())
    }

    fn chain_signing_request() -> CreateChainSigningJobRequest {
        let scope = ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet));
        let review = ReviewArtifact::new(
            scope,
            [0x31; 32],
            [0x32; 32],
            "reviewed Bitcoin Signet transaction".to_owned(),
            vec![0x01],
        )
        .unwrap();
        let review_binding = ReviewBinding::new(
            scope,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            "wallet-signers",
            1,
            review.schema_version,
            review.review_digest,
        )
        .unwrap();
        CreateChainSigningJobRequest {
            authorization_id: Uuid::from_bytes([0x40; 16]),
            operation_binding_digest: [0x41; 32],
            job: SigningJob {
                job_id: Uuid::from_bytes([0x42; 16]),
                intent_id: Uuid::from_bytes([0x43; 16]),
                profile_id: Uuid::from_bytes([0x44; 16]),
                wallet_id: Uuid::from_bytes([0x45; 16]),
                chain_scope: scope,
                signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
                backend_requirement: SignerBackendRequirement::FrostSecp256k1Tr,
                review,
                review_binding,
                policy_snapshot_digest: [0x46; 32],
                chain_snapshot_digest: [0x47; 32],
                online_parties: ["desktop".to_owned(), "mobile-backup".to_owned()],
                receiver: "desktop".to_owned(),
                session_id: [0x48; 32],
                expires_at: 1_800_000_100,
                created_at: 1_800_000_000,
            },
        }
    }

    struct HttpSigningStore {
        inner: InMemoryWalletStore,
        wallet_id: Uuid,
        authorization: AuthorizationState,
        execution: Option<ChainSigningExecution>,
        executor_claimed: bool,
        state: Option<ChainSigningJobState>,
    }

    impl HttpSigningStore {
        fn new(intent: SigningIntent, authorization: AuthorizationState) -> Self {
            let wallet_id = intent.wallet_id;
            let mut inner = InMemoryWalletStore::new();
            inner.insert_intent(intent).unwrap();
            Self {
                inner,
                wallet_id,
                authorization,
                execution: None,
                executor_claimed: false,
                state: None,
            }
        }
    }

    impl WalletStore for HttpSigningStore {
        fn descriptor(&self) -> StorageDescriptor {
            self.inner.descriptor()
        }

        fn wallet_id(&self) -> Option<Uuid> {
            Some(self.wallet_id)
        }

        fn insert_intent(&mut self, intent: SigningIntent) -> Result<(), WalletStoreError> {
            self.inner.insert_intent(intent)
        }

        fn get_intent(&self, id: &Uuid) -> Option<SigningIntent> {
            self.inner.get_intent(id)
        }

        fn list_intents(&self) -> Vec<SigningIntent> {
            self.inner.list_intents()
        }

        fn update_intent(
            &mut self,
            intent: SigningIntent,
            now: i64,
        ) -> Result<(), WalletStoreError> {
            self.inner.update_intent(intent, now)
        }

        fn webauthn_profile(&self) -> Result<Option<WebauthnProfileState>, WalletStoreError> {
            self.inner.webauthn_profile()
        }

        fn set_webauthn_profile(
            &mut self,
            profile: WebauthnProfileState,
        ) -> Result<(), WalletStoreError> {
            self.inner.set_webauthn_profile(profile)
        }

        fn insert_passkey(&mut self, passkey: PasskeyState) -> Result<(), WalletStoreError> {
            self.inner.insert_passkey(passkey)
        }

        fn list_passkeys(&self) -> Result<Vec<PasskeyState>, WalletStoreError> {
            self.inner.list_passkeys()
        }

        fn begin_approval(&mut self, state: ApprovalStartState) -> Result<(), WalletStoreError> {
            self.inner.begin_approval(state)
        }

        fn complete_approval(
            &mut self,
            state: ApprovalCompletionState,
        ) -> Result<AuthorizationState, WalletStoreError> {
            self.inner.complete_approval(state)
        }

        fn available_authorizations(
            &self,
            now: i64,
        ) -> Result<Vec<AuthorizationState>, WalletStoreError> {
            Ok((self.authorization.expires_at >= now)
                .then(|| self.authorization.clone())
                .into_iter()
                .collect())
        }

        fn claim_frost_nonce(
            &mut self,
            claim: FrostNonceClaimState,
        ) -> Result<(), WalletStoreError> {
            self.inner.claim_frost_nonce(claim)
        }

        fn create_chain_signing_job(
            &mut self,
            request: CreateChainSigningJobRequest,
            now: i64,
        ) -> Result<ChainSigningJobState, WalletStoreError> {
            let job = request.job;
            let state = ChainSigningJobState {
                job_id: job.job_id,
                intent_id: job.intent_id,
                wallet_id: job.wallet_id,
                profile_id: job.profile_id,
                chain_scope: job.chain_scope,
                signing_suite_id: job.signing_suite_id,
                backend_requirement: job.backend_requirement,
                review_schema_version: job.review.schema_version,
                review_digest: job.review.review_digest,
                signing_message_digest: job.review.signing_message_digest,
                policy_snapshot_digest: job.policy_snapshot_digest,
                chain_snapshot_digest: job.chain_snapshot_digest,
                session_id: job.session_id,
                online_parties: job.online_parties.clone(),
                receiver: job.receiver.clone(),
                operation_binding_digest: request.operation_binding_digest,
                status: ChainSigningJobStatus::Signing,
                final_signature: None,
                terminal_reason: None,
                expires_at: job.expires_at,
                created_at: job.created_at,
                updated_at: now,
            };
            self.execution = Some(ChainSigningExecution {
                job,
                operation_binding_digest: request.operation_binding_digest,
            });
            self.state = Some(state.clone());
            Ok(state)
        }

        fn chain_signing_job(
            &self,
            job_id: Uuid,
        ) -> Result<Option<ChainSigningJobState>, WalletStoreError> {
            Ok(self
                .state
                .as_ref()
                .filter(|state| state.job_id == job_id)
                .cloned())
        }

        fn chain_signing_execution(
            &self,
            job_id: Uuid,
        ) -> Result<Option<ChainSigningExecution>, WalletStoreError> {
            Ok(self
                .execution
                .as_ref()
                .filter(|execution| execution.job.job_id == job_id)
                .cloned())
        }

        fn claim_chain_executor(
            &mut self,
            execution: &ChainSigningExecution,
            _now: i64,
        ) -> Result<(), WalletStoreError> {
            let stored = self
                .execution
                .as_ref()
                .filter(|stored| {
                    stored.job.job_id == execution.job.job_id
                        && stored.operation_binding_digest == execution.operation_binding_digest
                })
                .ok_or_else(|| WalletStoreError::new("signing job binding mismatch"))?;
            if self.executor_claimed {
                return Err(WalletStoreError::new(
                    "chain executor claim already consumed",
                ));
            }
            let _ = stored;
            self.executor_claimed = true;
            Ok(())
        }

        fn finalize_chain_signing_job(
            &mut self,
            job_id: Uuid,
            operation_binding_digest: [u8; 32],
            final_signature: Vec<u8>,
            now: i64,
        ) -> Result<(), WalletStoreError> {
            let state = self
                .state
                .as_mut()
                .filter(|state| {
                    state.job_id == job_id
                        && state.operation_binding_digest == operation_binding_digest
                })
                .ok_or_else(|| WalletStoreError::new("signing job binding mismatch"))?;
            state.status = ChainSigningJobStatus::Finalized;
            state.final_signature = Some(final_signature);
            state.updated_at = now;
            Ok(())
        }
    }

    struct AcceptingBitcoinSuite(ChainScope);

    impl ChainSuite for AcceptingBitcoinSuite {
        fn scope(&self) -> ChainScope {
            self.0
        }

        fn capabilities(&self) -> ChainCapabilities {
            ChainCapabilities {
                address_derivation: true,
                transaction_review: true,
                final_signature_verification: true,
                broadcast: false,
            }
        }

        fn review_transaction(
            &self,
            transaction_material: &[u8],
        ) -> Result<ReviewArtifact, ReviewContractError> {
            ReviewArtifact::new(
                self.0,
                [0x31; 32],
                [0x32; 32],
                "reviewed".to_owned(),
                transaction_material.to_vec(),
            )
        }

        fn verify_finalized_signature(
            &self,
            _review: &ReviewArtifact,
            finalized_signature: &[u8],
        ) -> Result<(), ReviewContractError> {
            if finalized_signature == [0x30, 0x01, 0x02] {
                Ok(())
            } else {
                Err(ReviewContractError::InvalidFinalizedSignature(
                    "mock signature mismatch".to_owned(),
                ))
            }
        }
    }

    struct VerifiedMockExecutor {
        key: ChainSigningExecutorKey,
        suite: AcceptingBitcoinSuite,
    }

    impl ChainSigningExecutor for VerifiedMockExecutor {
        fn key(&self) -> ChainSigningExecutorKey {
            self.key.clone()
        }

        fn execute(
            &self,
            execution: &ChainSigningExecution,
            _now: i64,
        ) -> Result<VerifiedChainSignature, SigningJobError> {
            VerifiedChainSignature::verify(&self.suite, execution, vec![0x30, 0x01, 0x02])
        }
    }

    struct SlowVerifiedMockExecutor {
        key: ChainSigningExecutorKey,
        suite: AcceptingBitcoinSuite,
        started: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl ChainSigningExecutor for SlowVerifiedMockExecutor {
        fn key(&self) -> ChainSigningExecutorKey {
            self.key.clone()
        }

        fn execute(
            &self,
            execution: &ChainSigningExecution,
            _now: i64,
        ) -> Result<VerifiedChainSignature, SigningJobError> {
            self.started
                .send(())
                .map_err(|error| SigningJobError::Backend(error.to_string()))?;
            self.release
                .lock()
                .map_err(|_| SigningJobError::Backend("slow signer poisoned".to_owned()))?
                .recv()
                .map_err(|error| SigningJobError::Backend(error.to_string()))?;
            VerifiedChainSignature::verify(&self.suite, execution, vec![0x30, 0x01, 0x02])
        }
    }

    #[test]
    fn multichain_status_and_configuration_routes_are_typed_and_do_not_sign() {
        let wallet = service();
        let chains = multichain_service();

        let initial = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Get,
            "/api/v1/chains/status",
            "",
            1_800_000_000,
        );
        assert_eq!(initial.status, 200, "{}", initial.body);
        let initial: serde_json::Value = serde_json::from_str(&initial.body).unwrap();
        assert_eq!(
            initial["chains"][0]["chain_scope"]["network"],
            "bitcoin.signet"
        );
        assert_eq!(
            initial["chains"][0]["signing_suite_id"],
            "btc.bip340.frost-secp256k1-tr.v1"
        );

        let configured = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/chains/config",
            r#"{
                "chain_scope":{"schema_version":1,"chain":"chia","network":"chia.testnet11"},
                "signing_suite_id":"chia.bls12-381.aug.threshold-2of3.v1"
            }"#,
            1_800_000_001,
        );
        assert_eq!(configured.status, 200, "{}", configured.body);
        let configured: serde_json::Value = serde_json::from_str(&configured.body).unwrap();
        assert_eq!(configured["backend"]["state"], "unavailable");

        let current = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Get,
            "/api/v1/chains/config",
            "",
            1_800_000_002,
        );
        let current: serde_json::Value = serde_json::from_str(&current.body).unwrap();
        assert_eq!(current["chains"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn multichain_configuration_rejects_cross_chain_suite_without_mutating_state() {
        let wallet = service();
        let chains = multichain_service();
        let rejected = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/chains/config",
            r#"{
                "chain_scope":{"schema_version":1,"chain":"chia","network":"chia.testnet11"},
                "signing_suite_id":"btc.bip340.frost-secp256k1-tr.v1"
            }"#,
            1_800_000_000,
        );
        assert_eq!(rejected.status, 422, "{}", rejected.body);
        let body: serde_json::Value = serde_json::from_str(&rejected.body).unwrap();
        assert_eq!(body["error"]["code"], "unsupported-signing-suite");
        assert_eq!(chains.lock().unwrap().status().chains.len(), 7);
    }

    #[test]
    fn multichain_configuration_rejects_declaration_only_suite_without_mutating_state() {
        let wallet = service();
        let chains = multichain_service();
        let before = chains.lock().unwrap().status();
        let rejected = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/chains/config",
            r#"{
                "chain_scope":{"schema_version":1,"chain":"ergo","network":"ergo.testnet"},
                "signing_suite_id":"ergo.sigma.native.v1"
            }"#,
            1_800_000_000,
        );

        assert_eq!(rejected.status, 422, "{}", rejected.body);
        let body: serde_json::Value = serde_json::from_str(&rejected.body).unwrap();
        assert_eq!(body["error"]["code"], "signing-suite-not-executable");
        assert_eq!(chains.lock().unwrap().status(), before);
    }

    #[test]
    fn signing_job_routes_use_the_wallet_authorization_core_and_have_typed_lookup_errors() {
        let wallet = service();
        let chains = multichain_service();
        let request = chain_signing_request();

        let rejected = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/signing/jobs",
            &serde_json::to_string(&request).unwrap(),
            1_800_000_000,
        );
        assert_eq!(rejected.status, 409, "{}", rejected.body);
        let rejected: serde_json::Value = serde_json::from_str(&rejected.body).unwrap();
        assert_eq!(rejected["error"]["code"], "state_conflict");

        let missing = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Get,
            "/api/v1/signing/jobs/49494949-4949-4949-8949-494949494949",
            "",
            1_800_000_000,
        );
        assert_eq!(missing.status, 404, "{}", missing.body);
        let missing: serde_json::Value = serde_json::from_str(&missing.body).unwrap();
        assert_eq!(missing["error"]["code"], "signing_job_not_found");

        let missing_execution = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/signing/jobs/49494949-4949-4949-8949-494949494949/execute",
            "",
            1_800_000_000,
        );
        assert_eq!(missing_execution.status, 404, "{}", missing_execution.body);
        let missing_execution: serde_json::Value =
            serde_json::from_str(&missing_execution.body).unwrap();
        assert_eq!(missing_execution["error"]["code"], "signing_job_not_found");
    }

    #[test]
    fn signing_job_http_flow_creates_executes_and_queries_a_chain_verified_result() {
        let request = chain_signing_request();
        let intent = SigningIntent {
            id: request.job.intent_id,
            network: WalletBitcoinNetwork::Signet,
            protocol_version: 1,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: request.job.wallet_id,
            signer_id: 0,
            personal_signing_policy: None,
            tx_digest: request.job.review.signing_message_digest,
            session_id: request.job.session_id,
            expiry: request.job.expires_at,
            nonce: [0x52; 32],
            status: IntentStatus::Approved,
            created_at: request.job.created_at,
        };
        let authorization = AuthorizationState {
            id: request.authorization_id,
            intent_id: request.job.intent_id,
            binding_digest: request.operation_binding_digest,
            expires_at: request.job.expires_at,
            issued_at: request.job.created_at,
        };
        let store = HttpSigningStore::new(intent, authorization);
        let mut api = WalletNodeService::without_signer_with_store(
            RelyingPartyConfig::default(),
            Box::new(store),
            request.job.created_at,
        )
        .unwrap();
        api.register_chain_signing_executor(Box::new(VerifiedMockExecutor {
            key: ChainSigningExecutorKey::from_job(&request.job),
            suite: AcceptingBitcoinSuite(request.job.chain_scope),
        }));
        let wallet = Mutex::new(api);
        let chains = multichain_service();

        let created = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/signing/jobs",
            &serde_json::to_string(&request).unwrap(),
            request.job.created_at,
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let created: serde_json::Value = serde_json::from_str(&created.body).unwrap();
        assert_eq!(created["status"], "signing");
        assert!(created.get("secret_ref").is_none());

        let execute_path = format!("/api/v1/signing/jobs/{}/execute", request.job.job_id);
        let executed = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            &execute_path,
            "",
            request.job.created_at + 1,
        );
        assert_eq!(executed.status, 200, "{}", executed.body);
        let executed: serde_json::Value = serde_json::from_str(&executed.body).unwrap();
        assert_eq!(executed["status"], "finalized");
        assert_eq!(executed["final_signature"], json!([0x30, 0x01, 0x02]));

        let query_path = format!("/api/v1/signing/jobs/{}", request.job.job_id);
        let queried = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Get,
            &query_path,
            "",
            request.job.created_at + 2,
        );
        assert_eq!(queried.status, 200, "{}", queried.body);
        let queried: serde_json::Value = serde_json::from_str(&queried.body).unwrap();
        assert_eq!(queried["status"], "finalized");
        assert_eq!(queried["final_signature"], json!([0x30, 0x01, 0x02]));
    }

    #[test]
    fn slow_chain_signer_does_not_block_signing_job_reads() {
        let request = chain_signing_request();
        let intent = SigningIntent {
            id: request.job.intent_id,
            network: WalletBitcoinNetwork::Signet,
            protocol_version: 1,
            action: SigningAction::SignTaprootTransaction,
            wallet_id: request.job.wallet_id,
            signer_id: 0,
            personal_signing_policy: None,
            tx_digest: request.job.review.signing_message_digest,
            session_id: request.job.session_id,
            expiry: request.job.expires_at,
            nonce: [0x52; 32],
            status: IntentStatus::Approved,
            created_at: request.job.created_at,
        };
        let authorization = AuthorizationState {
            id: request.authorization_id,
            intent_id: request.job.intent_id,
            binding_digest: request.operation_binding_digest,
            expires_at: request.job.expires_at,
            issued_at: request.job.created_at,
        };
        let store = HttpSigningStore::new(intent, authorization);
        let mut api = WalletNodeService::without_signer_with_store(
            RelyingPartyConfig::default(),
            Box::new(store),
            request.job.created_at,
        )
        .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        api.register_chain_signing_executor(Box::new(SlowVerifiedMockExecutor {
            key: ChainSigningExecutorKey::from_job(&request.job),
            suite: AcceptingBitcoinSuite(request.job.chain_scope),
            started: started_tx,
            release: Mutex::new(release_rx),
        }));
        let wallet = Arc::new(Mutex::new(api));
        let chains = Arc::new(multichain_service());

        let created = dispatch_json_with_multichain(
            &wallet,
            &chains,
            &Method::Post,
            "/api/v1/signing/jobs",
            &serde_json::to_string(&request).unwrap(),
            request.job.created_at,
        );
        assert_eq!(created.status, 201, "{}", created.body);

        let execute_wallet = Arc::clone(&wallet);
        let execute_chains = Arc::clone(&chains);
        let execute_path = format!("/api/v1/signing/jobs/{}/execute", request.job.job_id);
        let execute = std::thread::spawn(move || {
            dispatch_json_with_multichain(
                &execute_wallet,
                &execute_chains,
                &Method::Post,
                &execute_path,
                "",
                request.job.created_at + 1,
            )
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("slow signer must start");

        let read_wallet = Arc::clone(&wallet);
        let read_chains = Arc::clone(&chains);
        let query_path = format!("/api/v1/signing/jobs/{}", request.job.job_id);
        let (read_tx, read_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let response = dispatch_json_with_multichain(
                &read_wallet,
                &read_chains,
                &Method::Get,
                &query_path,
                "",
                request.job.created_at + 1,
            );
            let _ = read_tx.send(response);
        });

        let read = read_rx.recv_timeout(Duration::from_millis(200));
        release_tx.send(()).unwrap();
        let executed = execute.join().unwrap();
        assert_eq!(executed.status, 200, "{}", executed.body);
        let read = read.expect("job read must not wait for the remote signer");
        assert_eq!(read.status, 200, "{}", read.body);
        let read: serde_json::Value = serde_json::from_str(&read.body).unwrap();
        assert_eq!(read["status"], "signing");
    }

    #[test]
    fn recovered_intent_approval_has_a_stable_state_conflict_error() {
        let response = node_error(WalletNodeError::RecoveredIntentApprovalUnavailable);
        assert_eq!(response.status, 409);
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(body["error"]["code"], "state_conflict");
    }

    fn p2tr_script(secret: u8) -> ScriptBuf {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        Address::p2tr(&secp, xonly, None, Network::Signet).script_pubkey()
    }

    fn transaction_review_json() -> serde_json::Value {
        let spent = OutPoint::new(Txid::from_byte_array([8; 32]), 1);
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(95_000),
                script_pubkey: p2tr_script(9),
            }],
        };
        json!({
            "raw_tx_hex": serialize_hex(&tx),
            "prevouts": [{
                "outpoint": spent.to_string(),
                "value_sat": 100_000,
                "script_pubkey_hex": hex::encode(p2tr_script(8).as_bytes()),
            }],
            "input_index": 0,
            "max_fee_sat": 5_000,
        })
    }

    #[test]
    fn transaction_review_routes_derive_digest_and_reject_digest_injection() {
        let state = service();
        let transaction = transaction_review_json();
        let inspect = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/inspect",
            &transaction.to_string(),
            1_800_000_000,
        );
        assert_eq!(inspect.status, 200, "{}", inspect.body);
        let review: serde_json::Value = serde_json::from_str(&inspect.body).unwrap();
        assert_eq!(review["fee_sat"], 5_000);
        assert_eq!(review["sighash_hex"].as_str().map(str::len), Some(64));
        assert!(state.lock().unwrap().list_intents().is_empty());

        let create = json!({
            "wallet_id": "00000000-0000-0000-0000-000000000001",
            "signer_id": 1,
            "session_id": "22".repeat(32),
            "expiry": 1_800_000_300_i64,
            "transaction": transaction,
        });
        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/intents",
            &create.to_string(),
            1_800_000_000,
        );
        assert_eq!(response.status, 201, "{}", response.body);
        let intent: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(intent["tx_digest"], review["sighash_hex"]);
        let id = intent["id"].as_str().unwrap();

        let stored = dispatch_json(
            &state,
            &Method::Get,
            &format!("/api/v1/transactions/intents/{id}"),
            "",
            1_800_000_001,
        );
        assert_eq!(stored.status, 200, "{}", stored.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored.body).unwrap()["txid"],
            review["txid"]
        );

        let mut injected = create;
        injected["tx_digest"] = json!("ff".repeat(32));
        let rejected = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/transactions/intents",
            &injected.to_string(),
            1_800_000_000,
        );
        assert_eq!(rejected.status, 400, "{}", rejected.body);
    }

    #[test]
    fn live_node_refresh_replaces_stale_state_and_closes_on_unavailability() {
        let state = service();
        update_node_snapshot(
            &state,
            Some(catomicals_wallet::NodeSnapshot {
                chain: "signet".into(),
                blocks: 319_732,
                headers: 319_732,
                subversion: "/Satoshi:29.4.0(inquisition)/".into(),
                op_cat_active: true,
            }),
        );
        assert_eq!(
            state.lock().unwrap().wallet_status().node.unwrap().blocks,
            319_732
        );

        update_node_snapshot(&state, None);
        assert!(state.lock().unwrap().wallet_status().node.is_none());
    }

    #[test]
    fn typed_status_intent_registration_and_signing_routes_are_secret_free() {
        let state = service();
        let mut payloads = Vec::new();
        for path in [
            "/api/v1/node/status",
            "/api/v1/wallet/status",
            "/api/v1/signer/status",
        ] {
            let response = dispatch_json(&state, &Method::Get, path, "", 1_800_000_000);
            assert_eq!(response.status, 200, "{}", response.body);
            payloads.push(response.body);
        }

        let create = CreateIntentRequest {
            wallet_id: Uuid::from_bytes([1; 16]),
            signer_id: 1,
            tx_digest: [2; 32],
            session_id: [3; 32],
            expiry: 1_800_000_300,
        };
        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/intents",
            &serde_json::to_string(&create).unwrap(),
            1_800_000_000,
        );
        assert_eq!(response.status, 201, "{}", response.body);
        let created = serde_json::from_str::<serde_json::Value>(&response.body).unwrap();
        assert_eq!(created["tx_digest"], hex::encode([2; 32]));
        assert_eq!(created["session_id"], hex::encode([3; 32]));
        assert_eq!(created["nonce"].as_str().map(str::len), Some(64));
        let id = created["id"].as_str().unwrap().to_owned();
        payloads.push(response.body);

        for path in [
            format!("/api/v1/intents/{id}"),
            format!("/api/v1/signing/{id}/status"),
        ] {
            let response = dispatch_json(&state, &Method::Get, &path, "", 1_800_000_001);
            assert_eq!(response.status, 200, "{}", response.body);
            payloads.push(response.body);
        }

        let response = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/webauthn/register/start",
            r#"{"label":"primary","user_name":"owner","display_name":"Owner"}"#,
            1_800_000_002,
        );
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(response.body.contains("publicKey"));
        payloads.push(response.body);

        let response = dispatch_json(
            &state,
            &Method::Post,
            &format!("/api/v1/intents/{id}/approve/start"),
            "",
            1_800_000_003,
        );
        assert_eq!(response.status, 409);

        let joined = payloads.join("\n").to_ascii_lowercase();
        for forbidden in [
            "key_package",
            "signing_share",
            "secret_share",
            "signing_nonces",
            "authorization_token",
        ] {
            assert!(!joined.contains(forbidden), "leaked field {forbidden}");
        }
    }

    #[test]
    fn missing_intent_and_route_have_typed_status_codes() {
        let state = service();
        let missing = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/intents/00000000-0000-0000-0000-000000000001",
            "",
            1_800_000_000,
        );
        assert_eq!(missing.status, 404);
        let route = dispatch_json(&state, &Method::Get, "/nope", "", 1_800_000_000);
        assert_eq!(route.status, 404);
    }

    #[test]
    fn protected_trade_routes_are_typed_and_reject_unverified_payloads() {
        let state = service();
        for path in ["/api/v1/trades/verify", "/api/v1/trades/intents"] {
            let response = dispatch_json(&state, &Method::Post, path, "{}", 1_800_000_000);
            assert_eq!(response.status, 400, "{path}: {}", response.body);
            assert!(!response.body.contains("route_not_found"));
        }
    }

    #[test]
    fn chat_message_lifecycle_is_typed_and_secret_free() {
        let state = service();
        let empty = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/chat/state",
            "",
            1_800_000_000,
        );
        assert_eq!(empty.status, 200, "{}", empty.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&empty.body).unwrap()["messages"],
            json!([])
        );

        let created = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages",
            r#"{"content":"What can this wallet do?"}"#,
            1_800_000_001,
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let value = serde_json::from_str::<serde_json::Value>(&created.body).unwrap();
        let message_id = value["user_message"]["id"].as_str().unwrap();

        let read = dispatch_json(
            &state,
            &Method::Get,
            &format!("/api/v1/chat/messages/{message_id}"),
            "",
            1_800_000_002,
        );
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read.body).unwrap()["content"],
            "What can this wallet do?"
        );

        let joined = format!("{}\n{}\n{}", empty.body, created.body, read.body);
        for forbidden in [
            "nonce",
            "authorization_token",
            "key_package",
            "signing_share",
            "secret_share",
            "verifier",
        ] {
            assert!(
                !joined.to_ascii_lowercase().contains(forbidden),
                "leaked {forbidden}"
            );
        }
    }

    #[test]
    fn chat_wallet_action_creates_only_a_passkey_required_intent() {
        let state = service();
        let request = json!({
            "content": "Prepare this exact transaction",
            "wallet_action": {
                "type": "sign_taproot_transaction",
                "wallet_id": "11111111-1111-1111-1111-111111111111",
                "signer_id": 1,
                "tx_digest": "22".repeat(32),
                "session_id": "33".repeat(32),
                "expiry": 1_800_000_600_i64
            }
        });
        let created = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages",
            &request.to_string(),
            1_800_000_000,
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let value = serde_json::from_str::<serde_json::Value>(&created.body).unwrap();
        let action = &value["wallet_message"]["wallet_action"];
        assert_eq!(action["authorization"], "passkey_required");
        assert_eq!(action["tx_digest_hex"], "22".repeat(32));
        assert_eq!(action["session_id_hex"], "33".repeat(32));
        assert!(action.get("intent_digest_hex").is_some());
        assert!(action.get("nonce").is_none());

        let signer = dispatch_json(
            &state,
            &Method::Get,
            "/api/v1/signer/status",
            "",
            1_800_000_001,
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&signer.body).unwrap()["approved_actions"],
            0
        );

        let chat_approval = dispatch_json(
            &state,
            &Method::Post,
            "/api/v1/chat/messages/11111111-1111-1111-1111-111111111111/approve",
            r#"{"approved":true}"#,
            1_800_000_002,
        );
        assert_eq!(chat_approval.status, 404);
    }

    #[test]
    fn chat_rejects_caller_supplied_authorization_fields() {
        let state = service();
        for body in [
            r#"{"content":"approve","verifier":"accept-all"}"#.to_owned(),
            json!({
                "content": "approve",
                "wallet_action": {
                    "type": "sign_taproot_transaction",
                    "wallet_id": "11111111-1111-1111-1111-111111111111",
                    "signer_id": 1,
                    "tx_digest": "22".repeat(32),
                    "session_id": "33".repeat(32),
                    "expiry": 1_800_000_600_i64,
                    "approved": true,
                    "credential": {"id": "fake"}
                }
            })
            .to_string(),
        ] {
            let response = dispatch_json(
                &state,
                &Method::Post,
                "/api/v1/chat/messages",
                &body,
                1_800_000_000,
            );
            assert_eq!(response.status, 400, "{}", response.body);
            assert!(response.body.contains("invalid_json"), "{}", response.body);
        }
        assert!(state.lock().unwrap().list_intents().is_empty());
    }

    #[test]
    fn loopback_bind_validation_rejects_hostname_prefix_spoofing() {
        assert!(is_loopback_bind("127.0.0.1:18787"));
        assert!(is_loopback_bind("127.23.45.67:18787"));
        assert!(is_loopback_bind("[::1]:18787"));
        assert!(is_loopback_bind("localhost:18787"));
        assert!(!is_loopback_bind("localhost.attacker.example:18787"));
        assert!(!is_loopback_bind("127.0.0.1.attacker.example:18787"));
        assert!(!is_loopback_bind("0.0.0.0:18787"));
        assert!(!is_loopback_bind("localhost:not-a-port"));
    }

    #[test]
    fn request_body_limit_rejects_oversized_json() {
        let oversized = vec![b'x'; MAX_HTTP_BODY_BYTES + 1];
        let response = read_json_body(std::io::Cursor::new(oversized)).unwrap_err();
        assert_eq!(response.status, 413);
        assert!(response.body.contains("request_body_too_large"));
    }
}
