use std::{
    collections::{HashSet, VecDeque},
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use bitcoin::XOnlyPublicKey;
use catomicals_cb_mpc_signer::{
    CbMpcCancellation, CbMpcRuntimeLimits, CbMpcSignerSet, PartyId, SessionTransport,
    TransportFailure, generate_native_provider_2_of_3,
};
use catomicals_chain_bitcoin::derive_p2tr_output_key_address;
use catomicals_chain_bitcoin_cash::Address as BitcoinCashAddress;
use catomicals_chain_bsv::Address as BsvAddress;
use catomicals_chain_chia::{
    ThresholdBlsDealerKeyKind, dealer_split_threshold_secret_2_of_3 as chia_dealer_split,
    encode_puzzle_hash, standard_threshold_puzzle_hash,
};
use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainId, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
use catomicals_chain_ergo::{
    dealer_split_threshold_secret_2_of_3 as ergo_dealer_split, p2pk_address,
};
use catomicals_chain_kaspa::{AddressKind as KaspaAddressKind, encode_address as kaspa_address};
use catomicals_secret_store::{
    FileSecretBackend, RuntimeProfile, SecretBackend, SecretBackendFactory, SecretValue,
};
use catomicals_signer_transport::certificate_spki_sha256;
use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
use catomicals_threshold::{
    ProviderIdentity, group_pubkey_xonly, participant_identifier, run_local_dkg,
};
use catomicals_wallet::{
    AddressBinding, RelyingPartyConfig, SignerAddressSnapshot, SignerProfile,
    SignerProfileStartupSnapshot, WalletNodeService,
};
use catomicals_wallet_storage::{
    NewAddressBinding, NewSignerCatalogEntry, NewSignerProfile,
    SecretBackend as StoredSecretBackend, SecretRef, SignerCatalogInstallOutcome,
    SignerProfileInventoryRecord, WalletStorage,
};
use rand::{RngCore, rngs::OsRng};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    cbmpc_executor_factory::{
        CB_MPC_PROTOCOL_STAGES, CB_MPC_RECOVERY_MANIFEST_VERSION, CB_MPC_TLS_IDENTITY_VERSION,
        CbMpcExecutorManifestV1, CbMpcRecoverySignerRefV1, CbMpcSignerRefV1,
        CbMpcTlsIdentityRefsV1, OpaqueSecretResolver, ResolverBackedShareProtector,
        SecretBackendResolver, recovery_share_aad, share_aad,
    },
    chia_ergo_executor_factory::{
        ThresholdShareReference, encode_chia_threshold_manifest_with_recovery,
        encode_ergo_threshold_manifest_with_recovery,
    },
    frost_executor_factory::{
        FrostOnlineSignerV1, FrostProviderKindV1, FrostProviderSecretV1, FrostSignerManifestV1,
    },
    multichain_wallet::MultiChainWalletSurface,
    wallet_executor_bootstrap::{
        ExecutorRegistrationState, WalletSnapshotProfileInventory, bootstrap_wallet_executors,
        snapshot_backed_factories,
    },
};
use crate::wallet::{ChainCustody, ChainNetworkProfile, ChainProvisionArgs};

const AUTHORIZATION_SIGNER_ID: &str = "passkey:owner";
const SIGNER_EPOCH: u64 = 1;
const CB_MPC_PARTIES: [&str; 3] = ["desktop", "mobile-backup", "onepassword"];

#[derive(Serialize)]
struct ProvisionSummary {
    status: &'static str,
    profiles: Vec<PublicProfileSummary>,
}

#[derive(Serialize)]
struct PublicProfileSummary {
    chain: &'static str,
    network: String,
    profile_id: Uuid,
    address: String,
    verification_key_hex: String,
}

struct StagedSecrets {
    backend: Arc<dyn SecretBackend>,
    handles: Vec<String>,
    manifest_paths: Vec<PathBuf>,
    cleanup_roots: Vec<PathBuf>,
    committed: bool,
}

impl StagedSecrets {
    fn new(backend: Arc<dyn SecretBackend>) -> Self {
        Self {
            backend,
            handles: Vec::new(),
            manifest_paths: Vec::new(),
            cleanup_roots: Vec::new(),
            committed: false,
        }
    }

    fn cleanup_roots(mut self, roots: impl IntoIterator<Item = PathBuf>) -> Self {
        self.cleanup_roots.extend(roots);
        self
    }

    fn put(&mut self, value: SecretValue) -> anyhow::Result<String> {
        let handle = self
            .backend
            .put_raw(value)
            .map_err(|_| anyhow::anyhow!("executor secret staging failed"))?;
        self.handles.push(handle.clone());
        Ok(handle)
    }

    fn write_manifest(&mut self, root: &Path, value: &[u8]) -> anyhow::Result<String> {
        let name = format!("frost-{}.json", Uuid::new_v4());
        let path = root.join(&name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        use std::io::Write as _;
        options
            .open(&path)
            .and_then(|mut file| file.write_all(value).and_then(|()| file.sync_all()))
            .context("writing staged FROST manifest")?;
        self.manifest_paths.push(path);
        Ok(format!("encrypted-file://{name}"))
    }
}

impl Drop for StagedSecrets {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for handle in self.handles.iter().rev() {
            let _ = self.backend.delete_raw(handle);
        }
        for path in self.manifest_paths.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for root in self.cleanup_roots.iter().rev() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

pub fn provision(args: ChainProvisionArgs) -> anyhow::Result<()> {
    match (args.network_profile, args.custody) {
        (ChainNetworkProfile::DefaultTestnets, ChainCustody::SelfHostedDevelopment) => {}
    }
    let requested_wallet_id = Uuid::parse_str(&args.wallet_id).context("invalid --wallet-id")?;
    let database = args.data_dir.join(crate::walletd::WALLET_DATABASE);
    if !database.is_file() {
        bail!("durable wallet is not initialized; run `catomicals wallet signer init` first");
    }
    let mut storage = WalletStorage::open(&database).context("opening durable wallet catalog")?;
    let wallet_id = storage.wallet_metadata()?.wallet_id;
    if wallet_id != requested_wallet_id {
        bail!("--wallet-id does not match the initialized durable wallet");
    }

    let existing = storage.signer_profile_inventory(wallet_id)?;
    if !existing.is_empty() {
        let snapshots = validate_existing_catalog(wallet_id, &existing)?;
        validate_managed_artifact_inventory(&args.data_dir, &snapshots)?;
        validate_startup_builders(&args.data_dir, &snapshots)?;
        print_summary("already_present", &snapshots)?;
        return Ok(());
    }

    let manifest_root = args.data_dir.join("executor-manifests");
    let secret_root = args.data_dir.join("executor-secrets");
    prepare_empty_managed_roots(&[&manifest_root, &secret_root])?;
    let backend = match SecretBackendFactory::self_hosted_development(&secret_root).resolve() {
        Ok(backend) => backend,
        Err(_) => {
            let _ = fs::remove_dir_all(&secret_root);
            bail!("self-hosted executor secret backend is unavailable");
        }
    };
    if let Err(error) = super::ensure_private_executor_directory(&manifest_root) {
        let _ = fs::remove_dir_all(&secret_root);
        return Err(error);
    }
    let mut staged =
        StagedSecrets::new(backend).cleanup_roots([manifest_root.clone(), secret_root.clone()]);
    let snapshots = provision_all_profiles(wallet_id, &manifest_root, &mut staged)?;
    validate_startup_builders(&args.data_dir, &snapshots)?;
    let catalog = snapshots_to_catalog(&snapshots, now())?;
    let outcome = storage.install_signer_catalog(&catalog)?;
    if outcome != SignerCatalogInstallOutcome::Installed {
        bail!("signer catalog changed while provisioning");
    }
    staged.committed = true;
    print_summary("installed", &snapshots)
}

fn provision_all_profiles(
    wallet_id: Uuid,
    manifest_root: &Path,
    staged: &mut StagedSecrets,
) -> anyhow::Result<Vec<SignerProfileStartupSnapshot>> {
    let snapshots = vec![
        provision_frost(
            wallet_id,
            ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet)),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            manifest_root,
            staged,
        )?,
        provision_cb_mpc(
            wallet_id,
            ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet)),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            staged,
        )?,
        provision_cb_mpc(
            wallet_id,
            ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet)),
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            staged,
        )?,
        provision_frost(
            wallet_id,
            ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet)),
            SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
            manifest_root,
            staged,
        )?,
        provision_cb_mpc(
            wallet_id,
            ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11)),
            SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
            staged,
        )?,
        provision_chia(wallet_id, staged)?,
        provision_ergo(wallet_id, staged)?,
    ];
    Ok(snapshots)
}

fn provision_frost(
    wallet_id: Uuid,
    scope: ChainScope,
    suite: SigningSuiteId,
    manifest_root: &Path,
    staged: &mut StagedSecrets,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    let profile_id = Uuid::new_v4();
    let signer_set_id = Uuid::new_v4();
    let mut dkg = run_local_dkg(3, 2).map_err(|error| anyhow::anyhow!("FROST DKG: {error}"))?;
    let public = dkg.public_key_package.clone();
    let group_key =
        group_pubkey_xonly(&public).map_err(|error| anyhow::anyhow!("FROST group key: {error}"))?;
    let mut participants = Vec::with_capacity(3);
    for signer_id in [1_u16, 2, 3] {
        let identifier = participant_identifier(signer_id)
            .map_err(|error| anyhow::anyhow!("FROST participant: {error}"))?;
        let verifying_share_digest = Sha256::digest(
            public
                .verifying_shares()
                .get(&identifier)
                .context("FROST verifying share missing")?
                .serialize()
                .map_err(|error| anyhow::anyhow!("FROST verifying share: {error}"))?,
        )
        .into();
        let identity = ProviderIdentity {
            wallet_id,
            signer_set_id,
            signer_epoch: SIGNER_EPOCH,
            signer_id,
            device_id: Uuid::new_v4(),
            device_generation: 1,
            group_pubkey_xonly: group_key,
            verifying_share_digest,
        };
        let package = dkg
            .key_packages
            .remove(&identifier)
            .context("FROST key package missing")?;
        let provider = FrostProviderSecretV1::local_encrypted(
            package
                .serialize()
                .map_err(|error| anyhow::anyhow!("FROST key package: {error}"))?,
        );
        let provider_ref = staged.put(SecretValue::new(serde_json::to_vec(&provider)?))?;
        participants.push(FrostOnlineSignerV1::from_identity(
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
        suite,
        signer_set_id,
        SIGNER_EPOCH,
        public
            .serialize()
            .map_err(|error| anyhow::anyhow!("FROST public package: {error}"))?,
        [participants[0].clone(), participants[1].clone()],
    )
    .with_recovery_signer(participants[2].clone());
    let secret_ref = staged.write_manifest(manifest_root, &serde_json::to_vec(&manifest)?)?;
    let key = XOnlyPublicKey::from_slice(&group_key).context("invalid FROST group key")?;
    let address = derive_p2tr_output_key_address(scope, key)
        .context("deriving FROST Taproot address")?
        .to_string();
    checked_snapshot(
        profile_id,
        wallet_id,
        scope,
        suite,
        SignerBackendRequirement::FrostSecp256k1Tr,
        signer_set_id.to_string(),
        group_key.to_vec(),
        secret_ref,
        address,
    )
}

fn provision_cb_mpc(
    wallet_id: Uuid,
    scope: ChainScope,
    suite: SigningSuiteId,
    staged: &mut StagedSecrets,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    let profile_id = Uuid::new_v4();
    let signer_set_id = Uuid::new_v4().to_string();
    let parties = CB_MPC_PARTIES
        .map(|party| PartyId::new(party).expect("fixed party identifiers"))
        .to_vec();
    let signer_set = CbMpcSignerSet::new(signer_set_id.clone(), SIGNER_EPOCH, 2, parties)
        .map_err(|_| anyhow::anyhow!("invalid CB-MPC signer set"))?;
    let network = MemoryNetwork::new(3);
    let transports = [
        network.transport(0),
        network.transport(1),
        network.transport(2),
    ];
    let limits = CbMpcRuntimeLimits::new(
        Duration::from_secs(30),
        Duration::from_secs(120),
        4 * 1024 * 1024,
    )
    .map_err(|_| anyhow::anyhow!("invalid CB-MPC runtime limits"))?;
    let providers = generate_native_provider_2_of_3(
        &signer_set,
        [&transports[0], &transports[1], &transports[2]],
        limits,
        &CbMpcCancellation::new(),
    )
    .map_err(|_| anyhow::anyhow!("CB-MPC 2-of-3 DKG failed"))?;
    let group_key = providers[0].group_public_key();
    let address = cb_mpc_address(scope, group_key)?;
    let mut snapshot = checked_snapshot(
        profile_id,
        wallet_id,
        scope,
        suite,
        SignerBackendRequirement::CbMpcThresholdEcdsa,
        signer_set_id.clone(),
        group_key.to_vec(),
        format!("encrypted-file://pending-{}", Uuid::new_v4()),
        address,
    )?;

    let identities = install_tls_identities(staged)?;
    let mut providers = providers.into_iter().map(Some).collect::<Vec<_>>();
    let mut signers = [0_usize, 2]
        .into_iter()
        .enumerate()
        .map(|(tls_index, provider_index)| {
            let provider = providers[provider_index]
                .take()
                .context("CB-MPC online provider missing")?;
            let party = CB_MPC_PARTIES[provider_index];
            Ok((
                provider,
                CbMpcSignerRefV1 {
                    party_id: party.to_owned(),
                    device_ref: format!("device://{party}/{}", Uuid::new_v4()),
                    sealed_share_ref: format!("encrypted-file://pending-{}", Uuid::new_v4()),
                    protector_key_ref: staged.put(SecretValue::new(random_bytes(32)))?,
                    endpoint_ref: format!("unix://cbmpc/{profile_id}/{party}"),
                    tls_identity_ref: identities[tls_index].clone(),
                },
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let recovery_provider = providers[1]
        .take()
        .context("CB-MPC recovery provider missing")?;
    let mut recovery_signer = CbMpcRecoverySignerRefV1 {
        party_id: CB_MPC_PARTIES[1].to_owned(),
        device_ref: format!("device://{}/{}", CB_MPC_PARTIES[1], Uuid::new_v4()),
        sealed_share_ref: format!("encrypted-file://pending-{}", Uuid::new_v4()),
        protector_key_ref: staged.put(SecretValue::new(random_bytes(32)))?,
    };
    let mut manifest = CbMpcExecutorManifestV1 {
        format_version: CB_MPC_RECOVERY_MANIFEST_VERSION,
        wallet_id,
        profile_id,
        chain_scope: scope,
        signing_suite_id: suite,
        signer_set_id,
        signer_epoch: SIGNER_EPOCH,
        protocol_stages: CB_MPC_PROTOCOL_STAGES,
        all_parties: CB_MPC_PARTIES.map(str::to_owned),
        active_signers: [signers[0].1.clone(), signers[1].1.clone()],
        recovery_signer: Some(recovery_signer.clone()),
        receiver: "desktop".to_owned(),
    };
    let resolver: Arc<dyn OpaqueSecretResolver> =
        Arc::new(SecretBackendResolver::new(Arc::clone(&staged.backend)));
    for (index, (provider, signer)) in signers.drain(..).enumerate() {
        let aad = share_aad(&snapshot, &manifest, &signer)
            .map_err(|_| anyhow::anyhow!("CB-MPC share binding failed"))?;
        let protector = ResolverBackedShareProtector::new(
            Arc::clone(&resolver),
            signer.protector_key_ref.clone(),
            aad,
        );
        let sealed = provider
            .seal_for_persistence(&protector)
            .map_err(|_| anyhow::anyhow!("CB-MPC share sealing failed"))?;
        manifest.active_signers[index].sealed_share_ref = staged.put(SecretValue::new(sealed))?;
    }
    let recovery_aad = recovery_share_aad(&snapshot, &manifest, &recovery_signer)
        .map_err(|_| anyhow::anyhow!("CB-MPC recovery share binding failed"))?;
    let recovery_protector = ResolverBackedShareProtector::new(
        Arc::clone(&resolver),
        recovery_signer.protector_key_ref.clone(),
        recovery_aad,
    );
    let sealed_recovery = recovery_provider
        .seal_for_persistence(&recovery_protector)
        .map_err(|_| anyhow::anyhow!("CB-MPC recovery share sealing failed"))?;
    recovery_signer.sealed_share_ref = staged.put(SecretValue::new(sealed_recovery))?;
    manifest.recovery_signer = Some(recovery_signer);
    manifest
        .validate_for(&snapshot)
        .map_err(|_| anyhow::anyhow!("CB-MPC manifest validation failed"))?;
    snapshot.secret_ref = staged.put(SecretValue::new(serde_json::to_vec(&manifest)?))?;
    Ok(snapshot)
}

fn provision_chia(
    wallet_id: Uuid,
    staged: &mut StagedSecrets,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    let dealer = loop {
        if let Ok(dealer) = chia_dealer_split(
            ThresholdBlsDealerKeyKind::FinalSigningKey,
            random_array(),
            random_array(),
        ) {
            break dealer;
        }
    };
    let scope = ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11));
    let group_key = dealer.commitment().group_public_key();
    let address = encode_puzzle_hash(scope, standard_threshold_puzzle_hash(group_key)?)?;
    let mut snapshot = checked_snapshot(
        Uuid::new_v4(),
        wallet_id,
        scope,
        SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        Uuid::new_v4().to_string(),
        group_key.to_vec(),
        format!("encrypted-file://pending-{}", Uuid::new_v4()),
        address,
    )?;
    let first = staged.put(SecretValue::new(
        dealer.shares()[0].export_for_provisioning().to_vec(),
    ))?;
    let second = staged.put(SecretValue::new(
        dealer.shares()[1].export_for_provisioning().to_vec(),
    ))?;
    let recovery = staged.put(SecretValue::new(
        dealer.shares()[2].export_for_provisioning().to_vec(),
    ))?;
    let manifest = encode_chia_threshold_manifest_with_recovery(
        &snapshot,
        dealer.commitment().coefficient_public_key(),
        [
            ThresholdShareReference::new(1, first).map_err(anyhow::Error::msg)?,
            ThresholdShareReference::new(2, second).map_err(anyhow::Error::msg)?,
        ],
        ThresholdShareReference::new(3, recovery).map_err(anyhow::Error::msg)?,
    )
    .map_err(anyhow::Error::msg)?;
    snapshot.secret_ref = staged.put(manifest)?;
    Ok(snapshot)
}

fn provision_ergo(
    wallet_id: Uuid,
    staged: &mut StagedSecrets,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    let dealer = loop {
        if let Ok(dealer) = ergo_dealer_split(random_array(), random_array()) {
            break dealer;
        }
    };
    let scope = ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet));
    let group_key = dealer.commitment().group_public_key();
    let address = p2pk_address(ErgoNetwork::Testnet, &group_key)?.to_string();
    let mut snapshot = checked_snapshot(
        Uuid::new_v4(),
        wallet_id,
        scope,
        SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        Uuid::new_v4().to_string(),
        group_key.to_vec(),
        format!("encrypted-file://pending-{}", Uuid::new_v4()),
        address,
    )?;
    let first = staged.put(SecretValue::new(
        dealer.shares()[0].export_for_provisioning().to_vec(),
    ))?;
    let second = staged.put(SecretValue::new(
        dealer.shares()[1].export_for_provisioning().to_vec(),
    ))?;
    let recovery = staged.put(SecretValue::new(
        dealer.shares()[2].export_for_provisioning().to_vec(),
    ))?;
    let manifest = encode_ergo_threshold_manifest_with_recovery(
        &snapshot,
        dealer.commitment().coefficient_public_key(),
        [
            ThresholdShareReference::new(1, first).map_err(anyhow::Error::msg)?,
            ThresholdShareReference::new(2, second).map_err(anyhow::Error::msg)?,
        ],
        ThresholdShareReference::new(3, recovery).map_err(anyhow::Error::msg)?,
    )
    .map_err(anyhow::Error::msg)?;
    snapshot.secret_ref = staged.put(manifest)?;
    Ok(snapshot)
}

#[allow(clippy::too_many_arguments)]
fn checked_snapshot(
    profile_id: Uuid,
    wallet_id: Uuid,
    scope: ChainScope,
    suite: SigningSuiteId,
    backend: SignerBackendRequirement,
    signer_set_id: String,
    verification_key: Vec<u8>,
    secret_ref: String,
    address: String,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    let profile = SignerProfile::new(
        profile_id,
        wallet_id,
        scope,
        suite,
        backend,
        signer_set_id.clone(),
        AUTHORIZATION_SIGNER_ID.to_owned(),
        SIGNER_EPOCH,
        2,
        3,
        verification_key.clone(),
        secret_ref.clone(),
    )
    .map_err(|_| anyhow::anyhow!("generated signer profile is invalid"))?;
    let binding_id = Uuid::new_v4();
    let binding = AddressBinding::new(binding_id, &profile, address.clone())
        .map_err(|_| anyhow::anyhow!("generated chain address is incompatible with its profile"))?;
    Ok(SignerProfileStartupSnapshot {
        profile_id,
        wallet_id,
        chain_scope: scope,
        signing_suite_id: suite,
        backend_requirement: backend,
        signer_set_id,
        authorization_signer_id: AUTHORIZATION_SIGNER_ID.to_owned(),
        signer_epoch: SIGNER_EPOCH,
        threshold: 2,
        max_signers: 3,
        verification_key_hex: hex::encode(&verification_key),
        secret_ref,
        address_bindings: vec![SignerAddressSnapshot {
            binding_id,
            chain_scope: scope,
            address,
            verification_key_digest_hex: hex::encode(binding.verification_key_digest()),
        }],
    })
}

fn cb_mpc_address(scope: ChainScope, group_key: [u8; 33]) -> anyhow::Result<String> {
    match scope.network {
        ChainNetwork::BitcoinCash(network) => {
            Ok(BitcoinCashAddress::p2pkh_from_public_key(network, &group_key)?.to_cashaddr()?)
        }
        ChainNetwork::Bsv(network) => {
            Ok(BsvAddress::p2pkh_from_public_key(network, &group_key)?.to_string())
        }
        ChainNetwork::Kaspa(network) => Ok(kaspa_address(
            network,
            KaspaAddressKind::PubKeyEcdsa,
            &group_key,
        )?),
        _ => bail!("unsupported CB-MPC chain scope"),
    }
}

fn install_tls_identities(staged: &mut StagedSecrets) -> anyhow::Result<[String; 2]> {
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let (server, server_key) = tls_leaf(
        "cbmpc.local",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    )?;
    let (client, client_key) = tls_leaf(
        "cbmpc-client.local",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    )?;
    let ca_ref = staged.put(SecretValue::new(ca.der().to_vec()))?;
    let server_cert_ref = staged.put(SecretValue::new(server.der().to_vec()))?;
    let server_key_ref = staged.put(SecretValue::new(server_key.serialize_der()))?;
    let client_cert_ref = staged.put(SecretValue::new(client.der().to_vec()))?;
    let client_key_ref = staged.put(SecretValue::new(client_key.serialize_der()))?;
    let server_pin_ref = staged.put(SecretValue::new(
        certificate_spki_sha256(server.der().as_ref())?.to_vec(),
    ))?;
    let client_pin_ref = staged.put(SecretValue::new(
        certificate_spki_sha256(client.der().as_ref())?.to_vec(),
    ))?;
    let server_refs = CbMpcTlsIdentityRefsV1 {
        format_version: CB_MPC_TLS_IDENTITY_VERSION,
        certificate_der_ref: server_cert_ref,
        private_key_pkcs8_der_ref: server_key_ref,
        peer_ca_certificate_der_ref: ca_ref.clone(),
        peer_spki_sha256_ref: client_pin_ref,
    };
    let client_refs = CbMpcTlsIdentityRefsV1 {
        format_version: CB_MPC_TLS_IDENTITY_VERSION,
        certificate_der_ref: client_cert_ref,
        private_key_pkcs8_der_ref: client_key_ref,
        peer_ca_certificate_der_ref: ca_ref,
        peer_spki_sha256_ref: server_pin_ref,
    };
    Ok([
        staged.put(SecretValue::new(serde_json::to_vec(&server_refs)?))?,
        staged.put(SecretValue::new(serde_json::to_vec(&client_refs)?))?,
    ])
}

fn tls_leaf(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> anyhow::Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, ca, ca_key)?;
    Ok((certificate, key))
}

fn snapshots_to_catalog(
    snapshots: &[SignerProfileStartupSnapshot],
    created_at: i64,
) -> anyhow::Result<Vec<NewSignerCatalogEntry>> {
    snapshots
        .iter()
        .map(|snapshot| {
            let secret_ref_id = Uuid::new_v4();
            let verification_key = hex::decode(&snapshot.verification_key_hex)?;
            let bindings = snapshot
                .address_bindings
                .iter()
                .map(|binding| {
                    Ok(NewAddressBinding {
                        binding_id: binding.binding_id,
                        profile_id: snapshot.profile_id,
                        chain_scope: binding.chain_scope,
                        address: binding.address.clone(),
                        verification_key_digest: hex::decode(&binding.verification_key_digest_hex)?
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid address binding digest"))?,
                        created_at,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(NewSignerCatalogEntry {
                secret_ref: SecretRef::new(
                    secret_ref_id,
                    StoredSecretBackend::EncryptedFile,
                    snapshot.secret_ref.clone(),
                    created_at,
                )?,
                profile: NewSignerProfile {
                    profile_id: snapshot.profile_id,
                    wallet_id: snapshot.wallet_id,
                    chain_scope: snapshot.chain_scope,
                    signing_suite_id: snapshot.signing_suite_id,
                    backend_requirement: snapshot.backend_requirement,
                    signer_set_id: snapshot.signer_set_id.clone(),
                    authorization_signer_id: snapshot.authorization_signer_id.clone(),
                    signer_epoch: snapshot.signer_epoch,
                    threshold: snapshot.threshold,
                    max_signers: snapshot.max_signers,
                    verification_key,
                    secret_ref_id,
                    created_at,
                },
                address_bindings: bindings,
            })
        })
        .collect()
}

fn validate_existing_catalog(
    wallet_id: Uuid,
    inventory: &[SignerProfileInventoryRecord],
) -> anyhow::Result<Vec<SignerProfileStartupSnapshot>> {
    if inventory.len() != 7 {
        bail!("existing signer catalog is partial; refusing to mutate it");
    }
    let mut snapshots = inventory
        .iter()
        .map(inventory_snapshot)
        .collect::<anyhow::Result<Vec<_>>>()?;
    snapshots.sort_by_key(|snapshot| chain_index(snapshot.chain_scope.chain));
    if snapshots
        .iter()
        .map(|snapshot| snapshot.signer_set_id.as_str())
        .collect::<HashSet<_>>()
        .len()
        != 7
        || snapshots
            .iter()
            .map(|snapshot| snapshot.secret_ref.as_str())
            .collect::<HashSet<_>>()
            .len()
            != 7
        || snapshots
            .iter()
            .map(|snapshot| snapshot.verification_key_hex.as_str())
            .collect::<HashSet<_>>()
            .len()
            != 7
    {
        bail!("existing signer catalog does not contain seven independent signer sets");
    }
    for (snapshot, (scope, suite, backend)) in snapshots.iter().zip(expected_profiles()) {
        if snapshot.wallet_id != wallet_id
            || snapshot.chain_scope != scope
            || snapshot.signing_suite_id != suite
            || snapshot.backend_requirement != backend
            || snapshot.signer_epoch != SIGNER_EPOCH
            || snapshot.threshold != 2
            || snapshot.max_signers != 3
            || snapshot.authorization_signer_id != AUTHORIZATION_SIGNER_ID
            || snapshot.address_bindings.len() != 1
        {
            bail!("existing signer catalog differs from the fixed seven-chain profile");
        }
        validate_snapshot_address(snapshot)?;
    }
    Ok(snapshots)
}

fn prepare_empty_managed_roots(roots: &[&Path]) -> anyhow::Result<()> {
    for root in roots {
        match fs::symlink_metadata(root) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    bail!("executor artifact root is not a managed directory");
                }
                if fs::read_dir(root)?.next().is_some() {
                    bail!("empty signer catalog has managed executor artifacts");
                }
                fs::remove_dir(root)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_managed_artifact_inventory(
    data_dir: &Path,
    snapshots: &[SignerProfileStartupSnapshot],
) -> anyhow::Result<()> {
    let manifest_root = data_dir.join("executor-manifests");
    let secret_root = data_dir.join("executor-secrets");
    for root in [&manifest_root, &secret_root] {
        let metadata = fs::symlink_metadata(root).with_context(|| {
            format!(
                "managed executor artifact root is missing: {}",
                root.display()
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("managed executor artifact root is invalid");
        }
    }
    super::ensure_private_executor_directory(&manifest_root)?;
    let backend = FileSecretBackend::open(&secret_root, RuntimeProfile::Development)
        .map_err(|_| anyhow::anyhow!("managed executor secret backend is invalid"))?;

    let mut expected_manifest_files = HashSet::new();
    let mut expected_secret_files = HashSet::from([secret_root.join("development.kek")]);
    let mut pending_secret_refs = VecDeque::new();
    for snapshot in snapshots {
        if snapshot.backend_requirement == SignerBackendRequirement::FrostSecp256k1Tr {
            let relative = snapshot
                .secret_ref
                .strip_prefix("encrypted-file://")
                .context("FROST manifest reference is invalid")?;
            let relative_path = Path::new(relative);
            if relative_path
                .parent()
                .is_some_and(|parent| parent != Path::new(""))
                || relative_path.file_name().is_none()
            {
                bail!("FROST manifest reference escapes its managed root");
            }
            let path = manifest_root.join(relative_path);
            let encoded = fs::read(&path).context("managed FROST manifest is missing")?;
            expected_manifest_files.insert(path);
            collect_encrypted_file_refs(
                &serde_json::from_slice(&encoded)?,
                &mut pending_secret_refs,
            );
        } else {
            pending_secret_refs.push_back(snapshot.secret_ref.clone());
        }
    }

    let mut visited_secret_refs = HashSet::new();
    while let Some(reference) = pending_secret_refs.pop_front() {
        if !visited_secret_refs.insert(reference.clone()) {
            continue;
        }
        let path = backend
            .record_path(&reference)
            .map_err(|_| anyhow::anyhow!("managed executor secret reference is invalid"))?;
        expected_secret_files.insert(path);
        let value = backend
            .get_raw(&reference)
            .map_err(|_| anyhow::anyhow!("managed executor secret is missing"))?;
        if let Ok(json) = serde_json::from_slice(value.expose()) {
            collect_encrypted_file_refs(&json, &mut pending_secret_refs);
        }
    }

    let (actual_manifest_files, actual_manifest_directories) =
        collect_managed_tree(&manifest_root)?;
    let (actual_secret_files, actual_secret_directories) = collect_managed_tree(&secret_root)?;
    if actual_manifest_files != expected_manifest_files
        || actual_manifest_directories != HashSet::from([manifest_root.clone()])
        || actual_secret_files != expected_secret_files
        || actual_secret_directories
            != HashSet::from([secret_root.clone(), secret_root.join("records")])
    {
        bail!("managed executor artifact inventory differs from the signer catalog");
    }
    Ok(())
}

fn collect_encrypted_file_refs(value: &serde_json::Value, pending: &mut VecDeque<String>) {
    match value {
        serde_json::Value::String(value) if value.starts_with("encrypted-file://") => {
            pending.push_back(value.clone());
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_encrypted_file_refs(value, pending);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_encrypted_file_refs(value, pending);
            }
        }
        _ => {}
    }
}

fn collect_managed_tree(root: &Path) -> anyhow::Result<(HashSet<PathBuf>, HashSet<PathBuf>)> {
    let mut files = HashSet::new();
    let mut directories = HashSet::from([root.to_path_buf()]);
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                bail!("managed executor artifact tree contains a symlink");
            }
            if file_type.is_dir() {
                directories.insert(path.clone());
                pending.push(path);
            } else if file_type.is_file() {
                files.insert(path);
            } else {
                bail!("managed executor artifact tree contains a special file");
            }
        }
    }
    Ok((files, directories))
}

fn inventory_snapshot(
    record: &SignerProfileInventoryRecord,
) -> anyhow::Result<SignerProfileStartupSnapshot> {
    Ok(SignerProfileStartupSnapshot {
        profile_id: record.profile.profile_id,
        wallet_id: record.profile.wallet_id,
        chain_scope: record.profile.chain_scope,
        signing_suite_id: record.profile.signing_suite_id,
        backend_requirement: record.profile.backend_requirement,
        signer_set_id: record.profile.signer_set_id.clone(),
        authorization_signer_id: record.profile.authorization_signer_id.clone(),
        signer_epoch: record.profile.signer_epoch,
        threshold: record.profile.threshold,
        max_signers: record.profile.max_signers,
        verification_key_hex: hex::encode(&record.profile.verification_key),
        secret_ref: record.secret_ref.clone(),
        address_bindings: record
            .address_bindings
            .iter()
            .map(|binding| SignerAddressSnapshot {
                binding_id: binding.binding_id,
                chain_scope: binding.chain_scope,
                address: binding.address.clone(),
                verification_key_digest_hex: hex::encode(binding.verification_key_digest),
            })
            .collect(),
    })
}

fn validate_snapshot_address(snapshot: &SignerProfileStartupSnapshot) -> anyhow::Result<()> {
    let profile = SignerProfile::new(
        snapshot.profile_id,
        snapshot.wallet_id,
        snapshot.chain_scope,
        snapshot.signing_suite_id,
        snapshot.backend_requirement,
        snapshot.signer_set_id.clone(),
        snapshot.authorization_signer_id.clone(),
        snapshot.signer_epoch,
        snapshot.threshold,
        snapshot.max_signers,
        hex::decode(&snapshot.verification_key_hex)?,
        snapshot.secret_ref.clone(),
    )
    .map_err(|_| anyhow::anyhow!("existing signer profile is invalid"))?;
    let binding = &snapshot.address_bindings[0];
    AddressBinding::new(binding.binding_id, &profile, binding.address.clone())
        .map_err(|_| anyhow::anyhow!("existing signer address is invalid"))?;
    Ok(())
}

fn validate_startup_builders(
    data_dir: &Path,
    snapshots: &[SignerProfileStartupSnapshot],
) -> anyhow::Result<()> {
    let builders = super::startup_executor_builders(data_dir, snapshots, true)?;
    let factories = snapshot_backed_factories(snapshots, builders)
        .map_err(|_| anyhow::anyhow!("executor factory catalog validation failed"))?;
    let inventory = WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(snapshots.to_vec()));
    let mut wallet = WalletNodeService::without_signer(RelyingPartyConfig::default())?;
    let mut surface = MultiChainWalletSurface::seven_chain_defaults();
    let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &factories);
    if report.registrations.len() != 7
        || report.registrations.iter().any(|registration| {
            registration.state != ExecutorRegistrationState::Registered
                || registration.error_code.is_some()
        })
    {
        bail!("one or more staged chain signer executors failed startup validation");
    }
    Ok(())
}

fn expected_profiles() -> Vec<(ChainScope, SigningSuiteId, SignerBackendRequirement)> {
    vec![
        (
            ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet)),
            SigningSuiteId::BITCOIN_BIP340_FROST_V1,
            SignerBackendRequirement::FrostSecp256k1Tr,
        ),
        (
            ChainScope::for_network(ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet)),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        ),
        (
            ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet)),
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        ),
        (
            ChainScope::for_network(ChainNetwork::FractalBitcoin(FractalBitcoinNetwork::Signet)),
            SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
            SignerBackendRequirement::FrostSecp256k1Tr,
        ),
        (
            ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11)),
            SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        ),
        (
            ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11)),
            SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ChiaBlsAugThreshold2of3,
        ),
        (
            ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet)),
            SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
            SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3,
        ),
    ]
}

fn print_summary(
    status: &'static str,
    snapshots: &[SignerProfileStartupSnapshot],
) -> anyhow::Result<()> {
    let profiles = snapshots
        .iter()
        .map(|snapshot| PublicProfileSummary {
            chain: snapshot.chain_scope.chain.as_str(),
            network: snapshot.chain_scope.network.as_str().to_owned(),
            profile_id: snapshot.profile_id,
            address: snapshot.address_bindings[0].address.clone(),
            verification_key_hex: snapshot.verification_key_hex.clone(),
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&ProvisionSummary { status, profiles })?
    );
    Ok(())
}

fn chain_index(chain: ChainId) -> usize {
    match chain {
        ChainId::Bitcoin => 0,
        ChainId::BitcoinCash => 1,
        ChainId::Bsv => 2,
        ChainId::FractalBitcoin => 3,
        ChainId::Kaspa => 4,
        ChainId::Chia => 5,
        ChainId::Ergo => 6,
    }
}

fn random_array() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
            let current = Instant::now();
            if current >= deadline {
                return Err(TransportFailure::Timeout);
            }
            let (next, timeout) = queue
                .available
                .wait_timeout(frames, deadline - current)
                .unwrap();
            frames = next;
            if timeout.timed_out() && frames.is_empty() {
                return Err(TransportFailure::Timeout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_persists_a_distinct_recovery_share_for_every_profile() {
        let directory = tempfile::tempdir().unwrap();
        let secret_root = directory.path().join("executor-secrets");
        let manifest_root = directory.path().join("executor-manifests");
        super::super::ensure_private_executor_directory(&manifest_root).unwrap();
        let backend = SecretBackendFactory::self_hosted_development(&secret_root)
            .resolve()
            .unwrap();
        let mut staged = StagedSecrets::new(Arc::clone(&backend));
        let snapshots =
            provision_all_profiles(Uuid::new_v4(), &manifest_root, &mut staged).unwrap();

        for snapshot in snapshots {
            let encoded =
                if snapshot.backend_requirement == SignerBackendRequirement::FrostSecp256k1Tr {
                    let relative = snapshot
                        .secret_ref
                        .strip_prefix("encrypted-file://")
                        .unwrap();
                    fs::read(manifest_root.join(relative)).unwrap()
                } else {
                    backend
                        .get_raw(&snapshot.secret_ref)
                        .unwrap()
                        .expose()
                        .to_vec()
                };
            let manifest: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            let recovery = match snapshot.backend_requirement {
                SignerBackendRequirement::FrostSecp256k1Tr
                | SignerBackendRequirement::CbMpcThresholdEcdsa => &manifest["recovery_signer"],
                SignerBackendRequirement::ChiaBlsAugThreshold2of3
                | SignerBackendRequirement::ErgoSigmaP2pkThreshold2of3 => {
                    &manifest["recovery_share"]
                }
                _ => panic!("unexpected provisioning backend"),
            };
            assert!(
                recovery.is_object(),
                "missing recovery material for {:?}",
                snapshot.chain_scope
            );
        }
    }

    #[test]
    fn uncommitted_staging_removes_secret_values_and_manifests() {
        let directory = tempfile::tempdir().unwrap();
        let secret_root = directory.path().join("executor-secrets");
        let manifest_root = directory.path().join("executor-manifests");
        super::super::ensure_private_executor_directory(&manifest_root).unwrap();
        let backend = SecretBackendFactory::self_hosted_development(&secret_root)
            .resolve()
            .unwrap();
        let handle;
        let manifest_path;
        {
            let mut staged = StagedSecrets::new(Arc::clone(&backend));
            handle = staged.put(SecretValue::new(vec![0x51; 32])).unwrap();
            let manifest_ref = staged
                .write_manifest(&manifest_root, br#"{"format_version":1}"#)
                .unwrap();
            manifest_path =
                manifest_root.join(manifest_ref.strip_prefix("encrypted-file://").unwrap());
            assert!(backend.get_raw(&handle).is_ok());
            assert!(manifest_path.is_file());
        }
        assert!(backend.get_raw(&handle).is_err());
        assert!(!manifest_path.exists());
    }
}
