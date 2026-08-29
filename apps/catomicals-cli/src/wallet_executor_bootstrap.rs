use super::multichain_wallet::{
    ConfigureChainRequest, MultiChainWalletSurface, SignerProfileStatus,
};
use std::collections::BTreeMap;

use catomicals_chain_domain::ChainScope;
use catomicals_signing_domain::{
    SignerBackendRequirement, SigningAvailability, SigningSuiteId, resolve_builtin_suite,
};
use catomicals_wallet::{
    ChainSigningExecutor, ChainSigningExecutorKey, SignerProfileStartupSnapshot, WalletNodeError,
    WalletNodeService,
};
use uuid::Uuid;

/// Public signer metadata used during startup. Private-share handles stay
/// inside the selected factory and never cross this contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSignerProfile {
    pub profile_id: Uuid,
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub backend_requirement: SignerBackendRequirement,
    pub signer_set_id: String,
    pub signer_epoch: u64,
    pub threshold: u16,
    pub max_signers: u16,
}

impl PublicSignerProfile {
    pub fn executor_key(&self) -> ChainSigningExecutorKey {
        ChainSigningExecutorKey {
            profile_id: self.profile_id,
            signing_suite_id: self.signing_suite_id,
            backend_requirement: self.backend_requirement.as_str().to_owned(),
        }
    }

    fn status(&self) -> SignerProfileStatus {
        SignerProfileStatus {
            profile_id: Some(self.profile_id),
            signer_set_id: self.signer_set_id.clone(),
            epoch: self.signer_epoch,
            min_signers: self.threshold,
            max_signers: self.max_signers,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Integration seam: concrete inventories map storage failures here.
pub enum ProfileInventoryError {
    Unavailable,
}

impl ProfileInventoryError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "executor-profile-inventory-unavailable",
        }
    }
}

pub trait PublicSignerProfileInventory: Send + Sync {
    fn profiles(&self) -> Result<Vec<PublicSignerProfile>, ProfileInventoryError>;
}

pub struct WalletSnapshotProfileInventory {
    profiles: Result<Vec<PublicSignerProfile>, ProfileInventoryError>,
}

impl WalletSnapshotProfileInventory {
    pub fn from_wallet_snapshot(
        snapshot: Result<Vec<SignerProfileStartupSnapshot>, WalletNodeError>,
    ) -> Self {
        let profiles = snapshot
            .map_err(|_| ProfileInventoryError::Unavailable)
            .map(|profiles| {
                profiles
                    .into_iter()
                    .map(|profile| PublicSignerProfile {
                        profile_id: profile.profile_id,
                        chain_scope: profile.chain_scope,
                        signing_suite_id: profile.signing_suite_id,
                        backend_requirement: profile.backend_requirement,
                        signer_set_id: profile.signer_set_id,
                        signer_epoch: profile.signer_epoch,
                        threshold: profile.threshold,
                        max_signers: profile.max_signers,
                    })
                    .collect()
            });
        Self { profiles }
    }
}

impl PublicSignerProfileInventory for WalletSnapshotProfileInventory {
    fn profiles(&self) -> Result<Vec<PublicSignerProfile>, ProfileInventoryError> {
        self.profiles.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Concrete provider factories use the full closed error set.
pub enum ExecutorFactoryError {
    ProviderUnavailable,
    InvalidConfiguration,
    UnsupportedProfile,
}

impl ExecutorFactoryError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "executor-provider-unavailable",
            Self::InvalidConfiguration => "executor-configuration-invalid",
            Self::UnsupportedProfile => "executor-profile-unsupported",
        }
    }
}

pub trait ChainSigningExecutorFactory: Send + Sync {
    fn backend_requirement(&self) -> SignerBackendRequirement;

    fn build(
        &self,
        profile: &PublicSignerProfile,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError>;
}

/// Private startup boundary for concrete signer runtimes. The builder receives
/// the complete durable snapshot, including only an opaque secret handle. It
/// must resolve that handle inside the selected signer backend and must never
/// return private-share bytes to the wallet process.
pub trait StartupExecutorBuilder: Send + Sync {
    fn build(
        &self,
        snapshot: &SignerProfileStartupSnapshot,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError>;
}

/// Adapts a production runtime builder to the public bootstrap catalog while
/// retaining sensitive startup metadata inside the factory boundary.
pub struct SnapshotBackedExecutorFactory {
    backend_requirement: SignerBackendRequirement,
    snapshots: BTreeMap<Uuid, SignerProfileStartupSnapshot>,
    builder: Box<dyn StartupExecutorBuilder>,
}

impl SnapshotBackedExecutorFactory {
    pub fn new(
        backend_requirement: SignerBackendRequirement,
        snapshots: Vec<SignerProfileStartupSnapshot>,
        builder: Box<dyn StartupExecutorBuilder>,
    ) -> Result<Self, ExecutorFactoryError> {
        let mut by_profile = BTreeMap::new();
        for snapshot in snapshots {
            if snapshot.backend_requirement != backend_requirement
                || snapshot.profile_id.is_nil()
                || by_profile.insert(snapshot.profile_id, snapshot).is_some()
            {
                return Err(ExecutorFactoryError::InvalidConfiguration);
            }
        }
        Ok(Self {
            backend_requirement,
            snapshots: by_profile,
            builder,
        })
    }
}

impl ChainSigningExecutorFactory for SnapshotBackedExecutorFactory {
    fn backend_requirement(&self) -> SignerBackendRequirement {
        self.backend_requirement
    }

    fn build(
        &self,
        profile: &PublicSignerProfile,
    ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
        let snapshot = self
            .snapshots
            .get(&profile.profile_id)
            .ok_or(ExecutorFactoryError::UnsupportedProfile)?;
        if snapshot.chain_scope != profile.chain_scope
            || snapshot.signing_suite_id != profile.signing_suite_id
            || snapshot.backend_requirement != profile.backend_requirement
            || snapshot.signer_set_id != profile.signer_set_id
            || snapshot.signer_epoch != profile.signer_epoch
            || snapshot.threshold != profile.threshold
            || snapshot.max_signers != profile.max_signers
        {
            return Err(ExecutorFactoryError::UnsupportedProfile);
        }
        self.builder.build(snapshot)
    }
}

/// Builds the production factory registry from concrete runtime builders.
/// An empty builder list is a valid fail-closed deployment: profiles remain
/// visible, but no executor is registered or reported ready.
pub fn snapshot_backed_factories(
    snapshots: &[SignerProfileStartupSnapshot],
    builders: Vec<(SignerBackendRequirement, Box<dyn StartupExecutorBuilder>)>,
) -> Result<Vec<Box<dyn ChainSigningExecutorFactory>>, ExecutorFactoryError> {
    builders
        .into_iter()
        .map(|(backend, builder)| {
            let backend_snapshots = snapshots
                .iter()
                .filter(|snapshot| snapshot.backend_requirement == backend)
                .cloned()
                .collect();
            SnapshotBackedExecutorFactory::new(backend, backend_snapshots, builder)
                .map(|factory| Box::new(factory) as Box<dyn ChainSigningExecutorFactory>)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorRegistrationState {
    Registered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorRegistration {
    pub profile_id: Uuid,
    pub chain_scope: ChainScope,
    pub state: ExecutorRegistrationState,
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutorBootstrapReport {
    pub inventory_error_code: Option<&'static str>,
    pub registrations: Vec<ExecutorRegistration>,
}

pub fn bootstrap_wallet_executors(
    wallet: &mut WalletNodeService,
    surface: &mut MultiChainWalletSurface,
    inventory: &dyn PublicSignerProfileInventory,
    factories: &[Box<dyn ChainSigningExecutorFactory>],
) -> ExecutorBootstrapReport {
    let mut profiles = match inventory.profiles() {
        Ok(profiles) => profiles,
        Err(error) => {
            return ExecutorBootstrapReport {
                inventory_error_code: Some(error.code()),
                registrations: Vec::new(),
            };
        }
    };
    profiles.sort_by_key(|profile| {
        (
            profile.chain_scope.chain,
            profile.signer_epoch,
            profile.profile_id,
        )
    });
    let mut report = ExecutorBootstrapReport::default();
    for profile in profiles {
        let request = ConfigureChainRequest {
            chain_scope: profile.chain_scope,
            signing_suite_id: profile.signing_suite_id,
        };
        let result = build_validated_executor(&profile, factories);
        match result {
            Ok(executor) => {
                wallet.register_chain_signing_executor(executor);
                if surface
                    .record_executor_registered(request, profile.status())
                    .is_ok()
                {
                    report.registrations.push(ExecutorRegistration {
                        profile_id: profile.profile_id,
                        chain_scope: profile.chain_scope,
                        state: ExecutorRegistrationState::Registered,
                        error_code: None,
                    });
                } else {
                    record_failure(
                        surface,
                        &profile,
                        "executor-profile-unsupported",
                        &mut report,
                    );
                }
            }
            Err(error_code) => record_failure(surface, &profile, error_code, &mut report),
        }
    }
    report
}

fn build_validated_executor(
    profile: &PublicSignerProfile,
    factories: &[Box<dyn ChainSigningExecutorFactory>],
) -> Result<Box<dyn ChainSigningExecutor>, &'static str> {
    if profile.profile_id.is_nil()
        || profile.signer_set_id.is_empty()
        || profile.signer_epoch == 0
        || profile.threshold == 0
        || profile.threshold > profile.max_signers
    {
        return Err("executor-profile-invalid");
    }
    let descriptor = resolve_builtin_suite(&profile.chain_scope, profile.signing_suite_id)
        .map_err(|_| "executor-profile-unsupported")?;
    if descriptor.backend_requirement != profile.backend_requirement {
        return Err("executor-profile-unsupported");
    }
    if descriptor.availability != SigningAvailability::Executable {
        return Err("executor-suite-unavailable");
    }
    let factory = factories
        .iter()
        .find(|factory| factory.backend_requirement() == profile.backend_requirement)
        .ok_or("executor-backend-unconfigured")?;
    let executor = factory.build(profile).map_err(ExecutorFactoryError::code)?;
    if executor.key() != profile.executor_key() {
        return Err("executor-key-mismatch");
    }
    Ok(executor)
}

fn record_failure(
    surface: &mut MultiChainWalletSurface,
    profile: &PublicSignerProfile,
    error_code: &'static str,
    report: &mut ExecutorBootstrapReport,
) {
    let request = ConfigureChainRequest {
        chain_scope: profile.chain_scope,
        signing_suite_id: profile.signing_suite_id,
    };
    surface.record_executor_failed(
        request,
        profile.status(),
        profile.backend_requirement,
        error_code,
    );
    report.registrations.push(ExecutorRegistration {
        profile_id: profile.profile_id,
        chain_scope: profile.chain_scope,
        state: ExecutorRegistrationState::Failed,
        error_code: Some(error_code),
    });
}

#[cfg(test)]
mod tests {
    use super::super::multichain_wallet::{BackendRuntimeState, MultiChainWalletSurface};
    use super::*;
    use catomicals_chain_domain::{BitcoinCashNetwork, ChainNetwork, ChainScope};
    use catomicals_signing_domain::{SignerBackendRequirement, SigningSuiteId};
    use catomicals_wallet::{
        ChainSigningExecution, ChainSigningExecutor, ChainSigningExecutorKey, SigningJobError,
        VerifiedChainSignature,
    };
    use uuid::Uuid;

    struct Inventory(Vec<PublicSignerProfile>);

    impl PublicSignerProfileInventory for Inventory {
        fn profiles(&self) -> Result<Vec<PublicSignerProfile>, ProfileInventoryError> {
            Ok(self.0.clone())
        }
    }

    struct NeverExecutor(ChainSigningExecutorKey);

    impl ChainSigningExecutor for NeverExecutor {
        fn key(&self) -> ChainSigningExecutorKey {
            self.0.clone()
        }

        fn execute(
            &self,
            _execution: &ChainSigningExecution,
            _now: i64,
        ) -> Result<VerifiedChainSignature, SigningJobError> {
            Err(SigningJobError::Backend("not called".to_owned()))
        }
    }

    struct Factory {
        backend: SignerBackendRequirement,
        fail_chain: Option<catomicals_chain_domain::ChainId>,
    }

    impl ChainSigningExecutorFactory for Factory {
        fn backend_requirement(&self) -> SignerBackendRequirement {
            self.backend
        }

        fn build(
            &self,
            profile: &PublicSignerProfile,
        ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
            if self.fail_chain == Some(profile.chain_scope.chain) {
                return Err(ExecutorFactoryError::ProviderUnavailable);
            }
            Ok(Box::new(NeverExecutor(profile.executor_key())))
        }
    }

    fn profile(
        discriminator: u8,
        network: ChainNetwork,
        suite: SigningSuiteId,
        backend: SignerBackendRequirement,
    ) -> PublicSignerProfile {
        PublicSignerProfile {
            profile_id: Uuid::from_bytes([discriminator; 16]),
            chain_scope: ChainScope::for_network(network),
            signing_suite_id: suite,
            backend_requirement: backend,
            signer_set_id: format!("signer-set-{discriminator}"),
            signer_epoch: 1,
            threshold: 2,
            max_signers: 3,
        }
    }

    #[test]
    fn empty_inventory_registers_nothing_and_keeps_all_seven_chains_unavailable() {
        let inventory = Inventory(Vec::new());
        let mut wallet = catomicals_wallet::WalletNodeService::without_signer(
            catomicals_wallet::RelyingPartyConfig::default(),
        )
        .unwrap();
        let mut surface = MultiChainWalletSurface::seven_chain_defaults();

        let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &[]);

        assert!(report.registrations.is_empty());
        assert!(surface.status().chains.iter().all(|chain| {
            chain.backend.state == BackendRuntimeState::Unavailable
                && chain.signer_profile.is_none()
                && !chain.ready_for_signing
        }));
    }

    #[test]
    fn one_factory_failure_is_isolated_and_uses_a_stable_error_code() {
        let bch = profile(
            0x21,
            ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        );
        let bsv = profile(
            0x22,
            ChainNetwork::Bsv(catomicals_chain_domain::BsvNetwork::Testnet),
            SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        );
        let inventory = Inventory(vec![bch, bsv]);
        let factories: Vec<Box<dyn ChainSigningExecutorFactory>> = vec![Box::new(Factory {
            backend: SignerBackendRequirement::CbMpcThresholdEcdsa,
            fail_chain: Some(catomicals_chain_domain::ChainId::Bsv),
        })];
        let mut wallet = catomicals_wallet::WalletNodeService::without_signer(
            catomicals_wallet::RelyingPartyConfig::default(),
        )
        .unwrap();
        let mut surface = MultiChainWalletSurface::seven_chain_defaults();

        let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &factories);

        assert_eq!(report.registrations.len(), 2);
        assert_eq!(
            report.registrations[0].state,
            ExecutorRegistrationState::Registered
        );
        assert_eq!(
            report.registrations[1].state,
            ExecutorRegistrationState::Failed
        );
        assert_eq!(
            report.registrations[1].error_code,
            Some("executor-provider-unavailable")
        );
        let status = surface.status();
        let bch_status = status
            .chains
            .iter()
            .find(|chain| chain.chain_scope.chain == catomicals_chain_domain::ChainId::BitcoinCash)
            .unwrap();
        let bsv_status = status
            .chains
            .iter()
            .find(|chain| chain.chain_scope.chain == catomicals_chain_domain::ChainId::Bsv)
            .unwrap();
        assert_eq!(bch_status.backend.state, BackendRuntimeState::Ready);
        assert_eq!(bsv_status.backend.state, BackendRuntimeState::Failed);
        assert_eq!(
            bsv_status.backend.error_code,
            Some("executor-provider-unavailable")
        );
    }

    #[test]
    fn wallet_snapshot_inventory_exposes_public_metadata_without_secret_handles() {
        let profile_id = Uuid::from_bytes([0x31; 16]);
        let snapshot = catomicals_wallet::SignerProfileStartupSnapshot {
            profile_id,
            wallet_id: Uuid::from_bytes([0x32; 16]),
            chain_scope: ChainScope::for_network(ChainNetwork::BitcoinCash(
                BitcoinCashNetwork::Chipnet,
            )),
            signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
            signer_set_id: "snapshot-set".to_owned(),
            authorization_signer_id: "passkey-owner".to_owned(),
            signer_epoch: 4,
            threshold: 2,
            max_signers: 3,
            verification_key_hex: "02aa".to_owned(),
            secret_ref: "opaque://must-not-cross-bootstrap-contract".to_owned(),
            address_bindings: Vec::new(),
        };

        let inventory = WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(vec![snapshot]));
        let public = inventory.profiles().unwrap();

        assert_eq!(public.len(), 1);
        assert_eq!(public[0].profile_id, profile_id);
        assert_eq!(public[0].signer_set_id, "snapshot-set");
        let debug = format!("{:?}", public[0]);
        assert!(!debug.contains("opaque://"));
        assert!(!debug.contains("passkey-owner"));
        assert!(!debug.contains("02aa"));
    }

    #[test]
    fn snapshot_backed_factory_keeps_the_opaque_profile_inside_the_builder_boundary() {
        use std::sync::{Arc, Mutex};

        struct RecordingBuilder {
            observed_secret_ref: Arc<Mutex<Option<String>>>,
        }

        impl StartupExecutorBuilder for RecordingBuilder {
            fn build(
                &self,
                snapshot: &SignerProfileStartupSnapshot,
            ) -> Result<Box<dyn ChainSigningExecutor>, ExecutorFactoryError> {
                *self.observed_secret_ref.lock().unwrap() = Some(snapshot.secret_ref.clone());
                Ok(Box::new(NeverExecutor(ChainSigningExecutorKey {
                    profile_id: snapshot.profile_id,
                    signing_suite_id: snapshot.signing_suite_id,
                    backend_requirement: snapshot.backend_requirement.as_str().to_owned(),
                })))
            }
        }

        let observed = Arc::new(Mutex::new(None));
        let snapshot = catomicals_wallet::SignerProfileStartupSnapshot {
            profile_id: Uuid::from_bytes([0x35; 16]),
            wallet_id: Uuid::from_bytes([0x36; 16]),
            chain_scope: ChainScope::for_network(ChainNetwork::BitcoinCash(
                BitcoinCashNetwork::Chipnet,
            )),
            signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            backend_requirement: SignerBackendRequirement::CbMpcThresholdEcdsa,
            signer_set_id: "snapshot-backed-set".to_owned(),
            authorization_signer_id: "passkey-owner".to_owned(),
            signer_epoch: 2,
            threshold: 2,
            max_signers: 3,
            verification_key_hex: "02aa".to_owned(),
            secret_ref: "encrypted-file://opaque-profile-manifest".to_owned(),
            address_bindings: Vec::new(),
        };
        let inventory =
            WalletSnapshotProfileInventory::from_wallet_snapshot(Ok(vec![snapshot.clone()]));
        let public = inventory.profiles().unwrap().remove(0);
        let factories = snapshot_backed_factories(
            &[snapshot],
            vec![(
                SignerBackendRequirement::CbMpcThresholdEcdsa,
                Box::new(RecordingBuilder {
                    observed_secret_ref: Arc::clone(&observed),
                }),
            )],
        )
        .unwrap();
        let mut wallet =
            WalletNodeService::without_signer(catomicals_wallet::RelyingPartyConfig::default())
                .unwrap();
        let mut surface = MultiChainWalletSurface::seven_chain_defaults();

        let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &factories);

        assert_eq!(report.registrations.len(), 1);
        assert_eq!(
            report.registrations[0].state,
            ExecutorRegistrationState::Registered
        );
        let bch = surface
            .status()
            .chains
            .into_iter()
            .find(|chain| chain.chain_scope.chain == catomicals_chain_domain::ChainId::BitcoinCash)
            .unwrap();
        assert!(bch.ready_for_signing);
        assert_eq!(bch.backend.state, BackendRuntimeState::Ready);
        assert_eq!(
            bch.signer_profile.unwrap().profile_id,
            Some(public.profile_id)
        );
        assert_eq!(
            observed.lock().unwrap().as_deref(),
            Some("encrypted-file://opaque-profile-manifest")
        );
        assert!(!format!("{public:?}").contains("opaque-profile-manifest"));
    }

    #[test]
    fn profile_without_a_configured_factory_is_reported_per_chain() {
        let bch = profile(
            0x41,
            ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet),
            SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
            SignerBackendRequirement::CbMpcThresholdEcdsa,
        );
        let inventory = Inventory(vec![bch]);
        let mut wallet = catomicals_wallet::WalletNodeService::without_signer(
            catomicals_wallet::RelyingPartyConfig::default(),
        )
        .unwrap();
        let mut surface = MultiChainWalletSurface::seven_chain_defaults();

        let report = bootstrap_wallet_executors(&mut wallet, &mut surface, &inventory, &[]);

        assert_eq!(
            report.registrations[0].error_code,
            Some("executor-backend-unconfigured")
        );
        let bch = surface
            .status()
            .chains
            .into_iter()
            .find(|chain| chain.chain_scope.chain == catomicals_chain_domain::ChainId::BitcoinCash)
            .unwrap();
        assert_eq!(bch.backend.state, BackendRuntimeState::Failed);
        assert_eq!(
            bch.backend.error_code,
            Some("executor-backend-unconfigured")
        );
    }
}
