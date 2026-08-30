use std::collections::BTreeMap;

use catomicals_chain_domain::{
    BitcoinCashNetwork, BitcoinNetwork, BsvNetwork, ChainNetwork, ChainScope, ChiaNetwork,
    ErgoNetwork, FractalBitcoinNetwork, KaspaNetwork,
};
use catomicals_signing_domain::{
    SignerBackendRequirement, SigningAvailability, SigningSuiteId, resolve_builtin_suite,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MULTICHAIN_WALLET_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendRuntimeState {
    Ready,
    Starting,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerProfileStatus {
    pub profile_id: Option<Uuid>,
    pub signer_set_id: String,
    pub epoch: u64,
    pub min_signers: u16,
    pub max_signers: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendStatus {
    pub id: &'static str,
    pub state: BackendRuntimeState,
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSigningStatus {
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
    pub suite_availability: SigningAvailability,
    pub signer_profile: Option<SignerProfileStatus>,
    pub backend: BackendStatus,
    pub ready_for_signing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultiChainWalletStatus {
    pub schema_version: u16,
    pub chains: Vec<ChainSigningStatus>,
}

pub type MultiChainWalletConfiguration = MultiChainWalletStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureChainRequest {
    pub chain_scope: ChainScope,
    pub signing_suite_id: SigningSuiteId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiChainConfigurationError {
    UnsupportedSigningSuite,
    SigningSuiteNotExecutable,
}

impl MultiChainConfigurationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSigningSuite => "unsupported-signing-suite",
            Self::SigningSuiteNotExecutable => "signing-suite-not-executable",
        }
    }
}

impl core::fmt::Display for MultiChainConfigurationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSigningSuite => {
                "the signing suite does not support the selected chain network"
            }
            Self::SigningSuiteNotExecutable => "the signing suite has no executable signer backend",
        })
    }
}

impl std::error::Error for MultiChainConfigurationError {}

/// Configuration and health registry only. It never receives digests, key
/// material, approvals, or signing requests; those remain in wallet-core.
pub struct MultiChainWalletSurface {
    chains: BTreeMap<catomicals_chain_domain::ChainId, ChainSigningStatus>,
}

impl MultiChainWalletSurface {
    #[cfg(test)]
    pub fn bitcoin_signet(
        signer_profile: Option<SignerProfileStatus>,
        frost_state: BackendRuntimeState,
    ) -> Self {
        let mut surface = Self {
            chains: BTreeMap::new(),
        };
        let request = ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet)),
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        };
        surface
            .configure(request)
            .expect("the built-in Bitcoin Signet configuration is valid");
        let status = surface
            .chains
            .get_mut(&catomicals_chain_domain::ChainId::Bitcoin)
            .expect("Bitcoin Signet was configured");
        status.backend.state = frost_state;
        status.signer_profile = signer_profile;
        status.ready_for_signing = status.suite_availability == SigningAvailability::Executable
            && status.backend.state == BackendRuntimeState::Ready
            && status
                .signer_profile
                .as_ref()
                .is_some_and(|profile| profile.profile_id.is_some());
        surface
    }

    /// Fixed product catalog. These are safe public test networks only; an
    /// executor is unavailable until bootstrap registers a concrete provider.
    pub fn seven_chain_defaults() -> Self {
        let mut surface = Self {
            chains: BTreeMap::new(),
        };
        for request in default_chain_configurations() {
            surface
                .configure(request)
                .expect("the built-in seven-chain catalog is valid");
        }
        surface
    }

    pub fn configuration(&self) -> MultiChainWalletConfiguration {
        self.status()
    }

    pub fn status(&self) -> MultiChainWalletStatus {
        MultiChainWalletStatus {
            schema_version: MULTICHAIN_WALLET_SCHEMA_VERSION,
            chains: self.chains.values().cloned().collect(),
        }
    }

    pub fn configure(
        &mut self,
        request: ConfigureChainRequest,
    ) -> Result<ChainSigningStatus, MultiChainConfigurationError> {
        let descriptor = resolve_builtin_suite(&request.chain_scope, request.signing_suite_id)
            .map_err(|_| MultiChainConfigurationError::UnsupportedSigningSuite)?;
        if descriptor.availability != SigningAvailability::Executable {
            return Err(MultiChainConfigurationError::SigningSuiteNotExecutable);
        }
        let backend_id = backend_id(descriptor.backend_requirement);
        let status = ChainSigningStatus {
            chain_scope: request.chain_scope,
            signing_suite_id: request.signing_suite_id,
            suite_availability: descriptor.availability,
            ready_for_signing: false,
            signer_profile: None,
            backend: BackendStatus {
                id: backend_id,
                state: BackendRuntimeState::Unavailable,
                error_code: None,
            },
        };
        self.chains
            .insert(request.chain_scope.chain, status.clone());
        Ok(status)
    }

    pub(super) fn record_executor_registered(
        &mut self,
        request: ConfigureChainRequest,
        profile: SignerProfileStatus,
    ) -> Result<ChainSigningStatus, MultiChainConfigurationError> {
        self.configure(request.clone())?;
        let status = self
            .chains
            .get_mut(&request.chain_scope.chain)
            .expect("configured chain status exists");
        status.signer_profile = Some(profile);
        status.backend.state = BackendRuntimeState::Ready;
        status.backend.error_code = None;
        status.ready_for_signing = status.suite_availability == SigningAvailability::Executable;
        Ok(status.clone())
    }

    pub(super) fn record_executor_failed(
        &mut self,
        request: ConfigureChainRequest,
        profile: SignerProfileStatus,
        backend_requirement: SignerBackendRequirement,
        error_code: &'static str,
    ) -> ChainSigningStatus {
        let chain_id = request.chain_scope.chain;
        let _ = self.configure(request);
        let status = self
            .chains
            .get_mut(&chain_id)
            .unwrap_or_else(|| panic!("the fixed product catalog is missing chain {chain_id}"));
        status.signer_profile = Some(profile);
        status.backend.id = backend_requirement.as_str();
        status.backend.state = BackendRuntimeState::Failed;
        status.backend.error_code = Some(error_code);
        status.ready_for_signing = false;
        status.clone()
    }
}

fn default_chain_configurations() -> [ConfigureChainRequest; 7] {
    [
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet)),
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::BitcoinCash(
                BitcoinCashNetwork::Chipnet,
            )),
            signing_suite_id: SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Bsv(BsvNetwork::Testnet)),
            signing_suite_id: SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::FractalBitcoin(
                FractalBitcoinNetwork::Signet,
            )),
            signing_suite_id: SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Kaspa(KaspaNetwork::Testnet11)),
            signing_suite_id: SigningSuiteId::KASPA_ECDSA_CB_MPC_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11)),
            signing_suite_id: SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        },
        ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet)),
            signing_suite_id: SigningSuiteId::ERGO_SIGMA_P2PK_THRESHOLD_2OF3_V1,
        },
    ]
}

fn backend_id(requirement: SignerBackendRequirement) -> &'static str {
    requirement.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use catomicals_chain_domain::{
        BitcoinNetwork, ChainNetwork, ChiaNetwork, FractalBitcoinNetwork,
    };
    use uuid::Uuid;

    fn bitcoin_signet() -> ChainScope {
        ChainScope::for_network(ChainNetwork::Bitcoin(BitcoinNetwork::Signet))
    }

    #[test]
    fn default_contract_preserves_bitcoin_signet_and_reports_the_real_signer_surface() {
        let profile = SignerProfileStatus {
            profile_id: Some(Uuid::from_bytes([0x10; 16])),
            signer_set_id: Uuid::from_bytes([0x11; 16]).to_string(),
            epoch: 3,
            min_signers: 2,
            max_signers: 3,
        };
        let surface = MultiChainWalletSurface::bitcoin_signet(
            Some(profile.clone()),
            BackendRuntimeState::Ready,
        );

        assert_eq!(surface.configuration().schema_version, 1);
        let status = surface.status();
        assert_eq!(status.chains.len(), 1);
        assert_eq!(status.chains[0].chain_scope, bitcoin_signet());
        assert_eq!(
            status.chains[0].signing_suite_id,
            SigningSuiteId::BITCOIN_BIP340_FROST_V1
        );
        assert_eq!(status.chains[0].signer_profile, Some(profile));
        assert_eq!(status.chains[0].backend.state, BackendRuntimeState::Ready);
        assert_eq!(status.chains[0].backend.id, "frost-secp256k1-tr");
    }

    #[test]
    fn configuration_rejects_a_suite_from_another_chain() {
        let mut surface = MultiChainWalletSurface::bitcoin_signet(None, BackendRuntimeState::Ready);
        let request = ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11)),
            signing_suite_id: SigningSuiteId::BITCOIN_BIP340_FROST_V1,
        };

        let error = surface.configure(request).unwrap_err();
        assert_eq!(error.code(), "unsupported-signing-suite");
        assert_eq!(surface.status().chains[0].chain_scope, bitcoin_signet());
    }

    #[test]
    fn legacy_signer_set_without_a_durable_chain_profile_is_not_ready_for_signing() {
        let profile = SignerProfileStatus {
            profile_id: None,
            signer_set_id: Uuid::from_bytes([0x18; 16]).to_string(),
            epoch: 1,
            min_signers: 2,
            max_signers: 3,
        };
        let surface =
            MultiChainWalletSurface::bitcoin_signet(Some(profile), BackendRuntimeState::Ready);

        assert_eq!(
            surface.status().chains[0].backend.state,
            BackendRuntimeState::Ready
        );
        assert!(!surface.status().chains[0].ready_for_signing);
    }

    #[test]
    fn configuration_reports_an_unwired_backend_without_claiming_signing_is_ready() {
        let mut surface = MultiChainWalletSurface::bitcoin_signet(None, BackendRuntimeState::Ready);
        let request = ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Chia(ChiaNetwork::Testnet11)),
            signing_suite_id: SigningSuiteId::CHIA_BLS12381_AUG_THRESHOLD_2OF3_V1,
        };

        let configured = surface.configure(request.clone()).unwrap();
        assert_eq!(configured.chain_scope, request.chain_scope);
        assert_eq!(configured.backend.state, BackendRuntimeState::Unavailable);
        assert_eq!(configured.backend.id, "chia-bls-aug-threshold-2of3");
    }

    #[test]
    fn configuration_rejects_declaration_only_suites() {
        let mut surface = MultiChainWalletSurface::bitcoin_signet(None, BackendRuntimeState::Ready);
        let before = surface.status();
        let request = ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::Ergo(ErgoNetwork::Testnet)),
            signing_suite_id: SigningSuiteId::ERGO_SIGMA_NATIVE_V1,
        };

        let error = surface.configure(request).unwrap_err();
        assert_eq!(error.code(), "signing-suite-not-executable");
        assert_eq!(surface.status(), before);
    }

    #[test]
    fn fractal_backend_does_not_claim_a_bitcoin_scoped_signer_profile() {
        let profile = SignerProfileStatus {
            profile_id: Some(Uuid::from_bytes([0x21; 16])),
            signer_set_id: Uuid::from_bytes([0x22; 16]).to_string(),
            epoch: 1,
            min_signers: 2,
            max_signers: 3,
        };
        let mut surface = MultiChainWalletSurface::bitcoin_signet(
            Some(profile.clone()),
            BackendRuntimeState::Ready,
        );
        let request = ConfigureChainRequest {
            chain_scope: ChainScope::for_network(ChainNetwork::FractalBitcoin(
                FractalBitcoinNetwork::Signet,
            )),
            signing_suite_id: SigningSuiteId::FRACTAL_BITCOIN_BIP340_FROST_V1,
        };

        let configured = surface.configure(request).unwrap();
        assert_eq!(configured.signer_profile, None);
        assert_eq!(configured.backend.state, BackendRuntimeState::Unavailable);
        assert!(!configured.ready_for_signing);
    }

    #[test]
    fn serialized_status_has_explicit_chain_suite_profile_and_backend_fields() {
        let surface = MultiChainWalletSurface::bitcoin_signet(None, BackendRuntimeState::Ready);
        let value = serde_json::to_value(surface.status()).unwrap();
        let chain = &value["chains"][0];

        assert_eq!(chain["chain_scope"]["network"], "bitcoin.signet");
        assert_eq!(
            chain["signing_suite_id"],
            "btc.bip340.frost-secp256k1-tr.v1"
        );
        assert!(chain.get("signer_profile").is_some());
        assert_eq!(chain["backend"]["state"], "ready");
        assert_eq!(chain["ready_for_signing"], false);
    }

    #[test]
    fn seven_chain_defaults_are_visible_and_unavailable_without_registered_executors() {
        let status = MultiChainWalletSurface::seven_chain_defaults().status();

        assert_eq!(status.chains.len(), 7);
        assert_eq!(
            status
                .chains
                .iter()
                .map(|chain| chain.chain_scope.chain)
                .collect::<Vec<_>>(),
            catomicals_chain_domain::ChainId::ALL
        );
        assert!(status.chains.iter().all(|chain| {
            chain.signer_profile.is_none()
                && chain.backend.state == BackendRuntimeState::Unavailable
                && !chain.ready_for_signing
        }));
    }
}
