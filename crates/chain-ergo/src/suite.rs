use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ErgoNetwork, ReviewArtifact,
    ReviewContractError,
};
use catomicals_signing_domain::{
    SigningAlgorithm, SigningSuite, SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};

use crate::ErgoAdapterError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErgoSignerMode {
    SingleProver,
    MultiParty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErgoSignerBackend {
    NativeSigma,
    Secp256k1Ecdsa,
    Secp256k1Frost,
}

#[derive(Debug, Clone, Copy)]
pub struct ErgoChainSuite {
    network: ErgoNetwork,
}

impl ErgoChainSuite {
    pub const fn new(network: ErgoNetwork) -> Self {
        Self { network }
    }

    pub const fn network(&self) -> ErgoNetwork {
        self.network
    }
}

impl ChainSuite for ErgoChainSuite {
    fn scope(&self) -> ChainScope {
        ChainScope::for_network(ChainNetwork::Ergo(self.network))
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            address_derivation: true,
            transaction_review: false,
            final_signature_verification: false,
            broadcast: false,
        }
    }

    fn review_transaction(
        &self,
        _transaction_material: &[u8],
    ) -> Result<ReviewArtifact, ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation {
            operation: "Ergo transaction review",
        })
    }

    fn verify_finalized_signature(
        &self,
        _review: &ReviewArtifact,
        _finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        Err(ReviewContractError::UnsupportedOperation {
            operation: "Ergo Sigma proof verification",
        })
    }
}

/// Declares the native Sigma contract without claiming that this crate executes it.
#[derive(Debug, Clone, Copy)]
pub struct ErgoSigningSuite {
    scope: ChainScope,
    descriptor: SigningSuiteDescriptor,
}

impl ErgoSigningSuite {
    pub fn new(network: ErgoNetwork) -> Result<Self, ErgoAdapterError> {
        let scope = ChainScope::for_network(ChainNetwork::Ergo(network));
        let descriptor = resolve_builtin_suite(&scope, SigningSuiteId::ERGO_SIGMA_NATIVE_V1)?;
        Ok(Self { scope, descriptor })
    }

    pub const fn signing_algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ErgoSigma
    }

    pub fn required_backend(
        &self,
        mode: ErgoSignerMode,
    ) -> Result<ErgoSignerBackend, ErgoAdapterError> {
        match mode {
            ErgoSignerMode::SingleProver => Ok(ErgoSignerBackend::NativeSigma),
            ErgoSignerMode::MultiParty => Err(ErgoAdapterError::SigmaMultisigUnavailable),
        }
    }

    pub fn validate_backend(
        &self,
        mode: ErgoSignerMode,
        backend: ErgoSignerBackend,
    ) -> Result<(), ErgoAdapterError> {
        if self.required_backend(mode)? == backend {
            Ok(())
        } else {
            Err(ErgoAdapterError::IncompatibleSignerBackend { mode, backend })
        }
    }

    /// Execution remains unavailable until a transaction-context-aware Sigma prover is wired in.
    pub fn sign(&self, _transaction_material: &[u8]) -> Result<Vec<u8>, ErgoAdapterError> {
        Err(ErgoAdapterError::SigmaSigningUnavailable)
    }
}

impl SigningSuite for ErgoSigningSuite {
    fn descriptor(&self) -> SigningSuiteDescriptor {
        self.descriptor
    }

    fn supports(&self, chain_scope: &ChainScope) -> bool {
        *chain_scope == self.scope
    }
}
