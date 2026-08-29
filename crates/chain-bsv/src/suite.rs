use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ReviewArtifact, ReviewContractError,
};
use catomicals_signing_domain::{
    SignerBackendRequirement, SigningExecutionMode, SigningSuiteDescriptor, SigningSuiteId,
    resolve_builtin_suite,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::{
    BsvError, BsvNetwork, BsvSigningRequest, ForkIdSighashType, transaction::network_name,
    verify_transaction_signature,
};

const MAX_REVIEW_MATERIAL_BYTES: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct BsvChainSuite {
    network: BsvNetwork,
    verifying_public_key: PublicKey,
}

impl BsvChainSuite {
    pub fn new(network: BsvNetwork, verifying_public_key: [u8; 33]) -> Result<Self, BsvError> {
        let verifying_public_key =
            PublicKey::from_slice(&verifying_public_key).map_err(|_| BsvError::InvalidPublicKey)?;
        Ok(Self {
            network,
            verifying_public_key,
        })
    }

    pub const fn network(&self) -> BsvNetwork {
        self.network
    }

    pub fn signing_descriptor(
        &self,
        mode: SigningExecutionMode,
    ) -> Result<SigningSuiteDescriptor, BsvError> {
        let suite_id = match mode {
            SigningExecutionMode::SingleSignerIsolated => SigningSuiteId::BSV_ECDSA_ISOLATED_V1,
            SigningExecutionMode::ThresholdInteractive => SigningSuiteId::BSV_ECDSA_CB_MPC_V1,
            SigningExecutionMode::NativeChainCoordinator => {
                return Err(BsvError::InvalidSigningSuite(
                    "BSV ECDSA has no native-chain coordinator backend".to_owned(),
                ));
            }
        };
        resolve_builtin_suite(&self.scope(), suite_id)
            .map_err(|error| BsvError::InvalidSigningSuite(error.to_string()))
    }

    pub fn validate_backend_requirement(
        &self,
        mode: SigningExecutionMode,
        backend: SignerBackendRequirement,
    ) -> Result<(), BsvError> {
        if self.signing_descriptor(mode)?.backend_requirement == backend {
            Ok(())
        } else {
            Err(BsvError::IncompatibleSignerBackend { mode, backend })
        }
    }
}

impl ChainSuite for BsvChainSuite {
    fn scope(&self) -> ChainScope {
        ChainScope::for_network(ChainNetwork::Bsv(self.network))
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
        if transaction_material.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "BSV signing material exceeds 1000000 bytes".to_owned(),
            ));
        }
        let request = BsvSigningRequest::decode(transaction_material).map_err(review_error)?;
        if request.network != self.network {
            return Err(review_error(BsvError::WrongSigningNetwork {
                configured: self.network,
                declared: request.network,
            }));
        }
        if request.sighash_type != ForkIdSighashType::ALL {
            return Err(review_error(BsvError::InvalidSighashType(
                request.sighash_type.to_u8(),
            )));
        }
        let signing_message_digest = request.signing_digest().map_err(review_error)?;
        let review_digest = Sha256::digest(transaction_material).into();
        ReviewArtifact::new(
            self.scope(),
            review_digest,
            signing_message_digest,
            format!(
                "BSV {}: sign input {} worth {} satoshis; {} outputs; SIGHASH_ALL|FORKID",
                network_name(self.network),
                request.input_index,
                request.input_value_satoshis,
                request.transaction.outputs.len()
            ),
        )
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        if review.scope != self.scope() {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "review scope does not match the BSV suite".to_owned(),
            ));
        }
        verify_transaction_signature(
            &self.verifying_public_key,
            review.signing_message_digest,
            finalized_signature,
            ForkIdSighashType::ALL,
        )
        .map_err(review_error)
    }
}

fn review_error(error: BsvError) -> ReviewContractError {
    ReviewContractError::InvalidFinalizedSignature(error.to_string())
}
