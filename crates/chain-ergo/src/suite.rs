use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ErgoNetwork,
    MAX_REVIEW_MATERIAL_BYTES, REVIEW_ARTIFACT_SCHEMA_VERSION, ReviewArtifact, ReviewContractError,
};
use catomicals_signing_domain::{
    Capabilities, SigningAlgorithm, SigningAvailability, SigningSuite, SigningSuiteDescriptor,
    SigningSuiteId, resolve_builtin_suite,
};
use ergo_lib::{
    chain::transaction::{Transaction, reduced::reduce_tx},
    ergotree_ir::{
        chain::address::Address,
        serialization::SigmaSerializable,
        sigma_protocol::sigma_boolean::{SigmaBoolean, SigmaProofOfKnowledgeTree},
    },
    wallet::{Wallet, secret_key::SecretKey, signing::TransactionContext},
};
use sha2::{Digest, Sha256};

use crate::{ErgoAdapterError, ErgoReviewMaterialV1};

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
            return Err(ReviewContractError::ReviewedMaterialTooLong {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
        let material = ErgoReviewMaterialV1::decode(transaction_material).map_err(review_error)?;
        let canonical = material.encode().map_err(review_error)?;
        if canonical != transaction_material {
            return Err(review_error(ErgoAdapterError::InvalidReviewMaterial(
                "non-canonical Ergo review material".into(),
            )));
        }
        if material.network != self.network {
            return Err(review_error(ErgoAdapterError::ReviewNetworkMismatch {
                expected: self.network,
                actual: material.network,
            }));
        }
        let state_context = material.state_context();
        let tx_context = TransactionContext::new(
            material.unsigned_tx.clone(),
            material.input_boxes.clone(),
            material.data_boxes.clone(),
        )
        .map_err(|error| {
            review_error(ErgoAdapterError::InvalidReviewMaterial(error.to_string()))
        })?;
        for (input_index, input_box) in material.input_boxes.iter().enumerate() {
            if !matches!(
                Address::recreate_from_ergo_tree(&input_box.ergo_tree),
                Ok(Address::P2Pk(_))
            ) {
                return Err(review_error(ErgoAdapterError::UnsupportedInputScript {
                    input_index,
                }));
            }
        }
        let reduced = reduce_tx(tx_context, &state_context).map_err(|error| {
            review_error(ErgoAdapterError::InvalidReviewMaterial(error.to_string()))
        })?;
        for (input_index, reduced_input) in reduced.reduced_inputs().iter().enumerate() {
            if !matches!(
                reduced_input.sigma_prop,
                SigmaBoolean::ProofOfKnowledge(SigmaProofOfKnowledgeTree::ProveDlog(_))
            ) {
                return Err(review_error(ErgoAdapterError::UnsupportedInputScript {
                    input_index,
                }));
            }
        }
        let review_digest: [u8; 32] = Sha256::digest(&canonical).into();
        let signing_message_digest: [u8; 32] = Sha256::digest(&material.bytes_to_sign).into();
        ReviewArtifact::new(
            self.scope(),
            review_digest,
            signing_message_digest,
            format!(
                "Ergo {:?} P2PK transaction with {} input(s) and {} output(s)",
                self.network,
                material.unsigned_tx.inputs.len(),
                material.unsigned_tx.output_candidates.len()
            ),
            canonical,
        )
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        if review.schema_version != REVIEW_ARTIFACT_SCHEMA_VERSION {
            return Err(ReviewContractError::UnsupportedSchemaVersion {
                expected: REVIEW_ARTIFACT_SCHEMA_VERSION,
                actual: review.schema_version,
            });
        }
        if review.scope != self.scope() {
            return Err(review_error(ErgoAdapterError::InvalidSignedTransaction(
                "review scope does not match the Ergo suite".into(),
            )));
        }
        let expected = self.review_transaction(&review.reviewed_material)?;
        if expected != *review {
            return Err(review_error(ErgoAdapterError::InvalidSignedTransaction(
                "review artifact binding mismatch".into(),
            )));
        }
        let material =
            ErgoReviewMaterialV1::decode(&review.reviewed_material).map_err(review_error)?;
        let signed = Transaction::sigma_parse_bytes(finalized_signature).map_err(|error| {
            review_error(ErgoAdapterError::InvalidSignedTransaction(
                error.to_string(),
            ))
        })?;
        if signed.sigma_serialize_bytes().map_err(|error| {
            review_error(ErgoAdapterError::InvalidSignedTransaction(
                error.to_string(),
            ))
        })? != finalized_signature
        {
            return Err(review_error(ErgoAdapterError::InvalidSignedTransaction(
                "non-canonical signed transaction encoding".into(),
            )));
        }
        ensure_signed_matches_review(&material, &signed).map_err(review_error)?;
        TransactionContext::new(
            signed,
            material.input_boxes.clone(),
            material.data_boxes.clone(),
        )
        .map_err(|error| {
            review_error(ErgoAdapterError::InvalidSignedTransaction(
                error.to_string(),
            ))
        })?
        .validate(&material.state_context())
        .map_err(|error| {
            review_error(ErgoAdapterError::InvalidSignedTransaction(
                error.to_string(),
            ))
        })
    }
}

/// Executes the native Sigma P2PK single-prover contract.
#[derive(Debug, Clone, Copy)]
pub struct ErgoSigningSuite {
    scope: ChainScope,
    descriptor: SigningSuiteDescriptor,
}

impl ErgoSigningSuite {
    pub fn new(network: ErgoNetwork) -> Result<Self, ErgoAdapterError> {
        let scope = ChainScope::for_network(ChainNetwork::Ergo(network));
        let mut descriptor = resolve_builtin_suite(&scope, SigningSuiteId::ERGO_SIGMA_NATIVE_V1)?;
        descriptor.capabilities = Capabilities {
            produces_consensus_signature: true,
            independently_verifiable: true,
            interactive_threshold: false,
            non_interactive_threshold: false,
        };
        descriptor.availability = SigningAvailability::Executable;
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

    /// Produces a complete signed Ergo transaction for the reviewed P2PK-only material.
    pub fn sign_p2pk(
        &self,
        review: &ReviewArtifact,
        secret_bytes: &[u8; 32],
    ) -> Result<Vec<u8>, ErgoAdapterError> {
        let network = match self.scope.network {
            ChainNetwork::Ergo(network) => network,
            _ => unreachable!("Ergo signing suite always owns an Ergo scope"),
        };
        let chain = ErgoChainSuite::new(network);
        let expected = chain
            .review_transaction(&review.reviewed_material)
            .map_err(|error| ErgoAdapterError::SigmaSigning(error.to_string()))?;
        if expected != *review {
            return Err(ErgoAdapterError::SigmaSigning(
                "review artifact binding mismatch".into(),
            ));
        }
        let material = ErgoReviewMaterialV1::decode(&review.reviewed_material)?;
        let secret =
            SecretKey::dlog_from_bytes(secret_bytes).ok_or(ErgoAdapterError::InvalidSecretKey)?;
        let wallet = Wallet::from_secrets(vec![secret]);
        let state_context = material.state_context();
        let tx_context = TransactionContext::new(
            material.unsigned_tx,
            material.input_boxes,
            material.data_boxes,
        )
        .map_err(|error| ErgoAdapterError::SigmaSigning(error.to_string()))?;
        wallet
            .sign_transaction(tx_context, &state_context, None)
            .map_err(|error| ErgoAdapterError::SigmaSigning(error.to_string()))?
            .sigma_serialize_bytes()
            .map_err(|error| ErgoAdapterError::SigmaSigning(error.to_string()))
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

fn ensure_signed_matches_review(
    material: &ErgoReviewMaterialV1,
    signed: &Transaction,
) -> Result<(), ErgoAdapterError> {
    let expected_bytes = &material.bytes_to_sign;
    let actual_bytes = signed
        .bytes_to_sign()
        .map_err(|error| ErgoAdapterError::InvalidSignedTransaction(error.to_string()))?;
    if expected_bytes != &actual_bytes {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "signed transaction bytes_to_sign differ from the reviewed transaction".into(),
        ));
    }
    if signed.inputs.len() != material.unsigned_tx.inputs.len()
        || signed
            .inputs
            .iter()
            .zip(material.unsigned_tx.inputs.iter())
            .any(|(signed_input, unsigned_input)| {
                signed_input.box_id != unsigned_input.box_id
                    || signed_input.spending_proof.extension != unsigned_input.extension
            })
    {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "input box or context extension differs from review".into(),
        ));
    }
    if signed.data_inputs != material.unsigned_tx.data_inputs {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "data inputs differ from review".into(),
        ));
    }
    if signed.output_candidates != material.unsigned_tx.output_candidates {
        return Err(ErgoAdapterError::InvalidSignedTransaction(
            "outputs differ from review".into(),
        ));
    }
    Ok(())
}

fn review_error(error: ErgoAdapterError) -> ReviewContractError {
    match error {
        ErgoAdapterError::UnsupportedReviewMaterialVersion { expected, actual } => {
            ReviewContractError::UnsupportedSchemaVersion { expected, actual }
        }
        other => ReviewContractError::InvalidFinalizedSignature(other.to_string()),
    }
}
