use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, MAX_REVIEW_MATERIAL_BYTES,
    REVIEW_ARTIFACT_SCHEMA_VERSION, ReviewArtifact, ReviewContractError,
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
            SigningExecutionMode::ThresholdNonInteractive => {
                return Err(BsvError::InvalidSigningSuite(
                    "BSV ECDSA has no non-interactive threshold backend".to_owned(),
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
            return Err(ReviewContractError::ReviewedMaterialTooLong {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
        let request = BsvSigningRequest::decode(transaction_material).map_err(review_error)?;
        let canonical_request = request.encode().map_err(review_error)?;
        if canonical_request != transaction_material {
            return Err(review_error(BsvError::InvalidSigningMaterial(
                "signing request is not canonically encoded".to_owned(),
            )));
        }
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
        let request_digest = Sha256::digest(&canonical_request).into();
        let script_digest: [u8; 32] = Sha256::digest(&request.script_code).into();
        let output_total: u128 = request
            .transaction
            .outputs
            .iter()
            .map(|output| u128::from(output.value_satoshis))
            .sum();
        let summary = format!(
            "BSV {}: {} input(s), {} output(s), output total {} satoshis; sign input {} worth {} satoshis; script sha256 {}; SIGHASH_ALL|FORKID",
            network_name(self.network),
            request.transaction.inputs.len(),
            request.transaction.outputs.len(),
            output_total,
            request.input_index,
            request.input_value_satoshis,
            encode_hex(script_digest),
        );
        let review_digest = review_digest(
            self.scope(),
            signing_message_digest,
            request_digest,
            &summary,
        );
        ReviewArtifact::new(
            self.scope(),
            review_digest,
            signing_message_digest,
            summary,
            canonical_request,
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
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "review scope does not match the BSV suite".to_owned(),
            ));
        }
        let expected = self
            .review_transaction(&review.reviewed_material)
            .map_err(unreproducible_review)?;
        if expected != *review {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "review artifact binding mismatch".to_owned(),
            ));
        }
        verify_transaction_signature(
            &self.verifying_public_key,
            expected.signing_message_digest,
            finalized_signature,
            ForkIdSighashType::ALL,
        )
        .map_err(review_error)
    }
}

fn review_error(error: BsvError) -> ReviewContractError {
    ReviewContractError::InvalidFinalizedSignature(error.to_string())
}

fn unreproducible_review(error: ReviewContractError) -> ReviewContractError {
    ReviewContractError::InvalidFinalizedSignature(format!(
        "review artifact cannot be reproduced: {error}"
    ))
}

fn review_digest(
    scope: ChainScope,
    signing_digest: [u8; 32],
    request_digest: [u8; 32],
    summary: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals.bsv.review.v2\0");
    hasher.update(scope.network.as_str().as_bytes());
    hasher.update(signing_digest);
    hasher.update(request_digest);
    hasher.update((summary.len() as u64).to_le_bytes());
    hasher.update(summary.as_bytes());
    hasher.finalize().into()
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
