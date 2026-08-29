use borsh::{BorshDeserialize, BorshSerialize};
use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, KaspaNetwork, ReviewArtifact,
    ReviewContractError,
};
use kaspa_consensus_core::{
    hashing::sighash_type::SigHashType,
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};
use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::{
    KaspaAdapterError, ecdsa_transaction_signing_hash, schnorr_transaction_signing_hash,
    transaction_signing_hash, verify_ecdsa_digest, verify_schnorr_digest,
};

const REVIEW_MATERIAL_SCHEMA_VERSION: u16 = 1;
const MAX_REVIEW_MATERIAL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KaspaVerifier {
    /// BIP340 x-only verification. The official secp256k1 verifier lifts the
    /// x-coordinate to the even-Y curve point required by the protocol.
    Schnorr([u8; 32]),
    Ecdsa([u8; 33]),
}

impl KaspaVerifier {
    fn validate(&self) -> Result<(), KaspaAdapterError> {
        match self {
            Self::Schnorr(public_key) => XOnlyPublicKey::from_slice(public_key)
                .map(|_| ())
                .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string())),
            Self::Ecdsa(public_key) => PublicKey::from_slice(public_key)
                .map(|_| ())
                .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string())),
        }
    }

    const fn name(&self) -> &'static str {
        match self {
            Self::Schnorr(_) => "schnorr",
            Self::Ecdsa(_) => "ecdsa",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KaspaReviewMaterial {
    schema_version: u16,
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    input_index: u32,
    hash_type: u8,
}

impl KaspaReviewMaterial {
    pub fn new(
        transaction: Transaction,
        entries: Vec<UtxoEntry>,
        input_index: usize,
        hash_type: SigHashType,
    ) -> Result<Self, KaspaAdapterError> {
        let input_index =
            u32::try_from(input_index).map_err(|_| KaspaAdapterError::InvalidInputIndex {
                input_index,
                inputs: transaction.inputs.len(),
            })?;
        let material = Self {
            schema_version: REVIEW_MATERIAL_SCHEMA_VERSION,
            transaction,
            entries,
            input_index,
            hash_type: hash_type.to_u8(),
        };
        material.validate()?;
        Ok(material)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KaspaAdapterError> {
        self.validate()?;
        borsh::to_vec(self)
            .map_err(|error| KaspaAdapterError::InvalidReviewMaterial(error.to_string()))
    }

    fn decode(encoded: &[u8]) -> Result<Self, KaspaAdapterError> {
        if encoded.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(KaspaAdapterError::ReviewMaterialTooLarge {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
        let material = borsh::from_slice::<Self>(encoded)
            .map_err(|error| KaspaAdapterError::InvalidReviewMaterial(error.to_string()))?;
        material.validate()?;
        Ok(material)
    }

    fn validate(&self) -> Result<(), KaspaAdapterError> {
        if self.schema_version != REVIEW_MATERIAL_SCHEMA_VERSION {
            return Err(KaspaAdapterError::InvalidReviewMaterial(format!(
                "unsupported schema version {}",
                self.schema_version
            )));
        }
        if self.transaction.inputs.len() != self.entries.len() {
            return Err(KaspaAdapterError::MismatchedUtxoCount {
                inputs: self.transaction.inputs.len(),
                entries: self.entries.len(),
            });
        }
        let mut canonical_transaction = self.transaction.clone();
        canonical_transaction.finalize();
        if canonical_transaction.id() != self.transaction.id() {
            return Err(KaspaAdapterError::InvalidReviewMaterial(
                "cached transaction id does not match the transaction fields".to_owned(),
            ));
        }
        let input_index = self.input_index as usize;
        if input_index >= self.transaction.inputs.len() {
            return Err(KaspaAdapterError::InvalidInputIndex {
                input_index,
                inputs: self.transaction.inputs.len(),
            });
        }
        SigHashType::from_u8(self.hash_type)
            .map_err(|error| KaspaAdapterError::InvalidReviewMaterial(error.to_owned()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KaspaChainSuite {
    network: KaspaNetwork,
    verifier: KaspaVerifier,
}

impl KaspaChainSuite {
    pub fn new(network: KaspaNetwork, verifier: KaspaVerifier) -> Result<Self, KaspaAdapterError> {
        verifier.validate()?;
        Ok(Self { network, verifier })
    }

    fn review(&self, encoded: &[u8]) -> Result<ReviewArtifact, KaspaAdapterError> {
        let material = KaspaReviewMaterial::decode(encoded)?;
        let hash_type = SigHashType::from_u8(material.hash_type)
            .map_err(|error| KaspaAdapterError::InvalidReviewMaterial(error.to_owned()))?;
        let input_index = material.input_index as usize;
        let populated = PopulatedTransaction::new(&material.transaction, material.entries.clone());
        let signing_message_digest = match self.verifier {
            KaspaVerifier::Schnorr(_) => {
                schnorr_transaction_signing_hash(&populated, input_index, hash_type)
            }
            KaspaVerifier::Ecdsa(_) => {
                ecdsa_transaction_signing_hash(&populated, input_index, hash_type)
            }
        };
        let total_output = material
            .transaction
            .outputs
            .iter()
            .try_fold(0u64, |sum, output| sum.checked_add(output.value))
            .ok_or_else(|| {
                KaspaAdapterError::InvalidReviewMaterial("output value sum overflow".to_owned())
            })?;
        let total_input = material
            .entries
            .iter()
            .try_fold(0u64, |sum, entry| sum.checked_add(entry.amount))
            .ok_or_else(|| {
                KaspaAdapterError::InvalidReviewMaterial("input value sum overflow".to_owned())
            })?;
        let fee = total_input.checked_sub(total_output).ok_or_else(|| {
            KaspaAdapterError::InvalidReviewMaterial(
                "transaction output value exceeds its populated input value".to_owned(),
            )
        })?;
        let summary = format!(
            "Kaspa {:?} {} transaction {} input {}/{}; {} inputs, {} outputs, {} sompi input, {} sompi output, {} sompi fee, sighash 0x{:02x}",
            self.network,
            self.verifier.name(),
            material.transaction.id(),
            input_index,
            material.transaction.inputs.len(),
            material.transaction.inputs.len(),
            material.transaction.outputs.len(),
            total_input,
            total_output,
            fee,
            hash_type.to_u8(),
        );
        ReviewArtifact::new(
            self.scope(),
            transaction_signing_hash(encoded),
            signing_message_digest,
            summary,
        )
        .map_err(|error| KaspaAdapterError::InvalidReviewMaterial(error.to_string()))
    }
}

impl ChainSuite for KaspaChainSuite {
    fn scope(&self) -> ChainScope {
        ChainScope::for_network(ChainNetwork::Kaspa(self.network))
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
        self.review(transaction_material)
            .map_err(|_| ReviewContractError::UnsupportedOperation {
                operation: "invalid Kaspa review material",
            })
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        if review.scope != self.scope() {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "review scope does not match this Kaspa suite".to_owned(),
            ));
        }
        let signature = <&[u8; 64]>::try_from(finalized_signature).map_err(|_| {
            ReviewContractError::InvalidFinalizedSignature(
                "Kaspa compact signatures must contain exactly 64 bytes".to_owned(),
            )
        })?;
        let result = match &self.verifier {
            KaspaVerifier::Schnorr(public_key) => {
                verify_schnorr_digest(&review.signing_message_digest, public_key, signature)
            }
            KaspaVerifier::Ecdsa(public_key) => {
                verify_ecdsa_digest(&review.signing_message_digest, public_key, signature)
            }
        };
        result.map_err(|error| ReviewContractError::InvalidFinalizedSignature(error.to_string()))
    }
}
