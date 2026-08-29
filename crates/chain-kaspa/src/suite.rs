use borsh::{BorshDeserialize, BorshSerialize};
use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, KaspaNetwork,
    MAX_REVIEW_MATERIAL_BYTES, REVIEW_ARTIFACT_SCHEMA_VERSION, ReviewArtifact, ReviewContractError,
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

const REVIEW_MATERIAL_SCHEMA_VERSION: u16 = 2;

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
    network: u8,
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    input_index: u32,
    hash_type: u8,
}

impl KaspaReviewMaterial {
    pub fn new(
        network: KaspaNetwork,
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
            network: encode_network(network),
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
        decode_network(self.network)?;
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
        let material_network = decode_network(material.network)?;
        if material_network != self.network {
            return Err(KaspaAdapterError::InvalidReviewMaterial(format!(
                "review material is bound to {}, not {}",
                network_name(material_network),
                network_name(self.network),
            )));
        }
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
        let material_digest = transaction_signing_hash(encoded);
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
        let review_digest = review_digest(
            self.scope(),
            self.verifier.name(),
            signing_message_digest,
            material_digest,
            &summary,
        );
        ReviewArtifact::new(
            self.scope(),
            review_digest,
            signing_message_digest,
            summary,
            encoded.to_vec(),
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
        if transaction_material.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ReviewContractError::ReviewedMaterialTooLong {
                max_bytes: MAX_REVIEW_MATERIAL_BYTES,
            });
        }
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
        if review.schema_version != REVIEW_ARTIFACT_SCHEMA_VERSION {
            return Err(ReviewContractError::UnsupportedSchemaVersion {
                expected: REVIEW_ARTIFACT_SCHEMA_VERSION,
                actual: review.schema_version,
            });
        }
        if review.scope != self.scope() {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "Kaspa review artifact binding mismatch".to_owned(),
            ));
        }
        let expected = self
            .review_transaction(&review.reviewed_material)
            .map_err(unreproducible_review)?;
        if expected != *review {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "Kaspa review artifact binding mismatch".to_owned(),
            ));
        }
        let material = KaspaReviewMaterial::decode(&review.reviewed_material)
            .map_err(|error| ReviewContractError::InvalidFinalizedSignature(error.to_string()))?;
        let (signature, hash_type) = parse_finalized_signature(finalized_signature)?;
        if hash_type.to_u8() != material.hash_type {
            return Err(ReviewContractError::InvalidFinalizedSignature(format!(
                "Kaspa signature hash type 0x{:02x} does not match reviewed hash type 0x{:02x}",
                hash_type.to_u8(),
                material.hash_type,
            )));
        }
        let result = match &self.verifier {
            KaspaVerifier::Schnorr(public_key) => {
                verify_schnorr_digest(&expected.signing_message_digest, public_key, signature)
            }
            KaspaVerifier::Ecdsa(public_key) => {
                verify_ecdsa_digest(&expected.signing_message_digest, public_key, signature)
            }
        };
        result.map_err(|error| ReviewContractError::InvalidFinalizedSignature(error.to_string()))
    }
}

fn review_digest(
    scope: ChainScope,
    verifier: &str,
    signing_message_digest: [u8; 32],
    material_digest: [u8; 32],
    summary: &str,
) -> [u8; 32] {
    let mut binding = Vec::with_capacity(128 + summary.len());
    binding.extend_from_slice(b"catomicals.kaspa.review.v2\0");
    binding.extend_from_slice(scope.network.as_str().as_bytes());
    binding.push(0);
    binding.extend_from_slice(verifier.as_bytes());
    binding.push(0);
    binding.extend_from_slice(&signing_message_digest);
    binding.extend_from_slice(&material_digest);
    binding.extend_from_slice(&(summary.len() as u64).to_le_bytes());
    binding.extend_from_slice(summary.as_bytes());
    transaction_signing_hash(binding)
}

fn unreproducible_review(error: ReviewContractError) -> ReviewContractError {
    ReviewContractError::InvalidFinalizedSignature(format!(
        "review artifact cannot be reproduced: {error}"
    ))
}

fn parse_finalized_signature(
    finalized_signature: &[u8],
) -> Result<(&[u8; 64], SigHashType), ReviewContractError> {
    let signature = match finalized_signature {
        [65, signature @ ..] if signature.len() == 65 => signature,
        signature if signature.len() == 65 => signature,
        _ => {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "Kaspa signature must be a 65-byte signature plus hash type, optionally wrapped in a direct 65-byte push script"
                    .to_owned(),
            ));
        }
    };
    let hash_type = SigHashType::from_u8(signature[64]).map_err(|error| {
        ReviewContractError::InvalidFinalizedSignature(format!(
            "invalid Kaspa signature hash type: {error}"
        ))
    })?;
    let compact = <&[u8; 64]>::try_from(&signature[..64]).map_err(|_| {
        ReviewContractError::InvalidFinalizedSignature(
            "invalid Kaspa compact signature length".to_owned(),
        )
    })?;
    Ok((compact, hash_type))
}

const fn encode_network(network: KaspaNetwork) -> u8 {
    match network {
        KaspaNetwork::Mainnet => 0,
        KaspaNetwork::Testnet10 => 1,
        KaspaNetwork::Testnet11 => 2,
        KaspaNetwork::Simnet => 3,
        KaspaNetwork::Devnet => 4,
    }
}

fn decode_network(encoded: u8) -> Result<KaspaNetwork, KaspaAdapterError> {
    match encoded {
        0 => Ok(KaspaNetwork::Mainnet),
        1 => Ok(KaspaNetwork::Testnet10),
        2 => Ok(KaspaNetwork::Testnet11),
        3 => Ok(KaspaNetwork::Simnet),
        4 => Ok(KaspaNetwork::Devnet),
        _ => Err(KaspaAdapterError::InvalidReviewMaterial(format!(
            "unknown Kaspa network discriminator {encoded}"
        ))),
    }
}

const fn network_name(network: KaspaNetwork) -> &'static str {
    match network {
        KaspaNetwork::Mainnet => "mainnet",
        KaspaNetwork::Testnet10 => "testnet10",
        KaspaNetwork::Testnet11 => "testnet11",
        KaspaNetwork::Simnet => "simnet",
        KaspaNetwork::Devnet => "devnet",
    }
}
