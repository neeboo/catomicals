use catomicals_chain_domain::{
    BitcoinCashNetwork, ChainCapabilities, ChainNetwork, ChainScope, ChainSuite, ReviewArtifact,
    ReviewContractError,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::{
    BitcoinCashSchnorrMessage, Error, ForkIdSighashType, Transaction, fork_id_sighash,
    verify_ecdsa_transaction_signature, verify_schnorr_transaction_signature,
};

const REQUEST_MAGIC: &[u8; 4] = b"BCHR";
const REQUEST_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const REQUEST_DIGEST_MARKER: &str = "; canonical request sha256 ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinCashSignatureAlgorithm {
    Ecdsa,
    Schnorr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinCashSigningRequest {
    pub network: BitcoinCashNetwork,
    pub transaction: Transaction,
    pub input_index: usize,
    pub script_code: Vec<u8>,
    pub input_value: u64,
    pub hash_type: ForkIdSighashType,
}

impl BitcoinCashSigningRequest {
    pub fn new(
        network: BitcoinCashNetwork,
        transaction: Transaction,
        input_index: usize,
        script_code: Vec<u8>,
        input_value: u64,
        hash_type: ForkIdSighashType,
    ) -> Self {
        Self {
            network,
            transaction,
            input_index,
            script_code,
            input_value,
            hash_type,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let transaction = self.transaction.encode();
        let mut encoded = Vec::with_capacity(42 + self.script_code.len() + transaction.len());
        encoded.extend_from_slice(REQUEST_MAGIC);
        encoded.push(REQUEST_VERSION);
        encoded.push(network_id(self.network));
        encoded.extend_from_slice(&self.hash_type.to_consensus().to_le_bytes());
        encoded.extend_from_slice(&(self.input_index as u64).to_le_bytes());
        encoded.extend_from_slice(&self.input_value.to_le_bytes());
        encoded.extend_from_slice(&(self.script_code.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&(transaction.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&self.script_code);
        encoded.extend_from_slice(&transaction);
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST_BYTES || bytes.len() < 42 {
            return Err(Error::InvalidSigningRequest);
        }
        if &bytes[..4] != REQUEST_MAGIC || bytes[4] != REQUEST_VERSION {
            return Err(Error::InvalidSigningRequest);
        }
        let network = network_from_id(bytes[5])?;
        let hash_type = ForkIdSighashType::from_consensus(read_u32(bytes, 6)?)?;
        let input_index =
            usize::try_from(read_u64(bytes, 10)?).map_err(|_| Error::InvalidSigningRequest)?;
        let input_value = read_u64(bytes, 18)?;
        let script_length =
            usize::try_from(read_u64(bytes, 26)?).map_err(|_| Error::InvalidSigningRequest)?;
        let transaction_length =
            usize::try_from(read_u64(bytes, 34)?).map_err(|_| Error::InvalidSigningRequest)?;
        let script_end = 42_usize
            .checked_add(script_length)
            .ok_or(Error::InvalidSigningRequest)?;
        let transaction_end = script_end
            .checked_add(transaction_length)
            .ok_or(Error::InvalidSigningRequest)?;
        if transaction_end != bytes.len() {
            return Err(Error::InvalidSigningRequest);
        }
        let script_code = bytes[42..script_end].to_vec();
        let transaction = Transaction::decode(&bytes[script_end..transaction_end])?;
        Ok(Self {
            network,
            transaction,
            input_index,
            script_code,
            input_value,
            hash_type,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinCashChainSuite {
    scope: ChainScope,
    algorithm: BitcoinCashSignatureAlgorithm,
    verification_key: Vec<u8>,
    hash_type: ForkIdSighashType,
}

impl BitcoinCashChainSuite {
    pub fn new(
        network: BitcoinCashNetwork,
        algorithm: BitcoinCashSignatureAlgorithm,
        verification_key: &[u8],
        hash_type: ForkIdSighashType,
    ) -> Result<Self, Error> {
        PublicKey::from_slice(verification_key).map_err(|_| Error::InvalidPublicKey)?;
        hash_type.signature_byte()?;
        if hash_type != ForkIdSighashType::ALL {
            return Err(Error::UnsafeReviewSighashType(hash_type.to_consensus()));
        }
        Ok(Self {
            scope: ChainScope::for_network(ChainNetwork::BitcoinCash(network)),
            algorithm,
            verification_key: verification_key.to_vec(),
            hash_type,
        })
    }
}

impl ChainSuite for BitcoinCashChainSuite {
    fn scope(&self) -> ChainScope {
        self.scope
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
        let request = BitcoinCashSigningRequest::decode(transaction_material)
            .map_err(invalid_transaction_material)?;
        let canonical_request = request.encode();
        if canonical_request != transaction_material {
            return Err(invalid_transaction_material(Error::InvalidSigningRequest));
        }
        let expected_network = match self.scope.network {
            ChainNetwork::BitcoinCash(network) => network,
            _ => unreachable!("BCH suite always has BCH scope"),
        };
        if request.network != expected_network {
            return Err(invalid_transaction_material(Error::WrongNetwork {
                expected: expected_network,
                actual: network_name(request.network),
            }));
        }
        if request.hash_type != self.hash_type {
            return Err(invalid_transaction_material(Error::UnsupportedSighashType(
                request.hash_type.to_consensus(),
            )));
        }
        let signing_message_digest = fork_id_sighash(
            &request.transaction,
            request.input_index,
            &request.script_code,
            request.input_value,
            request.hash_type,
        )
        .map_err(invalid_transaction_material)?;
        let request_digest: [u8; 32] = Sha256::digest(&canonical_request).into();
        let script_digest: [u8; 32] = Sha256::digest(&request.script_code).into();
        let output_total: u128 = request
            .transaction
            .outputs
            .iter()
            .map(|output| u128::from(output.value))
            .sum();
        let summary = format!(
            "Bitcoin Cash transaction: {} input(s), {} output(s), output total {} sat; signing input {} with input value {} sat; script sha256 {}; hashtype {:#x} (ALL|FORKID, complete review binding){}{}",
            request.transaction.inputs.len(),
            request.transaction.outputs.len(),
            output_total,
            request.input_index,
            request.input_value,
            encode_hex(script_digest),
            request.hash_type.to_consensus(),
            REQUEST_DIGEST_MARKER,
            encode_hex(request_digest),
        );
        let review_digest =
            review_digest(self.scope, signing_message_digest, request_digest, &summary);
        ReviewArtifact::new(self.scope, review_digest, signing_message_digest, summary)
    }

    fn verify_finalized_signature(
        &self,
        review: &ReviewArtifact,
        finalized_signature: &[u8],
    ) -> Result<(), ReviewContractError> {
        let request_digest = request_digest_from_summary(&review.summary);
        if review.schema_version != 1
            || review.scope != self.scope
            || request_digest.is_none()
            || review.review_digest
                != review_digest(
                    review.scope,
                    review.signing_message_digest,
                    request_digest.unwrap_or([0; 32]),
                    &review.summary,
                )
        {
            return Err(ReviewContractError::InvalidFinalizedSignature(
                "review artifact binding mismatch".to_owned(),
            ));
        }
        let result = match self.algorithm {
            BitcoinCashSignatureAlgorithm::Ecdsa => verify_ecdsa_transaction_signature(
                &self.verification_key,
                review.signing_message_digest,
                finalized_signature,
                self.hash_type,
            ),
            BitcoinCashSignatureAlgorithm::Schnorr => verify_schnorr_transaction_signature(
                &self.verification_key,
                BitcoinCashSchnorrMessage::from_digest(review.signing_message_digest),
                finalized_signature,
                self.hash_type,
            ),
        };
        result.map_err(|error| ReviewContractError::InvalidFinalizedSignature(error.to_string()))
    }
}

fn review_digest(
    scope: ChainScope,
    signing_digest: [u8; 32],
    request_digest: [u8; 32],
    summary: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"catomicals.bitcoin-cash.review.v1\0");
    hasher.update(scope.network.as_str().as_bytes());
    hasher.update(signing_digest);
    hasher.update(request_digest);
    hasher.update((summary.len() as u64).to_le_bytes());
    hasher.update(summary.as_bytes());
    hasher.finalize().into()
}

fn invalid_transaction_material(error: Error) -> ReviewContractError {
    ReviewContractError::UnsupportedOperation {
        operation: match error {
            Error::WrongNetwork { .. } => "Bitcoin Cash request for another network",
            Error::UnsupportedSighashType(_) | Error::MissingForkId => {
                "Bitcoin Cash request with unsupported hashtype"
            }
            _ => "malformed Bitcoin Cash signing request",
        },
    }
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

fn request_digest_from_summary(summary: &str) -> Option<[u8; 32]> {
    let (_, encoded) = summary.rsplit_once(REQUEST_DIGEST_MARKER)?;
    if encoded.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = decode_hex_nibble(chunk[0])? << 4 | decode_hex_nibble(chunk[1])?;
    }
    Some(digest)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn read_u32(bytes: &[u8], start: usize) -> Result<u32, Error> {
    bytes
        .get(start..start + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::InvalidSigningRequest)
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64, Error> {
    bytes
        .get(start..start + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::InvalidSigningRequest)
}

const fn network_id(network: BitcoinCashNetwork) -> u8 {
    match network {
        BitcoinCashNetwork::Mainnet => 0,
        BitcoinCashNetwork::Testnet3 => 1,
        BitcoinCashNetwork::Testnet4 => 2,
        BitcoinCashNetwork::Scalenet => 3,
        BitcoinCashNetwork::Chipnet => 4,
        BitcoinCashNetwork::Regtest => 5,
    }
}

fn network_from_id(id: u8) -> Result<BitcoinCashNetwork, Error> {
    match id {
        0 => Ok(BitcoinCashNetwork::Mainnet),
        1 => Ok(BitcoinCashNetwork::Testnet3),
        2 => Ok(BitcoinCashNetwork::Testnet4),
        3 => Ok(BitcoinCashNetwork::Scalenet),
        4 => Ok(BitcoinCashNetwork::Chipnet),
        5 => Ok(BitcoinCashNetwork::Regtest),
        _ => Err(Error::UnknownSigningRequestNetwork(id)),
    }
}

const fn network_name(network: BitcoinCashNetwork) -> &'static str {
    match network {
        BitcoinCashNetwork::Mainnet => "mainnet",
        BitcoinCashNetwork::Testnet3 => "testnet3",
        BitcoinCashNetwork::Testnet4 => "testnet4",
        BitcoinCashNetwork::Scalenet => "scalenet",
        BitcoinCashNetwork::Chipnet => "chipnet",
        BitcoinCashNetwork::Regtest => "regtest",
    }
}
