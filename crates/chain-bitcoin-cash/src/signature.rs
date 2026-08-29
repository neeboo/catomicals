use catomicals_chain_domain::{BitcoinCashNetwork, ChainNetwork, ChainScope};
use catomicals_signing_domain::{
    SigningSuite, SigningSuiteDescriptor, SigningSuiteId, resolve_builtin_suite,
};
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        ff::PrimeField,
        group::Group,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature as EcdsaSignature};
use sha2::{Digest, Sha256};

use crate::{Error, ForkIdSighashType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinCashSchnorrMessage([u8; 32]);

impl BitcoinCashSchnorrMessage {
    pub const BYTES: usize = 32;

    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinCashSchnorrSignature([u8; 64]);

impl BitcoinCashSchnorrSignature {
    pub const BYTES: usize = 64;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let signature = bytes
            .try_into()
            .map_err(|_| Error::InvalidSchnorrSignatureLength {
                actual: bytes.len(),
            })?;
        Ok(Self(signature))
    }

    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinCashSchnorrSuite {
    scope: ChainScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaBackend {
    Isolated,
    CbMpcThreshold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinCashEcdsaSuite {
    scope: ChainScope,
    backend: EcdsaBackend,
}

impl BitcoinCashEcdsaSuite {
    pub fn new(network: BitcoinCashNetwork, backend: EcdsaBackend) -> Self {
        Self {
            scope: ChainScope::for_network(ChainNetwork::BitcoinCash(network)),
            backend,
        }
    }
}

impl SigningSuite for BitcoinCashEcdsaSuite {
    fn descriptor(&self) -> SigningSuiteDescriptor {
        let suite_id = match self.backend {
            EcdsaBackend::Isolated => SigningSuiteId::BITCOIN_CASH_ECDSA_ISOLATED_V1,
            EcdsaBackend::CbMpcThreshold => SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1,
        };
        resolve_builtin_suite(&self.scope, suite_id)
            .expect("BCH scope and built-in BCH ECDSA suite are compatible")
    }

    fn supports(&self, chain_scope: &ChainScope) -> bool {
        self.scope == *chain_scope
    }
}

impl BitcoinCashSchnorrSuite {
    pub const MESSAGE_BYTES: usize = 32;
    pub const SIGNATURE_BYTES: usize = 64;
    pub const TRANSACTION_SIGNATURE_BYTES: usize = 65;

    pub fn new(network: BitcoinCashNetwork) -> Self {
        Self {
            scope: ChainScope::for_network(ChainNetwork::BitcoinCash(network)),
        }
    }
}

impl SigningSuite for BitcoinCashSchnorrSuite {
    fn descriptor(&self) -> SigningSuiteDescriptor {
        resolve_builtin_suite(
            &self.scope,
            SigningSuiteId::BITCOIN_CASH_SCHNORR_ISOLATED_V1,
        )
        .expect("BCH scope and built-in BCH Schnorr suite are compatible")
    }

    fn supports(&self, chain_scope: &ChainScope) -> bool {
        self.scope == *chain_scope
    }
}

pub fn sign_ecdsa(secret_key: [u8; 32], digest: [u8; 32]) -> Result<Vec<u8>, Error> {
    let secret_key = SecretKey::from_slice(&secret_key).map_err(|_| Error::InvalidSecretKey)?;
    let signature = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &secret_key);
    Ok(signature.serialize_der().to_vec())
}

pub fn assemble_ecdsa_transaction_signature(
    der_signature: &[u8],
    hash_type: ForkIdSighashType,
) -> Result<Vec<u8>, Error> {
    let signature = parse_standard_ecdsa(der_signature)?;
    let mut assembled = signature.serialize_der().to_vec();
    assembled.push(hash_type.signature_byte()?);
    Ok(assembled)
}

pub fn verify_ecdsa_transaction_signature(
    public_key: &[u8],
    digest: [u8; 32],
    transaction_signature: &[u8],
    expected_hash_type: ForkIdSighashType,
) -> Result<(), Error> {
    let (&actual_hash_type, der_signature) = transaction_signature
        .split_last()
        .ok_or(Error::InvalidSignatureEncoding)?;
    let expected_hash_type = expected_hash_type.signature_byte()?;
    if actual_hash_type != expected_hash_type {
        return Err(Error::SignatureHashTypeMismatch {
            expected: expected_hash_type,
            actual: actual_hash_type,
        });
    }
    let signature = parse_standard_ecdsa(der_signature)?;
    let public_key = PublicKey::from_slice(public_key).map_err(|_| Error::InvalidPublicKey)?;
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature, &public_key)
        .map_err(|_| Error::InvalidSignature)
}

pub fn assemble_schnorr_transaction_signature(
    signature: BitcoinCashSchnorrSignature,
    hash_type: ForkIdSighashType,
) -> Result<Vec<u8>, Error> {
    let mut assembled = Vec::with_capacity(BitcoinCashSchnorrSuite::TRANSACTION_SIGNATURE_BYTES);
    assembled.extend_from_slice(&signature.0);
    assembled.push(hash_type.signature_byte()?);
    Ok(assembled)
}

pub fn verify_schnorr_transaction_signature(
    public_key: &[u8],
    message: BitcoinCashSchnorrMessage,
    transaction_signature: &[u8],
    expected_hash_type: ForkIdSighashType,
) -> Result<(), Error> {
    if transaction_signature.len() != BitcoinCashSchnorrSuite::TRANSACTION_SIGNATURE_BYTES {
        return Err(Error::InvalidSchnorrSignatureLength {
            actual: transaction_signature.len().saturating_sub(1),
        });
    }
    let (&actual_hash_type, signature) = transaction_signature
        .split_last()
        .ok_or(Error::InvalidSignatureEncoding)?;
    let expected_hash_type = expected_hash_type.signature_byte()?;
    if actual_hash_type != expected_hash_type {
        return Err(Error::SignatureHashTypeMismatch {
            expected: expected_hash_type,
            actual: actual_hash_type,
        });
    }
    verify_schnorr(
        public_key,
        message,
        BitcoinCashSchnorrSignature::from_bytes(signature)?,
    )
}

pub fn verify_schnorr(
    public_key: &[u8],
    message: BitcoinCashSchnorrMessage,
    signature: BitcoinCashSchnorrSignature,
) -> Result<(), Error> {
    let encoded_public_key =
        EncodedPoint::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let public_key =
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_public_key))
            .ok_or(Error::InvalidPublicKey)?;
    let compressed_public_key = public_key.to_encoded_point(true);

    let r_bytes: FieldBytes = <[u8; 32]>::try_from(&signature.0[..32])
        .expect("fixed-size signature component")
        .into();
    if !bool::from(FieldElement::from_bytes(&r_bytes).is_some()) {
        return Err(Error::InvalidSignature);
    }
    let s_bytes: FieldBytes = <[u8; 32]>::try_from(&signature.0[32..])
        .expect("fixed-size signature component")
        .into();
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes)).ok_or(Error::InvalidSignature)?;

    let mut challenge_hasher = Sha256::new();
    challenge_hasher.update(r_bytes);
    challenge_hasher.update(compressed_public_key.as_bytes());
    challenge_hasher.update(message.0);
    let challenge_bytes: FieldBytes = challenge_hasher.finalize();
    let challenge = <Scalar as Reduce<U256>>::reduce_bytes(&challenge_bytes);

    let reconstructed =
        ProjectivePoint::GENERATOR * s - ProjectivePoint::from(public_key) * challenge;
    if bool::from(reconstructed.is_identity()) {
        return Err(Error::InvalidSignature);
    }
    let reconstructed = AffinePoint::from(reconstructed).to_encoded_point(false);
    let x = reconstructed.x().ok_or(Error::InvalidSignature)?;
    let y = reconstructed.y().ok_or(Error::InvalidSignature)?;
    if x[..] != signature.0[..32] {
        return Err(Error::InvalidSignature);
    }
    let y: FieldBytes = <[u8; 32]>::try_from(&y[..])
        .expect("SEC1 coordinate is 32 bytes")
        .into();
    let y = Option::<FieldElement>::from(FieldElement::from_bytes(&y))
        .ok_or(Error::InvalidSignature)?;
    if !bool::from(y.sqrt().is_some()) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn parse_standard_ecdsa(bytes: &[u8]) -> Result<EcdsaSignature, Error> {
    let signature = EcdsaSignature::from_der(bytes).map_err(|_| Error::InvalidSignatureEncoding)?;
    if signature.serialize_der().as_ref() != bytes {
        return Err(Error::InvalidSignatureEncoding);
    }
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(Error::InvalidSignatureEncoding);
    }
    Ok(signature)
}
