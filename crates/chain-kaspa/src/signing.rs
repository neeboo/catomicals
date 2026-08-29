use catomicals_signing_domain::SignerBackendRequirement;
use kaspa_consensus_core::{
    hashing::{
        sighash::{
            SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash,
        },
        sighash_type::SigHashType,
    },
    tx::VerifiableTransaction,
};
use kaspa_hashes::{Hasher, HasherBase, PersonalMessageSigningHash, TransactionSigningHash};
use secp256k1::{Message, PublicKey, XOnlyPublicKey, ecdsa, schnorr};

use crate::KaspaAdapterError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdSupport {
    ReviewOnly {
        required_backend: SignerBackendRequirement,
    },
    Executable {
        required_backend: SignerBackendRequirement,
    },
}

pub const fn kaspa_threshold_support() -> ThresholdSupport {
    ThresholdSupport::Executable {
        required_backend: SignerBackendRequirement::CbMpcThresholdEcdsa,
    }
}

pub fn transaction_signing_hash(data: impl AsRef<[u8]>) -> [u8; 32] {
    TransactionSigningHash::hash(data).as_bytes()
}

pub fn personal_message_signing_hash(message: &str) -> [u8; 32] {
    let mut hasher = PersonalMessageSigningHash::new();
    hasher.update(message.as_bytes());
    hasher.finalize().as_bytes()
}

pub fn schnorr_transaction_signing_hash(
    transaction: &impl VerifiableTransaction,
    input_index: usize,
    hash_type: SigHashType,
) -> [u8; 32] {
    calc_schnorr_signature_hash(
        transaction,
        input_index,
        hash_type,
        &SigHashReusedValuesUnsync::new(),
    )
    .as_bytes()
}

pub fn ecdsa_transaction_signing_hash(
    transaction: &impl VerifiableTransaction,
    input_index: usize,
    hash_type: SigHashType,
) -> [u8; 32] {
    calc_ecdsa_signature_hash(
        transaction,
        input_index,
        hash_type,
        &SigHashReusedValuesUnsync::new(),
    )
    .as_bytes()
}

pub fn assemble_schnorr_signature(signature: &[u8; 64], hash_type: SigHashType) -> [u8; 65] {
    assemble_signature(signature, hash_type)
}

pub fn assemble_ecdsa_signature(signature: &[u8; 64], hash_type: SigHashType) -> [u8; 65] {
    assemble_signature(signature, hash_type)
}

pub fn assemble_signature_script(signature_with_hash_type: &[u8; 65]) -> Vec<u8> {
    let mut script = Vec::with_capacity(66);
    script.push(65);
    script.extend_from_slice(signature_with_hash_type);
    script
}

pub fn verify_personal_message_schnorr(
    message: &str,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), KaspaAdapterError> {
    verify_schnorr_digest(
        &personal_message_signing_hash(message),
        public_key,
        signature,
    )
}

pub fn verify_schnorr_digest(
    digest: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), KaspaAdapterError> {
    let public_key = XOnlyPublicKey::from_slice(public_key)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))?;
    let signature = schnorr::Signature::from_slice(signature)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))?;
    let message = Message::from_digest(*digest);
    signature
        .verify(&message, &public_key)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))
}

pub fn verify_ecdsa_digest(
    digest: &[u8; 32],
    public_key: &[u8; 33],
    signature: &[u8; 64],
) -> Result<(), KaspaAdapterError> {
    let public_key = PublicKey::from_slice(public_key)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))?;
    let signature = ecdsa::Signature::from_compact(signature)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))?;
    ensure_low_s(signature)?;
    let message = Message::from_digest(*digest);
    signature
        .verify(&message, &public_key)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))
}

/// Converts a strict DER ECDSA signature into Kaspa's compact 64-byte form.
/// High-S signatures are rejected instead of silently normalized.
pub fn ecdsa_der_to_compact_low_s(signature: &[u8]) -> Result<[u8; 64], KaspaAdapterError> {
    let signature = ecdsa::Signature::from_der(signature)
        .map_err(|error| KaspaAdapterError::InvalidSignature(error.to_string()))?;
    ensure_low_s(signature)?;
    Ok(signature.serialize_compact())
}

fn ensure_low_s(signature: ecdsa::Signature) -> Result<(), KaspaAdapterError> {
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(KaspaAdapterError::InvalidSignature(
            "high-S ECDSA signatures are not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn assemble_signature(signature: &[u8; 64], hash_type: SigHashType) -> [u8; 65] {
    let mut assembled = [0u8; 65];
    assembled[..64].copy_from_slice(signature);
    assembled[64] = hash_type.to_u8();
    assembled
}
