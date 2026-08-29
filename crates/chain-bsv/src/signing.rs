use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};

use crate::{BsvError, BsvSigningRequest, ForkIdSighashType};

/// Converts the canonical low-S DER result of a threshold ECDSA session into
/// the exact BSV transaction-signature encoding selected by the reviewed
/// request. Invalid or non-canonical review material fails closed.
pub fn assemble_reviewed_cb_mpc_signature(
    reviewed_material: &[u8],
    der_signature: &[u8],
) -> Result<Vec<u8>, BsvError> {
    let request = BsvSigningRequest::decode(reviewed_material)?;
    append_sighash_byte(der_signature, request.sighash_type)
}

pub fn append_sighash_byte(
    der_signature: &[u8],
    sighash_type: ForkIdSighashType,
) -> Result<Vec<u8>, BsvError> {
    let signature = parse_canonical_signature(der_signature)?;
    let mut encoded = signature.serialize_der().to_vec();
    encoded.push(sighash_type.to_u8());
    Ok(encoded)
}

pub fn sign_digest(
    secret_key: &SecretKey,
    digest: [u8; 32],
    sighash_type: ForkIdSighashType,
) -> Result<Vec<u8>, BsvError> {
    let message = Message::from_digest(digest);
    let signature = Secp256k1::new().sign_ecdsa(&message, secret_key);
    append_sighash_byte(&signature.serialize_der(), sighash_type)
}

pub fn verify_transaction_signature(
    public_key: &PublicKey,
    digest: [u8; 32],
    encoded_signature: &[u8],
    expected_sighash_type: ForkIdSighashType,
) -> Result<(), BsvError> {
    let (&actual_sighash, der_signature) = encoded_signature
        .split_last()
        .ok_or(BsvError::InvalidDerSignature)?;
    let actual_sighash = ForkIdSighashType::from_u8(actual_sighash)?;
    if actual_sighash != expected_sighash_type {
        return Err(BsvError::InvalidSighashType(actual_sighash.to_u8()));
    }
    let signature = parse_canonical_signature(der_signature)?;
    let message = Message::from_digest(digest);
    Secp256k1::verification_only()
        .verify_ecdsa(&message, &signature, public_key)
        .map_err(|_| BsvError::SignatureVerificationFailed)
}

fn parse_canonical_signature(der_signature: &[u8]) -> Result<Signature, BsvError> {
    let signature =
        Signature::from_der(der_signature).map_err(|_| BsvError::InvalidDerSignature)?;
    if signature.serialize_der().as_ref() != der_signature {
        return Err(BsvError::InvalidDerSignature);
    }
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(BsvError::HighSSignature);
    }
    Ok(signature)
}
