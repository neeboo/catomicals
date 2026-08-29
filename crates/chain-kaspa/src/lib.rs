#![forbid(unsafe_code)]

//! Kaspa chain adapter.

mod address;
mod derivation;
mod signing;
mod suite;

pub use address::{AddressKind, KaspaAdapterError, KaspaAddress, encode_address, parse_address};
pub use derivation::{
    DerivationBranch, KASPA_COIN_TYPE, derive_multisig_path, derive_single_sig_path,
};
pub use signing::{
    ThresholdSupport, assemble_ecdsa_signature, assemble_schnorr_signature,
    assemble_signature_script, ecdsa_der_to_compact_low_s, ecdsa_transaction_signing_hash,
    kaspa_threshold_support, personal_message_signing_hash, schnorr_transaction_signing_hash,
    transaction_signing_hash, verify_ecdsa_digest, verify_personal_message_schnorr,
    verify_schnorr_digest,
};
pub use suite::{KaspaChainSuite, KaspaReviewMaterial, KaspaVerifier};
