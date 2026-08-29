use catomicals_chain_bitcoin_cash::{
    BitcoinCashEcdsaSuite, BitcoinCashNetwork, BitcoinCashSchnorrMessage,
    BitcoinCashSchnorrSignature, BitcoinCashSchnorrSuite, EcdsaBackend, Error, ForkIdSighashType,
    assemble_ecdsa_transaction_signature, assemble_schnorr_transaction_signature, sign_ecdsa,
    verify_ecdsa_transaction_signature, verify_schnorr, verify_schnorr_transaction_signature,
};
use catomicals_signing_domain::{
    SignerBackendRequirement, SigningAlgorithm, SigningExecutionMode, SigningSuite, SigningSuiteId,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[test]
fn ecdsa_signatures_are_strict_der_with_hashtype_and_verify() {
    let secret = [1_u8; 32];
    let digest = [42_u8; 32];
    let der = sign_ecdsa(secret, digest).unwrap();
    let transaction_signature =
        assemble_ecdsa_transaction_signature(&der, ForkIdSighashType::ALL).unwrap();
    assert_eq!(transaction_signature.last(), Some(&0x41));

    let secp = Secp256k1::new();
    let public = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap());
    verify_ecdsa_transaction_signature(
        &public.serialize(),
        digest,
        &transaction_signature,
        ForkIdSighashType::ALL,
    )
    .unwrap();

    assert!(matches!(
        verify_ecdsa_transaction_signature(
            &public.serialize(),
            [43_u8; 32],
            &transaction_signature,
            ForkIdSighashType::ALL,
        ),
        Err(Error::InvalidSignature)
    ));
    assert!(matches!(
        verify_ecdsa_transaction_signature(
            &public.serialize(),
            digest,
            &transaction_signature,
            ForkIdSighashType::NONE,
        ),
        Err(Error::SignatureHashTypeMismatch { .. })
    ));
}

#[test]
fn ecdsa_assembly_rejects_non_der_and_nonzero_fork_number() {
    assert!(matches!(
        assemble_ecdsa_transaction_signature(&[0; 64], ForkIdSighashType::ALL),
        Err(Error::InvalidSignatureEncoding)
    ));
    let alternate_fork = ForkIdSighashType::from_consensus(0x0001_0041).unwrap();
    let der = sign_ecdsa([1; 32], [2; 32]).unwrap();
    assert!(matches!(
        assemble_ecdsa_transaction_signature(&der, alternate_fork),
        Err(Error::UnsupportedForkId(0x100))
    ));
}

#[test]
fn bch_schnorr_matches_bchn_single_signature_vectors() {
    // BCHN master@b31ed10, secp256k1 schnorr tests_impl.h vector 1.
    let public =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    let message = BitcoinCashSchnorrMessage::from_digest([0; 32]);
    let signature = BitcoinCashSchnorrSignature::from_bytes(
        &hex::decode(
            "787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef6\
             7031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05",
        )
        .unwrap(),
    )
    .unwrap();
    verify_schnorr(&public, message, signature).unwrap();

    // BCHN vector 8: negated s must fail.
    let invalid = BitcoinCashSchnorrSignature::from_bytes(
        &hex::decode(
            "787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef6\
             8fce5677ce7a623cb20011225797ce7a8de1dc6ccd4f754a47da6c600e59543c",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_schnorr(&public, message, invalid),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn bch_schnorr_bytes_and_transaction_hashtype_are_exact() {
    assert!(matches!(
        BitcoinCashSchnorrSignature::from_bytes(&[0; 63]),
        Err(Error::InvalidSchnorrSignatureLength { actual: 63 })
    ));

    let public =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    let message = BitcoinCashSchnorrMessage::from_digest([0; 32]);
    let signature = BitcoinCashSchnorrSignature::from_bytes(
        &hex::decode(
            "787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef6\
             7031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05",
        )
        .unwrap(),
    )
    .unwrap();
    let transaction_signature =
        assemble_schnorr_transaction_signature(signature, ForkIdSighashType::ALL).unwrap();
    assert_eq!(transaction_signature.len(), 65);
    verify_schnorr_transaction_signature(
        &public,
        message,
        &transaction_signature,
        ForkIdSighashType::ALL,
    )
    .unwrap();
}

#[test]
fn bch_schnorr_suite_is_explicitly_isolated_not_generic_frost() {
    let suite = BitcoinCashSchnorrSuite::new(BitcoinCashNetwork::Chipnet);
    let descriptor = suite.descriptor();
    assert_eq!(
        descriptor.id,
        SigningSuiteId::BITCOIN_CASH_SCHNORR_ISOLATED_V1
    );
    assert_eq!(descriptor.algorithm, SigningAlgorithm::BitcoinCashSchnorr);
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::SingleSignerIsolated
    );
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::IsolatedBitcoinCashSchnorr
    );
}

#[test]
fn threshold_ecdsa_suite_requires_cb_mpc_backend() {
    let suite =
        BitcoinCashEcdsaSuite::new(BitcoinCashNetwork::Mainnet, EcdsaBackend::CbMpcThreshold);
    let descriptor = suite.descriptor();
    assert_eq!(descriptor.id, SigningSuiteId::BITCOIN_CASH_ECDSA_CB_MPC_V1);
    assert_eq!(
        descriptor.backend_requirement,
        SignerBackendRequirement::CbMpcThresholdEcdsa
    );
    assert_eq!(
        descriptor.execution_mode,
        SigningExecutionMode::ThresholdInteractive
    );
}
