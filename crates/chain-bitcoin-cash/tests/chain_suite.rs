use catomicals_chain_bitcoin_cash::{
    BitcoinCashChainSuite, BitcoinCashNetwork, BitcoinCashSignatureAlgorithm,
    BitcoinCashSigningRequest, ForkIdSighashType, OutPoint, Transaction, TxIn, TxOut,
    assemble_ecdsa_transaction_signature, sign_ecdsa,
};
use catomicals_chain_domain::{ChainNetwork, ChainSuite, ReviewArtifact, ReviewContractError};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn transaction() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: [3; 32],
                output_index: 1,
            },
            script_sig: vec![],
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOut {
            value: 49_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 7,
    }
}

fn ecdsa_suite(network: BitcoinCashNetwork) -> BitcoinCashChainSuite {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let public = PublicKey::from_secret_key(&secp, &secret);
    BitcoinCashChainSuite::new(
        network,
        BitcoinCashSignatureAlgorithm::Ecdsa,
        &public.serialize(),
        ForkIdSighashType::ALL,
    )
    .unwrap()
}

#[test]
fn chain_suite_reviews_and_verifies_the_bound_bch_signature() {
    let suite = ecdsa_suite(BitcoinCashNetwork::Chipnet);
    let request = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Chipnet,
        transaction(),
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::ALL,
    );
    let review = suite.review_transaction(&request.encode()).unwrap();
    assert_eq!(
        review.scope.network,
        ChainNetwork::BitcoinCash(BitcoinCashNetwork::Chipnet)
    );
    assert_eq!(review.signing_message_digest.len(), 32);
    assert!(review.summary.contains("input value 50000 sat"));
    assert!(review.summary.contains("output total 49000 sat"));
    assert!(!review.summary.contains("request sha256 "));
    assert_eq!(review.reviewed_material, request.encode());

    let der = sign_ecdsa([1; 32], review.signing_message_digest).unwrap();
    let signature = assemble_ecdsa_transaction_signature(&der, ForkIdSighashType::ALL).unwrap();
    suite
        .verify_finalized_signature(&review, &signature)
        .unwrap();

    let capabilities = suite.capabilities();
    assert!(capabilities.address_derivation);
    assert!(capabilities.transaction_review);
    assert!(capabilities.final_signature_verification);
    assert!(!capabilities.broadcast);
}

#[test]
fn chain_suite_rejects_sighash_modes_that_cannot_bind_a_full_review() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let public = PublicKey::from_secret_key(&secp, &secret);

    for hash_type in [
        ForkIdSighashType::NONE,
        ForkIdSighashType::SINGLE,
        ForkIdSighashType::ALL_ANYONECANPAY,
        ForkIdSighashType::NONE_ANYONECANPAY,
        ForkIdSighashType::SINGLE_ANYONECANPAY,
    ] {
        assert!(matches!(
            BitcoinCashChainSuite::new(
                BitcoinCashNetwork::Mainnet,
                BitcoinCashSignatureAlgorithm::Ecdsa,
                &public.serialize(),
                hash_type,
            ),
            Err(catomicals_chain_bitcoin_cash::Error::UnsafeReviewSighashType(_))
        ));
    }
}

#[test]
fn chain_suite_fails_closed_on_request_network_or_hashtype_mismatch() {
    let suite = ecdsa_suite(BitcoinCashNetwork::Mainnet);
    let wrong_network = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Testnet4,
        transaction(),
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::ALL,
    );
    assert!(suite.review_transaction(&wrong_network.encode()).is_err());

    let wrong_hash_type = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Mainnet,
        transaction(),
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::NONE,
    );
    assert!(suite.review_transaction(&wrong_hash_type.encode()).is_err());
}

#[test]
fn chain_suite_rejects_review_from_another_network_and_malformed_signature() {
    let mainnet = ecdsa_suite(BitcoinCashNetwork::Mainnet);
    let testnet = ecdsa_suite(BitcoinCashNetwork::Testnet3);
    let request = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Testnet3,
        transaction(),
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::ALL,
    );
    let review = testnet.review_transaction(&request.encode()).unwrap();
    assert!(matches!(
        mainnet.verify_finalized_signature(&review, &[0; 65]),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));

    let forged_scope = ReviewArtifact::new(
        mainnet.scope(),
        review.review_digest,
        review.signing_message_digest,
        review.summary,
        review.reviewed_material,
    )
    .unwrap();
    let forged_der = sign_ecdsa([1; 32], forged_scope.signing_message_digest).unwrap();
    let forged_signature =
        assemble_ecdsa_transaction_signature(&forged_der, ForkIdSighashType::ALL).unwrap();
    assert!(
        mainnet
            .verify_finalized_signature(&forged_scope, &forged_signature)
            .is_err()
    );
}

#[test]
fn final_verification_rejects_a_forged_artifact_with_unreviewed_material() {
    let suite = ecdsa_suite(BitcoinCashNetwork::Chipnet);
    let forged_digest = [0x44; 32];
    let forged = ReviewArtifact::new(
        suite.scope(),
        [0x55; 32],
        forged_digest,
        "attacker supplied BCH review".to_owned(),
        b"not a canonical BCH request".to_vec(),
    )
    .unwrap();
    let der = sign_ecdsa([1; 32], forged_digest).unwrap();
    let signature = assemble_ecdsa_transaction_signature(&der, ForkIdSighashType::ALL).unwrap();
    assert!(
        suite
            .verify_finalized_signature(&forged, &signature)
            .is_err()
    );
}

#[test]
fn signing_request_decoder_rejects_trailing_or_corrupt_network_bytes() {
    let request = BitcoinCashSigningRequest::new(
        BitcoinCashNetwork::Scalenet,
        transaction(),
        0,
        vec![0x51],
        50_000,
        ForkIdSighashType::ALL,
    );
    let encoded = request.encode();
    assert_eq!(BitcoinCashSigningRequest::decode(&encoded), Ok(request));

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(BitcoinCashSigningRequest::decode(&trailing).is_err());

    let mut unknown_network = encoded;
    unknown_network[5] = 99;
    assert!(BitcoinCashSigningRequest::decode(&unknown_network).is_err());
}
