use catomicals_chain_domain::{
    ChainCapabilities, ChainNetwork, ChainSuite, KaspaNetwork, ReviewContractError,
};
use catomicals_chain_kaspa::{
    KaspaChainSuite, KaspaReviewMaterial, KaspaVerifier, ecdsa_transaction_signing_hash,
    schnorr_transaction_signing_hash, transaction_signing_hash,
};
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

#[test]
fn suite_exposes_every_kaspa_network_and_fail_closed_capabilities() {
    let (_, x_only, _) = signing_keys();
    for network in [
        KaspaNetwork::Mainnet,
        KaspaNetwork::Testnet10,
        KaspaNetwork::Testnet11,
        KaspaNetwork::Simnet,
        KaspaNetwork::Devnet,
    ] {
        let suite = KaspaChainSuite::new(network, KaspaVerifier::Schnorr(x_only)).unwrap();
        assert_eq!(suite.scope().network, ChainNetwork::Kaspa(network));
        assert_eq!(
            suite.capabilities(),
            ChainCapabilities {
                address_derivation: true,
                transaction_review: true,
                final_signature_verification: true,
                broadcast: false,
            }
        );
    }
}

#[test]
fn schnorr_review_uses_the_official_transaction_digest_and_verifies_final_signature() {
    let (secret, x_only, _) = signing_keys();
    let (tx, entries) = review_transaction_fixture();
    let populated = PopulatedTransaction::new(&tx, entries.clone());
    let expected_digest = schnorr_transaction_signing_hash(&populated, 0, SIG_HASH_ALL);
    let material = KaspaReviewMaterial::new(tx, entries, 0, SIG_HASH_ALL).unwrap();
    let encoded = material.encode().unwrap();

    let suite =
        KaspaChainSuite::new(KaspaNetwork::Testnet11, KaspaVerifier::Schnorr(x_only)).unwrap();
    let review = suite.review_transaction(&encoded).unwrap();
    assert_eq!(review.signing_message_digest, expected_digest);
    assert_eq!(review.review_digest, transaction_signing_hash(&encoded));
    assert!(review.summary.contains("1 inputs"));
    assert!(review.summary.contains("1 outputs"));
    assert!(review.summary.contains("1000 sompi input"));
    assert!(review.summary.contains("900 sompi"));
    assert!(review.summary.contains("100 sompi fee"));

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(review.signing_message_digest),
        &keypair,
    );
    suite
        .verify_finalized_signature(&review, signature.as_ref())
        .unwrap();

    let mut wrong = *signature.as_ref();
    wrong[0] ^= 1;
    assert!(suite.verify_finalized_signature(&review, &wrong).is_err());
}

#[test]
fn ecdsa_review_uses_the_official_ecdsa_digest_and_verifies_compact_signature() {
    let (secret, _, compressed) = signing_keys();
    let (tx, entries) = review_transaction_fixture();
    let populated = PopulatedTransaction::new(&tx, entries.clone());
    let expected_digest = ecdsa_transaction_signing_hash(&populated, 0, SIG_HASH_ALL);
    let encoded = KaspaReviewMaterial::new(tx, entries, 0, SIG_HASH_ALL)
        .unwrap()
        .encode()
        .unwrap();

    let suite =
        KaspaChainSuite::new(KaspaNetwork::Devnet, KaspaVerifier::Ecdsa(compressed)).unwrap();
    let review = suite.review_transaction(&encoded).unwrap();
    assert_eq!(review.signing_message_digest, expected_digest);

    let signature = Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(review.signing_message_digest),
            &secret,
        )
        .serialize_compact();
    suite
        .verify_finalized_signature(&review, &signature)
        .unwrap();
}

#[test]
fn malformed_review_material_and_cross_network_reviews_are_rejected() {
    let (_, x_only, _) = signing_keys();
    let testnet =
        KaspaChainSuite::new(KaspaNetwork::Testnet10, KaspaVerifier::Schnorr(x_only)).unwrap();
    assert!(testnet.review_transaction(b"not a transaction").is_err());

    let (tx, entries) = review_transaction_fixture();
    let encoded = KaspaReviewMaterial::new(tx, entries, 0, SIG_HASH_ALL)
        .unwrap()
        .encode()
        .unwrap();
    let review = testnet.review_transaction(&encoded).unwrap();
    let mainnet =
        KaspaChainSuite::new(KaspaNetwork::Mainnet, KaspaVerifier::Schnorr(x_only)).unwrap();
    assert!(matches!(
        mainnet.verify_finalized_signature(&review, &[0; 64]),
        Err(ReviewContractError::InvalidFinalizedSignature(_))
    ));
}

#[test]
fn review_material_rejects_missing_utxos_and_invalid_input_indexes() {
    let (tx, entries) = review_transaction_fixture();
    assert!(KaspaReviewMaterial::new(tx.clone(), Vec::new(), 0, SIG_HASH_ALL).is_err());
    assert!(KaspaReviewMaterial::new(tx, entries, 1, SIG_HASH_ALL).is_err());
}

#[test]
fn review_material_rejects_a_stale_cached_transaction_id() {
    let (mut tx, entries) = review_transaction_fixture();
    tx.outputs[0].value = 899;
    assert!(KaspaReviewMaterial::new(tx, entries, 0, SIG_HASH_ALL).is_err());
}

fn signing_keys() -> (SecretKey, [u8; 32], [u8; 33]) {
    let secret = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ])
    .unwrap();
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    (
        secret,
        XOnlyPublicKey::from_keypair(&keypair).0.serialize(),
        PublicKey::from_keypair(&keypair).serialize(),
    )
}

fn review_transaction_fixture() -> (Transaction, Vec<UtxoEntry>) {
    let script = ScriptPublicKey::new(0, vec![0x20; 34].into());
    let tx = Transaction::new(
        0,
        vec![TransactionInput::new(
            TransactionOutpoint::new(Hash::from_bytes([0x11; 32]), 7),
            vec![],
            1,
            1,
        )],
        vec![TransactionOutput::new(900, script.clone())],
        42,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entries = vec![UtxoEntry::new(1_000, script, 8, false, None)];
    (tx, entries)
}
