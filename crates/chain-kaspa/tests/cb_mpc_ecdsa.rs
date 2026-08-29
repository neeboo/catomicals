use catomicals_chain_domain::{ChainSuite, KaspaNetwork};
use catomicals_chain_kaspa::{
    KaspaChainSuite, KaspaReviewMaterial, KaspaVerifier, assemble_ecdsa_signature,
    assemble_signature_script, ecdsa_der_to_compact_low_s, ecdsa_transaction_signing_hash,
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_address_script;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

#[test]
fn cb_mpc_compact_signature_executes_in_the_real_kaspa_script_engine() {
    let secret = secret(3);
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize();
    let (transaction, entries) = p2pk_ecdsa_transaction(public_key);
    let material = KaspaReviewMaterial::new(
        KaspaNetwork::Testnet11,
        transaction,
        entries,
        0,
        SIG_HASH_ALL,
    )
    .unwrap()
    .encode()
    .unwrap();
    let suite = KaspaChainSuite::new(
        KaspaNetwork::Testnet11,
        KaspaVerifier::EcdsaCbMpc(public_key),
    )
    .unwrap();
    let review = suite.review_transaction(&material).unwrap();

    let der = Secp256k1::new()
        .sign_ecdsa(
            &Message::from_digest(review.signing_message_digest),
            &secret,
        )
        .serialize_der();
    let compact = ecdsa_der_to_compact_low_s(der.as_ref()).unwrap();
    let wire = assemble_ecdsa_signature(&compact, SIG_HASH_ALL);
    let signature_script = assemble_signature_script(&wire);
    assert_eq!(wire.len(), 65);
    assert_eq!(signature_script.len(), 66);

    suite.verify_finalized_signature(&review, &wire).unwrap();
    suite
        .verify_finalized_signature(&review, &signature_script)
        .unwrap();
}

#[test]
fn cb_mpc_review_binds_group_key_to_the_spent_p2pk_ecdsa_utxo() {
    let expected_secret = secret(3);
    let expected_key = PublicKey::from_secret_key(&Secp256k1::new(), &expected_secret).serialize();
    let wrong_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret(4)).serialize();
    let (transaction, entries) = p2pk_ecdsa_transaction(wrong_key);
    let encoded =
        KaspaReviewMaterial::new(KaspaNetwork::Mainnet, transaction, entries, 0, SIG_HASH_ALL)
            .unwrap()
            .encode()
            .unwrap();
    let suite = KaspaChainSuite::new(
        KaspaNetwork::Mainnet,
        KaspaVerifier::EcdsaCbMpc(expected_key),
    )
    .unwrap();

    assert!(suite.review_transaction(&encoded).is_err());
}

#[test]
fn high_s_der_and_compact_signatures_fail_closed() {
    let secret = secret(3);
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize();
    let (transaction, entries) = p2pk_ecdsa_transaction(public_key);
    let populated = PopulatedTransaction::new(&transaction, entries.clone());
    let digest = ecdsa_transaction_signing_hash(&populated, 0, SIG_HASH_ALL);
    let low = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &secret);
    let mut high_compact = low.serialize_compact();
    let high_s = negate_scalar(&high_compact[32..]);
    high_compact[32..].copy_from_slice(&high_s);
    let high_der = secp256k1::ecdsa::Signature::from_compact(&high_compact)
        .unwrap()
        .serialize_der();
    assert!(ecdsa_der_to_compact_low_s(high_der.as_ref()).is_err());

    let encoded =
        KaspaReviewMaterial::new(KaspaNetwork::Devnet, transaction, entries, 0, SIG_HASH_ALL)
            .unwrap()
            .encode()
            .unwrap();
    let suite =
        KaspaChainSuite::new(KaspaNetwork::Devnet, KaspaVerifier::EcdsaCbMpc(public_key)).unwrap();
    let review = suite.review_transaction(&encoded).unwrap();
    let high_wire = assemble_ecdsa_signature(&high_compact, SIG_HASH_ALL);
    assert!(
        suite
            .verify_finalized_signature(&review, &high_wire)
            .is_err()
    );
}

fn p2pk_ecdsa_transaction(public_key: [u8; 33]) -> (Transaction, Vec<UtxoEntry>) {
    let input_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &public_key,
    ));
    let output_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret(9)).serialize();
    let output_script = pay_to_address_script(&Address::new(
        Prefix::Testnet,
        Version::PubKeyECDSA,
        &output_key,
    ));
    let transaction = Transaction::new(
        0,
        vec![TransactionInput::new(
            TransactionOutpoint::new(Hash::from_bytes([0x11; 32]), 7),
            vec![],
            1,
            1,
        )],
        vec![TransactionOutput::new(900, output_script)],
        42,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entries = vec![UtxoEntry::new(1_000, input_script, 8, false, None)];
    (transaction, entries)
}

fn secret(last_byte: u8) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = last_byte;
    SecretKey::from_slice(&bytes).unwrap()
}

fn negate_scalar(scalar: &[u8]) -> [u8; 32] {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let mut result = [0_u8; 32];
    let mut borrow = 0_u16;
    for index in (0..32).rev() {
        let minuend = u16::from(ORDER[index]);
        let subtrahend = u16::from(scalar[index]) + borrow;
        if minuend >= subtrahend {
            result[index] = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            result[index] = (256 + minuend - subtrahend) as u8;
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0);
    result
}
