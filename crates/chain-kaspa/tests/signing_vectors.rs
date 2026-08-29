use std::str::FromStr;

use catomicals_chain_kaspa::{
    ThresholdSupport, assemble_ecdsa_signature, assemble_schnorr_signature,
    assemble_signature_script, ecdsa_transaction_signing_hash, kaspa_threshold_support,
    personal_message_signing_hash, schnorr_transaction_signing_hash, transaction_signing_hash,
    verify_ecdsa_digest, verify_personal_message_schnorr, verify_schnorr_digest,
};
use catomicals_signing_domain::SignerBackendRequirement;
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::script_builder::ScriptBuilder;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

const OFFICIAL_MESSAGE_PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];

const OFFICIAL_MESSAGE_SIGNATURE: [u8; 64] = [
    0x40, 0xb9, 0xbb, 0x2b, 0xe0, 0xae, 0x02, 0x60, 0x72, 0x79, 0xed, 0xa6, 0x40, 0x15, 0xa8, 0xd8,
    0x6e, 0x37, 0x63, 0x27, 0x91, 0x70, 0x34, 0x0b, 0x82, 0x43, 0xf7, 0xce, 0x53, 0x44, 0xd7, 0x7a,
    0xff, 0x11, 0x91, 0x59, 0x8b, 0xaf, 0x2f, 0xd2, 0x61, 0x49, 0xca, 0xc3, 0xb4, 0xb1, 0x2c, 0x2c,
    0x43, 0x32, 0x61, 0xc0, 0x08, 0x34, 0xdb, 0x60, 0x98, 0xcb, 0x17, 0x2a, 0xa4, 0x8e, 0xf5, 0x22,
];

#[test]
fn official_domain_hash_and_transaction_sighash_vectors_match() {
    assert_eq!(
        hex::encode(transaction_signing_hash([])),
        "34c75037ad62740d4b3228f88f844f7901c07bfacd55a045be518eabc15e52ce"
    );

    let (tx, entries) = official_sighash_transaction();
    let populated = PopulatedTransaction::new(&tx, entries);
    assert_eq!(
        hex::encode(schnorr_transaction_signing_hash(
            &populated,
            0,
            SIG_HASH_ALL
        )),
        "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5"
    );
}

#[test]
fn official_personal_message_vector_verifies() {
    let digest = personal_message_signing_hash("Hello Kaspa!");
    verify_schnorr_digest(
        &digest,
        &OFFICIAL_MESSAGE_PUBLIC_KEY,
        &OFFICIAL_MESSAGE_SIGNATURE,
    )
    .unwrap();
    verify_personal_message_schnorr(
        "Hello Kaspa!",
        &OFFICIAL_MESSAGE_PUBLIC_KEY,
        &OFFICIAL_MESSAGE_SIGNATURE,
    )
    .unwrap();
    assert!(
        verify_personal_message_schnorr(
            "Not Hello Kaspa!",
            &OFFICIAL_MESSAGE_PUBLIC_KEY,
            &OFFICIAL_MESSAGE_SIGNATURE,
        )
        .is_err()
    );
}

#[test]
fn compact_schnorr_and_ecdsa_signatures_interoperate_with_official_secp256k1() {
    let (tx, entries) = official_sighash_transaction();
    let populated = PopulatedTransaction::new(&tx, entries);
    let schnorr_digest = schnorr_transaction_signing_hash(&populated, 0, SIG_HASH_ALL);
    let ecdsa_digest = ecdsa_transaction_signing_hash(&populated, 0, SIG_HASH_ALL);

    let secret = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ])
    .unwrap();
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret);

    let schnorr_message = Message::from_digest(schnorr_digest);
    let schnorr = secp.sign_schnorr_no_aux_rand(&schnorr_message, &keypair);
    let x_only = XOnlyPublicKey::from_keypair(&keypair).0.serialize();
    verify_schnorr_digest(&schnorr_digest, &x_only, schnorr.as_ref()).unwrap();

    let ecdsa_message = Message::from_digest(ecdsa_digest);
    let ecdsa = secp.sign_ecdsa(&ecdsa_message, &secret).serialize_compact();
    let public_key = PublicKey::from_secret_key(&secp, &secret).serialize();
    verify_ecdsa_digest(&ecdsa_digest, &public_key, &ecdsa).unwrap();
    assert!(verify_ecdsa_digest(&schnorr_digest, &public_key, &ecdsa).is_err());
}

#[test]
fn signatures_are_assembled_in_the_official_kaspa_wire_shape() {
    let schnorr = assemble_schnorr_signature(&[0x42; 64], SIG_HASH_ALL);
    let ecdsa = assemble_ecdsa_signature(&[0x24; 64], SIG_HASH_ALL);
    assert_eq!(schnorr.len(), 65);
    assert_eq!(ecdsa.len(), 65);
    assert_eq!(schnorr[64], SIG_HASH_ALL.to_u8());
    assert_eq!(ecdsa[64], SIG_HASH_ALL.to_u8());

    let script = assemble_signature_script(&schnorr);
    let official = ScriptBuilder::new().add_data(&schnorr).unwrap().drain();
    assert_eq!(script, official);
    assert_eq!(script.len(), 66);
    assert_eq!(script[0], 65);
}

#[test]
fn threshold_path_is_review_only_until_a_kaspa_ciphersuite_passes_official_vectors() {
    assert_eq!(
        kaspa_threshold_support(),
        ThresholdSupport::ReviewOnly {
            required_backend: SignerBackendRequirement::FrostSecp256k1Kaspa,
        }
    );
}

fn official_sighash_transaction() -> (Transaction, Vec<UtxoEntry>) {
    let previous_tx =
        Hash::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
    let script_1 =
        script_public_key("208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac");
    let script_2 =
        script_public_key("20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac");

    let tx = Transaction::new(
        0,
        vec![
            transaction_input(previous_tx, 0, 0),
            transaction_input(previous_tx, 1, 1),
            transaction_input(previous_tx, 2, 2),
        ],
        vec![
            TransactionOutput::new(300, script_2.clone()),
            TransactionOutput::new(300, script_1.clone()),
        ],
        1_615_462_089_000,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entries = vec![
        UtxoEntry::new(100, script_1, 0, false, None),
        UtxoEntry::new(200, script_2.clone(), 0, false, None),
        UtxoEntry::new(300, script_2, 0, false, None),
    ];
    (tx, entries)
}

fn script_public_key(hex_script: &str) -> ScriptPublicKey {
    ScriptPublicKey::new(0, hex::decode(hex_script).unwrap().into())
}

fn transaction_input(transaction_id: Hash, index: u32, sequence: u64) -> TransactionInput {
    TransactionInput::new(
        TransactionOutpoint::new(transaction_id, index),
        vec![],
        sequence,
        0,
    )
}
