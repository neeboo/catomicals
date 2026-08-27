use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    consensus::encode::serialize_hex,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    transaction,
};
use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};
use uuid::Uuid;

use crate::{
    CreateIntentRequest, CreateTransactionIntentRequest, RelyingPartyConfig, TransactionPrevout,
    TransactionReviewRequest, WalletNodeError, WalletNodeService,
};

fn service() -> WalletNodeService {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let participant = LocalFrostParticipant::new(
        1,
        dkg.key_packages
            .remove(&participant_identifier(1).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    WalletNodeService::new(
        RelyingPartyConfig::default(),
        Some(participant),
        dkg.public_key_package,
        2,
    )
    .unwrap()
}

fn p2tr_script(secret: u8) -> ScriptBuf {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[secret; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    Address::p2tr(&secp, xonly, None, Network::Signet).script_pubkey()
}

fn review_request() -> TransactionReviewRequest {
    let spent = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spent,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(95_000),
            script_pubkey: p2tr_script(8),
        }],
    };
    TransactionReviewRequest {
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![TransactionPrevout {
            outpoint: spent.to_string(),
            value_sat: 100_000,
            script_pubkey_hex: hex::encode(p2tr_script(7).as_bytes()),
        }],
        input_index: 0,
        max_fee_sat: 5_000,
    }
}

#[test]
fn reviewed_intent_uses_wallet_derived_sighash_and_keeps_review() {
    let mut service = service();
    let request = review_request();
    let expected = service.inspect_transaction(&request).unwrap();
    let intent = service
        .create_transaction_intent(
            CreateTransactionIntentRequest {
                wallet_id: Uuid::from_bytes([1; 16]),
                signer_id: 1,
                session_id: [2; 32],
                expiry: 1_800_000_300,
                transaction: request,
            },
            1_800_000_000,
        )
        .unwrap();

    assert_eq!(hex::encode(intent.tx_digest), expected.sighash_hex);
    let stored = service.transaction_review(intent.id).unwrap();
    assert_eq!(stored.txid, expected.txid);
    assert_eq!(stored.sighash_hex, expected.sighash_hex);
}

#[test]
fn cancel_removes_the_reviewed_transaction_binding() {
    let mut service = service();
    let intent = service
        .create_transaction_intent(
            CreateTransactionIntentRequest {
                wallet_id: Uuid::from_bytes([1; 16]),
                signer_id: 1,
                session_id: [2; 32],
                expiry: 1_800_000_300,
                transaction: review_request(),
            },
            1_800_000_000,
        )
        .unwrap();
    service.cancel_intent(intent.id, 1_800_000_001).unwrap();
    assert_eq!(
        service.transaction_review(intent.id).unwrap_err(),
        WalletNodeError::IntentNotFound
    );
}

#[test]
fn generic_digest_intent_cannot_claim_a_transaction_review() {
    let mut service = service();
    let intent = service
        .create_intent(
            CreateIntentRequest {
                wallet_id: Uuid::from_bytes([1; 16]),
                signer_id: 1,
                tx_digest: [3; 32],
                session_id: [2; 32],
                expiry: 1_800_000_300,
            },
            1_800_000_000,
        )
        .unwrap();
    assert_eq!(
        service.transaction_review(intent.id).unwrap_err(),
        WalletNodeError::IntentNotFound
    );
}
