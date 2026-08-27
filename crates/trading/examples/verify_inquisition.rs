//! Execute valid and adversarial protected-trade leaves with Bitcoin
//! Inquisition's `bitcoin-util evalscript`, including complete BIP341
//! transaction and prevout context.

use std::process::Command;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use catomicals_issuance::{
    pow::{hash_tail, pow_hash},
    state::IssuerState,
    terms::{IssuanceTerms, SuccessorRule, item_commitment},
    verify::{MintWitness, build_mint_tx, canonical_issuer_spk, item_owner_script, verify_mint},
};
use catomicals_trading::{
    AgentTradingApi, BuyRequest, CancelRequest, IssuanceProof, ItemReceipt, ListRequest,
    ListingTerms, Network, apply_trade_signature, buy_leaf_script, buyer_ownership_message,
    cancel_leaf_script,
};

const HEIGHT: u32 = 240_000;
const FLAGS: &str = "P2SH,WITNESS,TAPROOT,MINIMALDATA,CLEANSTACK,CHECKLOCKTIMEVERIFY,OP_CAT";

fn key(byte: u8) -> (SecretKey, bitcoin::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[byte; 32]).expect("fixed example secret");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    (secret, bitcoin::XOnlyPublicKey::from_keypair(&keypair).0)
}

fn outpoint(byte: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([byte; 32]), 0)
}

fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

fn issued_item(owner_key: bitcoin::XOnlyPublicKey) -> (ItemReceipt, IssuanceProof) {
    let terms = IssuanceTerms {
        item_id: [0x22; 32],
        target_prefix: 0,
        total_supply: 1,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 1,
        salt: [0x24; 32],
        metadata: b"inquisition protected trade item".to_vec(),
    };
    let state = IssuerState::initial(&terms, 0).expect("issuer state");
    let item_commitment = item_commitment(
        &state.terms_hash,
        0,
        0,
        &owner_key.serialize(),
        b"item payload",
    );
    let digest = pow_hash(&state.terms_hash, 0, 0, &item_commitment, 0);
    let witness = MintWitness {
        nonce: 0,
        item_commitment,
        hash_tail: hash_tail(&digest, 0),
        owner_key,
        payload: b"item payload".to_vec(),
    };
    let issuer_outpoint = outpoint(0x10);
    let issuer_utxo = TxOut {
        value: Amount::from_sat(12_000),
        script_pubkey: canonical_issuer_spk(&state),
    };
    let issuer_script = ScriptBuf::from_bytes(catomicals_issuance::script::issuer_script(&state));
    let spend_info = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, issuer_script.clone())
        .expect("issuer leaf")
        .finalize(
            &Secp256k1::verification_only(),
            catomicals_issuance::script::nums_internal_key(),
        )
        .expect("issuer tree");
    let control = spend_info
        .control_block(&(issuer_script, bitcoin::taproot::LeafVersion::TapScript))
        .expect("issuer control")
        .serialize();
    let mint_tx = build_mint_tx(
        issuer_outpoint,
        &issuer_utxo,
        &state,
        &witness,
        Amount::from_sat(10_000),
        None,
        control,
    )
    .expect("mint tx");
    let verified =
        verify_mint(&mint_tx, issuer_outpoint, &issuer_utxo, &terms).expect("verified mint");
    (
        ItemReceipt::from_verified_mint(&mint_tx, &verified, &terms).expect("item receipt"),
        IssuanceProof {
            raw_mint_tx_hex: serialize_hex(&mint_tx),
            issuer_outpoint,
            issuer_utxo,
            terms,
        },
    )
}

fn listing() -> (ListingTerms, IssuanceProof, SecretKey, SecretKey) {
    let (seller_secret, seller_key) = key(3);
    let (buyer_secret, _) = key(4);
    let (receipt, issuance_proof) = issued_item(seller_key);
    (
        ListingTerms {
            protocol_version: 1,
            network: Network::Signet,
            receipt,
            seller_key,
            seller_payout_script: item_owner_script(key(5).1),
            price_sat: 60_000,
            creator_fee_script: item_owner_script(key(6).1),
            creator_fee_sat: 3_000,
            cancel_script: item_owner_script(seller_key),
            expiry_height: HEIGHT + 144,
            max_network_fee_sat: 2_000,
        },
        issuance_proof,
        seller_secret,
        buyer_secret,
    )
}

fn list_tx(listing: &ListingTerms) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(listing.receipt.outpoint), input(outpoint(0x31))],
        output: vec![
            listing.order_txout().expect("order output"),
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    }
}

fn list_request(listing: &ListingTerms, issuance_proof: &IssuanceProof) -> ListRequest {
    ListRequest {
        listing: listing.clone(),
        issuance_proof: issuance_proof.clone(),
        raw_tx_hex: serialize_hex(&list_tx(listing)),
        prevouts: vec![
            listing.receipt.txout(),
            TxOut {
                value: Amount::from_sat(4_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    }
}

fn buy_request(
    listing: &ListingTerms,
    issuance_proof: &IssuanceProof,
    buyer_secret: &SecretKey,
) -> BuyRequest {
    let secp = Secp256k1::new();
    let buyer_pair = Keypair::from_secret_key(&secp, buyer_secret);
    let buyer_key = bitcoin::XOnlyPublicKey::from_keypair(&buyer_pair).0;
    let order_outpoint = OutPoint::new(list_tx(listing).compute_txid(), 0);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(order_outpoint), input(outpoint(0x41))],
        output: vec![
            TxOut {
                value: Amount::from_sat(listing.receipt.item_sat_amount),
                script_pubkey: item_owner_script(buyer_key),
            },
            TxOut {
                value: Amount::from_sat(listing.price_sat),
                script_pubkey: listing.seller_payout_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(listing.creator_fee_sat),
                script_pubkey: listing.creator_fee_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(6_000),
                script_pubkey: item_owner_script(buyer_key),
            },
        ],
    };
    let mut request = BuyRequest {
        listing: listing.clone(),
        list_request: Box::new(list_request(listing, issuance_proof)),
        order_outpoint,
        buyer_key,
        proposal_expiry_height: HEIGHT + 12,
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![
            listing.order_txout().expect("order output"),
            TxOut {
                value: Amount::from_sat(70_000),
                script_pubkey: item_owner_script(buyer_key),
            },
        ],
        buyer_ownership_signature: [0; 64],
    };
    request.buyer_ownership_signature = secp
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(buyer_ownership_message(&request).expect("buyer message")),
            &buyer_pair,
        )
        .serialize();
    request
}

fn cancel_request(listing: &ListingTerms, issuance_proof: &IssuanceProof) -> CancelRequest {
    let order_outpoint = OutPoint::new(list_tx(listing).compute_txid(), 0);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(listing.expiry_height).expect("height locktime"),
        input: vec![input(order_outpoint), input(outpoint(0x51))],
        output: vec![
            TxOut {
                value: Amount::from_sat(listing.receipt.item_sat_amount),
                script_pubkey: listing.cancel_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    };
    CancelRequest {
        listing: listing.clone(),
        list_request: Box::new(list_request(listing, issuance_proof)),
        order_outpoint,
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![
            listing.order_txout().expect("order output"),
            TxOut {
                value: Amount::from_sat(4_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    }
}

fn signed(verified: &catomicals_trading::VerifiedTrade, seller_secret: &SecretKey) -> Transaction {
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, seller_secret);
    let signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(verified.sighash), &pair)
        .serialize();
    apply_trade_signature(verified, signature).expect("apply signature")
}

fn evaluate(
    binary: &str,
    name: &str,
    tx: &Transaction,
    prevouts: &[TxOut],
    script: &ScriptBuf,
    expected: bool,
) {
    let signature = tx.input[0].witness.iter().next().expect("seller signature");
    let mut command = Command::new(binary);
    command
        .arg("-sigversion=tapscript")
        .arg(format!("-script_flags={FLAGS}"))
        .arg(format!("-tx={}", serialize_hex(tx)))
        .arg("-input=0");
    for prevout in prevouts {
        command.arg(format!("-spent_output={}", serialize_hex(prevout)));
    }
    let output = command
        .arg("evalscript")
        .arg(hex::encode(script.as_bytes()))
        .arg(hex::encode(signature))
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {binary}: {error}"));
    assert!(
        output.status.success(),
        "{name}: bitcoin-util invocation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{name}: invalid JSON: {error}"));
    let actual = report["success"].as_bool().expect("success boolean");
    for required in ["TAPROOT", "CLEANSTACK", "CHECKLOCKTIMEVERIFY", "OP_CAT"] {
        assert!(
            report["script_flags"]
                .as_array()
                .expect("script flags")
                .iter()
                .any(|flag| flag == required),
            "{name}: missing flag {required}"
        );
    }
    assert_eq!(actual, expected, "{name}: unexpected evalscript result");
    println!("{name}: success={actual} expected={expected}");
}

fn main() {
    let binary = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bitcoin-util-inq".to_owned());
    let (listing, issuance_proof, seller_secret, buyer_secret) = listing();
    AgentTradingApi::verify_list(&list_request(&listing, &issuance_proof), HEIGHT)
        .expect("valid list");

    let buy_request = buy_request(&listing, &issuance_proof, &buyer_secret);
    let buy = AgentTradingApi::verify_buy(&buy_request, HEIGHT).expect("valid buy");
    let signed_buy = signed(&buy, &seller_secret);
    let buy_script = buy_leaf_script(&listing).expect("buy leaf");
    evaluate(
        &binary,
        "valid-buy",
        &signed_buy,
        &buy.prevouts,
        &buy_script,
        true,
    );

    for (name, output_index, script_change) in [
        ("substituted-seller-payment", 1usize, false),
        ("substituted-creator-fee", 2usize, false),
        ("substituted-buyer-recipient", 0usize, true),
    ] {
        let mut changed = signed_buy.clone();
        if script_change {
            changed.output[output_index].script_pubkey = item_owner_script(key(9).1);
        } else {
            changed.output[output_index].value -= Amount::from_sat(1);
        }
        evaluate(&binary, name, &changed, &buy.prevouts, &buy_script, false);
    }

    let cancel_request = cancel_request(&listing, &issuance_proof);
    let cancel = AgentTradingApi::verify_cancel(&cancel_request, listing.expiry_height)
        .expect("valid mature cancel");
    let signed_cancel = signed(&cancel, &seller_secret);
    evaluate(
        &binary,
        "valid-cancel",
        &signed_cancel,
        &cancel.prevouts,
        &cancel_leaf_script(&listing).expect("cancel leaf"),
        true,
    );
}
