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
    AgentTradingApi, BuyRequest, CancelRequest, CandidateKind, CandidateStatus, CompetitionTracker,
    IssuanceProof, ItemReceipt, ListRequest, ListingTerms, Network, TradePath, WalletTradingApi,
    apply_trade_signature, buyer_ownership_message, listing_output_script,
};

const HEIGHT: u32 = 240_000;

fn key(byte: u8) -> (SecretKey, bitcoin::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    (secret, bitcoin::XOnlyPublicKey::from_keypair(&keypair).0)
}

fn spk(byte: u8) -> ScriptBuf {
    item_owner_script(key(byte).1)
}

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([byte; 32]), vout)
}

fn txin(previous_output: OutPoint, sequence: Sequence) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    }
}

fn issuer_control_block(state: &IssuerState) -> Vec<u8> {
    let script = ScriptBuf::from_bytes(catomicals_issuance::script::issuer_script(state));
    let info = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(
            &Secp256k1::verification_only(),
            catomicals_issuance::script::nums_internal_key(),
        )
        .unwrap();
    info.control_block(&(script, bitcoin::taproot::LeafVersion::TapScript))
        .unwrap()
        .serialize()
}

fn issued_item(owner_key: bitcoin::XOnlyPublicKey) -> (ItemReceipt, IssuanceProof) {
    let terms = IssuanceTerms {
        item_id: [0x22; 32],
        target_prefix: 0,
        total_supply: 1,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 1,
        salt: [0x24; 32],
        metadata: b"protected trading test item".to_vec(),
    };
    let state = IssuerState::initial(&terms, 0).unwrap();
    let commitment = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        b"item payload",
    );
    let digest = pow_hash(&state.terms_hash, state.lane, state.seq, &commitment, 0);
    let witness = MintWitness {
        nonce: 0,
        item_commitment: commitment,
        hash_tail: hash_tail(&digest, 0),
        owner_key,
        payload: b"item payload".to_vec(),
    };
    let issuer_outpoint = outpoint(0x10, 0);
    let issuer_utxo = TxOut {
        value: Amount::from_sat(12_000),
        script_pubkey: canonical_issuer_spk(&state),
    };
    let mint_tx = build_mint_tx(
        issuer_outpoint,
        &issuer_utxo,
        &state,
        &witness,
        Amount::from_sat(10_000),
        None,
        issuer_control_block(&state),
    )
    .unwrap();
    let verified = verify_mint(&mint_tx, issuer_outpoint, &issuer_utxo, &terms).unwrap();
    let receipt = ItemReceipt::from_verified_mint(&mint_tx, &verified, &terms).unwrap();
    (
        receipt,
        IssuanceProof {
            raw_mint_tx_hex: serialize_hex(&mint_tx),
            issuer_outpoint,
            issuer_utxo,
            terms,
        },
    )
}

struct Fixture {
    listing: ListingTerms,
    issuance_proof: IssuanceProof,
    seller_secret: SecretKey,
    buyer_secret: SecretKey,
}

fn fixture() -> Fixture {
    let (seller_secret, seller_key) = key(3);
    let (buyer_secret, _) = key(4);
    let (receipt, issuance_proof) = issued_item(seller_key);
    let listing = ListingTerms {
        protocol_version: 1,
        network: Network::Signet,
        receipt,
        seller_key,
        seller_payout_script: spk(5),
        price_sat: 60_000,
        creator_fee_script: spk(6),
        creator_fee_sat: 3_000,
        cancel_script: item_owner_script(seller_key),
        expiry_height: HEIGHT + 144,
        max_network_fee_sat: 2_000,
    };
    Fixture {
        listing,
        issuance_proof,
        seller_secret,
        buyer_secret,
    }
}

fn list_request(listing: &ListingTerms, issuance_proof: &IssuanceProof) -> ListRequest {
    let funding = TxOut {
        value: Amount::from_sat(4_000),
        script_pubkey: listing.cancel_script.clone(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            txin(listing.receipt.outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME),
            txin(outpoint(0x31, 0), Sequence::ENABLE_RBF_NO_LOCKTIME),
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(listing.receipt.item_sat_amount),
                script_pubkey: listing_output_script(listing).unwrap(),
            },
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    };
    ListRequest {
        listing: listing.clone(),
        issuance_proof: issuance_proof.clone(),
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![listing.receipt.txout(), funding],
    }
}

fn buy_request(
    listing: &ListingTerms,
    issuance_proof: &IssuanceProof,
    buyer_secret: &SecretKey,
) -> BuyRequest {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, buyer_secret);
    let buyer_key = bitcoin::XOnlyPublicKey::from_keypair(&keypair).0;
    let list_request = list_request(listing, issuance_proof);
    let listing_tx = AgentTradingApi::verify_list(&list_request, HEIGHT).unwrap();
    let order_outpoint = OutPoint::new(listing_tx.txid, 0);
    let funding = TxOut {
        value: Amount::from_sat(70_000),
        script_pubkey: item_owner_script(buyer_key),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            txin(order_outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME),
            txin(outpoint(0x41, 0), Sequence::ENABLE_RBF_NO_LOCKTIME),
        ],
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
        list_request: Box::new(list_request),
        order_outpoint,
        buyer_key,
        proposal_expiry_height: HEIGHT + 12,
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![listing.order_txout().unwrap(), funding],
        buyer_ownership_signature: [0; 64],
    };
    let message = Message::from_digest(buyer_ownership_message(&request).unwrap());
    request.buyer_ownership_signature = secp
        .sign_schnorr_no_aux_rand(&message, &keypair)
        .serialize();
    request
}

fn cancel_request(listing: &ListingTerms, issuance_proof: &IssuanceProof) -> CancelRequest {
    let list_request = list_request(listing, issuance_proof);
    let listing_tx = AgentTradingApi::verify_list(&list_request, HEIGHT).unwrap();
    let order_outpoint = OutPoint::new(listing_tx.txid, 0);
    let funding = TxOut {
        value: Amount::from_sat(4_000),
        script_pubkey: listing.cancel_script.clone(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(listing.expiry_height).unwrap(),
        input: vec![
            txin(order_outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME),
            txin(outpoint(0x51, 0), Sequence::ENABLE_RBF_NO_LOCKTIME),
        ],
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
        list_request: Box::new(list_request),
        order_outpoint,
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![listing.order_txout().unwrap(), funding],
    }
}

fn sign_verified(verified: &catomicals_trading::VerifiedTrade, secret: &SecretKey) -> Transaction {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(verified.sighash), &keypair)
        .serialize();
    apply_trade_signature(verified, signature).unwrap()
}

#[test]
fn list_buy_and_cancel_paths_are_independently_verified() {
    let fixture = fixture();
    let listing = &fixture.listing;
    let list = list_request(listing, &fixture.issuance_proof);
    let agent_list = AgentTradingApi::verify_list(&list, HEIGHT).unwrap();
    let wallet_list = WalletTradingApi::verify_list(&list, HEIGHT).unwrap();
    assert_eq!(agent_list.sighash, wallet_list.sighash);
    assert_eq!(agent_list.path, TradePath::List);
    assert!(
        catomicals_trading::verify_finalized(
            &sign_verified(&agent_list, &fixture.seller_secret),
            &agent_list
        )
        .is_ok()
    );

    let buy = buy_request(listing, &fixture.issuance_proof, &fixture.buyer_secret);
    let agent_buy = AgentTradingApi::verify_buy(&buy, HEIGHT).unwrap();
    let wallet_buy = WalletTradingApi::verify_buy(&buy, HEIGHT).unwrap();
    assert_eq!(agent_buy.sighash, wallet_buy.sighash);
    assert_eq!(agent_buy.path, TradePath::Buy);
    assert!(
        catomicals_trading::verify_finalized(
            &sign_verified(&agent_buy, &fixture.seller_secret),
            &agent_buy
        )
        .is_ok()
    );

    let cancel = cancel_request(listing, &fixture.issuance_proof);
    assert!(AgentTradingApi::verify_cancel(&cancel, listing.expiry_height - 1).is_err());
    let agent_cancel = AgentTradingApi::verify_cancel(&cancel, listing.expiry_height).unwrap();
    let wallet_cancel = WalletTradingApi::verify_cancel(&cancel, listing.expiry_height).unwrap();
    assert_eq!(agent_cancel.sighash, wallet_cancel.sighash);
    assert_eq!(agent_cancel.path, TradePath::Cancel);
    assert!(
        catomicals_trading::verify_finalized(
            &sign_verified(&agent_cancel, &fixture.seller_secret),
            &agent_cancel
        )
        .is_ok()
    );
}

#[test]
fn payout_fee_recipient_amount_and_copied_signatures_cannot_be_substituted() {
    let fixture = fixture();
    let request = buy_request(
        &fixture.listing,
        &fixture.issuance_proof,
        &fixture.buyer_secret,
    );
    let verified = AgentTradingApi::verify_buy(&request, HEIGHT).unwrap();
    let signed = sign_verified(&verified, &fixture.seller_secret);

    for (name, mutate) in [
        ("seller payout", 1usize),
        ("creator fee", 2usize),
        ("buyer recipient", 0usize),
    ] {
        let mut changed = signed.clone();
        if mutate == 0 {
            changed.output[mutate].script_pubkey = spk(9);
        } else {
            changed.output[mutate].value -= Amount::from_sat(1);
        }
        assert!(
            catomicals_trading::verify_finalized(&changed, &verified).is_err(),
            "copied signature accepted changed {name}"
        );
    }

    let mut partial = request.clone();
    let mut decoded: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&partial.raw_tx_hex).unwrap())
            .unwrap();
    decoded.output[1].script_pubkey = spk(10);
    partial.raw_tx_hex = serialize_hex(&decoded);
    assert!(AgentTradingApi::verify_buy(&partial, HEIGHT).is_err());
    assert!(WalletTradingApi::verify_buy(&partial, HEIGHT).is_err());
}

#[test]
fn buyer_ownership_is_authenticated_and_every_listing_rule_is_bound() {
    let fixture = fixture();
    let listing = &fixture.listing;
    let valid = buy_request(listing, &fixture.issuance_proof, &fixture.buyer_secret);
    let mut wrong_key = valid.clone();
    wrong_key.buyer_key = key(8).1;
    assert!(AgentTradingApi::verify_buy(&wrong_key, HEIGHT).is_err());
    assert!(WalletTradingApi::verify_buy(&wrong_key, HEIGHT).is_err());

    let commitment = listing.commitment().unwrap();
    let mut mutations = Vec::new();
    let mut x = listing.clone();
    x.receipt.item_id[0] ^= 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.receipt.terms_hash[0] ^= 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.receipt.item_commitment[0] ^= 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.price_sat += 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.creator_fee_sat += 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.receipt.item_sat_amount += 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.expiry_height += 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.max_network_fee_sat += 1;
    mutations.push(x);
    let mut x = listing.clone();
    x.cancel_script = spk(12);
    mutations.push(x);
    for changed in mutations {
        assert_ne!(commitment, changed.commitment().unwrap());
    }
}

#[test]
fn partial_witnesses_and_changed_prevouts_are_rejected_before_approval() {
    let fixture = fixture();
    let valid = buy_request(
        &fixture.listing,
        &fixture.issuance_proof,
        &fixture.buyer_secret,
    );

    let mut partial = valid.clone();
    let mut tx: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&partial.raw_tx_hex).unwrap())
            .unwrap();
    tx.input[0].witness.push([0x55; 64]);
    partial.raw_tx_hex = serialize_hex(&tx);
    assert!(AgentTradingApi::verify_buy(&partial, HEIGHT).is_err());
    assert!(WalletTradingApi::verify_buy(&partial, HEIGHT).is_err());

    let mut changed_prevout = valid.clone();
    changed_prevout.prevouts[1].value += Amount::from_sat(1);
    assert!(AgentTradingApi::verify_buy(&changed_prevout, HEIGHT).is_err());
    assert!(WalletTradingApi::verify_buy(&changed_prevout, HEIGHT).is_err());
}

#[test]
fn fabricated_receipts_and_cloned_order_outputs_have_no_lineage() {
    let fixture = fixture();
    let mut fabricated = list_request(&fixture.listing, &fixture.issuance_proof);
    fabricated.listing.receipt.item_id[0] ^= 1;
    assert!(matches!(
        AgentTradingApi::verify_list(&fabricated, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidReceipt)
    ));
    assert!(matches!(
        WalletTradingApi::verify_list(&fabricated, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidReceipt)
    ));

    let mut cloned = buy_request(
        &fixture.listing,
        &fixture.issuance_proof,
        &fixture.buyer_secret,
    );
    cloned.order_outpoint = outpoint(0x77, 0);
    let mut tx: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&cloned.raw_tx_hex).unwrap()).unwrap();
    tx.input[0].previous_output = cloned.order_outpoint;
    cloned.raw_tx_hex = serialize_hex(&tx);
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, &fixture.buyer_secret);
    cloned.buyer_ownership_signature = secp
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(buyer_ownership_message(&cloned).unwrap()),
            &pair,
        )
        .serialize();
    assert!(matches!(
        AgentTradingApi::verify_buy(&cloned, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidListingLineage)
    ));
    assert!(matches!(
        WalletTradingApi::verify_buy(&cloned, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidListingLineage)
    ));
}

#[test]
fn timestamp_locktimes_and_excessive_fees_are_rejected() {
    let fixture = fixture();
    let mut timestamp_listing = fixture.listing.clone();
    timestamp_listing.expiry_height = bitcoin::absolute::LOCK_TIME_THRESHOLD;
    assert!(timestamp_listing.validate().is_err());

    let mut buy = buy_request(
        &fixture.listing,
        &fixture.issuance_proof,
        &fixture.buyer_secret,
    );
    let mut tx: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&buy.raw_tx_hex).unwrap()).unwrap();
    tx.output[3].value -= Amount::from_sat(fixture.listing.max_network_fee_sat);
    buy.raw_tx_hex = serialize_hex(&tx);
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, &fixture.buyer_secret);
    buy.buyer_ownership_signature = secp
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(buyer_ownership_message(&buy).unwrap()),
            &pair,
        )
        .serialize();
    assert!(matches!(
        AgentTradingApi::verify_buy(&buy, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidFee)
    ));
    assert!(matches!(
        WalletTradingApi::verify_buy(&buy, HEIGHT),
        Err(catomicals_trading::TradeError::InvalidFee)
    ));
}

#[test]
fn two_buyers_and_buy_cancel_contention_resolve_as_one_outpoint_ordering() {
    let fixture = fixture();
    let listing = &fixture.listing;
    let buyer1 = buy_request(listing, &fixture.issuance_proof, &fixture.buyer_secret);
    let mut buyer2 = buy_request(listing, &fixture.issuance_proof, &key(7).0);
    let mut tx2: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&buyer2.raw_tx_hex).unwrap()).unwrap();
    tx2.input[1].previous_output = outpoint(0x42, 0);
    buyer2.raw_tx_hex = serialize_hex(&tx2);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &key(7).0);
    buyer2.buyer_ownership_signature = secp
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(buyer_ownership_message(&buyer2).unwrap()),
            &keypair,
        )
        .serialize();

    let buy1 = AgentTradingApi::verify_buy(&buyer1, HEIGHT).unwrap();
    let buy2 = AgentTradingApi::verify_buy(&buyer2, HEIGHT).unwrap();
    let cancel = AgentTradingApi::verify_cancel(
        &cancel_request(listing, &fixture.issuance_proof),
        listing.expiry_height,
    )
    .unwrap();
    assert_eq!(buy1.spent_order_outpoint, buy2.spent_order_outpoint);
    assert_eq!(buy1.spent_order_outpoint, cancel.spent_order_outpoint);

    let mut scoped = CompetitionTracker::new(buy1.spent_order_outpoint);
    scoped.submit_verified(&buy1).unwrap();
    let mut wrong_order = buy2.clone();
    wrong_order.spent_order_outpoint = outpoint(0x99, 0);
    assert!(matches!(
        scoped.submit_verified(&wrong_order),
        Err(catomicals_trading::TradeError::WrongCompetitionOutpoint)
    ));

    let mut tracker = CompetitionTracker::new(buy1.spent_order_outpoint);
    tracker.submit(buy1.txid, CandidateKind::Buy).unwrap();
    tracker.submit(buy2.txid, CandidateKind::Buy).unwrap();
    tracker.mark_pending(buy1.txid).unwrap();
    tracker.mark_pending(buy2.txid).unwrap();
    tracker.confirm(buy2.txid, HEIGHT + 1).unwrap();
    assert!(matches!(
        tracker.status(buy2.txid),
        Some(CandidateStatus::Confirmed { .. })
    ));
    assert_eq!(
        tracker.status(buy1.txid),
        Some(&CandidateStatus::Conflicted { winner: buy2.txid })
    );

    let late_candidate = Txid::from_byte_array([0x88; 32]);
    tracker.submit(late_candidate, CandidateKind::Buy).unwrap();
    assert_eq!(
        tracker.status(late_candidate),
        Some(&CandidateStatus::Conflicted { winner: buy2.txid })
    );
    assert!(tracker.submit(buy2.txid, CandidateKind::Buy).is_err());
    assert!(matches!(
        tracker.status(buy2.txid),
        Some(CandidateStatus::Confirmed { .. })
    ));

    let mut race = CompetitionTracker::new(buy1.spent_order_outpoint);
    race.submit(buy1.txid, CandidateKind::Buy).unwrap();
    race.submit(cancel.txid, CandidateKind::Cancel).unwrap();
    race.mark_pending(buy1.txid).unwrap();
    race.mark_pending(cancel.txid).unwrap();
    race.confirm(cancel.txid, listing.expiry_height + 1)
        .unwrap();
    let snapshot = race.snapshot();
    assert_eq!(snapshot.ordering, "one_outpoint_bitcoin_confirmation_order");
    assert!(!snapshot.miner_ordering_fairness);
    assert_eq!(
        race.status(buy1.txid),
        Some(&CandidateStatus::Conflicted {
            winner: cancel.txid
        })
    );
}
