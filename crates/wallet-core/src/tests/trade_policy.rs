use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use catomicals_issuance::{
    pow::{hash_tail, pow_hash},
    state::IssuerState,
    terms::{IssuanceTerms, SuccessorRule, item_commitment},
    verify::{MintWitness, build_mint_tx, canonical_issuer_spk, verify_mint},
};
use catomicals_trading::{
    IssuanceProof, ItemReceipt, ListRequest, ListingTerms, Network, TradeSigningRequest,
    WalletTradingApi, listing_output_script,
};
use uuid::Uuid;

use crate::{
    CreateTradeIntentRequest, DurableWalletStore, NodeSnapshot, RelyingPartyConfig,
    WalletNodeError, WalletNodeService,
};
use catomicals_threshold::{
    LocalFrostParticipant, NonceGuard, participant_identifier, run_local_dkg,
};

const NOW: i64 = 1_800_000_000;
const HEIGHT: u32 = 240_000;

fn key(byte: u8) -> bitcoin::XOnlyPublicKey {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
}

fn item_owner_script(key: bitcoin::XOnlyPublicKey) -> ScriptBuf {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&key.serialize());
    ScriptBuf::from_bytes(bytes)
}

fn txin(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
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
        metadata: b"wallet trade policy item".to_vec(),
    };
    let state = IssuerState::initial(&terms, 0).unwrap();
    let commitment = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        b"wallet item payload",
    );
    let digest = pow_hash(&state.terms_hash, state.lane, state.seq, &commitment, 0);
    let witness = MintWitness {
        nonce: 0,
        item_commitment: commitment,
        hash_tail: hash_tail(&digest, 0),
        owner_key,
        payload: b"wallet item payload".to_vec(),
    };
    let issuer_outpoint = OutPoint::new(Txid::from_byte_array([0x10; 32]), 0);
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

fn list_request() -> ListRequest {
    let seller_key = key(3);
    let (receipt, issuance_proof) = issued_item(seller_key);
    let listing = ListingTerms {
        protocol_version: 1,
        network: Network::Signet,
        receipt,
        seller_key,
        seller_payout_script: item_owner_script(key(4)),
        price_sat: 50_000,
        creator_fee_script: item_owner_script(key(5)),
        creator_fee_sat: 2_500,
        cancel_script: item_owner_script(seller_key),
        expiry_height: HEIGHT + 10,
        max_network_fee_sat: 2_000,
    };
    let funding = TxOut {
        value: Amount::from_sat(3_000),
        script_pubkey: listing.cancel_script.clone(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            txin(listing.receipt.outpoint),
            txin(OutPoint::new(Txid::from_byte_array([0x31; 32]), 0)),
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: listing_output_script(&listing).unwrap(),
            },
            TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: listing.cancel_script.clone(),
            },
        ],
    };
    ListRequest {
        listing: listing.clone(),
        issuance_proof,
        raw_tx_hex: serialize_hex(&tx),
        prevouts: vec![listing.receipt.txout(), funding],
    }
}

fn service(with_node: bool) -> WalletNodeService {
    let mut service = WalletNodeService::without_signer(RelyingPartyConfig::default()).unwrap();
    if with_node {
        service.set_node_snapshot(Some(NodeSnapshot {
            chain: "signet".into(),
            blocks: u64::from(HEIGHT),
            headers: u64::from(HEIGHT),
            subversion: "/Satoshi:29.4.0/".into(),
            op_cat_active: true,
        }));
    }
    service
}

fn configured_service() -> WalletNodeService {
    let mut dkg = run_local_dkg(3, 2).unwrap();
    let participant = LocalFrostParticipant::new(
        1,
        dkg.key_packages
            .remove(&participant_identifier(1).unwrap())
            .unwrap(),
        NonceGuard::new(),
    )
    .unwrap();
    let mut service = WalletNodeService::new(
        RelyingPartyConfig::default(),
        Some(participant),
        dkg.public_key_package,
        2,
    )
    .unwrap();
    service.set_node_snapshot(Some(NodeSnapshot {
        chain: "signet".into(),
        blocks: u64::from(HEIGHT),
        headers: u64::from(HEIGHT),
        subversion: "/Satoshi:29.4.0/".into(),
        op_cat_active: true,
    }));
    service
}

fn create_request(trade: TradeSigningRequest) -> CreateTradeIntentRequest {
    CreateTradeIntentRequest {
        wallet_id: Uuid::from_bytes([1; 16]),
        signer_id: 1,
        session_id: [3; 32],
        expiry: NOW + 300,
        trade,
    }
}

#[test]
fn wallet_derives_trade_sighash_and_agent_verifies_independently() {
    let list = list_request();
    let expected = WalletTradingApi::verify_list(&list, HEIGHT).unwrap();
    let trade = TradeSigningRequest::List(list);
    let mut service = service(true);
    let agent = service.verify_trade_for_agent(&trade).unwrap();
    assert_eq!(agent.sighash_hex, hex::encode(expected.sighash));

    let intent = service
        .create_trade_intent(create_request(trade), NOW)
        .unwrap();
    assert_eq!(intent.tx_digest, expected.sighash);
    assert_eq!(
        service.trade_verification(intent.id).unwrap().sighash_hex,
        hex::encode(expected.sighash)
    );
}

#[test]
fn malformed_raw_trade_never_reaches_passkey_approval() {
    let mut list = list_request();
    let mut tx: Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(&list.raw_tx_hex).unwrap()).unwrap();
    tx.output[0].value -= Amount::from_sat(1);
    list.raw_tx_hex = serialize_hex(&tx);
    let trade = TradeSigningRequest::List(list);
    let mut service = service(true);
    assert!(matches!(
        service.create_trade_intent(create_request(trade.clone()), NOW),
        Err(WalletNodeError::TradePolicy(_))
    ));
    assert!(matches!(
        service.verify_trade_for_agent(&trade),
        Err(WalletNodeError::TradePolicy(_))
    ));
}

#[test]
fn trusted_signet_state_is_required_and_policy_is_rechecked_before_passkey() {
    let trade = TradeSigningRequest::List(list_request());
    assert!(matches!(
        service(false).create_trade_intent(create_request(trade.clone()), NOW),
        Err(WalletNodeError::TradeNodeUnavailable)
    ));

    let mut service = service(true);
    let intent = service
        .create_trade_intent(create_request(trade), NOW)
        .unwrap();
    service.set_node_snapshot(Some(NodeSnapshot {
        chain: "signet".into(),
        blocks: u64::from(HEIGHT + 10),
        headers: u64::from(HEIGHT + 10),
        subversion: "/Satoshi:29.4.0/".into(),
        op_cat_active: true,
    }));
    assert!(matches!(
        service.approval_start(intent.id, NOW + 1),
        Err(WalletNodeError::TradePolicy(_))
    ));
}

#[test]
fn configured_wallet_rejects_a_listing_owned_by_another_seller_key() {
    let trade = TradeSigningRequest::List(list_request());
    assert!(matches!(
        configured_service().create_trade_intent(create_request(trade), NOW),
        Err(WalletNodeError::TradeSignerMismatch)
    ));
}

#[test]
fn durable_service_without_group_key_rejects_protected_trade_creation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.sqlite3");
    let store = DurableWalletStore::initialize(&database, Uuid::from_bytes([1; 16]), NOW).unwrap();
    let mut service = WalletNodeService::without_signer_with_store(
        RelyingPartyConfig::default(),
        Box::new(store),
        NOW,
    )
    .unwrap();
    service.set_node_snapshot(Some(NodeSnapshot {
        chain: "signet".into(),
        blocks: u64::from(HEIGHT),
        headers: u64::from(HEIGHT),
        subversion: "/Satoshi:29.4.0/".into(),
        op_cat_active: true,
    }));

    let trade = TradeSigningRequest::List(list_request());
    assert!(matches!(
        service.create_trade_intent(create_request(trade), NOW),
        Err(WalletNodeError::SignerNotConfigured)
    ));
}
