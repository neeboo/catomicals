use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, TxOut, Txid};
use catomicals_issuance::verify::item_owner_script;
use catomicals_trading::{ItemReceipt, ListingArtifacts, ListingTerms, Network};

fn key(byte: u8) -> bitcoin::XOnlyPublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
    let pair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    bitcoin::XOnlyPublicKey::from_keypair(&pair).0
}

fn listing() -> ListingTerms {
    let seller_key = key(3);
    ListingTerms {
        protocol_version: 1,
        network: Network::Signet,
        receipt: ItemReceipt {
            network: Network::Signet,
            outpoint: OutPoint::new(Txid::from_byte_array([0x11; 32]), 2),
            script_pubkey: item_owner_script(seller_key),
            item_sat_amount: 10_000,
            terms_hash: [0x22; 32],
            item_id: [0x33; 32],
            item_commitment: [0x44; 32],
            lane: 0,
            sequence: 7,
        },
        seller_key,
        seller_payout_script: item_owner_script(key(5)),
        price_sat: 60_000,
        creator_fee_script: item_owner_script(key(6)),
        creator_fee_sat: 3_000,
        cancel_script: item_owner_script(seller_key),
        expiry_height: 240_144,
        max_network_fee_sat: 2_000,
    }
}

#[test]
fn listing_artifacts_are_the_existing_listing_protocol_outputs() {
    let listing = listing();
    let artifacts = ListingArtifacts::new(&listing).unwrap();
    assert_eq!(
        artifacts.canonical_bytes,
        listing.canonical_bytes().unwrap()
    );
    assert_eq!(artifacts.commitment, listing.commitment().unwrap());
    assert_eq!(
        hex::encode(artifacts.commitment),
        "4c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce904"
    );
    assert_eq!(
        artifacts.buy_leaf,
        catomicals_trading::buy_leaf_script(&listing).unwrap()
    );
    assert_eq!(
        artifacts.cancel_leaf,
        catomicals_trading::cancel_leaf_script(&listing).unwrap()
    );
    assert_eq!(
        artifacts.listing_output,
        catomicals_trading::listing_output_script(&listing).unwrap()
    );
    assert_eq!(
        hex::encode(artifacts.buy_leaf.as_bytes()),
        "204c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce9047520531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337ac"
    );
    assert_eq!(
        hex::encode(artifacts.cancel_leaf.as_bytes()),
        "0310aa03b175204c96ce2192aa3bd8e30ab95ba84e1d0f88fb947e4e677a43e81f2624b4bce9047520531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337ac"
    );
    assert_eq!(
        hex::encode(artifacts.listing_output.as_bytes()),
        "5120f6cf2eddf0d2f7333ae887867e72d1dee7962d868e51c78aded22514ca9c0a94"
    );
    assert_eq!(artifacts.order_txout, listing.order_txout().unwrap());
    assert_eq!(
        artifacts.order_txout,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: artifacts.listing_output.clone(),
        }
    );
}
