//! Print the canonical issuer script (hex + asm) and a valid witness for a
//! sample issuance, so the script can be run through bitcoin-util-inq
//! evalscript as executable evidence.
//!
//! Usage: cargo run -p catomicals-issuance --example dump_issuer [target_prefix]

use catomicals_issuance::pow::{find_nonce, hash_tail, pow_hash};
use catomicals_issuance::script::{issuer_script, issuer_script_asm};
use catomicals_issuance::state::IssuerState;
use catomicals_issuance::terms::{IssuanceTerms, SuccessorRule, item_commitment};

fn main() {
    let target = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(1);
    let terms = IssuanceTerms {
        item_id: [0x42; 32],
        target_prefix: target,
        total_supply: 4,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 1,
        salt: [0x7a; 32],
        metadata: b"catomicals demo item".to_vec(),
    };
    let state = IssuerState::initial(&terms, 0).unwrap();
    let script = issuer_script(&state);
    println!("terms_hash     {}", hex::encode(terms.terms_hash()));
    println!("script_hex     {}", hex::encode(&script));
    println!("script_asm     {}", issuer_script_asm(&state));
    println!("script_len     {}", script.len());

    let payload = b"catomicals evalscript evidence item";
    let owner_key = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    };
    let ic = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        payload,
    );
    let nonce = find_nonce(
        &state.terms_hash,
        state.lane,
        state.seq,
        &ic,
        state.target_prefix,
        0,
    )
    .unwrap();
    let digest = pow_hash(&state.terms_hash, state.lane, state.seq, &ic, nonce);
    let tail = hash_tail(&digest, state.target_prefix);
    println!("item_commitment {}", hex::encode(ic));
    println!(
        "nonce          {} (le: {})",
        nonce,
        hex::encode(nonce.to_le_bytes())
    );
    println!("digest         {}", hex::encode(digest));
    println!("hash_tail      {}", hex::encode(&tail));
    println!("owner_key      {}", hex::encode(owner_key.serialize()));
    println!("payload        {}", hex::encode(payload));
    println!("witness_order  nonce item_commitment hash_tail owner_key payload");
    println!(
        "witness        {} {} {} {} {}",
        hex::encode(nonce.to_le_bytes()),
        hex::encode(ic),
        hex::encode(&tail),
        hex::encode(owner_key.serialize()),
        hex::encode(payload)
    );
}
