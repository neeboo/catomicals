//! Execute valid and adversarial issuer leaves with Bitcoin Inquisition's
//! `bitcoin-util evalscript` command.

use std::process::Command;

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use catomicals_issuance::pow::{find_nonce, hash_tail, meets_target, pow_hash};
use catomicals_issuance::script::issuer_script;
use catomicals_issuance::state::IssuerState;
use catomicals_issuance::terms::{IssuanceTerms, SuccessorRule, item_commitment};

const FLAGS: &str = "P2SH,WITNESS,TAPROOT,MINIMALDATA,CLEANSTACK,OP_CAT";

#[derive(Clone)]
struct Vector {
    nonce: u64,
    item_commitment: [u8; 32],
    hash_tail: Vec<u8>,
    owner_key: bitcoin::XOnlyPublicKey,
    payload: Vec<u8>,
}

fn terms(target_prefix: u8) -> IssuanceTerms {
    IssuanceTerms {
        item_id: [0x42; 32],
        target_prefix,
        total_supply: 4,
        successor_rule: SuccessorRule::RecursiveIssuer,
        lane_count: 1,
        salt: [0x7a; 32],
        metadata: b"catomicals inquisition evidence".to_vec(),
    }
}

fn owner_key() -> bitcoin::XOnlyPublicKey {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[3; 32]).expect("fixed example secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
}

fn vector(state: &IssuerState, nonce: u64, payload: &[u8]) -> Vector {
    let owner_key = owner_key();
    let commitment = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        payload,
    );
    let digest = pow_hash(&state.terms_hash, state.lane, state.seq, &commitment, nonce);
    Vector {
        nonce,
        item_commitment: commitment,
        hash_tail: hash_tail(&digest, state.target_prefix),
        owner_key,
        payload: payload.to_vec(),
    }
}

fn valid_vector(state: &IssuerState, payload: &[u8]) -> Vector {
    let owner = owner_key();
    let commitment = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner.serialize(),
        payload,
    );
    let nonce = find_nonce(
        &state.terms_hash,
        state.lane,
        state.seq,
        &commitment,
        state.target_prefix,
        0,
    )
    .expect("the bounded example target has a nonce");
    vector(state, nonce, payload)
}

fn evaluate(binary: &str, name: &str, state: &IssuerState, vector: &Vector, expected: bool) {
    let output = Command::new(binary)
        .arg("-sigversion=tapscript")
        .arg(format!("-script_flags={FLAGS}"))
        .arg("evalscript")
        .arg(hex::encode(issuer_script(state)))
        .arg(hex::encode(vector.nonce.to_le_bytes()))
        .arg(hex::encode(vector.item_commitment))
        .arg(hex::encode(&vector.hash_tail))
        .arg(hex::encode(vector.owner_key.serialize()))
        .arg(hex::encode(&vector.payload))
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {binary}: {error}"));
    assert!(
        output.status.success(),
        "{name}: bitcoin-util invocation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{name}: invalid bitcoin-util JSON: {error}"));
    let actual = report["success"]
        .as_bool()
        .unwrap_or_else(|| panic!("{name}: missing success boolean"));
    let flags = report["script_flags"]
        .as_array()
        .unwrap_or_else(|| panic!("{name}: missing script flags"));
    for required in ["TAPROOT", "MINIMALDATA", "CLEANSTACK", "OP_CAT"] {
        assert!(
            flags.iter().any(|flag| flag == required),
            "{name}: required flag {required} was not active"
        );
    }
    assert_ne!(
        report["opsuccess_found"],
        serde_json::Value::Bool(true),
        "{name}: OP_SUCCESS bypassed script execution"
    );
    assert_eq!(actual, expected, "{name}: unexpected evalscript result");
    if expected {
        assert_eq!(report["stack-after"], serde_json::json!(["01"]));
    }
    println!(
        "{name}: success={actual} expected={expected} error={}",
        report["error"].as_str().unwrap_or("none")
    );
}

fn main() {
    let binary = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bitcoin-util-inq".to_owned());
    let base = IssuerState::initial(&terms(1), 0).expect("valid base state");
    let valid = valid_vector(&base, b"valid item");
    evaluate(&binary, "valid", &base, &valid, true);

    let zero_target = IssuerState::initial(&terms(0), 0).expect("valid zero target state");
    let zero_nonce = vector(&zero_target, 0, b"nonce zero");
    evaluate(&binary, "nonce-zero", &zero_target, &zero_nonce, true);

    let mut wrong_nonce = valid.clone();
    loop {
        wrong_nonce.nonce = wrong_nonce.nonce.wrapping_add(1);
        let digest = pow_hash(
            &base.terms_hash,
            base.lane,
            base.seq,
            &wrong_nonce.item_commitment,
            wrong_nonce.nonce,
        );
        if !meets_target(&digest, base.target_prefix) {
            break;
        }
    }
    evaluate(&binary, "wrong-nonce", &base, &wrong_nonce, false);

    let mut altered_tail = valid.clone();
    altered_tail.hash_tail[0] ^= 1;
    evaluate(&binary, "altered-hash-tail", &base, &altered_tail, false);

    let changed_state = IssuerState {
        seq: base.seq + 1,
        ..base
    };
    evaluate(&binary, "changed-state", &changed_state, &valid, false);

    let exhausted = IssuerState {
        remaining: 0,
        ..zero_target
    };
    let exhausted_vector = vector(&exhausted, 0, b"exhausted");
    evaluate(
        &binary,
        "exhausted-supply",
        &exhausted,
        &exhausted_vector,
        false,
    );
}
