//! Issuer OP_CAT mint-gate tapscript construction.
//!
//! The issuer output is a P2TR output whose tapscript commits the issuance
//! state as constants and, for a valid spend, requires a witness of
//! `[nonce, item_commitment, hash_tail, owner_key, payload]` that:
//!
//! 1. satisfies the PoW challenge for the committed state:
//!    `SHA256(terms_hash || tagged_lane || tagged_seq || item_commitment || nonce)`
//!    begins with `target_prefix` copies of `0x01` (verified with a revealed
//!    `hash_tail`);
//! 2. is not minted when `remaining == 0`.
//!
//! The program leaves exactly one truthy stack element.

use crate::pow::{POW_PREFIX_BYTE, hash_tail, pow_hash};
use crate::state::{IssuerState, STATE_FIELD_TAG};

/// Tapscript leaf version used for the issuer gate.
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

// Opcode bytes used by the issuer program.
const OP_CAT: u8 = 0x7e;
const OP_EQUAL: u8 = 0x87;
const OP_SHA256: u8 = 0xa8;
const OP_PICK: u8 = 0x79;
const OP_DROP: u8 = 0x75;
const OP_NOT: u8 = 0x91;
const OP_VERIFY: u8 = 0x69;
const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;

/// Push the small integer `n` (0..=16) onto the stack using the `OP_PUSHNUM_n`
/// opcodes, then `OP_PICK` (which reads its depth from the stack).
fn push_pick(script: &mut Vec<u8>, n: u8) {
    assert!(n <= 16, "OP_PICK depth must fit an OP_PUSHNUM");
    script.push(0x50 + n); // OP_0 = 0x00; OP_PUSHNUM_1 = 0x51 ... OP_PUSHNUM_16 = 0x60
    script.push(OP_PICK);
}

/// Push a byte string using Bitcoin's minimal push-data encoding.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + data.len());
    match data.len() {
        0 => out.push(OP_0),
        1 if (1..=16).contains(&data[0]) => out.push(0x50 + data[0]),
        1 if data[0] == 0x81 => out.push(OP_1NEGATE),
        1..=75 => {
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        76..=255 => {
            out.push(0x4c); // OP_PUSHDATA1
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        256..=65535 => {
            out.push(0x4d); // OP_PUSHDATA2
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        _ => {
            out.push(0x4e); // OP_PUSHDATA4
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
    }
    out
}

/// The canonical OP_CAT-only issuer gate for a state.
///
/// Stack layout after the constants are pushed (top first):
/// `lane, target_prefix, remaining, seq, terms_hash, payload, owner_key,
/// hash_tail, item_commitment, nonce`.
pub fn issuer_script(state: &IssuerState) -> Vec<u8> {
    let mut s = Vec::new();
    // --- constants (the committed state) ---
    for constant in state.to_script_constants() {
        s.extend_from_slice(&push_data(&constant));
    }
    // --- PoW: copies -> nonce, item_commitment, seq, lane, terms_hash (top first) ---
    // OP_PICK takes its depth from the stack, so each depth uses an OP_PUSHNUM.
    push_pick(&mut s, 4); // copy terms_hash
    push_pick(&mut s, 1); // copy lane
    push_pick(&mut s, 5); // copy seq
    push_pick(&mut s, 11); // copy item_commitment
    push_pick(&mut s, 13); // copy nonce
    s.extend_from_slice(&[OP_CAT, OP_CAT, OP_CAT, OP_CAT]);
    s.push(OP_SHA256);
    // --- target check: H == 0x01^target_prefix || hash_tail ---
    s.extend_from_slice(&push_data(&vec![
        POW_PREFIX_BYTE;
        state.target_prefix as usize
    ]));
    push_pick(&mut s, 9); // copy hash_tail
    s.push(OP_CAT);
    s.push(OP_EQUAL);
    s.push(OP_VERIFY);
    // --- remaining must be non-zero ---
    push_pick(&mut s, 2); // copy tagged remaining
    s.extend_from_slice(&push_data(&[STATE_FIELD_TAG, 0, 0, 0, 0]));
    s.push(OP_EQUAL);
    s.push(OP_NOT);
    s.push(OP_VERIFY);
    // --- end with exactly one truthy element ---
    s.extend([OP_DROP; 10]);
    s.push(OP_1);
    s
}

/// Human-readable assembly of the issuer script (for documentation/evidence).
pub fn issuer_script_asm(state: &IssuerState) -> String {
    let parts: Vec<String> = state
        .to_script_constants()
        .iter()
        .map(hex::encode)
        .collect();
    format!(
        "<{}> <{}> <{}> <{}> <{}> 4 PICK 1 PICK 5 PICK 11 PICK 13 PICK CAT CAT CAT CAT SHA256 <target-prefix> 9 PICK CAT EQUAL VERIFY 2 PICK <tagged-zero> EQUAL NOT VERIFY DROP DROP DROP DROP DROP DROP DROP DROP DROP DROP TRUE",
        parts[0], parts[1], parts[2], parts[3], parts[4]
    )
}

/// Parse the committed state back out of an issuer tapscript.
///
/// Returns `None` if the script is not a canonical issuer script for any
/// state (template mismatch).
pub fn parse_issuer_script(script: &[u8]) -> Option<IssuerState> {
    // Constants occupy: 32B, 5B, 5B, 2B, 2B (with direct-push prefixes).
    let expected_const_len = (1 + 32) + (1 + 5) + (1 + 5) + (1 + 2) + (1 + 2);
    if script.len() < expected_const_len {
        return None;
    }
    let mut pos = 0usize;
    let mut consts = Vec::new();
    for _ in 0..5 {
        let plen = script[pos] as usize;
        if plen == 0 || plen > 75 || pos + 1 + plen > script.len() {
            return None;
        }
        consts.push(script[pos + 1..pos + 1 + plen].to_vec());
        pos += 1 + plen;
    }
    // The rest must be the canonical program template. We compare opcode-for-
    // opcode, allowing only the target-prefix push length to vary by target.
    let state = IssuerState::from_script_constants(
        &consts[0], &consts[1], &consts[2], &consts[3], &consts[4],
    )?;
    let canonical = issuer_script(&state);
    if script == canonical.as_slice() {
        Some(state)
    } else {
        None
    }
}

/// Compute the expected witness `hash_tail` for a state + item + nonce.
pub fn witness_hash_tail(state: &IssuerState, item_commitment: &[u8; 32], nonce: u64) -> Vec<u8> {
    hash_tail(
        &pow_hash(
            &state.terms_hash,
            state.lane,
            state.seq,
            item_commitment,
            nonce,
        ),
        state.target_prefix,
    )
}

/// Compute the canonical P2TR output key for a taproot script tree containing a
/// single leaf (`issuer_script(state)`), using the protocol NUMS internal key.
pub fn issuer_output_key(state: &IssuerState) -> bitcoin::XOnlyPublicKey {
    let internal_key = nums_internal_key();
    let builder = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, bitcoin::ScriptBuf::from_bytes(issuer_script(state)))
        .expect("canonical single-leaf taproot builder");
    let spend_info = builder
        .finalize(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            internal_key,
        )
        .expect("canonical taproot spend info");
    spend_info.output_key().to_x_only_public_key()
}

/// The protocol internal key: a nothing-up-my-sleeve point whose discrete log
/// is unknown. This is BIP341's published NUMS point, not a public seed treated
/// as a known secret scalar.
pub fn nums_internal_key() -> bitcoin::XOnlyPublicKey {
    const BIP341_NUMS_X: [u8; 32] = hex_literal();
    bitcoin::XOnlyPublicKey::from_slice(&BIP341_NUMS_X)
        .expect("the published BIP341 NUMS x-coordinate is a valid curve point")
}

const fn hex_literal() -> [u8; 32] {
    [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::IssuerState;
    use crate::terms::tests::sample_terms;

    #[test]
    fn script_roundtrips_through_parse() {
        let terms = sample_terms();
        let state = IssuerState::initial(&terms, 0).unwrap();
        let script = issuer_script(&state);
        let parsed = parse_issuer_script(&script).unwrap();
        assert_eq!(parsed, state);
        // A tampered state constant must not parse as canonical.
        let mut tampered = script.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(parse_issuer_script(&tampered).is_none());
        // A script with a different state must not parse as this state.
        let s2 = state.successor().unwrap().unwrap();
        assert_ne!(parse_issuer_script(&issuer_script(&s2)).unwrap(), state);
    }

    #[test]
    fn issuer_output_key_is_deterministic() {
        let terms = sample_terms();
        let s = IssuerState::initial(&terms, 0).unwrap();
        let k1 = issuer_output_key(&s);
        let k2 = issuer_output_key(&s);
        assert_eq!(k1, k2);
        let s2 = s.successor().unwrap().unwrap();
        assert_ne!(issuer_output_key(&s2), k1);
    }

    #[test]
    fn issuer_script_uses_minimal_pushes_and_ends_in_explicit_true() {
        let terms = sample_terms();
        let state = IssuerState::initial(&terms, 0).unwrap();
        let script = issuer_script(&state);
        let script_buf = bitcoin::ScriptBuf::from_bytes(script.clone());
        let parsed = script_buf
            .instructions_minimal()
            .collect::<Result<Vec<_>, _>>();

        assert!(parsed.is_ok(), "issuer script contains a non-minimal push");
        assert_eq!(script.last(), Some(&OP_1));
        assert!(script[..script.len() - 1].ends_with(&[OP_DROP; 10]));
    }

    #[test]
    fn nums_internal_key_is_the_bip341_unknown_discrete_log_point() {
        let k = nums_internal_key();
        assert_eq!(
            hex::encode(k.serialize()),
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        );
    }
}
