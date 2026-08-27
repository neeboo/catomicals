//! Proof-of-work challenge: a nonce must make `SHA256(pow_input)` begin with
//! `target_prefix` copies of the committed byte `0x01`.

use sha2::{Digest, Sha256};

use crate::state::STATE_FIELD_TAG;

/// Nonce width in bytes (little-endian u64).
pub const NONCE_LEN: usize = 8;
/// Repeated digest byte required by the PoW target. Unlike `0x00`, `0x01` can
/// be constructed by `OP_1` under `SCRIPT_VERIFY_MINIMALDATA`.
pub const POW_PREFIX_BYTE: u8 = 0x01;

/// Canonical PoW input.
///
/// `terms_hash || tag || lane || tag || seq || item_commitment || nonce` — the
/// exact order the tapscript concatenates (see `crate::script`), so the wallet
/// verifier and the script compute the same digest. Scalar state values use a
/// committed nonzero tag to remain fixed-width and minimally pushable.
pub fn pow_input(
    terms_hash: &[u8; 32],
    lane: u8,
    seq: u32,
    item_commitment: &[u8; 32],
    nonce: u64,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(32 + 2 + 5 + 32 + NONCE_LEN);
    input.extend_from_slice(terms_hash);
    input.push(STATE_FIELD_TAG);
    input.push(lane);
    input.push(STATE_FIELD_TAG);
    input.extend_from_slice(&seq.to_le_bytes());
    input.extend_from_slice(item_commitment);
    input.extend_from_slice(&nonce.to_le_bytes());
    input
}

/// The PoW digest for a candidate nonce.
pub fn pow_hash(
    terms_hash: &[u8; 32],
    lane: u8,
    seq: u32,
    item_commitment: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    Sha256::digest(pow_input(terms_hash, lane, seq, item_commitment, nonce)).into()
}

/// Does the digest satisfy the committed challenge (`target_prefix` repeated
/// `POW_PREFIX_BYTE` bytes)?
pub fn meets_target(digest: &[u8; 32], target_prefix: u8) -> bool {
    let k = target_prefix as usize;
    if k == 0 {
        return true;
    }
    if k > 32 {
        return false;
    }
    digest[..k].iter().all(|&b| b == POW_PREFIX_BYTE)
}

/// The public `hash_tail` the tapscript needs to verify the target prefix:
/// `digest[target_prefix..]`.
pub fn hash_tail(digest: &[u8; 32], target_prefix: u8) -> Vec<u8> {
    digest[target_prefix as usize..].to_vec()
}

/// A nonce iterator that scans `u64` values until the challenge is met.
pub fn find_nonce(
    terms_hash: &[u8; 32],
    lane: u8,
    seq: u32,
    item_commitment: &[u8; 32],
    target_prefix: u8,
    start: u64,
) -> Option<u64> {
    (start..).find(|&nonce| {
        meets_target(
            &pow_hash(terms_hash, lane, seq, item_commitment, nonce),
            target_prefix,
        )
    })
}

/// A nonce iterator that scans `u64` values with a max attempts bound and
/// reports the number of hashes tried (used by measurement).
pub fn find_nonce_bounded(
    terms_hash: &[u8; 32],
    lane: u8,
    seq: u32,
    item_commitment: &[u8; 32],
    target_prefix: u8,
    max_attempts: u64,
) -> Option<(u64, u64)> {
    let mut nonce = 0u64;
    let mut attempts = 0u64;
    while attempts < max_attempts {
        let h = pow_hash(terms_hash, lane, seq, item_commitment, nonce);
        if meets_target(&h, target_prefix) {
            return Some((nonce, attempts + 1));
        }
        nonce = nonce.wrapping_add(1);
        attempts += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::item_commitment;

    const TH: [u8; 32] = [0x11; 32];
    const OWNER: [u8; 32] = [0x22; 32];

    #[test]
    fn digest_and_tail_are_consistent() {
        let ic = item_commitment(&TH, 0, 3, &OWNER, b"payload");
        // Use a nonce that actually satisfies the target so the digest really
        // begins with two target-prefix bytes.
        let nonce = find_nonce_bounded(&TH, 0, 3, &ic, 2, 1_000_000).unwrap().0;
        let h = pow_hash(&TH, 0, 3, &ic, nonce);
        assert!(meets_target(&h, 2));
        let tail = hash_tail(&h, 2);
        assert_eq!(tail.len(), 30);
        let mut rebuilt = vec![POW_PREFIX_BYTE; 2];
        rebuilt.extend_from_slice(&tail);
        assert_eq!(rebuilt.as_slice(), &h[..]);
    }

    #[test]
    fn meets_target_respects_prefix_and_bounds() {
        let mut h = [POW_PREFIX_BYTE; 32];
        assert!(meets_target(&h, 32));
        assert!(meets_target(&h, 0));
        h[0] = 0;
        assert!(!meets_target(&h, 1));
        assert!(meets_target(&h, 0));
        assert!(!meets_target(&h, 33));
        h[0] = POW_PREFIX_BYTE;
        h[1] = 0;
        h[31] = 0xff;
        assert!(meets_target(&h, 1));
        assert!(!meets_target(&h, 2));
        h[1] = POW_PREFIX_BYTE;
        assert!(meets_target(&h, 2));
    }

    #[test]
    fn target_uses_a_minimally_pushable_nonzero_digest_prefix() {
        let mut digest = [0x01; 32];
        assert!(meets_target(&digest, 32));
        digest[1] = 0;
        assert!(meets_target(&digest, 1));
        assert!(!meets_target(&digest, 2));
    }

    #[test]
    fn find_nonce_finds_a_valid_nonce() {
        let ic = item_commitment(&TH, 0, 0, &OWNER, b"payload");
        let (nonce, attempts) = find_nonce_bounded(&TH, 0, 0, &ic, 2, 1_000_000).unwrap();
        assert!(attempts > 0);
        let h = pow_hash(&TH, 0, 0, &ic, nonce);
        assert!(meets_target(&h, 2));
        // Changing the item or the seq changes the required nonce.
        let ic2 = item_commitment(&TH, 0, 1, &OWNER, b"payload");
        assert!(!meets_target(&pow_hash(&TH, 0, 1, &ic2, nonce), 2));
    }

    #[test]
    fn weaker_target_finds_nonce_faster_or_equal() {
        let ic = item_commitment(&TH, 0, 0, &OWNER, b"p");
        let (_, hard) = find_nonce_bounded(&TH, 0, 0, &ic, 2, 1_000_000).unwrap();
        let (_, easy) = find_nonce_bounded(&TH, 0, 0, &ic, 1, 1_000_000).unwrap();
        assert!(easy <= hard);
    }
}
