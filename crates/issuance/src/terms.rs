//! Creator-defined issuance terms and their canonical commitment.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Protocol version tag for issuance term canonical serialization.
pub const TERMS_TAG: &[u8] = b"catomicals-issuance-v1";
/// Protocol version tag for item commitment canonical serialization.
pub const ITEM_TAG: &[u8] = b"catomicals-item-v1";

/// Successor rule identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SuccessorRule {
    /// One shared recursive issuer UTXO: each mint spends the previous issuer
    /// output and recreates it with decremented supply and incremented seq.
    RecursiveIssuer = 1,
    /// Precommitted sharded mint lanes: the issuance creates one issuer output
    /// per lane and mints inside a lane follow that lane's recursion.
    ShardedLanes = 2,
}

impl SuccessorRule {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::RecursiveIssuer),
            2 => Some(Self::ShardedLanes),
            _ => None,
        }
    }
}

/// Creator-defined issuance terms. Everything a valid mint depends on is
/// committed here; altering any field changes `terms_hash` and is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceTerms {
    /// Item identity commitment (hash of name/ticker/metadata chosen by creator).
    pub item_id: [u8; 32],
    /// PoW difficulty: required number of leading `0x01` bytes in the digest.
    pub target_prefix: u8,
    /// Total number of mintable items.
    pub total_supply: u32,
    /// Successor rule for the issuer state machine.
    pub successor_rule: SuccessorRule,
    /// Number of sharded lanes (1 for the recursive model).
    pub lane_count: u8,
    /// Creator challenge salt, committed so the same terms cannot be replayed
    /// under a different issuance.
    pub salt: [u8; 32],
    /// Creator metadata, committed but not interpreted.
    pub metadata: Vec<u8>,
}

impl IssuanceTerms {
    /// Canonical byte encoding of the terms.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 1 + 4 + 1 + 1 + 32 + 8 + self.metadata.len());
        out.extend_from_slice(TERMS_TAG);
        out.extend_from_slice(&self.item_id);
        out.push(self.target_prefix);
        out.extend_from_slice(&self.total_supply.to_le_bytes());
        out.push(self.successor_rule as u8);
        out.push(self.lane_count);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&(self.metadata.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.metadata);
        out
    }

    /// The commitment binding every creator term: `SHA256(canonical_bytes)`.
    pub fn terms_hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Number of shards to materialize as issuer outputs. The recursive model
    /// always materializes one; the lane model materializes `lane_count`.
    pub fn materialized_lanes(&self) -> u8 {
        match self.successor_rule {
            SuccessorRule::RecursiveIssuer => 1,
            SuccessorRule::ShardedLanes => self.lane_count.max(1),
        }
    }

    /// Split `total_supply` across lanes (even split; remainder goes to lane 0).
    pub fn lane_supply(&self, lane: u8) -> u32 {
        let lanes = self.materialized_lanes() as u32;
        let base = self.total_supply / lanes;
        let extra = self.total_supply % lanes;
        if (lane as u32) < extra {
            base + 1
        } else {
            base
        }
    }
}

/// Canonical item payload commitment: `SHA256(ITEM_TAG || terms_hash || lane ||
/// seq || owner_key || payload)`. The owner key binds the mined artifact to a
/// real spendable P2TR output selected before grinding the nonce.
pub fn item_commitment(
    terms_hash: &[u8; 32],
    lane: u8,
    seq: u32,
    owner_key: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(ITEM_TAG.len() + 32 + 1 + 4 + 32 + payload.len());
    input.extend_from_slice(ITEM_TAG);
    input.extend_from_slice(terms_hash);
    input.push(lane);
    input.extend_from_slice(&seq.to_le_bytes());
    input.extend_from_slice(owner_key);
    input.extend_from_slice(payload);
    Sha256::digest(input).into()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_terms() -> IssuanceTerms {
        IssuanceTerms {
            item_id: [0x42; 32],
            target_prefix: 1,
            total_supply: 4,
            successor_rule: SuccessorRule::RecursiveIssuer,
            lane_count: 1,
            salt: [0x7a; 32],
            metadata: b"catomicals demo item".to_vec(),
        }
    }

    #[test]
    fn terms_hash_is_stable_and_changes_on_every_field() {
        let base = sample_terms();
        let h = base.terms_hash();
        assert_eq!(h.len(), 32);
        // Altered target changes the commitment.
        let mut t = base.clone();
        t.target_prefix = 2;
        assert_ne!(t.terms_hash(), h);
        // Altered item identity changes the commitment.
        let mut t = base.clone();
        t.item_id = [0x43; 32];
        assert_ne!(t.terms_hash(), h);
        // Altered supply changes the commitment.
        let mut t = base.clone();
        t.total_supply = 5;
        assert_ne!(t.terms_hash(), h);
        // Altered successor rule changes the commitment.
        let mut t = base.clone();
        t.successor_rule = SuccessorRule::ShardedLanes;
        t.lane_count = 2;
        assert_ne!(t.terms_hash(), h);
        // Altered salt changes the commitment.
        let mut t = base.clone();
        t.salt = [0x01; 32];
        assert_ne!(t.terms_hash(), h);
        // Altered metadata changes the commitment.
        let mut t = base.clone();
        t.metadata.push(0);
        assert_ne!(t.terms_hash(), h);
    }

    #[test]
    fn lane_supply_splits_evenly_and_assigns_remainder_to_lane_zero() {
        let mut terms = sample_terms();
        terms.successor_rule = SuccessorRule::ShardedLanes;
        terms.total_supply = 10;
        terms.lane_count = 3;
        assert_eq!(terms.lane_supply(0), 4); // 10/3 = 3, remainder 1 -> lane 0 gets 4
        assert_eq!(terms.lane_supply(1), 3);
        assert_eq!(terms.lane_supply(2), 3);
        assert_eq!(terms.materialized_lanes(), 3);
    }

    #[test]
    fn item_commitment_binds_terms_lane_seq_and_payload() {
        let th = [0x11; 32];
        let owner = [0x22; 32];
        let a = item_commitment(&th, 0, 0, &owner, b"payload");
        assert_eq!(a.len(), 32);
        assert_ne!(item_commitment(&th, 1, 0, &owner, b"payload"), a);
        assert_ne!(item_commitment(&th, 0, 1, &owner, b"payload"), a);
        assert_ne!(item_commitment(&th, 0, 0, &[0x23; 32], b"payload"), a);
        assert_ne!(item_commitment(&th, 0, 0, &owner, b"payload2"), a);
        let th2 = [0x22; 32];
        assert_ne!(item_commitment(&th2, 0, 0, &owner, b"payload"), a);
    }
}
