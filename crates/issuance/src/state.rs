//! Issuer UTXO state machine.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::terms::{IssuanceTerms, SuccessorRule};

/// Nonzero tag committed in front of scalar state fields. The tag keeps zero
/// values fixed-width without relying on non-minimal one-byte data pushes.
pub const STATE_FIELD_TAG: u8 = 0x01;
/// Number of bytes used for tagged `seq`/`remaining` fields in the tapscript.
pub const STATE_INT_LEN: usize = 5;
/// Number of bytes used for tagged `target_prefix`/`lane` fields.
pub const STATE_BYTE_LEN: usize = 2;

fn encode_u32(value: u32) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(STATE_INT_LEN);
    encoded.push(STATE_FIELD_TAG);
    encoded.extend_from_slice(&value.to_le_bytes());
    encoded
}

fn encode_u8(value: u8) -> Vec<u8> {
    vec![STATE_FIELD_TAG, value]
}

/// Immutable state committed inside an issuer tapscript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerState {
    /// Commitment to the creator terms (`IssuanceTerms::terms_hash`).
    pub terms_hash: [u8; 32],
    /// Mint lane (0 for the recursive single-lane model).
    pub lane: u8,
    /// Slot sequence within the lane, starting at 0.
    pub seq: u32,
    /// Remaining mintable supply in this lane, including the current slot.
    pub remaining: u32,
    /// Required leading `0x01` bytes of the PoW digest.
    pub target_prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("target prefix must be between 0 and 32, got {0}")]
    TargetPrefixOutOfRange(u8),
    #[error("lane {0} is out of range for this issuance")]
    LaneOutOfRange(u8),
    #[error("sequence overflow")]
    SeqOverflow,
}

impl IssuerState {
    /// Build the initial issuer state for a lane of an issuance.
    pub fn initial(terms: &IssuanceTerms, lane: u8) -> Result<Self, StateError> {
        if terms.target_prefix > 32 {
            return Err(StateError::TargetPrefixOutOfRange(terms.target_prefix));
        }
        let lanes = terms.materialized_lanes();
        if lane >= lanes {
            return Err(StateError::LaneOutOfRange(lane));
        }
        Ok(Self {
            terms_hash: terms.terms_hash(),
            lane,
            seq: 0,
            remaining: terms.lane_supply(lane),
            target_prefix: terms.target_prefix,
        })
    }

    /// The successor state after one valid mint in this lane.
    pub fn successor(&self) -> Result<Option<Self>, StateError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let next_remaining = self.remaining - 1;
        let next_seq = self.seq.checked_add(1).ok_or(StateError::SeqOverflow)?;
        if next_remaining == 0 {
            // Supply exhausted: this lane terminates, no successor output.
            return Ok(None);
        }
        Ok(Some(Self {
            terms_hash: self.terms_hash,
            lane: self.lane,
            seq: next_seq,
            remaining: next_remaining,
            target_prefix: self.target_prefix,
        }))
    }

    /// Serialize the state fields in script-push order.
    pub fn to_script_constants(&self) -> Vec<Vec<u8>> {
        vec![
            self.terms_hash.to_vec(),
            encode_u32(self.seq),
            encode_u32(self.remaining),
            encode_u8(self.target_prefix),
            encode_u8(self.lane),
        ]
    }

    /// Decode script-push-ordered constants back into a state.
    pub fn from_script_constants(
        terms_hash: &[u8],
        seq: &[u8],
        remaining: &[u8],
        target_prefix: &[u8],
        lane: &[u8],
    ) -> Option<Self> {
        if terms_hash.len() != 32
            || seq.len() != STATE_INT_LEN
            || remaining.len() != STATE_INT_LEN
            || target_prefix.len() != STATE_BYTE_LEN
            || lane.len() != STATE_BYTE_LEN
            || seq[0] != STATE_FIELD_TAG
            || remaining[0] != STATE_FIELD_TAG
            || target_prefix[0] != STATE_FIELD_TAG
            || lane[0] != STATE_FIELD_TAG
        {
            return None;
        }
        Some(Self {
            terms_hash: terms_hash.try_into().ok()?,
            seq: u32::from_le_bytes(seq[1..].try_into().ok()?),
            remaining: u32::from_le_bytes(remaining[1..].try_into().ok()?),
            target_prefix: target_prefix[1],
            lane: lane[1],
        })
    }
}

/// The successor rule must stay in sync with the terms: the recursive model
/// materializes one lane, the lane model materializes `lane_count` lanes.
pub fn rule_for(terms: &IssuanceTerms) -> SuccessorRule {
    terms.successor_rule
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::tests::sample_terms;

    #[test]
    fn initial_state_uses_terms_hash_and_lane_supply() {
        let terms = sample_terms();
        let s = IssuerState::initial(&terms, 0).unwrap();
        assert_eq!(s.terms_hash, terms.terms_hash());
        assert_eq!(s.seq, 0);
        assert_eq!(s.remaining, terms.total_supply);
        assert_eq!(s.lane, 0);
        assert_eq!(s.target_prefix, 1);
    }

    #[test]
    fn successor_decrements_and_terminates_at_zero() {
        let terms = sample_terms();
        let s0 = IssuerState::initial(&terms, 0).unwrap();
        let s1 = s0.successor().unwrap().unwrap();
        assert_eq!(s1.seq, 1);
        assert_eq!(s1.remaining, 3);
        let s2 = s1.successor().unwrap().unwrap();
        assert_eq!(s2.seq, 2);
        assert_eq!(s2.remaining, 2);
        let s3 = s2.successor().unwrap().unwrap();
        assert_eq!(s3.seq, 3);
        assert_eq!(s3.remaining, 1);
        // Last mint: no successor.
        assert_eq!(s3.successor().unwrap(), None);
    }

    #[test]
    fn lane_state_is_scoped_per_lane() {
        let mut terms = sample_terms();
        terms.successor_rule = SuccessorRule::ShardedLanes;
        terms.lane_count = 2;
        terms.total_supply = 5;
        let l0 = IssuerState::initial(&terms, 0).unwrap();
        let l1 = IssuerState::initial(&terms, 1).unwrap();
        assert_eq!(l0.lane, 0);
        assert_eq!(l0.remaining, 3); // 5/2 = 2 + remainder 1 -> lane 0
        assert_eq!(l1.lane, 1);
        assert_eq!(l1.remaining, 2);
        // Out-of-range lane is rejected.
        assert!(IssuerState::initial(&terms, 2).is_err());
    }

    #[test]
    fn state_roundtrips_through_script_constants() {
        let terms = sample_terms();
        let s = IssuerState::initial(&terms, 0).unwrap();
        let consts = s.to_script_constants();
        let back = IssuerState::from_script_constants(
            &consts[0], &consts[1], &consts[2], &consts[3], &consts[4],
        )
        .unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn scalar_script_constants_have_a_committed_nonzero_tag() {
        let terms = sample_terms();
        let state = IssuerState::initial(&terms, 0).unwrap();
        let constants = state.to_script_constants();

        assert_eq!(
            constants[1],
            [vec![1], state.seq.to_le_bytes().to_vec()].concat()
        );
        assert_eq!(
            constants[2],
            [vec![1], state.remaining.to_le_bytes().to_vec()].concat()
        );
        assert_eq!(constants[3], vec![1, state.target_prefix]);
        assert_eq!(constants[4], vec![1, state.lane]);
    }
}
