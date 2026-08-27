//! Model comparison and cost/contention measurement.
//!
//! Two issuance structures are compared:
//!
//! * **Model A — shared issuer UTXO**: wallet policy expects every accepted
//!   mint to recreate the next issuer output. Accepted mints are serialized on
//!   one UTXO chain, but OP_CAT alone does not enforce recreation.
//! * **Model B — precommitted sharded mint lanes**: the issuance creates `L`
//!   initial issuer outputs. Wallet-policy-accepted mints inside a lane are
//!   serialized while lanes remain independent.
//!
//! Model A is the smallest measured wallet-policy model. Model B trades
//! issuance size for parallelism. Neither transition is consensus-enforced by
//! this OP_CAT-only leaf.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::pow::find_nonce_bounded;
use crate::state::IssuerState;
use crate::terms::{IssuanceTerms, SuccessorRule, item_commitment};

/// Consensus weight of a transaction (from the `bitcoin` crate).
pub fn tx_weight(tx: &Transaction) -> u64 {
    tx.weight().to_wu()
}

/// Virtual size in vbytes: `(weight + 3) / 4`.
pub fn tx_vbytes(tx: &Transaction) -> u64 {
    tx.weight().to_vbytes_ceil()
}

/// A representative signed funding input (P2WPKH) used only for size estimates.
fn funding_input() -> TxIn {
    let mut witness = Witness::new();
    witness.push([0x55; 72]); // DER-ish signature placeholder
    witness.push([0x33; 33]); // compressed pubkey
    TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness,
    }
}

/// Build the issuance transaction: one funding input and one issuer output per
/// lane (Model A = 1 lane, Model B = `lane_count` lanes).
pub fn build_issuance_tx(terms: &IssuanceTerms, issuer_value: Amount) -> Transaction {
    let lanes = terms.materialized_lanes();
    let mut outputs = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        let state = IssuerState::initial(terms, lane).expect("valid lane");
        outputs.push(TxOut {
            value: issuer_value,
            script_pubkey: crate::verify::canonical_issuer_spk(&state),
        });
    }
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![funding_input()],
        output: outputs,
    }
}

/// Cost and contention metrics for one model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelMetrics {
    pub name: String,
    pub lanes: u8,
    pub issuance_outputs: u32,
    pub issuance_tx_vbytes: u64,
    pub mint_tx_vbytes: u64,
    /// Expected blocks to complete the full supply, assuming one mint per block
    /// per lane (pipelined; see `mints_per_block` for concurrent lanes).
    pub supply_latency_blocks: u64,
    /// How many independent mint chains the model maintains.
    pub concurrent_chains: u32,
    /// Estimated sha256 attempts for one nonce at the committed target.
    pub expected_nonce_attempts: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelComparison {
    pub terms_summary: serde_json::Value,
    pub model_a: ModelMetrics,
    pub model_b: ModelMetrics,
    pub chosen_model: &'static str,
    pub rationale: String,
}

/// Estimate expected PoW attempts for a target prefix (`256^k`), saturating
/// when the expectation no longer fits in `u64`.
pub fn expected_attempts(target_prefix: u8) -> u64 {
    256u64.saturating_pow(target_prefix as u32)
}

/// Measure both models for one issuance definition.
pub fn compare(terms: &IssuanceTerms, issuer_value: Amount, item_value: Amount) -> ModelComparison {
    let terms_summary = serde_json::json!({
        "item_id": hex::encode(terms.item_id),
        "target_prefix": terms.target_prefix,
        "total_supply": terms.total_supply,
        "successor_rule": terms.successor_rule as u8,
        "lane_count": terms.lane_count,
        "salt": hex::encode(terms.salt),
        "terms_hash": hex::encode(terms.terms_hash()),
    });

    // ---- Model A: single recursive issuer ----
    let mut terms_a = terms.clone();
    terms_a.successor_rule = SuccessorRule::RecursiveIssuer;
    terms_a.lane_count = 1;
    let issuance_a = build_issuance_tx(&terms_a, issuer_value);
    let mint_a_vbytes = mint_tx_vbytes(&terms_a, issuer_value, item_value);
    let model_a = ModelMetrics {
        name: "A: shared issuer UTXO (wallet policy)".into(),
        lanes: 1,
        issuance_outputs: 1,
        issuance_tx_vbytes: tx_vbytes(&issuance_a),
        mint_tx_vbytes: mint_a_vbytes,
        supply_latency_blocks: terms_a.total_supply as u64,
        concurrent_chains: 1,
        expected_nonce_attempts: expected_attempts(terms_a.target_prefix),
    };

    // ---- Model B: precommitted sharded lanes ----
    let mut terms_b = terms.clone();
    terms_b.successor_rule = SuccessorRule::ShardedLanes;
    terms_b.lane_count = terms.lane_count.max(2);
    let issuance_b = build_issuance_tx(&terms_b, issuer_value);
    let mint_b_vbytes = mint_tx_vbytes(&terms_b, issuer_value, item_value);
    let lanes = terms_b.lane_count as u32;
    let max_lane_supply = (0..lanes)
        .map(|l| terms_b.lane_supply(l as u8) as u64)
        .max()
        .unwrap_or(0);
    let model_b = ModelMetrics {
        name: "B: sharded issuer lanes (wallet policy)".into(),
        lanes: terms_b.lane_count,
        issuance_outputs: lanes,
        issuance_tx_vbytes: tx_vbytes(&issuance_b),
        mint_tx_vbytes: mint_b_vbytes,
        supply_latency_blocks: max_lane_supply,
        concurrent_chains: lanes,
        expected_nonce_attempts: expected_attempts(terms_b.target_prefix),
    };

    ModelComparison {
        terms_summary,
        model_a,
        model_b,
        chosen_model: "A",
        rationale: "Model A has one issuer output and the smallest issuance transaction. The wallet verifier recognizes one canonical successor chain. OP_CAT alone does not enforce that successor output, so this is a wallet-policy model rather than a consensus-enforced recursion. Model B measures the cost of multiple independently verified lanes; it has the same OP_CAT-only boundary.".into(),
    }
}

/// Virtual size of a representative mint transaction for a model.
fn mint_tx_vbytes(terms: &IssuanceTerms, issuer_value: Amount, item_value: Amount) -> u64 {
    let state = IssuerState::initial(terms, 0).expect("valid state");
    let owner_key = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).expect("fixed key");
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    };
    let ic = item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &owner_key.serialize(),
        b"payload",
    );
    // Find a real nonce for realistic witness sizing.
    let (nonce, _) = find_nonce_bounded(
        &state.terms_hash,
        state.lane,
        state.seq,
        &ic,
        state.target_prefix,
        1_000_000,
    )
    .unwrap_or((0, 0));
    let digest = crate::pow::pow_hash(&state.terms_hash, state.lane, state.seq, &ic, nonce);
    let mw = crate::verify::MintWitness {
        nonce,
        item_commitment: ic,
        hash_tail: crate::pow::hash_tail(&digest, state.target_prefix),
        owner_key,
        payload: b"payload".to_vec(),
    };
    let issuer_utxo = TxOut {
        value: issuer_value,
        script_pubkey: crate::verify::canonical_issuer_spk(&state),
    };
    let succ = match state.successor() {
        Ok(Some(next)) => Some(TxOut {
            value: issuer_value - item_value - Amount::from_sat(500),
            script_pubkey: crate::verify::canonical_issuer_spk(&next),
        }),
        _ => None,
    };
    let control = {
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};
        let script = ScriptBuf::from_bytes(crate::script::issuer_script(&state));
        let builder = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("leaf");
        let info = builder
            .finalize(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                crate::script::nums_internal_key(),
            )
            .expect("spend info");
        info.control_block(&(script, LeafVersion::TapScript))
            .expect("control")
            .serialize()
    };
    let tx = crate::verify::build_mint_tx(
        OutPoint::null(),
        &issuer_utxo,
        &state,
        &mw,
        item_value,
        succ.as_ref(),
        control,
    )
    .expect("mint tx");
    tx_vbytes(&tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::tests::sample_terms;

    #[test]
    fn model_a_is_smaller_than_model_b_at_issuance() {
        let mut terms = sample_terms();
        terms.total_supply = 8;
        terms.lane_count = 4;
        let cmp = compare(&terms, Amount::from_sat(1_000_000), Amount::from_sat(1_000));
        assert_eq!(cmp.model_a.lanes, 1);
        assert_eq!(cmp.model_b.lanes, 4);
        assert!(cmp.model_a.issuance_tx_vbytes < cmp.model_b.issuance_tx_vbytes);
        // Model B should offer more concurrency.
        assert!(cmp.model_b.concurrent_chains > cmp.model_a.concurrent_chains);
        // Mint tx sizes are comparable (same script shape).
        assert!(cmp.model_a.mint_tx_vbytes > 0);
        assert!(cmp.model_b.mint_tx_vbytes > 0);
        assert_eq!(cmp.chosen_model, "A");
    }

    #[test]
    fn expected_attempts_grows_with_prefix() {
        assert_eq!(expected_attempts(0), 1);
        assert_eq!(expected_attempts(1), 256);
        assert_eq!(expected_attempts(2), 65_536);
        assert_eq!(expected_attempts(3), 16_777_216);
    }
}
