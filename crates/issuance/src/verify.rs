//! Wallet-side mint verification.
//!
//! Consensus (the issuer tapscript) enforces the PoW gate and rejects a state
//! whose committed `remaining` field is zero. This module applies the wider
//! wallet policy to the whole mint transaction: it
//! checks the owner-controlled item output, the successor issuer output, the supply/seq
//! bookkeeping, value conservation, and rejects replay, duplicate slot use,
//! altered creator terms, altered item identity, altered target, altered supply
//! and altered successor rules.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::pow::{hash_tail, meets_target, pow_hash};
use crate::script::{issuer_script, parse_issuer_script};
use crate::state::{IssuerState, StateError};
use crate::terms::{IssuanceTerms, item_commitment};

/// Parsed witness of a mint tapscript spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintWitness {
    pub nonce: u64,
    pub item_commitment: [u8; 32],
    pub hash_tail: Vec<u8>,
    /// Output key controlled by the recipient of the minted item.
    pub owner_key: bitcoin::XOnlyPublicKey,
    pub payload: Vec<u8>,
}

/// A fully verified mint, with the outputs classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMint {
    pub issuer_input_index: usize,
    pub issuer_state: IssuerState,
    pub witness: MintWitness,
    pub item_output_index: usize,
    pub item_output: TxOut,
    /// Present unless the mint exhausted the lane supply.
    pub successor_output_index: Option<usize>,
    pub successor_state: Option<IssuerState>,
    pub fee: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MintVerifyError {
    #[error("transaction spends no input from the issuer UTXO {0}")]
    NoIssuerInput(OutPoint),
    #[error("issuer input {0} is not a valid tapscript spend of the issuer output")]
    InvalidIssuerSpend(usize),
    #[error("issuer script in the spent output is not canonical: {0}")]
    MalformedIssuerScript(usize),
    #[error("state does not match the committed terms: {0}")]
    TermsMismatch(&'static str),
    #[error("issuer state is exhausted (remaining = 0)")]
    SupplyExhausted,
    #[error("witness must contain nonce, item_commitment, hash_tail, owner_key and payload")]
    MalformedWitness,
    #[error("owner key is not a valid secp256k1 x-only public key")]
    InvalidOwnerKey,
    #[error("nonce does not satisfy the committed PoW challenge")]
    PowNotSatisfied,
    #[error("hash_tail does not match the PoW digest")]
    HashTailMismatch,
    #[error("item_commitment does not match the revealed payload")]
    ItemCommitmentMismatch,
    #[error("expected exactly one owner-controlled item output, found {0}")]
    ItemOutputCount(usize),
    #[error("item output {0} is not controlled by the committed owner")]
    ItemOutputCommitment(usize),
    #[error("expected exactly one successor issuer output, found {0}")]
    SuccessorOutputCount(usize),
    #[error("successor output {0} does not carry the canonical next issuer state")]
    SuccessorOutputMismatch(usize),
    #[error("successor output present but supply is exhausted")]
    UnexpectedSuccessor,
    #[error("value conservation violated: inputs {inputs} < outputs {outputs}")]
    ValueNotConserved { inputs: u64, outputs: u64 },
    #[error("fee is negative or zero: {0}")]
    NonPositiveFee(u64),
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("output count {0} is not supported (expected item + optional successor)")]
    OutputCount(usize),
}

/// The item output is a spendable key-path P2TR controlled by `owner_key`.
pub fn item_owner_script(owner_key: bitcoin::XOnlyPublicKey) -> ScriptBuf {
    p2tr_output_script(owner_key)
}

/// The canonical P2TR output script for an issuer state.
pub fn canonical_issuer_spk(state: &IssuerState) -> ScriptBuf {
    p2tr_output_script(crate::script::issuer_output_key(state))
}

/// Build a key-path-only P2TR output script (`OP_1 <32B output key>`) directly
/// from an output key. This is exact: the 32 bytes ARE the output key.
pub fn p2tr_output_script(output_key: bitcoin::XOnlyPublicKey) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x51); // OP_1
    bytes.push(0x20); // push 32
    bytes.extend_from_slice(&output_key.serialize());
    ScriptBuf::from_bytes(bytes)
}

/// Extract the 32-byte output key from a key-path-only P2TR script
/// (`OP_1 <32B>`).
pub fn taproot_output_key(spk: &ScriptBuf) -> Option<bitcoin::XOnlyPublicKey> {
    let bytes = spk.to_bytes();
    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
        bitcoin::XOnlyPublicKey::from_slice(&bytes[2..34]).ok()
    } else {
        None
    }
}

/// Parse the five argument elements of a mint tapscript spend.
pub fn parse_mint_witness(stack: &[Vec<u8>]) -> Result<MintWitness, MintVerifyError> {
    if stack.len() != 5 {
        return Err(MintVerifyError::MalformedWitness);
    }
    let nonce = u64::from_le_bytes(
        stack[0]
            .as_slice()
            .try_into()
            .map_err(|_| MintVerifyError::MalformedWitness)?,
    );
    let item_commitment: [u8; 32] = stack[1]
        .as_slice()
        .try_into()
        .map_err(|_| MintVerifyError::MalformedWitness)?;
    let hash_tail = stack[2].clone();
    let owner_key = bitcoin::XOnlyPublicKey::from_slice(&stack[3])
        .map_err(|_| MintVerifyError::InvalidOwnerKey)?;
    let payload = stack[4].clone();
    Ok(MintWitness {
        nonce,
        item_commitment,
        hash_tail,
        owner_key,
        payload,
    })
}

/// Verify a mint transaction against the issuer UTXO being spent and the
/// committed terms.
///
/// `issuer_utxo` is the UTXO (scriptPubKey + value) that the mint spends;
/// `issuer_outpoint` is its outpoint in the transaction's input.
pub fn verify_mint(
    tx: &Transaction,
    issuer_outpoint: OutPoint,
    issuer_utxo: &TxOut,
    terms: &IssuanceTerms,
) -> Result<VerifiedMint, MintVerifyError> {
    // 1. Exactly one input spends the issuer UTXO.
    let issuer_input_index = tx
        .input
        .iter()
        .position(|i| i.previous_output == issuer_outpoint)
        .ok_or(MintVerifyError::NoIssuerInput(issuer_outpoint))?;

    // 2. The tapscript witness reveals [nonce, item_commitment, hash_tail,
    //    owner_key, payload, issuer_script, control_block]. Recover the committed state
    //    from the revealed script and bind it to the spent output's taproot
    //    commitment and to the canonical issuer output for that state.
    let witness_stack = tx.input[issuer_input_index].witness.to_vec();
    if witness_stack.len() != 7 {
        return Err(MintVerifyError::MalformedWitness);
    }
    let script_idx = witness_stack.len() - 2;
    let control_idx = witness_stack.len() - 1;
    let state = parse_issuer_script(&witness_stack[script_idx])
        .ok_or(MintVerifyError::MalformedIssuerScript(issuer_input_index))?;

    // The revealed script must be the canonical issuer script for that state.
    if witness_stack[script_idx] != issuer_script(&state) {
        return Err(MintVerifyError::InvalidIssuerSpend(issuer_input_index));
    }
    // The spent output must be the canonical P2TR issuer output for the state.
    let canonical_spk = canonical_issuer_spk(&state);
    if issuer_utxo.script_pubkey != canonical_spk {
        return Err(MintVerifyError::MalformedIssuerScript(issuer_input_index));
    }
    // The control block must prove the revealed script is committed in the
    // spent output's taproot tree.
    let output_key = taproot_output_key(&issuer_utxo.script_pubkey)
        .ok_or(MintVerifyError::InvalidIssuerSpend(issuer_input_index))?;
    let control = bitcoin::taproot::ControlBlock::decode(&witness_stack[control_idx])
        .map_err(|_| MintVerifyError::InvalidIssuerSpend(issuer_input_index))?;
    let revealed = bitcoin::ScriptBuf::from_bytes(witness_stack[script_idx].clone());
    if !control.verify_taproot_commitment(
        &bitcoin::secp256k1::Secp256k1::verification_only(),
        output_key,
        &revealed,
    ) {
        return Err(MintVerifyError::InvalidIssuerSpend(issuer_input_index));
    }

    // 3. State must match the committed terms exactly.
    check_terms(&state, terms)?;

    // 4. Parse the mint witness (the four argument elements).
    let mw = parse_mint_witness(&witness_stack[..script_idx])?;

    // 5. PoW: recompute the digest and check target + tail.
    let digest = pow_hash(
        &state.terms_hash,
        state.lane,
        state.seq,
        &mw.item_commitment,
        mw.nonce,
    );
    if !meets_target(&digest, state.target_prefix) {
        return Err(MintVerifyError::PowNotSatisfied);
    }
    if mw.hash_tail != hash_tail(&digest, state.target_prefix) {
        return Err(MintVerifyError::HashTailMismatch);
    }

    // 6. Item identity: the commitment must match the revealed payload.
    if item_commitment(
        &state.terms_hash,
        state.lane,
        state.seq,
        &mw.owner_key.serialize(),
        &mw.payload,
    ) != mw.item_commitment
    {
        return Err(MintVerifyError::ItemCommitmentMismatch);
    }

    // 7. Wallet-policy output classification: [owner item, (successor)] exactly.
    let item_script = item_owner_script(mw.owner_key);
    let item_indices: Vec<usize> = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == item_script)
        .map(|(i, _)| i)
        .collect();
    if item_indices.len() != 1 {
        return Err(MintVerifyError::ItemOutputCount(item_indices.len()));
    }
    let item_output_index = item_indices[0];

    // 8. Successor output (unless supply is exhausted).
    let successor_state = state.successor()?;
    let successor_output_index = match successor_state {
        Some(next) => {
            let next_script = canonical_issuer_spk(&next);
            let idxs: Vec<usize> = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| o.script_pubkey == next_script)
                .map(|(i, _)| i)
                .collect();
            if idxs.len() != 1 {
                return Err(MintVerifyError::SuccessorOutputCount(idxs.len()));
            }
            Some(idxs[0])
        }
        None => None,
    };
    if successor_state.is_none() && successor_output_index.is_some() {
        return Err(MintVerifyError::UnexpectedSuccessor);
    }

    // 9. Output count: exactly item + optional successor.
    let expected_outputs = if successor_state.is_some() { 2 } else { 1 };
    if tx.output.len() != expected_outputs {
        return Err(MintVerifyError::OutputCount(tx.output.len()));
    }

    // 10. Value conservation: inputs == item + successor + fee, fee > 0.
    let inputs = issuer_utxo.value.to_sat();
    let outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    if outputs > inputs {
        return Err(MintVerifyError::ValueNotConserved { inputs, outputs });
    }
    let fee = inputs - outputs;
    if fee == 0 {
        return Err(MintVerifyError::NonPositiveFee(fee));
    }

    Ok(VerifiedMint {
        issuer_input_index,
        issuer_state: state,
        witness: mw,
        item_output_index,
        item_output: tx.output[item_output_index].clone(),
        successor_output_index,
        successor_state,
        fee: Amount::from_sat(fee),
    })
}

/// Every field of the committed state must match the committed terms.
fn check_terms(state: &IssuerState, terms: &IssuanceTerms) -> Result<(), MintVerifyError> {
    if state.terms_hash != terms.terms_hash() {
        return Err(MintVerifyError::TermsMismatch("terms_hash"));
    }
    if state.target_prefix != terms.target_prefix {
        return Err(MintVerifyError::TermsMismatch("target_prefix"));
    }
    if state.lane >= terms.materialized_lanes() {
        return Err(MintVerifyError::TermsMismatch("lane"));
    }
    if state.remaining == 0 {
        return Err(MintVerifyError::SupplyExhausted);
    }
    Ok(())
}

/// Build the canonical mint transaction that the verifier accepts: one input
/// spending the issuer UTXO with the given witness, one owner-controlled item output
/// and (unless the supply is exhausted) one successor issuer output.
///
/// Used by the regtest demonstration and by model measurement.
pub fn build_mint_tx(
    issuer_outpoint: OutPoint,
    issuer_utxo: &TxOut,
    state: &IssuerState,
    witness: &MintWitness,
    item_value: Amount,
    successor_utxo: Option<&TxOut>,
    control_block: Vec<u8>,
) -> Result<Transaction, MintVerifyError> {
    let stack = vec![
        witness.nonce.to_le_bytes().to_vec(),
        witness.item_commitment.to_vec(),
        witness.hash_tail.clone(),
        witness.owner_key.serialize().to_vec(),
        witness.payload.clone(),
        issuer_script(state),
        control_block,
    ];
    let mut witness_obj = Witness::new();
    for item in stack {
        witness_obj.push(item);
    }

    let mut outputs = vec![TxOut {
        value: item_value,
        script_pubkey: item_owner_script(witness.owner_key),
    }];
    if let Some(succ) = successor_utxo {
        outputs.push(succ.clone());
    }

    let total_out: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    let input_value = issuer_utxo.value.to_sat();
    if total_out > input_value {
        return Err(MintVerifyError::ValueNotConserved {
            inputs: input_value,
            outputs: total_out,
        });
    }

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: issuer_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: witness_obj,
        }],
        output: outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::find_nonce;
    use crate::script::nums_internal_key;
    use crate::state::IssuerState;
    use crate::terms::item_commitment;
    use crate::terms::tests::sample_terms;
    use bitcoin::hashes::Hash;

    fn test_owner_key() -> bitcoin::XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn alternate_owner_key() -> bitcoin::XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[4; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn replace_witness(tx: &mut Transaction, stack: &[Vec<u8>]) {
        let mut witness = Witness::new();
        for item in stack {
            witness.push(item);
        }
        tx.input[0].witness = witness;
    }

    /// A helper that builds a fully valid mint transaction for a state.
    fn make_mint(
        state: &IssuerState,
        payload: &[u8],
    ) -> (Transaction, OutPoint, TxOut, MintWitness) {
        let owner_key = test_owner_key();
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
        let mw = MintWitness {
            nonce,
            item_commitment: ic,
            hash_tail: hash_tail(&digest, state.target_prefix),
            owner_key,
            payload: payload.to_vec(),
        };
        let issuer_utxo = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: canonical_issuer_spk(state),
        };
        // Control block: single-leaf tree, empty merkle path.
        let control = control_block_for(state);
        let succ_utxo = state.successor().unwrap().map(|next| TxOut {
            value: Amount::from_sat(96_000),
            script_pubkey: canonical_issuer_spk(&next),
        });
        let tx = build_mint_tx(
            OutPoint::new(bitcoin::Txid::from_byte_array([0x11; 32]), 0),
            &issuer_utxo,
            state,
            &mw,
            Amount::from_sat(1_000),
            succ_utxo.as_ref(),
            control,
        )
        .unwrap();
        (
            tx,
            OutPoint::new(bitcoin::Txid::from_byte_array([0x11; 32]), 0),
            issuer_utxo,
            mw,
        )
    }

    fn control_block_for(state: &IssuerState) -> Vec<u8> {
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::taproot::TaprootBuilder;
        let internal = nums_internal_key();
        let script = ScriptBuf::from_bytes(issuer_script(state));
        let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
        let spend_info = builder
            .finalize(&Secp256k1::verification_only(), internal)
            .unwrap();
        spend_info
            .control_block(&(script, bitcoin::taproot::LeafVersion::TapScript))
            .unwrap()
            .serialize()
    }

    fn valid_mint() -> (Transaction, OutPoint, TxOut, MintWitness, IssuanceTerms) {
        let terms = sample_terms();
        let state = IssuerState::initial(&terms, 0).unwrap();
        let (tx, op, utxo, mw) = make_mint(&state, b"hello world");
        (tx, op, utxo, mw, terms)
    }

    #[test]
    fn accepts_a_valid_mint() {
        let (tx, op, utxo, _, terms) = valid_mint();
        let v = verify_mint(&tx, op, &utxo, &terms).unwrap();
        assert_eq!(v.issuer_state.seq, 0);
        assert_eq!(v.item_output_index, 0);
        assert_eq!(
            taproot_output_key(&v.item_output.script_pubkey),
            Some(test_owner_key())
        );
        assert_eq!(v.successor_output_index, Some(1));
        assert_eq!(v.successor_state.unwrap().seq, 1);
        assert!(v.fee.to_sat() > 0);
    }

    #[test]
    fn rejects_wrong_nonce() {
        let (mut tx, op, utxo, mw, terms) = valid_mint();
        // Mutate the witness nonce to an invalid value.
        let stack = tx.input[0].witness.to_vec();
        let mut stack = stack;
        let mut nonce = u64::from_le_bytes(stack[0].as_slice().try_into().unwrap());
        // Find a nonce that does NOT satisfy the target.
        loop {
            nonce += 1;
            let digest = pow_hash(&terms.terms_hash(), 0, 0, &mw.item_commitment, nonce);
            if !meets_target(&digest, terms.target_prefix) {
                break;
            }
        }
        stack[0] = nonce.to_le_bytes().to_vec();
        let mut witness = Witness::new();
        for item in &stack {
            witness.push(item);
        }
        tx.input[0].witness = witness;
        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::PowNotSatisfied)
        );
    }

    #[test]
    fn rejects_wrong_hash_tail() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        let mut stack = tx.input[0].witness.to_vec();
        stack[2].push(0);
        let mut witness = Witness::new();
        for item in &stack {
            witness.push(item);
        }
        tx.input[0].witness = witness;
        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::HashTailMismatch)
        );
    }

    #[test]
    fn rejects_an_invalid_owner_xonly_key_without_panicking() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        let mut stack = tx.input[0].witness.to_vec();
        stack[3] = vec![0xff; 32];
        replace_witness(&mut tx, &stack);

        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::InvalidOwnerKey)
        );
    }

    #[test]
    fn rejects_an_item_output_not_controlled_by_the_committed_owner() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        tx.output[0].script_pubkey = item_owner_script(alternate_owner_key());

        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::ItemOutputCount(0))
        );
    }

    #[test]
    fn rejects_a_control_block_not_committed_by_the_spent_p2tr_output() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        let mut stack = tx.input[0].witness.to_vec();
        let control_index = stack.len() - 1;
        stack[control_index][1] ^= 1;
        replace_witness(&mut tx, &stack);

        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::InvalidIssuerSpend(0))
        );
    }

    #[test]
    fn rejects_altered_item_payload() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        let mut stack = tx.input[0].witness.to_vec();
        stack[4] = b"tampered".to_vec();
        replace_witness(&mut tx, &stack);
        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::ItemCommitmentMismatch)
        );
    }

    #[test]
    fn rejects_missing_item_output() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        // Remove the item output.
        tx.output.remove(0);
        assert!(matches!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::ItemOutputCount(_)) | Err(MintVerifyError::OutputCount(_))
        ));
    }

    #[test]
    fn rejects_altered_successor_output() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        // Tamper with the successor output scriptPubKey.
        let idx = tx.output.len() - 1;
        tx.output[idx].script_pubkey = p2tr_output_script(nums_internal_key());
        assert!(matches!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::SuccessorOutputCount(_))
        ));
    }

    #[test]
    fn rejects_value_not_conserved() {
        let (mut tx, op, utxo, _, terms) = valid_mint();
        // Increase an output value so outputs exceed inputs.
        tx.output[0].value = Amount::from_sat(200_000);
        assert_eq!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::ValueNotConserved {
                inputs: 100_000,
                outputs: 200_000 + tx.output[1].value.to_sat()
            })
        );
    }

    #[test]
    fn rejects_terms_mismatch() {
        let (tx, op, utxo, _, _) = valid_mint();
        let mut terms = sample_terms();
        terms.target_prefix = 2; // altered creator term
        assert!(matches!(
            verify_mint(&tx, op, &utxo, &terms),
            Err(MintVerifyError::TermsMismatch(_))
        ));
    }

    #[test]
    fn rejects_spending_a_non_issuer_utxo() {
        let terms = sample_terms();
        let bogus_utxo = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_hex(
                "5120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
        };
        let state = IssuerState::initial(&terms, 0).unwrap();
        let (tx, op, _, _) = make_mint(&state, b"p");
        assert!(matches!(
            verify_mint(&tx, op, &bogus_utxo, &terms),
            Err(MintVerifyError::MalformedIssuerScript(_))
        ));
    }

    #[test]
    fn accepts_last_mint_without_successor() {
        let terms = sample_terms();
        let mut state = IssuerState::initial(&terms, 0).unwrap();
        // Fast-forward to the last slot.
        state = IssuerState {
            seq: 3,
            remaining: 1,
            ..state
        };
        let (tx, op, utxo, _) = make_mint(&state, b"last");
        let v = verify_mint(&tx, op, &utxo, &terms).unwrap();
        assert_eq!(v.successor_output_index, None);
        assert_eq!(v.successor_state, None);
        assert_eq!(tx.output.len(), 1);
    }

    #[test]
    fn rejects_replay_of_the_same_mint_against_a_spent_issuer() {
        // Replay is a double spend: the verifier looks at the issuer UTXO the
        // input claims to spend. A second identical transaction spending the
        // same outpoint is rejected by consensus (the UTXO no longer exists);
        // at the verification layer, spending the same outpoint with a stale
        // state is caught because the *live* issuer UTXO differs.
        let (tx, op, utxo, _, terms) = valid_mint();
        let v1 = verify_mint(&tx, op, &utxo, &terms).unwrap();
        // The successor is now the live issuer; replaying v1's input against it
        // must fail (state mismatch: successor seq is 1, not 0).
        let successor_utxo = TxOut {
            value: v1.item_output.value,
            script_pubkey: tx.output[1].script_pubkey.clone(),
        };
        assert!(matches!(
            verify_mint(&tx, op, &successor_utxo, &terms),
            Err(MintVerifyError::MalformedIssuerScript(_))
        ));
    }
}
