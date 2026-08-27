//! Indexer: discovers issuer-leaf reveals and P2TR output candidates.
//!
//! The indexer never decides validity — it reports what a transaction *looks
//! like* at the structural level:
//!
//! * issuer spends are recognized because a tapscript-path spend reveals the
//!   issuer tapscript in its witness, from which the committed state is parsed;
//! * only after such a reveal, P2TR outputs (`OP_1 <32B>`) are reported as
//!   unclassified candidates. A reveal is not proof that the spent output
//!   committed to the leaf, and a candidate is not automatically an item.
//!
//! Validity is decided by consensus (the issuer tapscript) and by wallet
//! verification (`crate::verify::verify_mint`).

use bitcoin::{OutPoint, Transaction, TxOut};

use crate::script::parse_issuer_script;
use crate::state::IssuerState;

/// A discovered issuer spend: the input outpoint plus the state committed in
/// the revealed issuer tapscript.
#[derive(Debug, Clone)]
pub struct DiscoveredIssuerSpend {
    pub outpoint: OutPoint,
    pub input_index: usize,
    pub state: IssuerState,
}

/// An unclassified P2TR output in a transaction that reveals an issuer leaf.
#[derive(Debug, Clone)]
pub struct DiscoveredP2trCandidate {
    pub output_index: usize,
    pub value: u64,
    /// The 32-byte output key of the P2TR output.
    pub output_key: [u8; 32],
}

/// Structural discovery for one transaction.
#[derive(Debug, Clone)]
pub struct TxDiscovery {
    pub txid: bitcoin::Txid,
    pub consumed_issuers: Vec<DiscoveredIssuerSpend>,
    pub p2tr_candidates: Vec<DiscoveredP2trCandidate>,
}

/// Read the 32-byte output key of a key-path-only P2TR output (`OP_1 <32B>`).
pub fn p2tr_output_key_bytes(output: &TxOut) -> Option<[u8; 32]> {
    let bytes = output.script_pubkey.to_bytes();
    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
        bytes[2..34].try_into().ok()
    } else {
        None
    }
}

/// Scan one transaction and report issuer-leaf reveals and P2TR candidates.
/// Discovery only: no validity decisions are made here.
pub fn discover(tx: &Transaction) -> TxDiscovery {
    let mut d = TxDiscovery {
        txid: tx.compute_txid(),
        consumed_issuers: Vec::new(),
        p2tr_candidates: Vec::new(),
    };
    for (input_index, input) in tx.input.iter().enumerate() {
        let stack = input.witness.to_vec();
        if stack.len() < 2 {
            continue;
        }
        let script = &stack[stack.len() - 2];
        if let Some(state) = parse_issuer_script(script) {
            d.consumed_issuers.push(DiscoveredIssuerSpend {
                outpoint: input.previous_output,
                input_index,
                state,
            });
        }
    }
    if !d.consumed_issuers.is_empty() {
        for (output_index, output) in tx.output.iter().enumerate() {
            if let Some(key) = p2tr_output_key_bytes(output) {
                d.p2tr_candidates.push(DiscoveredP2trCandidate {
                    output_index,
                    value: output.value.to_sat(),
                    output_key: key,
                });
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{find_nonce, hash_tail, pow_hash};
    use crate::state::IssuerState;
    use crate::terms::{item_commitment, tests::sample_terms};
    use crate::verify::{MintWitness, build_mint_tx, canonical_issuer_spk};
    use bitcoin::hashes::Hash;

    fn owner_key() -> bitcoin::XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        bitcoin::XOnlyPublicKey::from_keypair(&keypair).0
    }

    fn control_block(state: &IssuerState) -> Vec<u8> {
        use crate::script::issuer_output_key;
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};
        #[allow(unused_imports)]
        let _ = issuer_output_key;
        use bitcoin::ScriptBuf;
        use bitcoin::secp256k1::Secp256k1;
        let script = ScriptBuf::from_bytes(crate::script::issuer_script(state));
        let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
        let info = builder
            .finalize(
                &Secp256k1::verification_only(),
                crate::script::nums_internal_key(),
            )
            .unwrap();
        info.control_block(&(script, LeafVersion::TapScript))
            .unwrap()
            .serialize()
    }

    #[test]
    fn discovers_issuer_reveal_and_p2tr_candidates_without_deciding_validity() {
        let terms = sample_terms();
        let state = IssuerState::initial(&terms, 0).unwrap();
        let owner_key = owner_key();
        let ic = item_commitment(&state.terms_hash, 0, 0, &owner_key.serialize(), b"payload");
        let nonce = find_nonce(&state.terms_hash, 0, 0, &ic, 1, 0).unwrap();
        let digest = pow_hash(&state.terms_hash, 0, 0, &ic, nonce);
        let mw = MintWitness {
            nonce,
            item_commitment: ic,
            hash_tail: hash_tail(&digest, 1),
            owner_key,
            payload: b"payload".to_vec(),
        };
        let issuer_utxo = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: canonical_issuer_spk(&state),
        };
        let succ = state.successor().unwrap().map(|next| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(96_000),
            script_pubkey: canonical_issuer_spk(&next),
        });
        let tx = build_mint_tx(
            bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([0x01; 32]), 0),
            &issuer_utxo,
            &state,
            &mw,
            bitcoin::Amount::from_sat(1_000),
            succ.as_ref(),
            control_block(&state),
        )
        .unwrap();
        let d = discover(&tx);
        // The mint spends one issuer (state recovered from the witness).
        assert_eq!(d.consumed_issuers.len(), 1);
        assert_eq!(d.consumed_issuers[0].state, state);
        // Two structurally identical P2TR candidates: owner item + successor.
        // The indexer reports both; the wallet verifier classifies them.
        assert_eq!(d.p2tr_candidates.len(), 2);
        assert_eq!(d.p2tr_candidates[0].output_index, 0);
        assert_eq!(d.p2tr_candidates[0].output_key, owner_key.serialize());
        assert_eq!(d.p2tr_candidates[1].output_index, 1);
    }

    #[test]
    fn non_mint_transaction_has_no_issuer_spends() {
        let unrelated_p2tr = crate::verify::item_owner_script(owner_key());
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: unrelated_p2tr,
            }],
        };
        let d = discover(&tx);
        assert!(d.consumed_issuers.is_empty());
        assert!(d.p2tr_candidates.is_empty());
    }
}
