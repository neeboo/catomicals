//! Wallet-owned review of unsigned Taproot key-spend transactions.

use std::{collections::HashSet, str::FromStr};

use bitcoin::{
    Address, Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut,
    consensus::encode::{deserialize, serialize_hex},
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionPrevout {
    pub outpoint: String,
    pub value_sat: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionReviewRequest {
    pub raw_tx_hex: String,
    pub prevouts: Vec<TransactionPrevout>,
    pub input_index: usize,
    pub max_fee_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedInput {
    pub index: usize,
    pub outpoint: String,
    pub value_sat: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    pub address: Option<String>,
    pub sequence: u32,
    pub signals_rbf: bool,
    pub signing_input: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedOutput {
    pub index: usize,
    pub value_sat: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    pub address: Option<String>,
    pub dust: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionWarning {
    pub code: String,
    pub message: String,
    pub input_index: Option<usize>,
    pub output_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReview {
    pub network: String,
    pub txid: String,
    pub wtxid: String,
    pub raw_tx_hex: String,
    pub version: i32,
    pub lock_time: u32,
    pub total_size: usize,
    pub weight_wu: u64,
    pub vsize: usize,
    pub input_count: usize,
    pub output_count: usize,
    pub input_total_sat: u64,
    pub output_total_sat: u64,
    pub fee_sat: u64,
    pub fee_rate_milli_sat_vb: u64,
    pub max_fee_sat: u64,
    pub signals_rbf: bool,
    pub input_index: usize,
    pub sighash_type: String,
    pub sighash_hex: String,
    pub inputs: Vec<ReviewedInput>,
    pub outputs: Vec<ReviewedOutput>,
    pub warnings: Vec<TransactionWarning>,
    pub signing_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionReviewError {
    #[error("raw transaction must be canonical hexadecimal Bitcoin encoding")]
    InvalidRawTransaction,
    #[error("transaction has no inputs")]
    EmptyInputs,
    #[error("transaction has no outputs")]
    EmptyOutputs,
    #[error("coinbase transactions cannot be reviewed for wallet signing")]
    Coinbase,
    #[error("transaction already contains scriptSig or witness data")]
    TransactionAlreadySigned,
    #[error("one ordered prevout is required for every transaction input")]
    PrevoutCountMismatch,
    #[error("prevout at input {input_index} does not match the transaction outpoint")]
    PrevoutMismatch { input_index: usize },
    #[error("transaction spends the same outpoint more than once")]
    DuplicateInput,
    #[error("prevout {input_index} has an invalid outpoint or script")]
    InvalidPrevout { input_index: usize },
    #[error("signing input index is out of range")]
    InputIndexOutOfRange,
    #[error("selected signing input is not a Taproot output")]
    SigningInputNotTaproot,
    #[error("transaction amount arithmetic overflowed")]
    AmountOverflow,
    #[error("transaction outputs exceed the supplied input values")]
    OutputsExceedInputs,
    #[error("transaction fee {fee_sat} sat exceeds the declared maximum {max_fee_sat} sat")]
    FeeExceedsLimit { fee_sat: u64, max_fee_sat: u64 },
    #[error("unable to derive the BIP341 key-spend signature hash")]
    TaprootSighash,
}

fn script_type(script: &Script) -> &'static str {
    if script.is_p2tr() {
        "p2tr"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_op_return() {
        "op_return"
    } else if script.is_witness_program() {
        "witness_unknown"
    } else {
        "unknown"
    }
}

fn address(script: &Script) -> Option<String> {
    Address::from_script(script, Network::Signet)
        .ok()
        .map(|address| address.to_string())
}

fn checked_total(values: impl IntoIterator<Item = u64>) -> Result<u64, TransactionReviewError> {
    values
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(TransactionReviewError::AmountOverflow)
}

pub fn inspect_transaction(
    request: &TransactionReviewRequest,
) -> Result<TransactionReview, TransactionReviewError> {
    let raw = hex::decode(&request.raw_tx_hex)
        .map_err(|_| TransactionReviewError::InvalidRawTransaction)?;
    let tx: Transaction =
        deserialize(&raw).map_err(|_| TransactionReviewError::InvalidRawTransaction)?;
    if serialize_hex(&tx) != request.raw_tx_hex.to_ascii_lowercase() {
        return Err(TransactionReviewError::InvalidRawTransaction);
    }
    if tx.input.is_empty() {
        return Err(TransactionReviewError::EmptyInputs);
    }
    if tx.output.is_empty() {
        return Err(TransactionReviewError::EmptyOutputs);
    }
    if tx.is_coinbase() {
        return Err(TransactionReviewError::Coinbase);
    }
    if tx
        .input
        .iter()
        .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
    {
        return Err(TransactionReviewError::TransactionAlreadySigned);
    }
    if request.prevouts.len() != tx.input.len() {
        return Err(TransactionReviewError::PrevoutCountMismatch);
    }
    if request.input_index >= tx.input.len() {
        return Err(TransactionReviewError::InputIndexOutOfRange);
    }

    let mut seen = HashSet::with_capacity(tx.input.len());
    let mut prevout_txouts = Vec::with_capacity(tx.input.len());
    let mut inputs = Vec::with_capacity(tx.input.len());
    for (index, (input, supplied)) in tx.input.iter().zip(&request.prevouts).enumerate() {
        if !seen.insert(input.previous_output) {
            return Err(TransactionReviewError::DuplicateInput);
        }
        let outpoint = OutPoint::from_str(&supplied.outpoint)
            .map_err(|_| TransactionReviewError::InvalidPrevout { input_index: index })?;
        if outpoint != input.previous_output {
            return Err(TransactionReviewError::PrevoutMismatch { input_index: index });
        }
        let script_bytes = hex::decode(&supplied.script_pubkey_hex)
            .map_err(|_| TransactionReviewError::InvalidPrevout { input_index: index })?;
        let script_pubkey = ScriptBuf::from_bytes(script_bytes);
        let txout = TxOut {
            value: Amount::from_sat(supplied.value_sat),
            script_pubkey: script_pubkey.clone(),
        };
        inputs.push(ReviewedInput {
            index,
            outpoint: outpoint.to_string(),
            value_sat: supplied.value_sat,
            script_pubkey_hex: hex::encode(script_pubkey.as_bytes()),
            script_type: script_type(&script_pubkey).into(),
            address: address(&script_pubkey),
            sequence: input.sequence.to_consensus_u32(),
            signals_rbf: input.sequence.is_rbf(),
            signing_input: index == request.input_index,
        });
        prevout_txouts.push(txout);
    }

    if !prevout_txouts[request.input_index].script_pubkey.is_p2tr() {
        return Err(TransactionReviewError::SigningInputNotTaproot);
    }

    let input_total_sat = checked_total(request.prevouts.iter().map(|prevout| prevout.value_sat))?;
    let output_total_sat = checked_total(tx.output.iter().map(|output| output.value.to_sat()))?;
    let fee_sat = input_total_sat
        .checked_sub(output_total_sat)
        .ok_or(TransactionReviewError::OutputsExceedInputs)?;
    if fee_sat > request.max_fee_sat {
        return Err(TransactionReviewError::FeeExceedsLimit {
            fee_sat,
            max_fee_sat: request.max_fee_sat,
        });
    }

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            request.input_index,
            &Prevouts::All(&prevout_txouts),
            TapSighashType::Default,
        )
        .map_err(|_| TransactionReviewError::TaprootSighash)?;

    let mut warnings = Vec::new();
    if tx.version != bitcoin::transaction::Version::TWO {
        warnings.push(TransactionWarning {
            code: "non_v2_transaction".into(),
            message: "Transaction version is not 2.".into(),
            input_index: None,
            output_index: None,
        });
    }
    if tx.lock_time.to_consensus_u32() != 0 {
        warnings.push(TransactionWarning {
            code: "absolute_lock_time".into(),
            message: "Transaction has a non-zero absolute lock time.".into(),
            input_index: None,
            output_index: None,
        });
    }
    let signals_rbf = tx.input.iter().any(|input| input.sequence.is_rbf());
    if signals_rbf {
        warnings.push(TransactionWarning {
            code: "replaceable".into(),
            message: "At least one input signals opt-in transaction replacement.".into(),
            input_index: None,
            output_index: None,
        });
    }

    let outputs: Vec<_> = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let kind = script_type(&output.script_pubkey);
            let dust = !output.script_pubkey.is_op_return()
                && output.value < output.script_pubkey.minimal_non_dust();
            if output.script_pubkey.is_op_return() {
                warnings.push(TransactionWarning {
                    code: "op_return".into(),
                    message: "Output carries provably unspendable OP_RETURN data.".into(),
                    input_index: None,
                    output_index: Some(index),
                });
            } else if kind == "unknown" || kind == "witness_unknown" {
                warnings.push(TransactionWarning {
                    code: "unknown_output_script".into(),
                    message: "Output script is not a recognized standard address type.".into(),
                    input_index: None,
                    output_index: Some(index),
                });
            }
            if dust {
                warnings.push(TransactionWarning {
                    code: "dust_output".into(),
                    message: "Output is below the default dust threshold for its script.".into(),
                    input_index: None,
                    output_index: Some(index),
                });
            }
            ReviewedOutput {
                index,
                value_sat: output.value.to_sat(),
                script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                script_type: kind.into(),
                address: address(&output.script_pubkey),
                dust,
            }
        })
        .collect();

    let vsize = tx.vsize();
    let fee_rate_milli_sat_vb = if vsize == 0 {
        0
    } else {
        fee_sat
            .checked_mul(1_000)
            .ok_or(TransactionReviewError::AmountOverflow)?
            / u64::try_from(vsize).map_err(|_| TransactionReviewError::AmountOverflow)?
    };
    if fee_rate_milli_sat_vb > 100_000 {
        warnings.push(TransactionWarning {
            code: "high_fee_rate".into(),
            message: "Fee rate exceeds 100 sat/vB.".into(),
            input_index: None,
            output_index: None,
        });
    }

    Ok(TransactionReview {
        network: "signet".into(),
        txid: tx.compute_txid().to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        raw_tx_hex: serialize_hex(&tx),
        version: tx.version.0,
        lock_time: tx.lock_time.to_consensus_u32(),
        total_size: tx.total_size(),
        weight_wu: tx.weight().to_wu(),
        vsize,
        input_count: tx.input.len(),
        output_count: tx.output.len(),
        input_total_sat,
        output_total_sat,
        fee_sat,
        fee_rate_milli_sat_vb,
        max_fee_sat: request.max_fee_sat,
        signals_rbf,
        input_index: request.input_index,
        sighash_type: "default".into(),
        sighash_hex: hex::encode(sighash.to_byte_array()),
        inputs,
        outputs,
        warnings,
        signing_allowed: true,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, absolute,
        consensus::encode::serialize_hex,
        hashes::Hash,
        secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
        transaction,
    };

    use super::{
        TransactionPrevout, TransactionReviewError, TransactionReviewRequest, inspect_transaction,
    };

    fn p2tr_script(secret: u8) -> ScriptBuf {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        Address::p2tr(&secp, xonly, None, Network::Signet).script_pubkey()
    }

    fn outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([tag; 32]), vout)
    }

    fn sample() -> (Transaction, TransactionReviewRequest) {
        let spent = outpoint(1, 0);
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: p2tr_script(2),
            }],
        };
        let request = TransactionReviewRequest {
            raw_tx_hex: serialize_hex(&tx),
            prevouts: vec![TransactionPrevout {
                outpoint: spent.to_string(),
                value_sat: 100_000,
                script_pubkey_hex: hex::encode(p2tr_script(1).as_bytes()),
            }],
            input_index: 0,
            max_fee_sat: 10_000,
        };
        (tx, request)
    }

    #[test]
    fn valid_review_derives_totals_outputs_and_bip341_digest() {
        let (_, request) = sample();
        let review = inspect_transaction(&request).unwrap();

        assert_eq!(review.network, "signet");
        assert_eq!(review.input_total_sat, 100_000);
        assert_eq!(review.output_total_sat, 90_000);
        assert_eq!(review.fee_sat, 10_000);
        assert_eq!(review.input_count, 1);
        assert_eq!(review.output_count, 1);
        assert!(review.signals_rbf);
        assert!(review.signing_allowed);
        assert_eq!(review.sighash_hex.len(), 64);
        assert_eq!(review.outputs[0].script_type, "p2tr");
        assert!(
            review.outputs[0]
                .address
                .as_deref()
                .unwrap()
                .starts_with("tb1p")
        );
    }

    #[test]
    fn reordered_or_wrong_prevout_is_rejected() {
        let (_, mut request) = sample();
        request.prevouts[0].outpoint = outpoint(9, 1).to_string();
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::PrevoutMismatch { input_index: 0 }
        );
    }

    #[test]
    fn duplicate_inputs_are_rejected() {
        let (mut tx, mut request) = sample();
        tx.input.push(tx.input[0].clone());
        request.prevouts.push(request.prevouts[0].clone());
        request.raw_tx_hex = serialize_hex(&tx);
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::DuplicateInput
        );
    }

    #[test]
    fn witness_bearing_transaction_is_rejected() {
        let (mut tx, mut request) = sample();
        tx.input[0].witness.push([1_u8; 64]);
        request.raw_tx_hex = serialize_hex(&tx);
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::TransactionAlreadySigned
        );
    }

    #[test]
    fn outputs_above_inputs_are_rejected() {
        let (mut tx, mut request) = sample();
        tx.output[0].value = Amount::from_sat(100_001);
        request.raw_tx_hex = serialize_hex(&tx);
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::OutputsExceedInputs
        );
    }

    #[test]
    fn fee_ceiling_is_enforced() {
        let (_, mut request) = sample();
        request.max_fee_sat = 9_999;
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::FeeExceedsLimit {
                fee_sat: 10_000,
                max_fee_sat: 9_999,
            }
        );
    }

    #[test]
    fn signing_input_must_exist() {
        let (_, mut request) = sample();
        request.input_index = 1;
        assert_eq!(
            inspect_transaction(&request).unwrap_err(),
            TransactionReviewError::InputIndexOutOfRange
        );
    }
}
