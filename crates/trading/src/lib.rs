//! Signet-only protected fixed-price trading for issuance-scoped item receipts.
//!
//! The Taproot leaves commit the listing and require the seller signature. The
//! signature uses `SIGHASH_DEFAULT`, which commits all inputs and outputs. The
//! available OP_CAT opcode does not inspect outputs; payout, fee, recipient,
//! and item classification are independently enforced by agent and wallet
//! policy before signing.

use std::collections::BTreeMap;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LISTING_TAG: &[u8] = b"catomicals/fixed-price-listing/v1\0";
const BUYER_TAG: &[u8] = b"catomicals/buyer-ownership/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Signet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemReceipt {
    pub network: Network,
    pub outpoint: OutPoint,
    pub script_pubkey: ScriptBuf,
    pub item_sat_amount: u64,
    pub terms_hash: [u8; 32],
    pub item_id: [u8; 32],
    pub item_commitment: [u8; 32],
    pub lane: u8,
    pub sequence: u32,
}

impl ItemReceipt {
    /// Scope a trading receipt from an issuance transaction that has already
    /// passed `catomicals_issuance::verify::verify_mint`.
    pub fn from_verified_mint(
        mint_tx: &Transaction,
        verified: &catomicals_issuance::verify::VerifiedMint,
        terms: &catomicals_issuance::terms::IssuanceTerms,
    ) -> Result<Self, TradeError> {
        if verified.issuer_state.terms_hash != terms.terms_hash()
            || verified.item_output_index >= mint_tx.output.len()
            || mint_tx.output[verified.item_output_index] != verified.item_output
        {
            return Err(TradeError::InvalidReceipt);
        }
        Ok(Self {
            network: Network::Signet,
            outpoint: OutPoint::new(
                mint_tx.compute_txid(),
                u32::try_from(verified.item_output_index)
                    .map_err(|_| TradeError::InvalidReceipt)?,
            ),
            script_pubkey: verified.item_output.script_pubkey.clone(),
            item_sat_amount: verified.item_output.value.to_sat(),
            terms_hash: verified.issuer_state.terms_hash,
            item_id: terms.item_id,
            item_commitment: verified.witness.item_commitment,
            lane: verified.issuer_state.lane,
            sequence: verified.issuer_state.seq,
        })
    }

    pub fn txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.item_sat_amount),
            script_pubkey: self.script_pubkey.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingTerms {
    pub protocol_version: u16,
    pub network: Network,
    pub receipt: ItemReceipt,
    pub seller_key: bitcoin::XOnlyPublicKey,
    pub seller_payout_script: ScriptBuf,
    pub price_sat: u64,
    pub creator_fee_script: ScriptBuf,
    pub creator_fee_sat: u64,
    pub cancel_script: ScriptBuf,
    pub expiry_height: u32,
    pub max_network_fee_sat: u64,
}

impl ListingTerms {
    pub fn validate(&self) -> Result<(), TradeError> {
        if self.protocol_version != 1 {
            return Err(TradeError::UnsupportedVersion);
        }
        if self.network != Network::Signet || self.receipt.network != Network::Signet {
            return Err(TradeError::WrongNetwork);
        }
        if self.receipt.item_sat_amount == 0 || self.price_sat == 0 || self.creator_fee_sat == 0 {
            return Err(TradeError::InvalidAmount);
        }
        if self.expiry_height == 0
            || self.expiry_height >= bitcoin::absolute::LOCK_TIME_THRESHOLD
            || self.max_network_fee_sat == 0
        {
            return Err(TradeError::InvalidRule);
        }
        if self.seller_payout_script.is_empty()
            || self.creator_fee_script.is_empty()
            || self.cancel_script.is_empty()
            || self.seller_payout_script == self.creator_fee_script
        {
            return Err(TradeError::InvalidScript);
        }
        if self.receipt.script_pubkey
            != catomicals_issuance::verify::item_owner_script(self.seller_key)
        {
            return Err(TradeError::ReceiptOwnerMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TradeError> {
        self.validate()?;
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(LISTING_TAG);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(b"signet\0");
        out.extend_from_slice(self.receipt.outpoint.txid.as_byte_array());
        out.extend_from_slice(&self.receipt.outpoint.vout.to_be_bytes());
        push_len_prefixed(&mut out, self.receipt.script_pubkey.as_bytes());
        out.extend_from_slice(&self.receipt.item_sat_amount.to_be_bytes());
        out.extend_from_slice(&self.receipt.terms_hash);
        out.extend_from_slice(&self.receipt.item_id);
        out.extend_from_slice(&self.receipt.item_commitment);
        out.push(self.receipt.lane);
        out.extend_from_slice(&self.receipt.sequence.to_be_bytes());
        out.extend_from_slice(&self.seller_key.serialize());
        push_len_prefixed(&mut out, self.seller_payout_script.as_bytes());
        out.extend_from_slice(&self.price_sat.to_be_bytes());
        push_len_prefixed(&mut out, self.creator_fee_script.as_bytes());
        out.extend_from_slice(&self.creator_fee_sat.to_be_bytes());
        push_len_prefixed(&mut out, self.cancel_script.as_bytes());
        out.extend_from_slice(&self.expiry_height.to_be_bytes());
        out.extend_from_slice(&self.max_network_fee_sat.to_be_bytes());
        Ok(out)
    }

    pub fn commitment(&self) -> Result<[u8; 32], TradeError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn order_txout(&self) -> Result<TxOut, TradeError> {
        Ok(TxOut {
            value: Amount::from_sat(self.receipt.item_sat_amount),
            script_pubkey: listing_output_script(self)?,
        })
    }
}

/// Complete deterministic outputs for one concrete fixed-price order.
///
/// This is deliberately scoped to an exact [`ListingTerms`] instance. It is
/// not a generic market template and does not add any Taproot construction
/// separate from the protocol functions below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingArtifacts {
    pub canonical_bytes: Vec<u8>,
    pub commitment: [u8; 32],
    pub buy_leaf: ScriptBuf,
    pub cancel_leaf: ScriptBuf,
    pub listing_output: ScriptBuf,
    pub order_txout: TxOut,
}

impl ListingArtifacts {
    pub fn new(listing: &ListingTerms) -> Result<Self, TradeError> {
        listing.validate()?;
        Ok(Self {
            canonical_bytes: listing.canonical_bytes()?,
            commitment: listing.commitment()?,
            buy_leaf: buy_leaf_script(listing)?,
            cancel_leaf: cancel_leaf_script(listing)?,
            listing_output: listing_output_script(listing)?,
            order_txout: listing.order_txout()?,
        })
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRequest {
    pub listing: ListingTerms,
    pub issuance_proof: IssuanceProof,
    pub raw_tx_hex: String,
    pub prevouts: Vec<TxOut>,
}

/// Complete executable mint provenance for the scoped item receipt. A trusted
/// Signet index still establishes confirmation; receipt metadata alone is
/// never sufficient for policy acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceProof {
    pub raw_mint_tx_hex: String,
    pub issuer_outpoint: OutPoint,
    pub issuer_utxo: TxOut,
    pub terms: catomicals_issuance::terms::IssuanceTerms,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyRequest {
    pub listing: ListingTerms,
    pub list_request: Box<ListRequest>,
    pub order_outpoint: OutPoint,
    pub buyer_key: bitcoin::XOnlyPublicKey,
    pub proposal_expiry_height: u32,
    pub raw_tx_hex: String,
    pub prevouts: Vec<TxOut>,
    #[serde(with = "hex_array64")]
    pub buyer_ownership_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelRequest {
    pub listing: ListingTerms,
    pub list_request: Box<ListRequest>,
    pub order_outpoint: OutPoint,
    pub raw_tx_hex: String,
    pub prevouts: Vec<TxOut>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "path", content = "request", rename_all = "snake_case")]
pub enum TradeSigningRequest {
    List(ListRequest),
    Buy(BuyRequest),
    Cancel(CancelRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradePath {
    List,
    Buy,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrade {
    pub path: TradePath,
    pub txid: Txid,
    pub sighash: [u8; 32],
    pub input_index: usize,
    pub spent_order_outpoint: OutPoint,
    pub fee_sat: u64,
    pub listing_commitment: [u8; 32],
    pub transaction: Transaction,
    pub prevouts: Vec<TxOut>,
    pub seller_key: bitcoin::XOnlyPublicKey,
    witness_script: Option<ScriptBuf>,
    control_block: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TradeError {
    #[error("unsupported trading protocol version")]
    UnsupportedVersion,
    #[error("only Signet is supported")]
    WrongNetwork,
    #[error("invalid zero amount")]
    InvalidAmount,
    #[error("invalid listing rule")]
    InvalidRule,
    #[error("invalid or ambiguous output script")]
    InvalidScript,
    #[error("receipt is not controlled by the committed seller key")]
    ReceiptOwnerMismatch,
    #[error("item receipt does not match its issuance-verified mint")]
    InvalidReceipt,
    #[error("order outpoint does not derive from the canonical listing transaction")]
    InvalidListingLineage,
    #[error("raw transaction is not canonical transaction hex")]
    InvalidRawTransaction,
    #[error("pre-approval transaction must have empty scriptSig and witness data")]
    PartiallySigned,
    #[error("transaction version or locktime is invalid for this path")]
    InvalidTransactionHeader,
    #[error("transaction inputs do not match the protected path")]
    InvalidInputs,
    #[error("ordered previous outputs are incomplete or do not match")]
    InvalidPrevouts,
    #[error("transaction outputs do not exactly match protected policy")]
    InvalidOutputs,
    #[error("transaction fee must be positive and at most the committed maximum")]
    InvalidFee,
    #[error("listing or buyer proposal has expired")]
    Expired,
    #[error("cancel path is not active until the committed expiry height")]
    CancelNotMature,
    #[error("buyer ownership proof is invalid")]
    InvalidBuyerProof,
    #[error("taproot construction or sighash failed")]
    Taproot,
    #[error("final transaction differs from the approved transaction")]
    FinalTransactionMismatch,
    #[error("seller signature is invalid")]
    InvalidSellerSignature,
    #[error("candidate does not spend this listing outpoint")]
    WrongCompetitionOutpoint,
    #[error("candidate is unknown or already resolved")]
    InvalidCandidateState,
}

fn push32(bytes: [u8; 32]) -> Result<PushBytesBuf, TradeError> {
    PushBytesBuf::try_from(bytes.to_vec()).map_err(|_| TradeError::Taproot)
}

pub fn buy_leaf_script(listing: &ListingTerms) -> Result<ScriptBuf, TradeError> {
    Ok(Builder::new()
        .push_slice(push32(listing.commitment()?)?)
        .push_opcode(OP_DROP)
        .push_x_only_key(&listing.seller_key)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

pub fn cancel_leaf_script(listing: &ListingTerms) -> Result<ScriptBuf, TradeError> {
    Ok(Builder::new()
        .push_int(i64::from(listing.expiry_height))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_slice(push32(listing.commitment()?)?)
        .push_opcode(OP_DROP)
        .push_x_only_key(&listing.seller_key)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

fn spend_info(listing: &ListingTerms) -> Result<TaprootSpendInfo, TradeError> {
    listing.validate()?;
    TaprootBuilder::new()
        .add_leaf(1, buy_leaf_script(listing)?)
        .map_err(|_| TradeError::Taproot)?
        .add_leaf(1, cancel_leaf_script(listing)?)
        .map_err(|_| TradeError::Taproot)?
        .finalize(
            &Secp256k1::verification_only(),
            catomicals_issuance::script::nums_internal_key(),
        )
        .map_err(|_| TradeError::Taproot)
}

pub fn listing_output_script(listing: &ListingTerms) -> Result<ScriptBuf, TradeError> {
    Ok(ScriptBuf::new_p2tr_tweaked(
        spend_info(listing)?.output_key(),
    ))
}

pub fn buyer_ownership_message(request: &BuyRequest) -> Result<[u8; 32], TradeError> {
    let tx = decode_unsigned(&request.raw_tx_hex)?;
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(BUYER_TAG);
    bytes.extend_from_slice(&request.listing.commitment()?);
    bytes.extend_from_slice(request.order_outpoint.txid.as_byte_array());
    bytes.extend_from_slice(&request.order_outpoint.vout.to_be_bytes());
    bytes.extend_from_slice(tx.compute_txid().as_byte_array());
    bytes.extend_from_slice(&request.buyer_key.serialize());
    bytes.extend_from_slice(&request.proposal_expiry_height.to_be_bytes());
    bytes.extend_from_slice(&(request.prevouts.len() as u64).to_be_bytes());
    for prevout in &request.prevouts {
        let encoded = serialize(prevout);
        push_len_prefixed(&mut bytes, &encoded);
    }
    Ok(Sha256::digest(bytes).into())
}

fn verify_buyer(request: &BuyRequest) -> Result<(), TradeError> {
    let signature = schnorr::Signature::from_slice(&request.buyer_ownership_signature)
        .map_err(|_| TradeError::InvalidBuyerProof)?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(buyer_ownership_message(request)?),
            &request.buyer_key,
        )
        .map_err(|_| TradeError::InvalidBuyerProof)
}

fn decode_unsigned(raw_hex: &str) -> Result<Transaction, TradeError> {
    let bytes = hex::decode(raw_hex).map_err(|_| TradeError::InvalidRawTransaction)?;
    let tx: Transaction = deserialize(&bytes).map_err(|_| TradeError::InvalidRawTransaction)?;
    if serialize(&tx) != bytes {
        return Err(TradeError::InvalidRawTransaction);
    }
    if tx
        .input
        .iter()
        .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
    {
        return Err(TradeError::PartiallySigned);
    }
    Ok(tx)
}

fn decode_transaction(raw_hex: &str) -> Result<Transaction, TradeError> {
    let bytes = hex::decode(raw_hex).map_err(|_| TradeError::InvalidRawTransaction)?;
    let tx: Transaction = deserialize(&bytes).map_err(|_| TradeError::InvalidRawTransaction)?;
    if serialize(&tx) != bytes {
        return Err(TradeError::InvalidRawTransaction);
    }
    Ok(tx)
}

fn verify_issuance_receipt(request: &ListRequest) -> Result<(), TradeError> {
    let mint_tx = decode_transaction(&request.issuance_proof.raw_mint_tx_hex)?;
    let verified = catomicals_issuance::verify::verify_mint(
        &mint_tx,
        request.issuance_proof.issuer_outpoint,
        &request.issuance_proof.issuer_utxo,
        &request.issuance_proof.terms,
    )
    .map_err(|_| TradeError::InvalidReceipt)?;
    let receipt =
        ItemReceipt::from_verified_mint(&mint_tx, &verified, &request.issuance_proof.terms)?;
    if receipt != request.listing.receipt {
        return Err(TradeError::InvalidReceipt);
    }
    Ok(())
}

fn common_inputs(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), TradeError> {
    if tx.input.len() < 2 || tx.input.len() != prevouts.len() {
        return Err(TradeError::InvalidPrevouts);
    }
    let mut inputs = std::collections::BTreeSet::new();
    if tx
        .input
        .iter()
        .any(|input| !inputs.insert(input.previous_output))
    {
        return Err(TradeError::InvalidInputs);
    }
    Ok(())
}

fn fee(tx: &Transaction, prevouts: &[TxOut], max: u64) -> Result<u64, TradeError> {
    let inputs = prevouts
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
    let outputs = tx
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
    let fee = inputs
        .and_then(|inputs| outputs.and_then(|outputs| inputs.checked_sub(outputs)))
        .ok_or(TradeError::InvalidFee)?;
    if fee == 0 || fee > max {
        return Err(TradeError::InvalidFee);
    }
    Ok(fee)
}

fn valid_header(tx: &Transaction, zero_locktime: bool) -> bool {
    tx.version == bitcoin::transaction::Version::TWO
        && (!zero_locktime || tx.lock_time == bitcoin::absolute::LockTime::ZERO)
}

fn item_script(key: bitcoin::XOnlyPublicKey) -> ScriptBuf {
    catomicals_issuance::verify::item_owner_script(key)
}

fn list_outputs(tx: &Transaction, listing: &ListingTerms) -> bool {
    if tx.output.len() != 2 {
        return false;
    }
    tx.output[0] == listing.order_txout().unwrap_or(TxOut::NULL)
        && tx.output[1].script_pubkey == listing.cancel_script
}

fn buy_outputs(tx: &Transaction, listing: &ListingTerms, buyer: bitcoin::XOnlyPublicKey) -> bool {
    if !(tx.output.len() == 3 || tx.output.len() == 4) {
        return false;
    }
    tx.output[0]
        == (TxOut {
            value: Amount::from_sat(listing.receipt.item_sat_amount),
            script_pubkey: item_script(buyer),
        })
        && tx.output[1]
            == (TxOut {
                value: Amount::from_sat(listing.price_sat),
                script_pubkey: listing.seller_payout_script.clone(),
            })
        && tx.output[2]
            == (TxOut {
                value: Amount::from_sat(listing.creator_fee_sat),
                script_pubkey: listing.creator_fee_script.clone(),
            })
        && (tx.output.len() == 3 || tx.output[3].script_pubkey == item_script(buyer))
}

fn cancel_outputs(tx: &Transaction, listing: &ListingTerms) -> bool {
    if !(tx.output.len() == 1 || tx.output.len() == 2) {
        return false;
    }
    tx.output[0]
        == (TxOut {
            value: Amount::from_sat(listing.receipt.item_sat_amount),
            script_pubkey: listing.cancel_script.clone(),
        })
        && (tx.output.len() == 1 || tx.output[1].script_pubkey == listing.cancel_script)
}

fn sighash(
    tx: &Transaction,
    prevouts: &[TxOut],
    leaf: Option<&ScriptBuf>,
) -> Result<[u8; 32], TradeError> {
    let mut cache = SighashCache::new(tx);
    let prevouts = Prevouts::All(prevouts);
    let hash = match leaf {
        Some(script) => cache.taproot_script_spend_signature_hash(
            0,
            &prevouts,
            bitcoin::TapLeafHash::from_script(script, LeafVersion::TapScript),
            TapSighashType::Default,
        ),
        None => cache.taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default),
    }
    .map_err(|_| TradeError::Taproot)?;
    Ok(hash.to_byte_array())
}

fn verified(
    path: TradePath,
    listing: &ListingTerms,
    tx: Transaction,
    prevouts: Vec<TxOut>,
    spent: OutPoint,
    fee_sat: u64,
) -> Result<VerifiedTrade, TradeError> {
    let script = match path {
        TradePath::List => None,
        TradePath::Buy => Some(buy_leaf_script(listing)?),
        TradePath::Cancel => Some(cancel_leaf_script(listing)?),
    };
    let control_block = if let Some(script) = &script {
        Some(
            spend_info(listing)?
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .ok_or(TradeError::Taproot)?
                .serialize(),
        )
    } else {
        None
    };
    Ok(VerifiedTrade {
        path,
        txid: tx.compute_txid(),
        sighash: sighash(&tx, &prevouts, script.as_ref())?,
        input_index: 0,
        spent_order_outpoint: spent,
        fee_sat,
        listing_commitment: listing.commitment()?,
        transaction: tx,
        prevouts,
        seller_key: listing.seller_key,
        witness_script: script,
        control_block,
    })
}

/// Agent-facing verifier. This implementation performs its own raw policy
/// classification and never accepts a wallet verdict as input.
pub struct AgentTradingApi;

impl AgentTradingApi {
    pub fn verify(request: &TradeSigningRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        match request {
            TradeSigningRequest::List(request) => Self::verify_list(request, height),
            TradeSigningRequest::Buy(request) => Self::verify_buy(request, height),
            TradeSigningRequest::Cancel(request) => Self::verify_cancel(request, height),
        }
    }

    pub fn verify_list(request: &ListRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        request.listing.validate()?;
        verify_issuance_receipt(request)?;
        if height >= request.listing.expiry_height {
            return Err(TradeError::Expired);
        }
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        common_inputs(&tx, &request.prevouts)?;
        if !valid_header(&tx, true) {
            return Err(TradeError::InvalidTransactionHeader);
        }
        if tx.input[0].previous_output != request.listing.receipt.outpoint {
            return Err(TradeError::InvalidInputs);
        }
        if request.prevouts[0] != request.listing.receipt.txout() {
            return Err(TradeError::InvalidPrevouts);
        }
        if !list_outputs(&tx, &request.listing) {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, request.listing.max_network_fee_sat)?;
        verified(
            TradePath::List,
            &request.listing,
            tx,
            request.prevouts.clone(),
            request.listing.receipt.outpoint,
            fee_sat,
        )
    }

    pub fn verify_buy(request: &BuyRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        request.listing.validate()?;
        if request.list_request.listing != request.listing {
            return Err(TradeError::InvalidListingLineage);
        }
        let listed = Self::verify_list(&request.list_request, height)?;
        let canonical_order = OutPoint::new(listed.txid, 0);
        if request.order_outpoint != canonical_order {
            return Err(TradeError::InvalidListingLineage);
        }
        if height >= request.listing.expiry_height
            || height > request.proposal_expiry_height
            || request.proposal_expiry_height > request.listing.expiry_height
        {
            return Err(TradeError::Expired);
        }
        verify_buyer(request)?;
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        common_inputs(&tx, &request.prevouts)?;
        if !valid_header(&tx, true) {
            return Err(TradeError::InvalidTransactionHeader);
        }
        if tx.input[0].previous_output != request.order_outpoint {
            return Err(TradeError::InvalidInputs);
        }
        if request.prevouts[0] != request.listing.order_txout()? {
            return Err(TradeError::InvalidPrevouts);
        }
        if !buy_outputs(&tx, &request.listing, request.buyer_key) {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, request.listing.max_network_fee_sat)?;
        verified(
            TradePath::Buy,
            &request.listing,
            tx,
            request.prevouts.clone(),
            request.order_outpoint,
            fee_sat,
        )
    }

    pub fn verify_cancel(
        request: &CancelRequest,
        height: u32,
    ) -> Result<VerifiedTrade, TradeError> {
        request.listing.validate()?;
        if request.list_request.listing != request.listing {
            return Err(TradeError::InvalidListingLineage);
        }
        let listed = Self::verify_list(
            &request.list_request,
            request.listing.expiry_height.saturating_sub(1),
        )?;
        let canonical_order = OutPoint::new(listed.txid, 0);
        if request.order_outpoint != canonical_order {
            return Err(TradeError::InvalidListingLineage);
        }
        if height < request.listing.expiry_height {
            return Err(TradeError::CancelNotMature);
        }
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        common_inputs(&tx, &request.prevouts)?;
        if tx.version != bitcoin::transaction::Version::TWO
            || tx.lock_time.to_consensus_u32() < request.listing.expiry_height
            || tx.input.iter().any(|input| input.sequence.is_final())
        {
            return Err(TradeError::InvalidTransactionHeader);
        }
        if tx.input[0].previous_output != request.order_outpoint {
            return Err(TradeError::InvalidInputs);
        }
        if request.prevouts[0] != request.listing.order_txout()? {
            return Err(TradeError::InvalidPrevouts);
        }
        if !cancel_outputs(&tx, &request.listing) {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, request.listing.max_network_fee_sat)?;
        verified(
            TradePath::Cancel,
            &request.listing,
            tx,
            request.prevouts.clone(),
            request.order_outpoint,
            fee_sat,
        )
    }
}

/// Wallet-facing verifier. It repeats transaction decoding and all material
/// checks instead of trusting or consuming an agent-produced verdict.
pub struct WalletTradingApi;

impl WalletTradingApi {
    pub fn verify_list(request: &ListRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        let listing = &request.listing;
        listing.validate()?;
        verify_issuance_receipt(request)?;
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        if height >= listing.expiry_height
            || !valid_header(&tx, true)
            || tx.input.len() < 2
            || tx.input.len() != request.prevouts.len()
            || tx.input[0].previous_output != listing.receipt.outpoint
            || request.prevouts.first() != Some(&listing.receipt.txout())
        {
            return Err(TradeError::InvalidInputs);
        }
        common_inputs(&tx, &request.prevouts)?;
        let expected_order = listing.order_txout()?;
        if tx.output.len() != 2
            || tx.output.first() != Some(&expected_order)
            || tx.output[1].script_pubkey != listing.cancel_script
        {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, listing.max_network_fee_sat)?;
        verified(
            TradePath::List,
            listing,
            tx,
            request.prevouts.clone(),
            listing.receipt.outpoint,
            fee_sat,
        )
    }

    pub fn verify_buy(request: &BuyRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        let listing = &request.listing;
        listing.validate()?;
        if request.list_request.listing != *listing {
            return Err(TradeError::InvalidListingLineage);
        }
        let listed = Self::verify_list(&request.list_request, height)?;
        let canonical_order = OutPoint::new(listed.txid, 0);
        if request.order_outpoint != canonical_order {
            return Err(TradeError::InvalidListingLineage);
        }
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        if height >= listing.expiry_height
            || height > request.proposal_expiry_height
            || request.proposal_expiry_height > listing.expiry_height
        {
            return Err(TradeError::Expired);
        }
        verify_buyer(request)?;
        if !valid_header(&tx, true)
            || tx.input.len() < 2
            || tx.input.len() != request.prevouts.len()
            || tx.input[0].previous_output != request.order_outpoint
            || request.prevouts.first() != Some(&listing.order_txout()?)
        {
            return Err(TradeError::InvalidInputs);
        }
        common_inputs(&tx, &request.prevouts)?;
        let buyer_script = item_script(request.buyer_key);
        let exact = tx.output.len() == 3 || tx.output.len() == 4;
        if !exact
            || tx.output[0].value.to_sat() != listing.receipt.item_sat_amount
            || tx.output[0].script_pubkey != buyer_script
            || tx.output[1].value.to_sat() != listing.price_sat
            || tx.output[1].script_pubkey != listing.seller_payout_script
            || tx.output[2].value.to_sat() != listing.creator_fee_sat
            || tx.output[2].script_pubkey != listing.creator_fee_script
            || (tx.output.len() == 4 && tx.output[3].script_pubkey != buyer_script)
        {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, listing.max_network_fee_sat)?;
        verified(
            TradePath::Buy,
            listing,
            tx,
            request.prevouts.clone(),
            request.order_outpoint,
            fee_sat,
        )
    }

    pub fn verify_cancel(
        request: &CancelRequest,
        height: u32,
    ) -> Result<VerifiedTrade, TradeError> {
        let listing = &request.listing;
        listing.validate()?;
        if request.list_request.listing != *listing {
            return Err(TradeError::InvalidListingLineage);
        }
        let listed = Self::verify_list(
            &request.list_request,
            listing.expiry_height.saturating_sub(1),
        )?;
        let canonical_order = OutPoint::new(listed.txid, 0);
        if request.order_outpoint != canonical_order {
            return Err(TradeError::InvalidListingLineage);
        }
        let tx = decode_unsigned(&request.raw_tx_hex)?;
        if height < listing.expiry_height {
            return Err(TradeError::CancelNotMature);
        }
        if tx.version != bitcoin::transaction::Version::TWO
            || tx.lock_time.to_consensus_u32() < listing.expiry_height
            || tx.input.iter().any(|input| input.sequence.is_final())
            || tx.input.len() < 2
            || tx.input.len() != request.prevouts.len()
            || tx.input[0].previous_output != request.order_outpoint
            || request.prevouts.first() != Some(&listing.order_txout()?)
        {
            return Err(TradeError::InvalidInputs);
        }
        common_inputs(&tx, &request.prevouts)?;
        if tx.output.is_empty()
            || tx.output.len() > 2
            || tx.output[0].value.to_sat() != listing.receipt.item_sat_amount
            || tx.output[0].script_pubkey != listing.cancel_script
            || (tx.output.len() == 2 && tx.output[1].script_pubkey != listing.cancel_script)
        {
            return Err(TradeError::InvalidOutputs);
        }
        let fee_sat = fee(&tx, &request.prevouts, listing.max_network_fee_sat)?;
        verified(
            TradePath::Cancel,
            listing,
            tx,
            request.prevouts.clone(),
            request.order_outpoint,
            fee_sat,
        )
    }

    pub fn verify(request: &TradeSigningRequest, height: u32) -> Result<VerifiedTrade, TradeError> {
        match request {
            TradeSigningRequest::List(request) => Self::verify_list(request, height),
            TradeSigningRequest::Buy(request) => Self::verify_buy(request, height),
            TradeSigningRequest::Cancel(request) => Self::verify_cancel(request, height),
        }
    }
}

pub fn apply_trade_signature(
    verified: &VerifiedTrade,
    signature: [u8; 64],
) -> Result<Transaction, TradeError> {
    let mut tx = verified.transaction.clone();
    let witness = &mut tx.input[verified.input_index].witness;
    *witness = Witness::new();
    witness.push(signature);
    if let Some(script) = &verified.witness_script {
        witness.push(script.as_bytes());
        witness.push(verified.control_block.as_ref().ok_or(TradeError::Taproot)?);
    }
    Ok(tx)
}

pub fn verify_finalized(
    finalized: &Transaction,
    verified: &VerifiedTrade,
) -> Result<(), TradeError> {
    if finalized.compute_txid() != verified.txid
        || finalized.input.len() != verified.transaction.input.len()
    {
        return Err(TradeError::FinalTransactionMismatch);
    }
    let witness = &finalized.input[verified.input_index].witness;
    let expected_len = if verified.path == TradePath::List {
        1
    } else {
        3
    };
    if witness.len() != expected_len {
        return Err(TradeError::FinalTransactionMismatch);
    }
    let elements = witness.to_vec();
    if verified.path != TradePath::List
        && (elements[1] != verified.witness_script.as_ref().unwrap().as_bytes()
            || elements[2] != *verified.control_block.as_ref().unwrap())
    {
        return Err(TradeError::FinalTransactionMismatch);
    }
    let signature = schnorr::Signature::from_slice(&elements[0])
        .map_err(|_| TradeError::InvalidSellerSignature)?;
    let leaf = verified.witness_script.as_ref();
    let actual_sighash = sighash(finalized, &verified.prevouts, leaf)?;
    if actual_sighash != verified.sighash {
        return Err(TradeError::FinalTransactionMismatch);
    }
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(actual_sighash),
            &verified.seller_key,
        )
        .map_err(|_| TradeError::InvalidSellerSignature)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Buy,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Submitted,
    Pending,
    Confirmed { height: u32 },
    Conflicted { winner: Txid },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSnapshot {
    pub txid: Txid,
    pub kind: CandidateKind,
    pub status: CandidateStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompetitionSnapshot {
    pub outpoint: OutPoint,
    pub ordering: String,
    pub miner_ordering_fairness: bool,
    pub candidates: Vec<CandidateSnapshot>,
}

#[derive(Debug, Clone)]
pub struct CompetitionTracker {
    outpoint: OutPoint,
    candidates: BTreeMap<Txid, (CandidateKind, CandidateStatus)>,
}

impl CompetitionTracker {
    pub fn new(outpoint: OutPoint) -> Self {
        Self {
            outpoint,
            candidates: BTreeMap::new(),
        }
    }

    pub fn submit(&mut self, txid: Txid, kind: CandidateKind) -> Result<(), TradeError> {
        if self.candidates.contains_key(&txid) {
            return Err(TradeError::InvalidCandidateState);
        }
        let status = self
            .candidates
            .iter()
            .find_map(|(candidate_txid, (_, status))| {
                matches!(status, CandidateStatus::Confirmed { .. }).then_some(*candidate_txid)
            })
            .map_or(CandidateStatus::Submitted, |winner| {
                CandidateStatus::Conflicted { winner }
            });
        self.candidates.insert(txid, (kind, status));
        Ok(())
    }

    pub fn submit_verified(&mut self, candidate: &VerifiedTrade) -> Result<(), TradeError> {
        if candidate.spent_order_outpoint != self.outpoint {
            return Err(TradeError::WrongCompetitionOutpoint);
        }
        let kind = match candidate.path {
            TradePath::Buy => CandidateKind::Buy,
            TradePath::Cancel => CandidateKind::Cancel,
            TradePath::List => return Err(TradeError::InvalidCandidateState),
        };
        self.submit(candidate.txid, kind)
    }

    pub fn mark_pending(&mut self, txid: Txid) -> Result<(), TradeError> {
        let (_, status) = self
            .candidates
            .get_mut(&txid)
            .ok_or(TradeError::InvalidCandidateState)?;
        if *status != CandidateStatus::Submitted {
            return Err(TradeError::InvalidCandidateState);
        }
        *status = CandidateStatus::Pending;
        Ok(())
    }

    pub fn confirm(&mut self, winner: Txid, height: u32) -> Result<(), TradeError> {
        match self.candidates.get(&winner) {
            Some((_, CandidateStatus::Submitted | CandidateStatus::Pending)) => {}
            _ => return Err(TradeError::InvalidCandidateState),
        }
        for (txid, (_, status)) in &mut self.candidates {
            *status = if *txid == winner {
                CandidateStatus::Confirmed { height }
            } else {
                CandidateStatus::Conflicted { winner }
            };
        }
        Ok(())
    }

    pub fn status(&self, txid: Txid) -> Option<&CandidateStatus> {
        self.candidates.get(&txid).map(|(_, status)| status)
    }

    pub fn snapshot(&self) -> CompetitionSnapshot {
        CompetitionSnapshot {
            outpoint: self.outpoint,
            ordering: "one_outpoint_bitcoin_confirmation_order".into(),
            miner_ordering_fairness: false,
            candidates: self
                .candidates
                .iter()
                .map(|(txid, (kind, status))| CandidateSnapshot {
                    txid: *txid,
                    kind: *kind,
                    status: status.clone(),
                })
                .collect(),
        }
    }
}

mod hex_array64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte hex signature"))
    }
}
