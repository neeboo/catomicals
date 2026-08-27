use bitcoin::{BlockHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};

pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Chain inclusion status of a record in the current canonical view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationStatus {
    Confirmed,
}

/// Strength of the local claim represented by an indexed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationKind {
    /// Parsed from a block without applying covenant policy.
    DiscoveryOnly,
    /// Accepted by the named wallet-policy verifier. This is not a consensus claim.
    WalletPolicyVerified,
}

/// Pointer into the raw block retained by [`BlockRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvidenceRef {
    pub block_hash: BlockHash,
    pub tx_index: u32,
}

/// Reproducible derivation lineage attached to each query-facing record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub txid: Txid,
    pub tx_index: u32,
    pub input_index: Option<u32>,
    pub output_index: Option<u32>,
    pub raw_evidence: RawEvidenceRef,
    pub verifier_version: String,
    pub confirmation: ConfirmationStatus,
    pub observation: ObservationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tip {
    pub hash: BlockHash,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    pub hash: BlockHash,
    pub height: u32,
    pub previous_hash: BlockHash,
    pub transaction_count: u32,
    /// Consensus-encoded block bytes used by every `RawEvidenceRef`.
    pub raw_block: Vec<u8>,
    pub confirmation: ConfirmationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub txid: Txid,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoRecord {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceTransitionRecord {
    pub terms_hash: [u8; 32],
    pub lane: u8,
    pub sequence: u32,
    pub remaining_before: u32,
    pub issuer_outpoint: OutPoint,
    pub item_outpoint: OutPoint,
    pub successor_outpoint: Option<OutPoint>,
    pub item_commitment: [u8; 32],
    pub owner_key: [u8; 32],
    pub fee_sat: u64,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointManifest {
    pub label: String,
    pub schema_version: u32,
    pub tip: Tip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyStats {
    pub transactions: u32,
    pub created_outputs: u32,
    pub spent_outputs: u32,
    pub issuance_transitions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UndoRecord {
    pub block_hash: BlockHash,
    pub height: u32,
    pub previous_tip: Option<Tip>,
    pub created_txids: Vec<Txid>,
    pub created_outpoints: Vec<OutPoint>,
    pub restored_utxos: Vec<UtxoRecord>,
    pub created_transitions: Vec<(Txid, u32)>,
}
