use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use bincode::config;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, OutPoint, TxOut, Txid};
use catomicals_issuance::indexer::discover;
use catomicals_issuance::terms::IssuanceTerms;
use catomicals_issuance::verify::verify_mint;
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, DBRecoveryMode, Options,
    SliceTransform, WriteBatch, WriteOptions,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::types::{
    ApplyStats, BlockRecord, CheckpointManifest, ConfirmationStatus, IssuanceTransitionRecord,
    ObservationKind, Provenance, RawEvidenceRef, SCHEMA_VERSION, Tip, TransactionRecord,
    UndoRecord, UtxoRecord,
};

const CF_BLOCKS: &str = "blocks";
const CF_HEIGHTS: &str = "heights";
const CF_TRANSACTIONS: &str = "transactions";
const CF_UTXOS: &str = "utxos";
const CF_TRANSITIONS: &str = "issuance_transitions";
const CF_UNDO: &str = "undo";
const CF_CHECKPOINTS: &str = "checkpoints";
const CF_META: &str = "meta";
const META_TIP: &[u8] = b"tip";
const META_SCHEMA: &[u8] = b"schema-version";

#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub verifier_version: String,
    issuance_terms: BTreeMap<[u8; 32], IssuanceTerms>,
    pub durable_writes: bool,
}

impl IndexerConfig {
    pub fn new(
        verifier_version: impl Into<String>,
        issuance_terms: impl IntoIterator<Item = IssuanceTerms>,
    ) -> Self {
        let issuance_terms = issuance_terms
            .into_iter()
            .map(|terms| (terms.terms_hash(), terms))
            .collect();
        Self {
            verifier_version: verifier_version.into(),
            issuance_terms,
            durable_writes: true,
        }
    }

    pub fn with_durable_writes(mut self, durable_writes: bool) -> Self {
        self.durable_writes = durable_writes;
        self
    }
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("record encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("record decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error("record contains {0} unexpected trailing bytes")]
    TrailingBytes(usize),
    #[error("required column family is missing: {0}")]
    MissingColumnFamily(&'static str),
    #[error("database schema {found} is unsupported; expected {expected}")]
    Schema { found: u32, expected: u32 },
    #[error("block height {actual} does not follow expected height {expected}")]
    HeightMismatch { expected: u32, actual: u32 },
    #[error("block parent {actual} does not match current tip {expected}")]
    ParentMismatch {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("block {0} is already indexed")]
    DuplicateBlock(BlockHash),
    #[error("transaction {0} is already indexed")]
    DuplicateTransaction(Txid),
    #[error("transaction spends missing or already spent outpoint {0}")]
    MissingPrevout(OutPoint),
    #[error("transaction repeats input outpoint {0}")]
    DuplicateInput(OutPoint),
    #[error("index is empty")]
    Empty,
    #[error("block {0} is not a canonical ancestor")]
    UnknownAncestor(BlockHash),
    #[error("replacement branch is not contiguous at height {0}")]
    InvalidReplacement(u32),
    #[error("checkpoint label must be non-empty")]
    EmptyCheckpointLabel,
    #[error("index writer lock is poisoned")]
    WriterPoisoned,
}

pub struct Indexer {
    db: DB,
    config: IndexerConfig,
    writer: Mutex<()>,
}

impl Indexer {
    pub fn open(path: impl AsRef<Path>, config: IndexerConfig) -> Result<Self, IndexError> {
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_atomic_flush(true);
        db_options.set_wal_recovery_mode(DBRecoveryMode::AbsoluteConsistency);
        db_options.set_bytes_per_sync(1 << 20);

        let descriptors = [
            descriptor(CF_BLOCKS, false),
            descriptor(CF_HEIGHTS, false),
            descriptor(CF_TRANSACTIONS, true),
            descriptor(CF_UTXOS, true),
            descriptor(CF_TRANSITIONS, true),
            descriptor(CF_UNDO, true),
            descriptor(CF_CHECKPOINTS, false),
            descriptor(CF_META, false),
        ];
        let db = DB::open_cf_descriptors(&db_options, path, descriptors)?;
        let indexer = Self {
            db,
            config,
            writer: Mutex::new(()),
        };
        indexer.initialize_schema()?;
        Ok(indexer)
    }

    fn initialize_schema(&self) -> Result<(), IndexError> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(cf, META_SCHEMA)? {
            Some(bytes) => {
                let found: u32 = decode(&bytes)?;
                if found != SCHEMA_VERSION {
                    return Err(IndexError::Schema {
                        found,
                        expected: SCHEMA_VERSION,
                    });
                }
            }
            None => {
                self.db.put_cf(cf, META_SCHEMA, encode(&SCHEMA_VERSION)?)?;
                self.db.flush_wal(true)?;
            }
        }
        Ok(())
    }

    pub fn tip(&self) -> Result<Option<Tip>, IndexError> {
        self.get(CF_META, META_TIP)
    }

    pub fn block_by_height(&self, height: u32) -> Result<Option<BlockRecord>, IndexError> {
        let Some(hash_bytes) = self.db.get_cf(self.cf(CF_HEIGHTS)?, height_key(height))? else {
            return Ok(None);
        };
        self.get(CF_BLOCKS, &hash_bytes)
    }

    pub fn transaction(&self, txid: Txid) -> Result<Option<TransactionRecord>, IndexError> {
        self.get(CF_TRANSACTIONS, txid.as_byte_array())
    }

    pub fn utxo(&self, outpoint: OutPoint) -> Result<Option<UtxoRecord>, IndexError> {
        self.get(CF_UTXOS, &outpoint_key(outpoint))
    }

    /// Batch point lookup for wallet and API query paths.
    pub fn utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<UtxoRecord>>, IndexError> {
        let cf = self.cf(CF_UTXOS)?;
        let keys: Vec<[u8; 36]> = outpoints.iter().copied().map(outpoint_key).collect();
        self.db
            .multi_get_cf(keys.iter().map(|key| (cf, key)))
            .into_iter()
            .map(|result| match result? {
                Some(bytes) => Ok(Some(decode(&bytes)?)),
                None => Ok(None),
            })
            .collect()
    }

    pub fn issuance_transition(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Result<Option<IssuanceTransitionRecord>, IndexError> {
        self.get(CF_TRANSITIONS, &transition_key(txid, input_index))
    }

    pub fn checkpoint(&self, label: &str) -> Result<Option<CheckpointManifest>, IndexError> {
        self.get(CF_CHECKPOINTS, label.as_bytes())
    }

    /// Commit every source and derived record for one block in one WAL-backed batch.
    pub fn apply_block(&self, height: u32, block: &Block) -> Result<ApplyStats, IndexError> {
        let _writer = self.writer()?;
        self.apply_block_locked(height, block)
    }

    fn apply_block_locked(&self, height: u32, block: &Block) -> Result<ApplyStats, IndexError> {
        let previous_tip = self.tip()?;
        let (expected_height, expected_parent) = match previous_tip {
            Some(tip) => (tip.height.saturating_add(1), tip.hash),
            None => (0, BlockHash::all_zeros()),
        };
        if height != expected_height {
            return Err(IndexError::HeightMismatch {
                expected: expected_height,
                actual: height,
            });
        }
        if block.header.prev_blockhash != expected_parent {
            return Err(IndexError::ParentMismatch {
                expected: expected_parent,
                actual: block.header.prev_blockhash,
            });
        }

        let block_hash = block.block_hash();
        if self.block(block_hash)?.is_some() {
            return Err(IndexError::DuplicateBlock(block_hash));
        }

        let mut unique_txids = HashSet::with_capacity(block.txdata.len());
        let block_txids: Vec<Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
        for txid in &block_txids {
            if !unique_txids.insert(*txid) {
                return Err(IndexError::DuplicateTransaction(*txid));
            }
        }
        let transaction_cf = self.cf(CF_TRANSACTIONS)?;
        for (txid, result) in block_txids.iter().zip(
            self.db.multi_get_cf(
                block_txids
                    .iter()
                    .map(|txid| (transaction_cf, txid.as_byte_array())),
            ),
        ) {
            if result?.is_some() {
                return Err(IndexError::DuplicateTransaction(*txid));
            }
        }

        let mut batch = WriteBatch::default();
        let mut overlay = HashMap::<OutPoint, Option<UtxoRecord>>::new();
        let mut created_in_block = HashSet::<OutPoint>::new();
        let mut restored_utxos = Vec::new();
        let mut created_outpoints = Vec::new();
        let mut created_txids = Vec::new();
        let mut created_transitions = Vec::new();
        let mut stats = ApplyStats::default();

        for (tx_index, (tx, txid)) in block.txdata.iter().zip(block_txids).enumerate() {
            let mut seen_inputs = HashSet::with_capacity(tx.input.len());
            for input in &tx.input {
                if !input.previous_output.is_null() && !seen_inputs.insert(input.previous_output) {
                    return Err(IndexError::DuplicateInput(input.previous_output));
                }
            }

            let mut input_records = Vec::with_capacity(tx.input.len());
            for input in &tx.input {
                if input.previous_output.is_null() {
                    input_records.push(None);
                } else {
                    input_records.push(Some(
                        self.resolve_overlay_utxo(&overlay, input.previous_output)?,
                    ));
                }
            }

            for discovered in discover(tx).consumed_issuers {
                let Some(terms) = self.config.issuance_terms.get(&discovered.state.terms_hash)
                else {
                    continue;
                };
                let Some(previous) = input_records
                    .get(discovered.input_index)
                    .and_then(Option::as_ref)
                else {
                    continue;
                };
                let previous_output = TxOut {
                    value: bitcoin::Amount::from_sat(previous.value_sat),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(previous.script_pubkey.clone()),
                };
                let Ok(verified) = verify_mint(tx, discovered.outpoint, &previous_output, terms)
                else {
                    continue;
                };
                let input_index = verified.issuer_input_index as u32;
                let item_output_index = verified.item_output_index as u32;
                let record = IssuanceTransitionRecord {
                    terms_hash: verified.issuer_state.terms_hash,
                    lane: verified.issuer_state.lane,
                    sequence: verified.issuer_state.seq,
                    remaining_before: verified.issuer_state.remaining,
                    issuer_outpoint: discovered.outpoint,
                    item_outpoint: OutPoint::new(txid, item_output_index),
                    successor_outpoint: verified
                        .successor_output_index
                        .map(|index| OutPoint::new(txid, index as u32)),
                    item_commitment: verified.witness.item_commitment,
                    owner_key: verified.witness.owner_key.serialize(),
                    fee_sat: verified.fee.to_sat(),
                    provenance: provenance(
                        block_hash,
                        height,
                        txid,
                        tx_index as u32,
                        Some(input_index),
                        Some(item_output_index),
                        &self.config.verifier_version,
                        ObservationKind::WalletPolicyVerified,
                    ),
                };
                batch.put_cf(
                    self.cf(CF_TRANSITIONS)?,
                    transition_key(txid, input_index),
                    encode(&record)?,
                );
                created_transitions.push((txid, input_index));
                stats.issuance_transitions += 1;
            }

            for (input_index, input) in tx.input.iter().enumerate() {
                if input.previous_output.is_null() {
                    continue;
                }
                let Some(record) = input_records[input_index].clone() else {
                    return Err(IndexError::MissingPrevout(input.previous_output));
                };
                if !created_in_block.contains(&input.previous_output) {
                    restored_utxos.push(record);
                }
                overlay.insert(input.previous_output, None);
                batch.delete_cf(self.cf(CF_UTXOS)?, outpoint_key(input.previous_output));
                stats.spent_outputs += 1;
            }

            let transaction = TransactionRecord {
                txid,
                provenance: provenance(
                    block_hash,
                    height,
                    txid,
                    tx_index as u32,
                    None,
                    None,
                    &self.config.verifier_version,
                    ObservationKind::DiscoveryOnly,
                ),
            };
            batch.put_cf(
                self.cf(CF_TRANSACTIONS)?,
                txid.as_byte_array(),
                encode(&transaction)?,
            );
            created_txids.push(txid);
            stats.transactions += 1;

            for (output_index, output) in tx.output.iter().enumerate() {
                let output_index = output_index as u32;
                let outpoint = OutPoint::new(txid, output_index);
                let record = UtxoRecord {
                    outpoint,
                    value_sat: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.to_bytes(),
                    provenance: provenance(
                        block_hash,
                        height,
                        txid,
                        tx_index as u32,
                        None,
                        Some(output_index),
                        &self.config.verifier_version,
                        ObservationKind::DiscoveryOnly,
                    ),
                };
                batch.put_cf(self.cf(CF_UTXOS)?, outpoint_key(outpoint), encode(&record)?);
                overlay.insert(outpoint, Some(record));
                created_in_block.insert(outpoint);
                created_outpoints.push(outpoint);
                stats.created_outputs += 1;
            }
        }

        let block_record = BlockRecord {
            hash: block_hash,
            height,
            previous_hash: block.header.prev_blockhash,
            transaction_count: block.txdata.len() as u32,
            raw_block: serialize(block),
            confirmation: ConfirmationStatus::Confirmed,
        };
        batch.put_cf(
            self.cf(CF_BLOCKS)?,
            block_hash.as_byte_array(),
            encode(&block_record)?,
        );
        batch.put_cf(
            self.cf(CF_HEIGHTS)?,
            height_key(height),
            block_hash.as_byte_array(),
        );
        let tip = Tip {
            hash: block_hash,
            height,
        };
        batch.put_cf(self.cf(CF_META)?, META_TIP, encode(&tip)?);
        let undo = UndoRecord {
            block_hash,
            height,
            previous_tip,
            created_txids,
            created_outpoints,
            restored_utxos,
            created_transitions,
        };
        batch.put_cf(
            self.cf(CF_UNDO)?,
            block_hash.as_byte_array(),
            encode(&undo)?,
        );

        let mut options = WriteOptions::default();
        options.set_sync(self.config.durable_writes);
        self.db.write_opt(batch, &options)?;
        Ok(stats)
    }

    pub fn rollback_tip(&self) -> Result<Tip, IndexError> {
        let _writer = self.writer()?;
        self.rollback_tip_locked()
    }

    fn rollback_tip_locked(&self) -> Result<Tip, IndexError> {
        let tip = self.tip()?.ok_or(IndexError::Empty)?;
        let undo: UndoRecord = self
            .get(CF_UNDO, tip.hash.as_byte_array())?
            .ok_or(IndexError::UnknownAncestor(tip.hash))?;
        let mut batch = WriteBatch::default();

        batch.delete_cf(self.cf(CF_BLOCKS)?, tip.hash.as_byte_array());
        batch.delete_cf(self.cf(CF_HEIGHTS)?, height_key(tip.height));
        batch.delete_cf(self.cf(CF_UNDO)?, tip.hash.as_byte_array());
        for txid in undo.created_txids {
            batch.delete_cf(self.cf(CF_TRANSACTIONS)?, txid.as_byte_array());
        }
        for outpoint in undo.created_outpoints {
            batch.delete_cf(self.cf(CF_UTXOS)?, outpoint_key(outpoint));
        }
        for record in undo.restored_utxos {
            batch.put_cf(
                self.cf(CF_UTXOS)?,
                outpoint_key(record.outpoint),
                encode(&record)?,
            );
        }
        for (txid, input_index) in undo.created_transitions {
            batch.delete_cf(self.cf(CF_TRANSITIONS)?, transition_key(txid, input_index));
        }
        match undo.previous_tip {
            Some(previous) => batch.put_cf(self.cf(CF_META)?, META_TIP, encode(&previous)?),
            None => batch.delete_cf(self.cf(CF_META)?, META_TIP),
        }
        let mut options = WriteOptions::default();
        options.set_sync(self.config.durable_writes);
        self.db.write_opt(batch, &options)?;
        Ok(tip)
    }

    pub fn rollback_to(&self, ancestor: BlockHash) -> Result<(), IndexError> {
        let _writer = self.writer()?;
        self.rollback_to_locked(ancestor)
    }

    fn rollback_to_locked(&self, ancestor: BlockHash) -> Result<(), IndexError> {
        let ancestor_record = self
            .block(ancestor)?
            .ok_or(IndexError::UnknownAncestor(ancestor))?;
        if self
            .block_by_height(ancestor_record.height)?
            .map(|b| b.hash)
            != Some(ancestor)
        {
            return Err(IndexError::UnknownAncestor(ancestor));
        }
        loop {
            let tip = self.tip()?.ok_or(IndexError::Empty)?;
            if tip.hash == ancestor {
                return Ok(());
            }
            if tip.height <= ancestor_record.height {
                return Err(IndexError::UnknownAncestor(ancestor));
            }
            self.rollback_tip_locked()?;
        }
    }

    /// Roll back to a known canonical ancestor, then attach a validated header chain.
    /// Each detach and attach remains an independently atomic block operation.
    pub fn reorganize(
        &self,
        ancestor: BlockHash,
        replacement: &[(u32, Block)],
    ) -> Result<(), IndexError> {
        let _writer = self.writer()?;
        let ancestor_record = self
            .block(ancestor)?
            .ok_or(IndexError::UnknownAncestor(ancestor))?;
        if self
            .block_by_height(ancestor_record.height)?
            .map(|b| b.hash)
            != Some(ancestor)
        {
            return Err(IndexError::UnknownAncestor(ancestor));
        }
        let mut expected_height = ancestor_record.height + 1;
        let mut expected_parent = ancestor;
        for (height, block) in replacement {
            if *height != expected_height || block.header.prev_blockhash != expected_parent {
                return Err(IndexError::InvalidReplacement(*height));
            }
            expected_height = expected_height.saturating_add(1);
            expected_parent = block.block_hash();
        }

        self.rollback_to_locked(ancestor)?;
        for (height, block) in replacement {
            self.apply_block_locked(*height, block)?;
        }
        Ok(())
    }

    /// Create a RocksDB hard-link checkpoint with the current tip and undo log.
    pub fn create_checkpoint(
        &self,
        label: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<CheckpointManifest, IndexError> {
        let _writer = self.writer()?;
        let label = label.into();
        if label.is_empty() {
            return Err(IndexError::EmptyCheckpointLabel);
        }
        let manifest = CheckpointManifest {
            label: label.clone(),
            schema_version: SCHEMA_VERSION,
            tip: self.tip()?.ok_or(IndexError::Empty)?,
        };
        self.db.flush_wal(true)?;
        Checkpoint::new(&self.db)?.create_checkpoint(path.as_ref())?;

        let checkpoint = Self::open(path, self.config.clone())?;
        checkpoint.put_checkpoint(&manifest)?;
        self.put_checkpoint(&manifest)?;
        Ok(manifest)
    }

    fn put_checkpoint(&self, manifest: &CheckpointManifest) -> Result<(), IndexError> {
        let mut options = WriteOptions::default();
        options.set_sync(true);
        let mut batch = WriteBatch::default();
        batch.put_cf(
            self.cf(CF_CHECKPOINTS)?,
            manifest.label.as_bytes(),
            encode(manifest)?,
        );
        self.db.write_opt(batch, &options)?;
        Ok(())
    }

    fn block(&self, hash: BlockHash) -> Result<Option<BlockRecord>, IndexError> {
        self.get(CF_BLOCKS, hash.as_byte_array())
    }

    fn resolve_overlay_utxo(
        &self,
        overlay: &HashMap<OutPoint, Option<UtxoRecord>>,
        outpoint: OutPoint,
    ) -> Result<UtxoRecord, IndexError> {
        match overlay.get(&outpoint) {
            Some(Some(record)) => Ok(record.clone()),
            Some(None) => Err(IndexError::MissingPrevout(outpoint)),
            None => self
                .utxo(outpoint)?
                .ok_or(IndexError::MissingPrevout(outpoint)),
        }
    }

    fn writer(&self) -> Result<MutexGuard<'_, ()>, IndexError> {
        self.writer.lock().map_err(|_| IndexError::WriterPoisoned)
    }

    fn get<T: DeserializeOwned>(
        &self,
        cf: &'static str,
        key: &[u8],
    ) -> Result<Option<T>, IndexError> {
        self.db
            .get_cf(self.cf(cf)?, key)?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    fn cf(&self, name: &'static str) -> Result<&ColumnFamily, IndexError> {
        self.db
            .cf_handle(name)
            .ok_or(IndexError::MissingColumnFamily(name))
    }
}

fn descriptor(name: &'static str, point_lookup: bool) -> ColumnFamilyDescriptor {
    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::Snappy);
    options.set_write_buffer_size(32 << 20);
    if point_lookup {
        options.optimize_for_point_lookup(64);
        options.set_prefix_extractor(SliceTransform::create_fixed_prefix(32));
    }
    ColumnFamilyDescriptor::new(name, options)
}

#[allow(clippy::too_many_arguments)]
fn provenance(
    block_hash: BlockHash,
    block_height: u32,
    txid: Txid,
    tx_index: u32,
    input_index: Option<u32>,
    output_index: Option<u32>,
    verifier_version: &str,
    observation: ObservationKind,
) -> Provenance {
    Provenance {
        block_hash,
        block_height,
        txid,
        tx_index,
        input_index,
        output_index,
        raw_evidence: RawEvidenceRef {
            block_hash,
            tx_index,
        },
        verifier_version: verifier_version.to_owned(),
        confirmation: ConfirmationStatus::Confirmed,
        observation,
    }
}

fn height_key(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}

fn outpoint_key(outpoint: OutPoint) -> [u8; 36] {
    let mut key = [0_u8; 36];
    key[..32].copy_from_slice(outpoint.txid.as_byte_array());
    key[32..].copy_from_slice(&outpoint.vout.to_be_bytes());
    key
}

fn transition_key(txid: Txid, input_index: u32) -> [u8; 36] {
    let mut key = [0_u8; 36];
    key[..32].copy_from_slice(txid.as_byte_array());
    key[32..].copy_from_slice(&input_index.to_be_bytes());
    key
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, config::standard())
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, IndexError> {
    let (value, consumed) = bincode::serde::decode_from_slice(bytes, config::standard())?;
    if consumed != bytes.len() {
        return Err(IndexError::TrailingBytes(bytes.len() - consumed));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decoder_rejects_trailing_bytes() {
        let mut bytes = encode(&42_u32).unwrap();
        bytes.push(0xff);
        assert!(decode::<u32>(&bytes).is_err());
    }
}
