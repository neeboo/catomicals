use std::fs;
use std::path::Path;
use std::time::Instant;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};
use catomicals_indexer::{Indexer, IndexerConfig};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let durable = args.iter().any(|arg| arg == "--durable");
    let block_count = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--blocks="))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(2_000);
    let temp = tempfile::tempdir().expect("temporary benchmark database");
    let config = IndexerConfig::new("measure-indexer-v1", []).with_durable_writes(durable);
    let indexer = Indexer::open(temp.path(), config).expect("open indexer");
    let mut previous = BlockHash::all_zeros();
    let mut raw_bytes = 0_u64;
    let mut outpoints = Vec::with_capacity(block_count as usize);

    let started = Instant::now();
    for height in 0..block_count {
        let tx = coinbase(height);
        outpoints.push(OutPoint::new(tx.compute_txid(), 0));
        let block = block(previous, height, tx);
        raw_bytes += serialize(&block).len() as u64;
        indexer.apply_block(height, &block).expect("apply block");
        previous = block.block_hash();
    }
    let ingest = started.elapsed();

    let read_started = Instant::now();
    let rows = indexer.utxos(&outpoints).expect("batch UTXO read");
    assert!(rows.iter().all(Option::is_some));
    let batch_read = read_started.elapsed();

    let rollback_count = block_count.min(100);
    let rollback_started = Instant::now();
    for _ in 0..rollback_count {
        indexer.rollback_tip().expect("rollback tip");
    }
    let rollback = rollback_started.elapsed();
    let database_bytes = directory_size(temp.path()).expect("database size");

    println!("mode={}", if durable { "sync-wal" } else { "async-wal" });
    println!("blocks={block_count}");
    println!("raw_block_bytes={raw_bytes}");
    println!("database_bytes={database_bytes}");
    println!(
        "database_to_raw_ratio={:.2}",
        database_bytes as f64 / raw_bytes.max(1) as f64
    );
    println!("ingest_ms={:.2}", ingest.as_secs_f64() * 1_000.0);
    println!(
        "blocks_per_second={:.2}",
        block_count as f64 / ingest.as_secs_f64()
    );
    println!("batch_utxo_count={}", outpoints.len());
    println!(
        "batch_utxo_read_ms={:.2}",
        batch_read.as_secs_f64() * 1_000.0
    );
    println!("rollback_blocks={rollback_count}");
    println!("rollback_ms={:.2}", rollback.as_secs_f64() * 1_000.0);
}

fn coinbase(height: u32) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, (height & 0xff) as u8]),
        }],
    }
}

fn block(previous: BlockHash, nonce: u32, transaction: Transaction) -> Block {
    Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: previous,
            merkle_root: TxMerkleNode::all_zeros(),
            time: nonce,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        },
        txdata: vec![transaction],
    }
}

fn directory_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += directory_size(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}
