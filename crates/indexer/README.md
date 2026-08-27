# Catomicals Covenant Indexer

This crate is the first rebuildable discovery index for Catomicals. It stores
Bitcoin block data and local covenant observations in RocksDB. It is not a
consensus engine and is never an authorization or signing dependency.

## Trust boundary

- Bitcoin Core / Inquisition remains the source for canonical blocks and
  transaction acceptance.
- The indexer stores a queryable projection. A missing, stale, or corrupted
  index may break discovery, but must not change what a wallet signs.
- `WalletPolicyVerified` means that the versioned Catomicals issuance verifier
  accepted a transition. It does not claim that Bitcoin consensus enforces the
  wider issuance policy.
- Every transaction, UTXO, and issuance transition retains block hash, height,
  txid, transaction/input/output indexes, verifier version, confirmation state,
  and a pointer to the raw block evidence.

## Column families

| Column family | Contents | Access shape |
| --- | --- | --- |
| `blocks` | Canonical block metadata and raw consensus bytes | Block hash lookup |
| `heights` | Canonical height to block hash | Sequential sync and reorg |
| `transactions` | Transaction lineage | Txid point lookup |
| `utxos` | Current unspent outputs | Outpoint point and batch lookup |
| `issuance_transitions` | Verified issuance observations | Txid + input index |
| `undo` | Per-block inverse mutations | Tip rollback |
| `checkpoints` | Named physical checkpoint manifests | Label lookup |
| `meta` | Schema version and canonical tip | Startup and apply path |

UTXO, transaction, transition, and undo keys start with a 32-byte txid or block
hash prefix. Those families use point-lookup tuning and fixed-prefix bloom
filters. Blocks are compressed once; derived records refer to those raw bytes
instead of duplicating raw transactions.

## Atomicity and recovery

One WAL-backed RocksDB `WriteBatch` commits the block, transactions, UTXO
changes, covenant transitions, undo record, height mapping, and new tip. The
default write mode syncs the WAL before returning. A process failure therefore
exposes either the previous tip or the complete new block.

Every state-changing entry point also holds one process-local writer lock from
tip validation through batch commit. RocksDB's database lock excludes a second
process opening the same directory for writes. Competing blocks at one height
therefore cannot both update the canonical view.

`rollback_tip` applies one undo record atomically. `rollback_to` repeats that
operation for a deep reorg. `reorganize` validates the complete replacement
header chain before detaching the old branch, then attaches each replacement
block atomically. If a replacement block contains invalid index inputs, the
database remains at a valid prefix of the replacement branch.

`create_checkpoint` uses RocksDB's physical checkpoint API, which hard-links
immutable SST files where the filesystem permits it. The checkpoint contains
the current UTXO set, raw blocks, undo history, schema version, and a named
manifest. Open the checkpoint as a normal `Indexer`, then replay later blocks
to rebuild the tail.

## Current issuance slice

The first covenant adapter recognizes an issuance tapscript reveal, loads the
spent output from the indexed UTXO set, selects creator terms by `terms_hash`,
and invokes `catomicals-issuance::verify_mint`. A successful observation stores
the issuer input, item output, optional successor issuer output, state sequence,
commitment, owner key, fee, and full provenance.

Unknown issuance terms and policy-invalid reveals do not reject a Bitcoin
block. They simply produce no `WalletPolicyVerified` transition.

## Build requirements

The Rust RocksDB binding requires a C++ toolchain and `libclang`. It can build
the bundled RocksDB source, or link a compatible system RocksDB. On Homebrew
macOS installations, a system build can use:

```sh
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
export DYLD_FALLBACK_LIBRARY_PATH="$LIBCLANG_PATH"
export ROCKSDB_LIB_DIR="$(brew --prefix rocksdb)/lib"
export ROCKSDB_INCLUDE_DIR="$(brew --prefix rocksdb)/include"
cargo test -p catomicals-indexer
```

The paths are environment configuration only and are not embedded in the
crate.

## Performance measurement

The measurement example reports ingestion rate, physical database size versus
raw input bytes, one ordered `multi_get` over all UTXOs, and 100-block rollback
time:

```sh
cargo run -p catomicals-indexer --release --example measure_indexer -- --blocks=2000
cargo run -p catomicals-indexer --release --example measure_indexer -- --blocks=200 --durable
```

The asynchronous mode isolates RocksDB encoding and write amplification. The
durable mode measures the production default with a synced WAL per block.

## Deliberate first-slice limits

- The caller supplies an already ordered canonical block stream. Node RPC sync
  and health checks remain a separate integration step.
- A fresh database accepts only height `0` with an all-zero parent hash. Initial
  sync therefore starts from genesis, or from a physical checkpoint that
  already contains the full UTXO state. The height parameter alone is not a
  UTXO bootstrap mechanism.
- Undo history is retained without pruning, so deep reorg recovery is bounded
  by available storage rather than a fixed depth.
- Mempool and unconfirmed observations are not indexed.
- There is no public HTTP or MCP query service in this crate yet.
