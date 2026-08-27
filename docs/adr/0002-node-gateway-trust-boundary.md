# ADR 0002: typed node access and a non-authoritative indexer

- Status: Accepted for B0
- Date: 2026-08-27
- Scope: Bitcoin Inquisition, external full nodes, remote gateways, indexers, wallet review

## Context

The current node client exposes health information, and current transaction inspection accepts ordered prevout material from its caller. That is suitable for an early local demonstration but cannot be the final source of chain facts used for approval or signing. The planned system also needs searchable covenant, issuance, order, and reorg data.

Raw Bitcoin RPC exposure to a renderer, plugin, browser tab, MCP client, or executor would leak node credentials and allow unreviewed node operations. Treating an indexer as the ownership or settlement source would make its bugs and reorg lag consensus-critical to the wallet.

## Decision

`walletd` uses an allowlisted typed node adapter. The first implementation remains inside `node-client`; it may later be extracted into a gateway when a second process or remote deployment needs it.

The minimum trusted interface contains:

- `health` and deployment compatibility;
- `chain_snapshot` with network, tip identity, height, and freshness;
- `resolve_prevouts` from outpoints supplied by the transaction;
- `transaction_status`;
- `test_mempool_accept`;
- `broadcast_transaction` after a fresh pre-broadcast review.

No caller can send an arbitrary RPC method or arbitrary RPC parameters through this interface.

### Trust rules

1. The configured chain and OP_CAT deployment profile must match the policy and wallet profile.
2. `walletd` assigns every review a `node_snapshot_id` derived from typed chain data.
3. Caller-provided prevouts may be used only as hints during the compatibility period. `walletd` resolves authoritative prevouts and rejects any mismatch.
4. Approval cannot continue after the bound snapshot becomes stale or a reorg invalidates its facts.
5. Proposal review, pre-sign review, and pre-broadcast mempool review each read fresh node state.
6. Remote gateways require authenticated transport and an explicit resource identity. Loopback RPC credentials are never forwarded to clients.
7. Node errors, ambiguity, stale state, deployment mismatch, and incomplete prevouts close the write, sign, and broadcast paths.

### Indexer boundary

The indexer stores rebuildable projections in a dedicated RocksDB: blocks, transactions, UTXOs, covenant transitions, mint and market views, checkpoints, and reorg undo data. Column families separate those domains, and each connected block commits its undo record, projections, and checkpoint in one `WriteBatch`. The database, WAL, snapshots, and checkpoints are independent from the authoritative `walletd` SQLite store.

Indexer responses carry freshness, tip identity, and reorg state. They may drive search, charts, discovery, and agent context. Before approval or signing, `walletd` independently resolves every relevant fact through the typed node adapter and policy verifier.

Deleting or rebuilding the indexer must not delete wallet authorization, signing nonce history, policy activation, or broadcast audit records. An unavailable indexer may degrade discovery but cannot weaken wallet verification.

## Security invariants

- UI, MCP, executors, Cordis plugins, and browser tabs never receive raw Bitcoin RPC credentials.
- No raw RPC proxy or generic `call(method, params)` is part of a public or plugin-facing API.
- A review reference contains a snapshot identifier and digest, not an assertion that displayed values remain current.
- Reorg handling invalidates affected reviews and produces auditable state transitions.
- Broadcast is a wallet operation following intent approval and a fresh review; indexer ingestion is not broadcast confirmation.

## Consequences

- The wallet can support a managed Inquisition node, an external node, and a remote authenticated gateway behind one typed contract.
- Search and market projections can evolve without changing settlement rules.
- Additional latency from fresh node checks is accepted for custody-sensitive paths.
- The current caller-supplied prevout contract remains a documented compatibility limitation until typed resolution is implemented.

## Rejected alternatives

- Reverse proxying full-node RPC: too broad and couples credentials to untrusted clients.
- Signing from indexer data: makes a rebuildable projection authoritative.
- Reusing one startup snapshot for an entire session: misses reorgs and stale mempool conditions.
- Continuing after partial node responses: creates ambiguous transaction meaning.
