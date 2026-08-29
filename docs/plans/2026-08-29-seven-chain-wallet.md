# Seven-chain Wallet Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add explicit address derivation, transaction review, signing, verification, and network-safe broadcast contracts for Bitcoin, Bitcoin Cash, BSV, Fractal Bitcoin, Kaspa, Chia, and Ergo.

**Architecture:** Introduce a chain-domain crate for consensus-facing behavior and a signing-domain crate for algorithm/topology behavior. Wallet-core binds reviewed chain artifacts to Passkey authorization and delegates execution to existing FROST or chain-native backends. RPC presets map explicitly to concrete chain networks and never double as address-network identifiers.

**Tech Stack:** Rust, serde, bitcoin 0.32, Zcash Foundation FROST crates, chain-official Rust libraries where available, Vitest/TypeScript for desktop network and address boundaries.

---

### Task 1: Split concrete networks from RPC presets

**Files:**
- Create: `crates/chain-domain/Cargo.toml`
- Create: `crates/chain-domain/src/lib.rs`
- Create: `crates/chain-domain/src/network.rs`
- Create: `crates/chain-domain/tests/network_contract.rs`
- Create: `desktop/src/chains/network-contract.ts`
- Create: `desktop/src/chains/network-contract.test.ts`
- Modify: `Cargo.toml`
- Modify: `desktop/src/chains/rpc/presets.ts`
- Modify: `desktop/src/chains/address/types.ts`

**Steps:**
1. Write failing tests proving RPC preset IDs cannot be used as address/signing networks and every preset maps to one concrete network.
2. Run the Rust and desktop tests and confirm the missing types/mapping cause the expected failures.
3. Add versioned `ChainId`, `ChainNetwork`, `RpcPresetId`, and explicit mappings for all configured networks.
4. Re-run the focused tests and the existing address/RPC suites.
5. Commit only Task 1 files.

### Task 2: Define chain and signing suite contracts

**Files:**
- Create: `crates/chain-domain/src/address.rs`
- Create: `crates/chain-domain/src/review.rs`
- Create: `crates/chain-domain/src/suite.rs`
- Create: `crates/chain-domain/tests/domain_separation.rs`
- Create: `crates/signing-domain/Cargo.toml`
- Create: `crates/signing-domain/src/lib.rs`
- Create: `crates/signing-domain/src/suite.rs`
- Create: `crates/signing-domain/src/operation.rs`
- Create: `crates/signing-domain/tests/contracts.rs`
- Modify: `Cargo.toml`

**Steps:**
1. Write compile-time and behavior tests for `ChainSuite`, `SigningSuite`, stable suite IDs, execution topology and versioned review artifacts.
2. Verify the tests fail because the contracts do not exist.
3. Implement the smallest object-safe contracts with bounded versioned data types and no secret-bearing fields.
4. Add domain-separation tests covering chain, concrete network, suite, signer set and epoch drift.
5. Run focused tests, workspace tests and strict Clippy; commit Task 2.

### Task 3: Implement Bitcoin and Fractal address derivation

**Files:**
- Create: `crates/chain-domain/src/bitcoin_family.rs`
- Create: `crates/chain-domain/tests/bitcoin_vectors.rs`
- Modify: `crates/chain-domain/src/lib.rs`

**Steps:**
1. Import BIP84/BIP86/BIP350 fixtures and write failing key-to-address round-trip tests for every supported Bitcoin and Fractal network profile.
2. Add failure cases for cross-chain identity, wrong HRP/version bytes and Fractal network ambiguity.
3. Implement public-key address derivation and strict parsing using the existing `bitcoin` dependency.
4. Run official vectors and all chain-domain tests; commit Task 3.

### Task 4: Generalize Bitcoin-family transaction review and FROST binding

**Files:**
- Create: `crates/chain-domain/src/bitcoin_review.rs`
- Create: `crates/chain-domain/tests/bitcoin_signing.rs`
- Modify: `crates/wallet-core/src/transaction.rs`
- Modify: `crates/wallet-core/src/intent.rs`
- Modify: `crates/wallet-core/src/gate.rs`
- Modify: `crates/threshold-signer/src/session.rs`

**Steps:**
1. Write failing tests for Bitcoin/Fractal concrete network review, BIP341 vectors, 64/65-byte signature encoding and chain-domain nonce separation.
2. Verify existing Signet-hardcoded behavior fails those tests.
3. Route review through a concrete chain profile while preserving the current Signet API as a compatibility wrapper.
4. Bind chain, network, suite and spend path into intent and FROST authorization digests.
5. Run wallet-core, threshold-signer and Bitcoin Inquisition E2E; commit Task 4.

### Task 5: Implement BCH and BSV suites

**Files:**
- Create: `crates/chain-domain/src/bitcoin_cash.rs`
- Create: `crates/chain-domain/src/bsv.rs`
- Create: `crates/chain-domain/tests/bitcoin_cash_vectors.rs`
- Create: `crates/chain-domain/tests/bsv_vectors.rs`
- Create: `crates/signing-domain/src/secp256k1_ecdsa.rs`

**Steps:**
1. Add official address, derivation, serialization, sighash/fork-id and signature vectors as failing tests.
2. Implement complete review and independent verification before adding signer execution.
3. Evaluate consensus-compatible Schnorr paths against `frost-secp256k1`; enable FROST only where exact vectors pass.
4. Add an isolated ECDSA backend contract for paths that cannot use FROST; do not implement a new threshold ECDSA protocol.
5. Run focused tests and node adapter tests; commit Task 5.

### Task 6: Implement Kaspa suite

**Files:**
- Create: `crates/chain-domain/src/kaspa.rs`
- Create: `crates/chain-domain/tests/kaspa_vectors.rs`
- Create: `crates/signing-domain/src/kaspa.rs`

**Steps:**
1. Add official mainnet/testnet/simnet address, derivation, transaction digest and signature fixtures as failing tests.
2. Implement the Kaspa transaction review and verification path using official Rust components where possible.
3. Compare exact native Schnorr vectors with `frost-secp256k1`; use a dedicated ciphersuite ID if the hash/challenge domain differs.
4. Keep ECDSA address paths on an isolated ECDSA backend until a reviewed threshold backend exists.
5. Run tests and commit Task 6.

### Task 7: Implement Chia suite and threshold-BLS seam

**Files:**
- Create: `crates/chain-domain/src/chia.rs`
- Create: `crates/chain-domain/tests/chia_vectors.rs`
- Create: `crates/signing-domain/src/bls.rs`
- Modify: `desktop/src/chains/rpc/chia.ts`
- Modify: `desktop/src/chains/rpc/adapters.test.ts`

**Steps:**
1. Add failing official vectors for `m/12381/8444/2/index`, synthetic keys, puzzle hashes, `AGG_SIG_ME`, aggregate verification and mainnet/testnet11 constants.
2. Add a failing RPC test proving `push_tx` uses locally computed spend-bundle name and reads the official status response.
3. Implement standard wallet derivation, puzzle hash, signing-target construction and local aggregate verification with official Chia Rust libraries.
4. Add a `threshold-bls` backend seam; single-signature fallback stays isolated and cannot claim FROST support.
5. Add mTLS client-certificate support for local Chia RPC, run focused tests and commit Task 7.

### Task 8: Implement Ergo suite

**Files:**
- Create: `crates/chain-domain/src/ergo.rs`
- Create: `crates/chain-domain/tests/ergo_vectors.rs`
- Create: `crates/signing-domain/src/ergo.rs`

**Steps:**
1. Add official P2PK/P2SH/P2S, derivation, unsigned transaction and proof vectors as failing tests.
2. Implement transaction review and independent proof verification using official Ergo components where available.
3. Expose a chain-native signer backend; keep it isolated until a mature compatible MPC implementation is selected and tested.
4. Run focused tests and commit Task 8.

### Task 9: Connect wallet-core, durable state, HTTP and MCP

**Files:**
- Create: `crates/wallet-core/src/chain_registry.rs`
- Create: `crates/wallet-core/src/signing_executor.rs`
- Modify: `crates/wallet-core/src/node.rs`
- Modify: `crates/wallet-core/src/durable_store.rs`
- Modify: `crates/wallet-storage/src/models.rs`
- Create: `crates/wallet-storage/migrations/0006_chain_accounts.sql`
- Modify: `apps/catomicals-cli/src/wallet_serve.rs`
- Modify: `apps/catomicals-cli/src/mcp.rs`

**Steps:**
1. Write failing tests for chain-account persistence, activation gates, restart recovery and forbidden MCP signing/approval/broadcast tools.
2. Add the registry and durable model binding wallet, chain, network, derivation policy, suite, signer set and epoch.
3. Add address-derive, address-parse, review, intent and status APIs. Keep approval and signer rounds outside MCP.
4. Execute signer work outside database transactions and global request locks.
5. Run wallet-core/storage/CLI tests and commit Task 9.

### Task 10: Conformance, activation and release verification

**Files:**
- Create: `scripts/verify-seven-chain-wallet.sh`
- Create: `docs/seven-chain-conformance.md`
- Modify: `README.md`
- Modify: `README.zh.md`

**Steps:**
1. Run official vectors for every implemented network profile.
2. Run wrong-network, wrong-suite, wrong-epoch, nonce-reuse and wrong-message rejection tests.
3. Run available local-node E2E tests, with Bitcoin Inquisition Signet mandatory.
4. Confirm every mainnet signing/broadcast combination remains disabled without a matching audited activation record.
5. Run full Rust, desktop, web and Electron E2E suites, strict Clippy and formatting checks.
6. Record exact supported/experimental/disabled combinations, commit, push and restart the app for smoke testing.
