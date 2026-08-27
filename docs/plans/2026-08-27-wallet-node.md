# Self-hosted Passkey and FROST Wallet Node Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver a Signet-only self-hosted wallet node with real browser WebAuthn approval, exact-bound one-time FROST participation, local DKG, typed HTTP routes, and adversarial tests.

**Architecture:** `catomicals-threshold` owns DKG and two-round signing state; `catomicals-wallet` owns immutable intents, WebAuthn RP state, credentials, and internal approval capabilities; the CLI adapts typed service methods to JSON without exposing secrets. All current persistence is memory-only and identified as such.

**Tech Stack:** Rust 2024, `webauthn-rs` 0.5, Zcash Foundation `frost-secp256k1-tr` 2.2, `tiny_http`, serde, ring-backed test authenticator.

---

### Task 1: Distributed key generation and two-round interfaces

**Files:**
- Create: `crates/threshold-signer/src/dkg.rs`
- Create: `crates/threshold-signer/src/participant.rs`
- Modify: `crates/threshold-signer/src/lib.rs`
- Test: `crates/threshold-signer/tests/distributed_signing.rs`

1. Write tests that call a missing local 2-of-3 DKG function, compare public packages, run two participant rounds, and reject replay/substitution.
2. Run the focused test and confirm missing APIs fail compilation.
3. Wrap FROST DKG parts 1-3 so each participant owns secret state; add participant/coordinator round APIs whose public return types exclude long-lived shares and nonces.
4. Run the focused tests and existing threshold tests.

### Task 2: Real WebAuthn relying party and exact approval capability

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/wallet-core/Cargo.toml`
- Create: `crates/wallet-core/src/webauthn.rs`
- Create: `crates/wallet-core/src/node.rs`
- Modify: `crates/wallet-core/src/api.rs`
- Modify: `crates/wallet-core/src/lib.rs`
- Test: `crates/wallet-core/tests/webauthn_ceremonies.rs`

1. Write a real software-authenticator integration test for localhost registration and approval, followed by replay and intent/session/message/signer/expiry mutation cases.
2. Run it and confirm the missing wallet-node API fails compilation.
3. Add strict RP configuration, server-side one-use ceremony maps, serializable credentials, credential updates, and a private verified-approval capability.
4. Add a wallet-node façade that stores authorization internally and only lets the configured participant consume it for the bound FROST round.
5. Run focused and wallet-core tests.

### Task 3: Typed HTTP routes and local demonstrations

**Files:**
- Modify: `apps/catomicals-cli/src/wallet.rs`
- Replace: `apps/catomicals-cli/src/wallet_serve.rs`
- Modify: `apps/catomicals-cli/src/frost_demo.rs`
- Test: `apps/catomicals-cli/tests/wallet_node_http.rs`

1. Write dispatch-level tests for node/wallet/signer status, intent lifecycle, registration start/finish, approval start/finish, signing status, CORS, and secret-free payloads.
2. Run them and confirm new routes fail.
3. Route typed request/response values through the wallet-node façade; add configurable RP ID/origin and local-only HTTP versus HTTPS deployment validation.
4. Change the FROST demo to use local distributed key generation and participant/coordinator interfaces; label the dealer path test-only.
5. Run route tests and the CLI 2-of-3 demo.

### Task 4: Documentation and verification

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`

1. Document endpoints, browser calls, deployment origin rules, persistence loss, process-memory secrets, transport assumptions, and Signet-only status.
2. Run formatting, workspace tests, Clippy with warnings denied, the DKG/signing demo, and payload secret scans.
3. Inspect the diff while excluding Ouroboros runtime paths and return only the required Orbs JSON.
