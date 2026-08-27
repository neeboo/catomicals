# MCP and Transaction Review Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add wallet-owned Bitcoin transaction review and a real local stdio MCP server without exposing Passkey approval or FROST signing to agents.

**Architecture:** A pure transaction-review module decodes unsigned Bitcoin transactions, validates ordered prevouts and fee policy, and derives a BIP341 key-spend digest. The wallet stores reviewed requests beside intents and rechecks them before WebAuthn. The MCP process uses the official Rust SDK and delegates atomic tools to the existing loopback HTTP node so UI and agents share state.

**Tech Stack:** Rust 2024, rust-bitcoin 0.32, serde, tiny_http, rmcp 3.1, tokio, reqwest, React 19, TypeScript, TanStack Router/Query.

---

### Task 1: Define and implement transaction review

**Files:**
- Create: `crates/wallet-core/src/transaction.rs`
- Modify: `crates/wallet-core/src/lib.rs`
- Test: `crates/wallet-core/src/transaction.rs`

1. Write failing tests for a valid Taproot key-spend review, reordered
   prevouts, duplicate inputs, witness-bearing input, negative fee, excessive
   fee, and out-of-range signing input.
2. Run the focused tests and confirm failure because the review API is absent.
3. Add strict request/response types, decoding, script classification, amount
   accounting, warnings, and BIP341 digest derivation.
4. Run focused tests and confirm all review vectors pass.

### Task 2: Bind reviewed transactions to wallet intents

**Files:**
- Modify: `crates/wallet-core/src/node.rs`
- Modify: `crates/wallet-core/src/tests/transaction_review.rs`
- Modify: `crates/wallet-core/src/lib.rs`

1. Write failing service tests proving that the caller cannot select the
   digest, the created intent equals the derived digest, and approval start
   rejects a stored request that no longer passes review.
2. Add `inspect_transaction`, `create_transaction_intent`, and
   `transaction_review` methods plus the stored request map.
3. Re-run the focused wallet tests.

### Task 3: Add typed HTTP routes

**Files:**
- Modify: `apps/catomicals-cli/src/wallet_serve.rs`

1. Write failing route tests for `POST /api/v1/transactions/inspect`,
   `POST /api/v1/transactions/intents`, and
   `GET /api/v1/transactions/intents/{id}`.
2. Implement strict parsing, typed errors, and secret-free responses.
3. Run the CLI route tests.

### Task 4: Add transaction review UI

**Files:**
- Modify: `web/src/lib/types.ts`
- Modify: `web/src/lib/api.ts`
- Modify: `web/src/lib/hooks.ts`
- Modify: `web/src/routeTree.ts`
- Modify: `web/src/routes/root.tsx`
- Create: `web/src/routes/transactions.tsx`

1. Add exact TypeScript request and response contracts.
2. Add a `/transactions` screen for raw transaction, ordered prevout JSON,
   input index, fee ceiling, inspection result, warnings, and reviewed intent
   creation.
3. Link a created intent to the existing Passkey review screen.
4. Run typecheck and production build.

### Task 5: Implement the stdio MCP server

**Files:**
- Modify: `Cargo.toml`
- Modify: `apps/catomicals-cli/Cargo.toml`
- Modify: `apps/catomicals-cli/src/main.rs`
- Create: `apps/catomicals-cli/src/mcp.rs`
- Test: `apps/catomicals-cli/src/mcp.rs`

1. Write failing tests for the exact tool list, shared-state reads, transaction
   inspection, reviewed intent creation, typed wallet errors, and the absence
   of approval/signing tools.
2. Add the official `rmcp` SDK, async runtime, loopback-only HTTP client, tool
   schemas, rich structured results, and `catomicals mcp serve`.
3. Run MCP protocol tests through the SDK client transport.

### Task 6: Document and verify

**Files:**
- Modify: `README.md`
- Modify: `docs/wallet-node.md`
- Modify: `docs/web-wallet.md`
- Modify: `docs/security.md`
- Create: `docs/mcp.md`

1. Document launch configuration for Codex and DeepSeek harnesses, the
   transaction-review contract, the capability map, and the user-only approval
   boundary.
2. Run formatting, Clippy, all workspace tests, frontend typecheck/build,
   Inquisition issuance/trading vectors, an MCP stdio smoke test, and browser
   verification.
3. The repository currently has no `HEAD`; defer commit steps until an initial
   commit exists or the user requests one.

