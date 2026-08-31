# CovHub Proposal Import Implementation Plan

> **For DSH:** Execute this plan test-first and return the exact Ouroboros attempt JSON requested by the supervising task.

**Goal:** Let Catomicals agents inspect a CovHub wallet proposal and create only a pending, Passkey-gated intent after the wallet independently reproduces the selected chain review.

**Architecture:** Add a strict CovHub v1 parser in the trust-bearing Rust core, verify canonical JSON and transaction hashes locally, and route decoded material through the existing `ChainSuite`. Expose read-only inspection and pending-intent creation through wallet HTTP and MCP while reusing the existing approval/signing boundaries.

**Tech Stack:** Rust, serde/serde_jcs, SHA-256, existing seven-chain suites, RMCP, walletd HTTP, TypeScript desktop proxy tests.

---

### Task 1: Proposal parser and independent review

**Files:**
- Create: `crates/wallet-core/src/covhub.rs`
- Modify: `crates/wallet-core/src/lib.rs`
- Create: `crates/wallet-core/src/tests/covhub_proposal.rs`
- Create: `schemas/covhub/covhub-canvas-v1.json`
- Create: `schemas/covhub/covhub-code-confirmation-v1.json`
- Create: `schemas/covhub/covhub-wallet-proposal-v1.json`
- Create: `schemas/covhub/fixtures/*.json`

1. Add failing tests using a real Kaspa Testnet11 review fixture. Cover unknown fields, malformed Base64, decoded material over 1,000,000 bytes, JCS digest mismatch, transaction hash mismatch, expiry, analysis-only, unsupported network, and a one-byte transaction mutation.
2. Confirm the tests fail because the parser and reviewer do not exist.
3. Implement strict contracts. Resolve a local chain suite from `ChainScope`, call `review_transaction`, and return the wallet-derived `ReviewArtifact`; never accept a proposal-provided signing digest.
4. Run `cargo test -p catomicals-wallet covhub` and commit.

### Task 2: Pending intent binding

**Files:**
- Modify: `crates/wallet-core/src/covhub.rs`
- Modify only the minimum authority-domain files needed under `crates/wallet-core/src/`
- Test: `crates/wallet-core/src/tests/covhub_proposal.rs`

1. Add failing tests proving an eligible proposal plus a matching local signer profile can create a pending intent bound to the exact `ChainScope`, review digest, signing-message digest, session, expiry, and profile.
2. Add failing tests proving no intent is created for profile drift, unavailable backend, analysis-only, expired proposal, or digest/review mismatch.
3. Preserve the Passkey gate. Do not create a `SigningJob` before approval and do not weaken existing Bitcoin intent invariants to fake multi-chain support. If the current durable intent model cannot express a chain-neutral binding safely, introduce a narrow versioned intent type and migration rather than storing Kaspa as Bitcoin Signet.
4. Run wallet-core tests and commit.

### Task 3: HTTP, MCP, and desktop bridge

**Files:**
- Modify: `apps/catomicals-cli/src/wallet_serve.rs`
- Modify: `apps/catomicals-cli/src/mcp.rs`
- Modify: `desktop/src/wallet-proxy.ts`
- Modify: `desktop/src/wallet-proxy.test.ts`
- Add focused Rust HTTP/MCP tests beside the existing modules.

1. Add failing tests for `/api/v1/covhub/proposals/inspect`, `/api/v1/covhub/proposals/intents`, MCP `inspect_covhub_wallet_proposal`, and MCP `create_covhub_signing_intent`.
2. Require the complete proposal as input; never make the wallet fetch proposal-supplied URLs. Inspection is read-only. Intent creation may only produce a pending intent.
3. Confirm the MCP tool router still exposes no approval, signing, secret, or broadcast tool.
4. Run focused Rust and desktop tests and commit.

### Task 4: Cross-repository fixture and full verification

1. Compare the three schema fixtures with `/Users/ghostcorn/.config/superpowers/worktrees/covhub/catomicals-agent-contracts/apps/runner/tests/fixtures/` and make the shared objects byte-compatible.
2. Run `cargo test -p catomicals-wallet`, the relevant Catomicals CLI tests, `pnpm --dir desktop test`, and `pnpm --dir desktop typecheck`.
3. Report changed files, exact commands, pass/fail counts, security invariants, and any remaining blocker in the final Ouroboros JSON.

