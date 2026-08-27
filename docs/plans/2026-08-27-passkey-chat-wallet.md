# Passkey-Gated Chat Wallet Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a minimal in-memory chat surface whose wallet-action proposals create immutable signing intents and can only be approved through the existing WebAuthn ceremony.

**Architecture:** `WalletNodeService` owns in-memory chat messages beside intents and projects current intent state into secret-free chat responses. The HTTP adapter exposes typed list/read/create chat routes; chat accepts only text plus an optional typed signing proposal and has no approval endpoint. The React route uses those APIs, then sends users to the existing intent detail page for exact-bound Passkey approval.

**Tech Stack:** Rust 2024, serde, tiny_http, React 19, TypeScript, TanStack Router and Query, Tailwind CSS v4.

---

### Task 1: Define chat lifecycle and security boundary

**Files:**
- Create: `crates/wallet-core/src/chat.rs`
- Modify: `crates/wallet-core/src/lib.rs`
- Test: `crates/wallet-core/src/chat.rs`

1. Write tests for text-message lifecycle, wallet-action validation, and secret-free public projections.
2. Run the focused wallet-core tests and confirm failure because chat types do not exist.
3. Implement typed chat requests, messages, roles, kinds, intent bindings, validation, and in-memory storage.
4. Run the focused tests and confirm they pass.

### Task 2: Integrate chat with wallet intents

**Files:**
- Modify: `crates/wallet-core/src/node.rs`
- Test: `crates/wallet-core/src/tests/chat_wallet.rs`
- Modify: `crates/wallet-core/src/lib.rs`

1. Write service tests proving ordinary messages create no intent, wallet actions create an exact-bound pending intent, current intent state is projected into chat, and no chat method can authorize signing.
2. Run the focused tests and confirm failure for missing service methods.
3. Add list/read/create chat methods that delegate wallet actions to the existing intent creation path and expose no authorization capability.
4. Run the focused tests and confirm they pass.

### Task 3: Add typed HTTP routes and boundary tests

**Files:**
- Modify: `apps/catomicals-cli/src/wallet_serve.rs`

1. Write route tests for `GET /api/v1/chat/state`, `GET /api/v1/chat/messages/{id}`, and `POST /api/v1/chat/messages`, including unknown verifier/approval fields and nonexistent chat approval routes.
2. Run the CLI test target and confirm the new route tests fail.
3. Implement the routes and typed error mapping with strict unknown-field rejection.
4. Run the CLI tests and confirm they pass.

### Task 4: Add the web chat page

**Files:**
- Modify: `web/src/lib/types.ts`
- Modify: `web/src/lib/api.ts`
- Modify: `web/src/lib/hooks.ts`
- Modify: `web/src/routeTree.ts`
- Modify: `web/src/routes/root.tsx`
- Create: `web/src/routes/chat.tsx`

1. Add exact TypeScript response/request types and query/mutation hooks.
2. Add `/chat` to the router and navigation.
3. Implement a monochrome conversation view with text composer, explicit signing-action fields, approval-required cards, typed error/loading/empty states, and links to the existing Passkey approval screen.
4. Run TypeScript checking and the production build.

### Task 5: Document and verify

**Files:**
- Modify: `README.md`
- Modify: `docs/wallet-node.md`
- Modify: `docs/web-wallet.md`

1. Document the chat route, typed APIs, exact binding, memory-only state, and absence of a chat authorization override.
2. Run formatting, wallet-core tests, workspace tests, CLI tests, web typecheck, and web build.
3. Inspect the final diff while excluding `.ouroboros/`, `.orbs/`, and `.git/orbs/`.
