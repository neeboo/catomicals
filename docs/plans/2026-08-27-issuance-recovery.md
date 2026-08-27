# OP_CAT issuance recovery implementation plan

> **For Codex:** REQUIRED SUB-SKILLS: use `superpowers:test-driven-development` for each behavior change and `superpowers:verification-before-completion` before reporting completion.

**Goal:** Recover the issuance crate as an honestly scoped OP_CAT-only proof-of-work mint gate with valid Taproot commitments, spendable owner outputs, and executable Bitcoin Inquisition evidence.

**Architecture:** Keep the issuer leaf responsible only for the committed state, supply-not-zero check, and PoW gate. Wallet verification recovers the leaf from the witness, verifies its control block against the spent P2TR output, and applies the non-consensus output/state-transition policy. Item outputs use a real owner x-only key; their payload commitment binds that owner. A BIP446 output-template variant remains documentation-only until executable covenant code exists.

**Tech stack:** Rust 2024, `rust-bitcoin` 0.32, secp256k1/BIP341 Taproot, Bitcoin Inquisition v29.4 `bitcoin-util evalscript`.

---

### Task 1: Capture failing protocol regressions

**Files:**
- Modify: `crates/issuance/src/script.rs`
- Modify: `crates/issuance/src/pow.rs`
- Modify: `crates/issuance/src/verify.rs`
- Modify: `crates/issuance/src/indexer.rs`

1. Add tests for the published BIP341 NUMS x-coordinate, minimal script pushes, `OP_DROP* OP_TRUE` termination, nonce zero, invalid x-only bytes, owner-key binding, altered control blocks, and indexer candidate scoping.
2. Run each focused test and confirm it fails for the intended missing behavior.

### Task 2: Make state and PoW encodings executable under policy flags

**Files:**
- Modify: `crates/issuance/src/state.rs`
- Modify: `crates/issuance/src/pow.rs`
- Modify: `crates/issuance/src/script.rs`

1. Encode scalar state fields with a committed nonzero field tag so zero values retain fixed width without non-minimal single-byte pushes.
2. Use a repeated committed nonzero digest prefix (`0x01`) as the PoW target, preserving the same probability as leading-zero bytes while remaining minimally pushable.
3. Compare `remaining` as bytes, drop all leftovers, then append explicit `OP_TRUE`.
4. Run focused tests until green.

### Task 3: Harden Taproot and item ownership verification

**Files:**
- Modify: `crates/issuance/src/terms.rs`
- Modify: `crates/issuance/src/verify.rs`
- Modify: `crates/issuance/src/models.rs`
- Modify: `crates/issuance/src/indexer.rs`

1. Replace the derived-secret internal key with the BIP341 NUMS point.
2. Add a real owner x-only key to mint witnesses and bind it into `item_commitment`.
3. Emit a spendable P2TR owner output; reject malformed owner keys without panicking.
4. Verify the revealed issuer leaf and control block against the spent output.
5. Limit P2TR output discovery to transactions that reveal a canonical issuer leaf and label outputs only as candidates.
6. Run focused tests until green.

### Task 4: Add executable Inquisition evidence

**Files:**
- Modify: `crates/issuance/examples/dump_issuer.rs`
- Create: `scripts/verify-issuance-inquisition.sh`

1. Emit deterministic valid, nonce-zero, wrong-nonce, altered-tail, changed-state, and exhausted-supply vectors.
2. Execute them with `-sigversion=tapscript` and `P2SH,WITNESS,TAPROOT,MINIMALDATA,CLEANSTACK,OP_CAT`.
3. Require valid and nonce-zero cases to succeed and every adversarial case to fail without `OP_SUCCESS` bypass.

### Task 5: Correct claims and measurements

**Files:**
- Modify: `docs/plans/2026-08-27-covenant-pow-issuance.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`
- Modify: `README.md`
- Delete: `scripts/patch-proc-macro-registry.sh`

1. Document the nonzero prefix encoding and spendable owner output.
2. State that OP_CAT consensus enforces only the mint gate and exhaustion check; successor and item output policy remain wallet-enforced.
3. Label BIP446 `OP_TEMPLATEHASH` as an additional opcode dependency and do not claim a hardened variant is implemented.
4. Record fresh sizes and executable evidence commands.

### Task 6: Fresh completion verification

1. Run `cargo fmt --all -- --check`.
2. Run `cargo clippy --workspace --all-targets -- -D warnings`.
3. Run `cargo test -p catomicals-issuance`.
4. Run `cargo test --workspace`.
5. Run `scripts/verify-issuance-inquisition.sh`.
6. Inspect the final diff/status while excluding `.ouroboros/`, `.orbs/`, and `.git/orbs/`.
