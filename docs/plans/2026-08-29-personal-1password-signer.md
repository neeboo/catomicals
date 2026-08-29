# Personal 1Password Signer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver a personal 2-of-3 FROST signer profile in which walletd holds share 1, a desktop native signer loads share 2 from 1Password after interactive approval, and an offline phone/recovery package holds share 3.

**Architecture:** A single trusted bootstrap creates one signer set and three participant packages. Walletd and the desktop signer communicate through the existing pinned mTLS transport and use the existing threshold session state machine. The desktop package is wrapped with a computer-bound key; 1Password stores only the wrapped package while the computer security store keeps the non-exportable or locally protected unwrap key. Electron and the renderer store only provider references and health state. Share bytes remain inside Rust processes, are bounded and zeroized, and are never placed in environment variables, command-line arguments, logs, temporary files, Electron IPC, or MCP responses. The first release treats the phone share as an encrypted recovery package; native phone signing is a later milestone.

**Tech Stack:** Rust, `frost-secp256k1-tr`, existing `threshold-signer`, `signer-transport`, `wallet-storage`, 1Password CLI desktop integration, Electron/Cordis, React/Vitest.

---

## Non-negotiable security contract

- The profile is 2-of-3. Daily signing uses walletd plus the desktop signer; the phone/recovery participant remains offline.
- All three shares must originate from the same signer set, epoch, group key, and public key package. Independently initialized wallet instances cannot be combined.
- 1Password unlock proves access to the vault. Catomicals still requires a separate transaction-specific approval bound to the reviewed intent, policy, Taproot sighash, signer set, epoch, session, and expiry.
- The 1Password provider uses an interactive desktop session. Service-account and Connect bearer-token environments are rejected.
- The non-secret `op://` reference may be stored in configuration. Only a device-wrapped participant package may cross a bounded OS pipe directly into the Rust signer helper. Copying that 1Password item to another device must not reveal a usable share.
- Electron, the renderer, Cordis plugins, MCP, and ordinary process supervisors must never receive the share.
- The bootstrap is explicitly a personal Signet bootstrap, not distributed DKG. Production-grade onboarding later replaces it with distributed DKG or audited resharing.

## Task 1: Personal signer-set package contract

**Files:**

- Create: `crates/threshold-signer/src/personal.rs`
- Modify: `crates/threshold-signer/src/lib.rs`
- Create: `crates/threshold-signer/tests/personal_profile.rs`

**Work:**

1. Add failing tests for a versioned personal profile created from one `run_local_dkg(3, 2)` result.
2. Define public metadata shared by all participants: profile ID, wallet ID, signer-set ID, epoch, group x-only key, public key package, threshold, and participant descriptors.
3. Define participant secret packages that bind one key package to the public profile and reject participant, group key, threshold, or epoch drift.
4. Keep serialization deterministic and bounded. Secret types must use zeroizing containers and redact `Debug` output.
5. Prove that any two packages can sign the same message and that independently generated packages are rejected.

## Task 2: Restricted 1Password share loader

**Files:**

- Create: `crates/secret-store/src/onepassword.rs`
- Modify: `crates/secret-store/src/lib.rs`
- Modify: `crates/secret-store/Cargo.toml`
- Create: `crates/secret-store/tests/onepassword.rs`

**Work:**

1. Add failing tests using a fake executable for success, timeout, oversized output, non-zero exit, malformed payload, and secret-bearing stderr.
2. Execute the configured `op` binary directly with `op read <reference>`; never invoke a shell.
3. Validate the executable and `op://` reference, clear inherited secret-token variables, and reject service-account/Connect operation.
4. Read stdout through a strict bound and timeout, sanitize all errors, discard stderr content, and return a zeroizing wrapped-package value. Unwrap only inside the Rust signer with the computer-bound key.
5. Verify no test error, display, or debug output contains the fixture share.

## Task 2.5: Device-bound package protection

Task 3 depends on this device-protection slice. It cannot be activated with a plaintext package or a software fallback.

**Files:**

- Create: `crates/secret-store/src/device_wrap.rs`
- Create: `crates/secret-store/src/platform/macos_secure_enclave.rs`
- Modify: `crates/secret-store/src/lib.rs`
- Add focused cross-platform and macOS integration tests

**Work:**

1. Define a versioned `DeviceWrappedPackageV1` and `DeviceKeyProtector` contract. Bind the AEAD associated data to profile digest, signer ID, signer epoch, device generation, key ID, provider, algorithm, and format version.
2. Generate a random data-encryption key, encrypt the participant package with XChaCha20-Poly1305, and wrap only that data-encryption key with a device key.
3. On macOS, use a Data Protection Keychain Secure Enclave P-256 key with `AccessibleWhenUnlockedThisDeviceOnly`, user presence, and private-key usage. Use Apple ECIES to wrap and unwrap the data-encryption key. Do not invoke `/usr/bin/security` and do not reuse Electron `safeStorage`.
4. Refuse software fallback when the profile requires Secure Enclave protection. Map platform errors to fixed non-secret codes and zeroize the data-encryption key and plaintext package on every path.
5. Package and sign the signer helper as an app-like helper with its own private Keychain access group before claiming production Secure Enclave support. Raw development binaries may use only a clearly labelled fake protector in tests.

## Task 3: Native desktop signer service

**Files:**

- Create: `apps/catomicals-cli/src/signer_serve.rs`
- Modify: `apps/catomicals-cli/src/main.rs`
- Modify: `apps/catomicals-cli/src/commands.rs` or the current CLI command module
- Add focused CLI integration tests under `apps/catomicals-cli/tests/`

**Work:**

1. Add a `signer serve` command that loads public configuration from a mode-0600 file, retrieves its wrapped participant package through the restricted 1Password loader, and unwraps it with a computer-bound key provider.
2. Construct a `SignerProvider` and serve it through the existing `MtlsSignerServer` with signer-set, epoch, participant, device-generation, and SPKI pin checks.
3. Keep the share inside the Rust helper. Zeroize it after provider construction or shutdown according to the backend ownership model.
4. Provide health output containing only non-secret identity and readiness fields.
5. Add a real loopback mTLS test where walletd-side share 1 and the 1Password-backed signer share 2 produce a valid BIP340 signature while share 3 stays offline.

## Task 4: Wallet-node multi-provider signing operation

**Files:**

- Create: `crates/wallet-core/src/signing_operation.rs`
- Modify: `crates/wallet-core/src/node.rs`
- Modify: `crates/wallet-core/src/intent.rs`
- Modify: `crates/wallet-core/src/gate.rs`
- Modify storage APIs/migrations only when required by the operation state machine
- Add focused wallet-core and wallet-storage tests

**Work:**

1. Replace the single-participant authorization meaning with a group authorization bound to signer set, epoch, allowed participant set, and threshold.
2. Register local and remote providers by participant ID and validate them against the public signer profile before accepting work.
3. Run remote round calls outside the wallet-wide mutex and SQLite transactions. Expose an operation ID and persist state transitions before and after network boundaries.
4. Collect two commitments, freeze one canonical signing package, collect and validate two shares, aggregate, verify, and persist the final signature.
5. Abort and burn pending nonces on expiry, context drift, participant mismatch, remote timeout, or invalid share. Preserve recovery by operation ID where the provider already produced a share.

## Task 5: Desktop/Cordis configuration and status

**Files:**

- Create a dedicated signer supervisor under `desktop/src/signers/`
- Modify the existing generic Cordis settings schema and renderer components
- Add desktop and web tests beside the affected modules

**Work:**

1. Add a Personal signer profile section with walletd, 1Password desktop signer, and phone/recovery participant status.
2. Store only enabled state, profile ID, non-secret `op://` reference, certificate references, and health state.
3. Start the Rust signer helper through a dedicated supervisor. Do not reuse the generic process manager that buffers stdout/stderr.
4. Keep passkey transaction approval separate from 1Password vault unlock in both interaction and wording.
5. Show concise indicators in their owning menus; do not add persistent status prose to the conversation shell.

## Task 6: Recovery package, documentation, and verification

**Files:**

- Create: `docs/security/personal-signer-profile.md`
- Create: `docs/operations/onepassword-desktop-signer.md`
- Update: `README.md` and `README.zh-CN.md` only with concise links/status
- Add an end-to-end test script under `scripts/` if no existing harness fits

**Work:**

1. Produce an encrypted participant-3 recovery package with an explicit checksum and restore validation. Do not claim a phone client exists yet.
2. Document loss and recovery matrices for walletd, desktop/1Password, and phone/recovery combinations.
3. Document 1Password CLI desktop integration, required interactive unlock, token-environment rejection, rotation, and revocation.
4. Run Rust workspace tests, strict lint for touched crates, desktop/web tests and type checks, the real mTLS 2-of-3 test, and secret-leak scans over process arguments, logs, test output, and generated files.
5. Review the final diff for security-contract compliance before merging to `main`. Do not restart or migrate the currently running wallet until the new profile is fully provisioned and explicitly cut over.

## Milestone boundary

The first merge is complete only when Tasks 1-3 prove a real two-process 2-of-3 signature using one signer package loaded through the restricted 1Password interface. Wallet cutover, desktop activation, and recovery workflows remain disabled until Tasks 4-6 pass their own end-to-end tests.
