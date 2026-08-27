# Foundation architecture

This repository contains the Signet-only foundation and development web UI for Catomicals covenant work. It does not authorize mainnet use.

## Components

- `catomicals-node-client` is an outbound, read-only health client. It defaults to `127.0.0.1:38332`, uses Bitcoin Core cookie authentication, calls `getdeploymentinfo`, and accepts only `chain=signet` with active `op_cat` (BIP 347). A non-loopback RPC URL requires the explicit `--allow-non-loopback` flag.
- `catomicals-wallet` creates immutable signing intents and turns a cryptographically verified WebAuthn approval into a one-time authorization. The digest binds the domain separator, protocol version, `network=signet`, action, intent and wallet IDs, signer ID, exact transaction digest, FROST session ID, expiry, and nonce.
- `catomicals-threshold` owns the signer-use seam. Each signer rechecks the session, transaction digest, signer ID, expiry, one-time authorization state, key-package identity, and FROST nonce claim before producing a share.
- `catomicals-issuance` builds a single-leaf P2TR proof-of-work gate for Bitcoin Inquisition. The OP_CAT leaf enforces the current leaf's PoW and rejects tagged `remaining = 0`. Wallet verification separately checks the revealed leaf/control block, owner-bound spendable item output, canonical successor, values, and fees. Those output and successor rules are client policy because this leaf does not introspect outputs.
- `catomicals-trading` scopes one issuance-verified item receipt into a two-leaf P2TR fixed-price order. Its buy and height-locked cancel leaves commit the listing and require a seller `SIGHASH_DEFAULT` signature. Separate agent and wallet implementations decode the unsigned raw transaction, verify ordered prevouts, authenticate buyer ownership, classify exact outputs, and derive the BIP341 sighash.
- `catomicals` exposes node health, development demonstrations, and the typed wallet-node HTTP adapter. Mock Passkey approval cannot enter the wallet authorization gate; approval finish calls the embedded relying party directly.

## Signing flow

1. The wallet creates a Signet Taproot-transaction intent with a fresh nonce.
2. The relying party generates a fresh WebAuthn challenge and stores its one-use authentication state beside the immutable intent digest, signer ID, session ID, exact message, and expiry.
3. The embedded relying party checks the credential, challenge, signature, exact origin, RP ID hash, authenticator flags, and counter policy; the node then rechecks every stored intent binding.
4. The gate issues a one-time authorization with `issued_at` and `expiry`.
5. A signer share checks all bindings and current time, then atomically claims its FROST nonce in the local guard.
6. Two shares from the three-participant set aggregate into a 64-byte BIP340 signature. Tests verify that signature with both `frost-secp256k1-tr` and the independent `rust-secp256k1` implementation.

The wallet node embeds a `webauthn-rs` relying party. Registration and authentication ceremony state is server-side and one-use. Each approval state freezes the canonical intent digest, local participant, FROST session, message, and expiry; only successful browser verification installs an internal signer authorization.

The threshold crate exposes DKG participant flow plus explicit FROST participant/coordinator rounds. A participant returns public commitments in round one and can produce a signature share in round two only after consuming an exact-bound authorization. The local 2-of-3 demonstration uses the Zcash Foundation DKG and verifies the aggregate BIP340 signature.

## Protected trading flow

1. An issuance-verified receipt identifies one seller-controlled item outpoint, its issuance identity and rules, and its exact sat amount.
2. A list transaction preserves that amount in the canonical two-leaf order output. Extra funding pays the network fee.
3. A buyer proposal spends the order outpoint, preserves the item amount to the authenticated buyer key, and pays the exact seller price and fixed creator fee. The buyer signs a proposal commitment covering the listing, transaction, ordered prevouts, key, and proposal expiry.
4. The agent dry-run and wallet intent endpoint perform separate raw-transaction verification. The wallet chooses the BIP341 message and stores the original request beside the intent.
5. Immediately before WebAuthn approval starts, the wallet repeats its verifier against the current trusted Signet height. FROST signs only the exact derived message after Passkey approval.
6. At the committed height, the cancel leaf becomes valid and returns the preserved item amount to the seller's cancellation script. Buy and cancel spend the same order outpoint; Bitcoin confirmation ordering selects at most one winner.

The seller signature enforces the exact signed transaction under Bitcoin consensus. OP_CAT does not inspect or classify outputs here. A buy signed before expiry may confirm after expiry and race a mature cancel. The implementation makes no miner-ordering or first-seen fairness claim.

All current stores and secrets remain in memory. The local DKG router, intent store, WebAuthn credential store, ceremony maps, authorization replay set, signer nonce guard, and key package are development foundations. A production design still needs isolated durable secret storage, atomic crash-safe replay state, authenticated inter-signer transport, consistent broadcast, backup/recovery, operational access control, and an independent review.

## Network boundary

The Rust intent type has only a `Signet` network variant, node identity rejects every other chain, and the supplied configuration selects Signet. Mainnet signing and deployment are prohibited. Removing that boundary requires a new protocol version, an independent security review, migration design, and explicit operator controls; changing a configuration string is insufficient.

## Issuance opcode boundary

The implemented leaf depends on BIP347 `OP_CAT` and standard Taproot operations. It does not use BIP446 `OP_TEMPLATEHASH`. Adding an output-template variant would be a separate protocol with an additional opcode dependency and new executable evidence; it cannot be presented as an OP_CAT-only property.
