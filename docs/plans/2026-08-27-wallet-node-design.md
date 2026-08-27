# Self-hosted wallet node design

## Scope and security boundary

The wallet node is a self-hosted WebAuthn relying party and one FROST participant. It is Signet-only. A browser may register a Passkey and complete an approval ceremony; agents may create and inspect immutable signing intents but cannot mint approvals. The HTTP surface only serializes public status, WebAuthn browser options and results, intent metadata, FROST commitments/signature status, and aggregate signatures. Long-lived key packages, DKG round-two packages, signing nonces, and one-time authorizations remain Rust-only values without API serialization.

`webauthn-rs` performs the complete relying-party verification. Registration and authentication request state remains server-side and is removed before finish verification, so a response cannot be replayed even after a failed attempt. Authentication requests are stored together with the intent ID, canonical intent digest, signer ID, exact FROST session ID, exact 32-byte message, and expiry. Finish re-reads the intent and compares every binding before releasing a private one-time authorization. The library requires user verification and validates challenge, type, origin, RP ID hash, user presence, authenticator signature, and signature counter. Credential counter and backup-state updates are applied after successful authentication.

The default development RP is `localhost` at `http://localhost:18787`. Configuration accepts an explicit RP ID and origin; non-local deployment origins must use HTTPS. The service rejects an origin whose host is outside the RP ID boundary.

## Threshold protocols

The threshold crate exposes stateful participant and coordinator interfaces. Each participant retains its own key package, signing nonces, and nonce replay guard. Round one returns only public commitments. Round two accepts an exact signing package and consumes a `SigningAuthorization`; message/session/signer substitutions and duplicate round-two calls fail. The coordinator collects unique commitments and shares, builds the signing package, aggregates at the threshold, and verifies the BIP340 result.

Distributed key generation wraps the Zcash Foundation `frost-secp256k1-tr` three-part DKG. Each local participant owns its round-one and round-two secret state. The local 2-of-3 demonstration simulates authenticated broadcast/confidential delivery in one process and confirms every participant derives the same public package. The existing trusted-dealer helper remains available only under an explicitly test-only name and warning.

## Persistence and testing

This first node deliberately stores credentials, ceremony state, intents, authorization replay state, FROST nonces, and key material in process memory. Restart loses all state. It has no encrypted-at-rest secret store, atomic crash recovery, authenticated remote participant transport, backup, or hardware isolation. Status and documentation expose these limitations, and the CLI refuses to imply production readiness.

Tests construct a software WebAuthn authenticator with a real P-256 key. They complete registration and authentication against localhost and then mutate origin, RP ID hash, challenge, UV/UP flags, signature, intent, signer, session, message, expiry, and ceremony ID. Tests cover replay, substitution, counter updates, exact authorization consumption, local DKG, and 2-of-3 aggregate signing. HTTP dispatch tests assert typed routes and scan every payload for secret-field names.
