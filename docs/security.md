# Security status and boundaries

## Status

This code is a development foundation for Bitcoin Inquisition Signet. It has not received an independent Catomicals security audit and must not hold or sign for assets with real-world value.

`frost-secp256k1-tr` 2.2 is used for the 2-of-3 threshold BIP340 path. Catomicals has not commissioned or completed an independent audit of this dependency or of its integration here. The tests prove interoperability and reject the covered failure cases; they do not constitute a cryptographic audit. Mainnet use is prohibited.

## Enforced properties

- The intent digest binds protocol version 1, Signet, the Taproot-transaction signing action, wallet ID, signer ID, exact transaction digest, FROST session ID, expiry, and a fresh nonce. The intent ID is also bound.
- Structural and callback-based approval verifiers are compiled only into package unit tests. The production crate does not export them, and neither `WalletApi` nor `AuthorizationGate` exposes a verifier-injection method. Only the crate-private capability returned by the complete WebAuthn relying-party finish ceremony can issue a production signing authorization.
- The CLI and HTTP surfaces refuse mock approvals. The self-hosted HTTP service accepts approval only through its complete WebAuthn relying-party finish ceremony.
- Chat can create and read proposals, but it cannot approve or sign. Its typed request rejects unknown authorization fields, it exposes no approval route, and its response projection omits intent nonces, credential responses, verifier inputs, one-time authorizations, and signer secrets. A chat-created action reaches the signer only through the same exact-bound WebAuthn intent ceremony as every other signing intent.
- The wallet node now embeds `webauthn-rs` and stores registration/authentication ceremony state server-side. It requires user verification and verifies challenge, operation type, exact origin, RP ID hash, user presence, user verification, credential signature, and signature counter. Ceremony state is removed before finish verification.
- The first successful local registration claims the in-memory wallet. Concurrent bootstrap ceremonies cannot add another credential after that first finish, but production still needs a separately authenticated bootstrap channel; localhost development assumes a trusted host and immediate enrollment.
- An approval ceremony is frozen to the intent ID and digest, participant ID, exact FROST session, exact message, and expiry. Successful verification creates an internal authorization; no HTTP response contains that authorization.
- Authorizations record their real issuance time. Expiry is checked when authorization is issued and checked again immediately before a signer produces a share.
- Authorizations are one-time and exact-bound. Wrong session, wrong transaction digest, wrong signer, expired use, and second use are rejected.
- FROST nonces are fingerprinted and rejected on any repeated claim, including a repeated claim in another session.
- The 2-of-3 acceptance test produces a 64-byte aggregate signature and verifies it using an independent BIP340 implementation. It also proves wrong-message, wrong-signer, and nonce-reuse rejection.
- Node RPC defaults to loopback, uses cookie authentication, and requires an explicit opt-in for non-loopback URLs. Node health calls `getdeploymentinfo` and requires active BIP 347 / `OP_CAT` on Signet.
- The issuance leaf uses BIP341's published NUMS x-only point rather than deriving an internal key from a known public scalar. Its state constants use tagged fixed-width encoding, its repeated `0x01` PoW prefix is minimally pushable, and it ends with cleanstack `OP_TRUE`.
- The issuance verifier recovers the leaf from the witness and verifies its control block against the spent P2TR output. The item commitment binds a validated owner x-only key, and the item output is spendable by that owner.
- A fixed-price listing commitment binds Signet, the scoped item outpoint and issuance identity, seller key and payout, price, fixed creator fee, item sat amount, cancellation recipient, expiry height, and maximum network fee. The order uses the BIP341 NUMS internal key and has only committed buy and cancel leaves.
- Buy proposals authenticate the buyer x-only key with an independent BIP340 proof over the listing, order outpoint, unsigned transaction ID, ordered prevouts, buyer key, and proposal expiry. Both agent and wallet APIs independently decode and verify raw unsigned transactions; the wallet derives the BIP341 `SIGHASH_DEFAULT` message and repeats policy before WebAuthn approval.
- Executable Bitcoin Inquisition vectors prove valid buy and mature cancel leaves, then prove a copied seller signature fails after seller-payout, creator-fee, or buyer-recipient substitution. Rust tests additionally reject partial witnesses, changed prevouts, wrong ownership proofs, amount changes, premature cancellation, and excessive fees.
- Two buyers and buy-versus-cancel are represented as competing spends of one order outpoint. Candidates expose submitted, pending, confirmed, and conflicted states. Confirmation marks every loser conflicted; submission order carries no fairness guarantee.

## Known gaps before any production consideration

- The Zcash Foundation DKG is implemented and exercised locally, but deployment still needs authenticated consistent broadcast and confidential authenticated round-two delivery. The trusted-dealer helper is test-only.
- Chat history, credentials, ceremony state, intent replay state, signer nonce state, and the participant key package are all in memory. They are not durable, encrypted at rest, atomic across crashes, backed up, or hardware isolated.
- The typed HTTP API has no application login, operator authorization, or built-in rate limiter. It defaults to loopback and caps each body at 1 MiB plus chat history at 500 messages; any non-loopback deployment still requires an authenticating, rate-limiting reverse proxy. CORS is not authentication.
- Codex and DeepSeek harnesses can launch the local stdio MCP adapter. It only connects to unauthenticated loopback HTTP and exposes proposal, inspection, cancellation, chat, and status tools. Passkey approval, FROST rounds, signature shares, signing, and broadcast are absent from the tool surface. Remote MCP transport and authentication are not implemented.
- The CLI's ephemeral local DKG creates all three participants in one process before discarding two. It demonstrates integration and is not distributed custody.
- There is no hardened key custody, remote signer protocol, policy engine, transaction parser/display, backup/recovery ceremony, incident response, or dependency audit.
- Bitcoin Inquisition activates experimental consensus changes on Signet. Its behavior is not evidence that a covenant is valid or available on Bitcoin mainnet.
- The OP_CAT issuance leaf cannot inspect outputs. It does not consensus-enforce an item output, owner, successor state, decrement, fee, or continuation. Those checks are wallet policy, and an otherwise valid gate spend can stop or diverge from that policy.
- The protected-trade leaves commit listing data but do not parse outputs. Exact seller payment, creator fee, recipient, and preserved item amount are protected by the seller's `SIGHASH_DEFAULT` signature plus wallet policy. This is a cooperative signed order, not a permissionless output-introspection covenant. Caller-supplied prevouts must ultimately match the Signet UTXO set or the signature will be invalid on chain; production still needs authenticated RPC-backed prevout resolution inside the verifier.
- Listing expiry controls new wallet approvals, and the cancel leaf uses `OP_CHECKLOCKTIMEVERIFY`. A buy signed before expiry remains a valid Bitcoin transaction afterward and can contend with cancellation. Miner ordering decides which spend confirms; no fairness property is claimed.
- BIP446 `OP_TEMPLATEHASH` is only identified as a possible additional dependency. No hardened template variant is implemented or claimed.

No operator should remove the Signet restriction until these gaps are closed and the complete system, including `frost-secp256k1-tr`, has passed independent cryptographic and application security review.
