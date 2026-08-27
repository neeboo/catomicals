# Self-hosted wallet node

The wallet node is a Signet-only development service. It is both a WebAuthn relying party and one FROST participant. It never returns a FROST key package, DKG secret package, signing nonce, one-time authorization, or long-lived key share from HTTP.

## Start locally

```bash
cargo run -p catomicals -- wallet serve \
  --addr 127.0.0.1:18787 \
  --rp-id localhost \
  --rp-origin http://localhost:5173 \
  --cors-origin http://localhost:5173
```

The default origin is the local Vite development server; the typed API listens on port 18787. The command runs a local 2-of-3 DKG and retains participant 1. This provisioning path is ephemeral development code: one process briefly creates all local participants, discards two participants, and loses the remaining share on restart. It is not suitable for real custody.

For a remote deployment, terminate TLS at a trusted reverse proxy, set an exact HTTPS origin such as `https://wallet.example`, set the stable RP ID such as `wallet.example`, and opt into the non-loopback bind. The proxy must preserve request bodies, must not log WebAuthn responses, and must enforce application authentication and request-rate limits. The service validates the signed browser origin; CORS alone is not treated as authentication.

## Typed HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/node/status` | Signet, RP, persistence, and custody limits |
| `GET` | `/api/v1/wallet/status` | wallet, node, threshold, credential, and intent status |
| `GET` | `/api/v1/signer/status` | local participant and public group-key status |
| `GET` | `/api/v1/chat/state` | list in-memory chat messages and the count of wallet actions awaiting Passkey approval |
| `GET` | `/api/v1/chat/messages/{id}` | read one secret-free chat message with its current intent projection |
| `POST` | `/api/v1/chat/messages` | add text and optionally create one exact-bound signing intent |
| `POST` | `/api/v1/intents` | create an immutable Signet signing intent |
| `GET` | `/api/v1/intents` | list intents |
| `GET` | `/api/v1/intents/{id}` | read one intent |
| `POST` | `/api/v1/intents/{id}/cancel` | cancel a pending intent |
| `POST` | `/api/v1/transactions/inspect` | decode an unsigned transaction, verify ordered prevouts and fee policy, and derive its BIP341 digest |
| `POST` | `/api/v1/transactions/intents` | repeat transaction review and create a Passkey-gated intent using the wallet-derived digest |
| `GET` | `/api/v1/transactions/intents/{id}` | repeat review and display the full stored transaction binding |
| `POST` | `/api/v1/trades/verify` | independently dry-run a raw list, buy, or cancel request with agent policy |
| `POST` | `/api/v1/trades/intents` | wallet-verify a raw trade, derive its BIP341 digest, and create a Passkey-gated intent |
| `GET` | `/api/v1/trades/intents/{id}` | repeat wallet policy and display the stored trade binding |
| `POST` | `/api/v1/webauthn/register/start` | start browser Passkey registration |
| `POST` | `/api/v1/webauthn/register/finish` | verify and store the browser registration response |
| `GET` | `/api/v1/webauthn/credentials` | list public credential summaries |
| `POST` | `/api/v1/intents/{id}/approve/start` | start an assertion bound server-side to one intent and signer |
| `POST` | `/api/v1/intents/{id}/approve/finish` | verify the browser assertion and release one internal signer action |
| `GET` | `/api/v1/signing/{id}/status` | read the threshold-signing phase and public binding |

`CreateIntentRequest` uses `tx_digest` and `session_id` as 64-character hex strings. All success and error responses are JSON. Approval finish has no development override and accepts only the `PublicKeyCredential` returned by `navigator.credentials.get()`.

The generic `/api/v1/intents` route remains an opaque low-level development
primitive. A transaction intended for user review must use
`/api/v1/transactions/intents`. That route accepts complete unsigned
transaction data and has no caller-selected digest. The node requires one
trusted previous output per input in exact order, enforces the declared fee
ceiling, derives the BIP341 key-spend message, stores the original request, and
repeats review before starting WebAuthn.

## Chat wallet boundary

`POST /api/v1/chat/messages` accepts a required `content` string and one
optional typed `wallet_action`. The only wallet-affecting chat action is
`sign_taproot_transaction`:

```json
{
  "content": "Prepare this exact Taproot signing action",
  "wallet_action": {
    "type": "sign_taproot_transaction",
    "wallet_id": "00000000-0000-0000-0000-000000000001",
    "signer_id": 1,
    "tx_digest": "0000000000000000000000000000000000000000000000000000000000000000",
    "session_id": "1111111111111111111111111111111111111111111111111111111111111111",
    "expiry": 1800000600
  }
}
```

The node validates the same signer and expiry rules as `/api/v1/intents`,
creates an immutable pending `SigningIntent`, and returns a public binding with
the intent digest, action, wallet, signer, transaction digest, FROST session,
expiry, lifecycle status, and `passkey_required` authorization state. Chat
responses do not serialize the intent nonce, FROST material, credential
response, one-time authorization, or any verifier.

Both request types use `deny_unknown_fields`. Caller-supplied fields such as
`approved`, `credential`, `assertion`, or `verifier` are rejected as invalid
JSON. There is deliberately no `/api/v1/chat/.../approve` endpoint. A chat
action remains a proposal until the existing
`/api/v1/intents/{id}/approve/start` and `/finish` WebAuthn ceremony succeeds.
The web `/chat` route links each pending action to that exact intent review and
approval screen.

Chat retains at most 500 messages (250 user/wallet exchanges), and the HTTP
adapter rejects request bodies larger than 1 MiB before JSON dispatch. The
generic chat signing action binds an opaque caller-supplied digest; it does not
decode a raw transaction or explain outputs and fees. Use the protected-trade
intent API when its transaction-aware policy applies, and do not treat the
generic digest display as production transaction review.

Protected trades must use `/api/v1/trades/intents`; that request has no caller-selected transaction digest. It contains the typed list, buy, or cancel request with canonical raw unsigned transaction hex and one ordered previous output per input. The wallet requires a trusted active Signet node snapshot, performs its own verification, derives the `SIGHASH_DEFAULT` BIP341 message, and saves the immutable trade request. `/approve/start` repeats wallet verification at the latest snapshot height before it creates any WebAuthn challenge. `/api/v1/trades/verify` runs the separate agent implementation and does not create an intent or signing authority.

## Browser ceremonies

Registration starts with a JSON body containing `label`, `user_name`, and `display_name`. Convert the returned base64url challenge, user ID, and excluded credential IDs to `ArrayBuffer` values before calling `navigator.credentials.create()`. Send its result, using the ordinary WebAuthn JSON representation, as `credential` together with the opaque `ceremony_id` to the finish endpoint.

Initial enrollment trusts the local operator: the first valid registration claims the in-memory wallet, and later registrations are locked, including ceremonies that raced with the winner. Start the node only on a trusted host and enroll immediately. A production deployment needs a separate authenticated bootstrap channel or one-use operator secret.

Approval follows the same pattern with `navigator.credentials.get()`. The start response includes a public `binding` for display: intent digest, signer ID, FROST session ID, exact message digest, and expiry. The node also stores that binding alongside the one-use WebAuthn authentication state. Finish removes the state before verification. A failed attempt, a replay, another intent ID, any changed immutable intent field, or expiry cannot release participation.

`webauthn-rs` requests required user verification and verifies the signed challenge, operation type, exact origin, RP ID hash, user-presence flag, user-verification flag, authenticator signature, credential ID, and signature counter. Successful authentication updates the stored counter and backup state.

## Persistence and custody limits

All state is process memory only: chat messages, credentials, ceremony state, intents, used intent nonces, FROST nonces, authorizations, and the participant key package. There is no encrypted database, filesystem key format, hardware-backed key, atomic crash recovery, backup, recovery ceremony, authenticated remote participant transport, or multi-process locking. Restart loses chat history and replay history as well as keys and credentials, so the service must not protect assets with real-world value.

The DKG library interface implements all three Zcash Foundation FROST DKG parts. Its local router only demonstrates message flow. A deployment needs authenticated consistent broadcast for round one and confidential authenticated point-to-point delivery for round two. The legacy trusted-dealer helper remains test-only.
