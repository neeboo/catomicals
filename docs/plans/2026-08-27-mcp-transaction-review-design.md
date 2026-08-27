# MCP and transaction review design

## Goal

Give Codex, DeepSeek, and other MCP clients the same proposal and inspection
capabilities as the local wallet UI while keeping WebAuthn approval and FROST
signing unavailable to agents.

## Approaches considered

1. Run a separate wallet inside the MCP subprocess. This is simple, but it
   creates a second in-memory key set and splits intents from the browser UI.
2. Mount Streamable HTTP MCP inside the wallet node. This gives one process,
   but requires replacing the current synchronous HTTP server and defining
   remote MCP authentication before the product needs remote transport.
3. Run a local stdio MCP adapter that calls the wallet node's typed loopback
   HTTP API. This shares state with the UI, follows the standard local MCP
   launch model, and keeps the custody boundary in one service.

The first implementation uses option 3. Streamable HTTP remains future work.

## Transaction review contract

`POST /api/v1/transactions/inspect` accepts:

- canonical unsigned transaction hex;
- one ordered previous-output record for every input, including the exact
  outpoint, amount, and script pubkey;
- the input index whose Taproot key-spend digest is requested;
- a caller-visible maximum fee in satoshis.

The wallet decodes the transaction itself and rejects witness-bearing inputs,
coinbase transactions, duplicate inputs, missing or reordered prevouts,
negative fees, invalid scripts, an out-of-range input index, and fees above the
declared ceiling. The result includes txid, version, locktime, size, weight,
vsize, input/output totals, fee and feerate, RBF signalling, classified inputs
and outputs, Signet addresses where available, warnings, and the BIP341
`SIGHASH_DEFAULT` key-spend digest.

`POST /api/v1/transactions/intents` takes the same review request plus wallet,
signer, FROST session, and expiry fields. It derives the signing digest from the
decoded transaction, creates a pending intent, and stores the original request.
The wallet repeats the review immediately before starting WebAuthn approval.
The caller never supplies the digest for this route.

## MCP surface

The stdio server exposes atomic tools:

- `get_wallet_status`
- `list_signing_intents`
- `read_signing_intent`
- `cancel_signing_intent`
- `get_chat_state`
- `add_chat_message`
- `inspect_transaction`
- `create_transaction_intent`
- `check_protected_trade`

Tool results return the same JSON objects used by the UI. MCP exposes no
registration, WebAuthn approval, FROST round, signature-share, or broadcast
tool. A user must review and approve an intent in the browser.

## Capability map

| User capability | UI | MCP | Status |
| --- | --- | --- | --- |
| Read wallet state | Overview | `get_wallet_status` | covered |
| Read intents | Intents | `list_signing_intents`, `read_signing_intent` | covered |
| Cancel pending intent | Intent detail | `cancel_signing_intent` | covered |
| Read and add chat messages | Chat | `get_chat_state`, `add_chat_message` | covered |
| Inspect raw transaction | Transactions | `inspect_transaction` | new |
| Create reviewed signing intent | Transactions | `create_transaction_intent` | new |
| Check protected trade | Typed API | `check_protected_trade` | covered by MCP |
| Register or approve with Passkey | Passkeys / intent detail | unavailable | user-only |
| Produce FROST share or broadcast | no UI | unavailable | custody-only |

## Testing

Pure Rust tests cover decoding, ordered prevouts, totals, fee ceilings, output
classification, and Taproot digest derivation. Wallet-node tests prove intent
creation binds the derived digest and approval re-runs the review. HTTP tests
cover the two typed routes and reject caller-supplied digest or approval fields.
MCP protocol tests use the official Rust SDK client to list and call tools over
an in-process transport, then verify shared wallet state through the HTTP
adapter. Browser testing covers transaction inspection and the link to Passkey
review.

