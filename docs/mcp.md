# Local MCP wallet adapter

Catomicals ships a standard-input/output MCP server backed by the same local
wallet node used by the browser UI. It does not load another key share or keep
a second intent store.

## Start

Run the wallet node first:

```bash
cargo run -p catomicals -- wallet serve
```

Build the CLI once so an MCP harness can launch a stable executable path:

```bash
cargo build -p catomicals
```

Use this server definition in a Codex, DeepSeek, or other MCP-compatible local
harness:

```json
{
  "mcpServers": {
    "catomicals": {
      "command": "/absolute/path/to/catomicals/target/debug/catomicals",
      "args": [
        "mcp",
        "serve",
        "--wallet-url",
        "http://127.0.0.1:18787"
      ]
    }
  }
}
```

The wallet URL is limited to unauthenticated loopback HTTP. Standard output is
reserved for MCP protocol frames; launch errors go to standard error.

## Tools

| Tool | Effect |
| --- | --- |
| `get_wallet_status` | Read wallet, node, signer, and intent state |
| `list_signing_intents` | List immutable intents |
| `read_signing_intent` | Read one intent |
| `cancel_signing_intent` | Cancel a pending intent |
| `get_chat_state` | Read the local chat transcript |
| `add_chat_message` | Add plain text without a wallet action |
| `inspect_transaction` | Decode an unsigned transaction, validate ordered prevouts and fee policy, then derive its BIP341 digest |
| `create_transaction_intent` | Repeat review and create a Passkey-gated intent using a wallet-derived digest |
| `check_protected_trade` | Verify a typed list, buy, or cancel request without creating signing authority |
| `inspect_covhub_wallet_proposal` | Strictly parse a complete `covhub.wallet-proposal/v1`, verify its canonical RFC 8785 content digest, decode and size-check the transaction material, and independently re-run the local chain suite to reproduce the review. Read-only; never accepts a CovHub-provided digest or status |
| `create_covhub_signing_intent` | Repeat full CovHub inspection and, only for an eligible unexpired digest-verified proposal matched to a local signer profile, create a **pending** intent and persist it durably in the wallet intent store |

`read_signing_intent` and `cancel_signing_intent` accept only a canonical UUID
`intent_id`; any other string is rejected before an HTTP request is built so an
id can never re-route the call to another wallet endpoint.

The server has no Passkey registration, approval, FROST round, signature-share,
signing, or broadcast tool. MCP clients can prepare and inspect proposals. A
person reviews the decoded transaction and approves its exact intent in the web
wallet.

## CovHub durable pending intents

`create_covhub_signing_intent` persists the pending intent through the wallet's
existing durable intent store, so it is visible to the same list, read, cancel,
restore, and human Passkey approval routes as every other wallet intent:

- `GET /api/v1/intents` lists it with the chain-neutral CovHub binding.
- `GET /api/v1/intents/{id}` reads it.
- `POST /api/v1/intents/{id}/cancel` cancels it while still pending.
- Reopening a durable wallet restores it unchanged.
- `POST /api/v1/intents/{id}/approve/start` and `/finish` present it to the
  human Passkey flow; the approval challenge is exactly the CovHub intent
  digest.

Only the wallet creates the durable record. The agent supplies the complete
proposal, a 64-character lowercase-hex `session_id`, and the local
`profile_id`; the wallet re-runs the chain review, mints the one-time approval
nonce, and stores the binding. The agent surface exposes no approval, Passkey
assertion capture, secret, nonce, signing, or broadcast operation.

## Transaction inputs

`inspect_transaction` requires canonical unsigned transaction hex, exactly one
trusted prevout for each input in transaction order, the Taproot input index,
and a maximum fee. Each prevout includes `outpoint`, `value_sat`, and
`script_pubkey_hex`.

`create_transaction_intent` wraps the same object with `wallet_id`, `signer_id`,
fresh 32-byte hexadecimal `session_id`, and Unix `expiry`. It has no
`tx_digest` input. The wallet decodes the transaction and derives the
`SIGHASH_DEFAULT` message again immediately before WebAuthn approval.
