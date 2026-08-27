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

The server has no Passkey registration, approval, FROST round, signature-share,
signing, or broadcast tool. MCP clients can prepare and inspect proposals. A
person reviews the decoded transaction and approves its exact intent in the web
wallet.

## Transaction inputs

`inspect_transaction` requires canonical unsigned transaction hex, exactly one
trusted prevout for each input in transaction order, the Taproot input index,
and a maximum fee. Each prevout includes `outpoint`, `value_sat`, and
`script_pubkey_hex`.

`create_transaction_intent` wraps the same object with `wallet_id`, `signer_id`,
fresh 32-byte hexadecimal `session_id`, and Unix `expiry`. It has no
`tx_digest` input. The wallet decodes the transaction and derives the
`SIGHASH_DEFAULT` message again immediately before WebAuthn approval.
