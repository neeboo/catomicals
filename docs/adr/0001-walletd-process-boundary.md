# ADR 0001: `walletd` is the wallet authority and sole writer

- Status: Accepted for B0
- Date: 2026-08-27
- Scope: local wallet runtime, desktop host, web client, MCP adapters, signers

## Context

The current `catomicals wallet serve` process owns wallet state in memory. The web client and the local MCP adapter use its HTTP API, while the MCP adapter deliberately omits approval, FROST, signing, and broadcast tools. Durable storage, the desktop host, executor adapters, and plugin settings will add more clients to the same wallet.

Giving those clients direct database or signer access would create several competing authorities. It would also let a compromised renderer or agent bypass the review and pre-sign checks performed by the wallet.

## Decision

`walletd` is the single authoritative process for wallet state and the sole writer of the authoritative wallet database.

All clients use a typed local interface:

```text
web / desktop renderer / CLI / MCP / executor
                    |
                    v
          desktop typed bridge or local API
                    |
                    v
                 walletd
       /             |              \
policy registry  node adapter  threshold signer
```

The desktop host may supervise `walletd`, protect host settings with operating-system facilities, and host executors and Cordis plugins. It does not open the wallet database, hold plaintext FROST shares, or manufacture signing authorization.

### Authoritative request sequence

1. A client asks `walletd` to inspect complete transaction material.
2. `walletd` resolves chain facts through the trusted node adapter and returns a review reference.
3. A client may create a pending intent bound to the reviewed material, policy hash, and node snapshot.
4. A human completes the required approval ceremony through the trusted wallet interface.
5. Immediately before signing, `walletd` re-reads the intent, policy, prevouts, chain snapshot, authorization, and nonce state.
6. Only `walletd` may release a request to the threshold signer and decide whether a signed transaction is eligible for broadcast.

Proposal review and pre-sign review are independent checks. A cached UI card or agent summary is never signing authority.

### Agent and MCP boundary

The wallet MCP v1 surface is frozen to these nine wire names:

- `get_wallet_status`
- `list_signing_intents`
- `read_signing_intent`
- `cancel_signing_intent`
- `get_chat_state`
- `add_chat_message`
- `inspect_transaction`
- `create_transaction_intent`
- `check_protected_trade`

This surface can read state, verify proposals, add plain chat messages, create pending intents, and cancel pending intents. It cannot approve, activate a signer, run a FROST round, produce a signature share, sign, or broadcast.

Plugin configuration uses a separate desktop-host capability family. Agents may read plugin metadata and health, validate a patch, and create a `plugin_settings_intent`. There is no agent-callable direct apply operation. After human confirmation, the host re-reads the current plugin version and secret references, validates and migrates in isolation, performs health checks, and promotes the candidate only when it is healthy.

### Data ownership

| Data | Authority | Other components |
| --- | --- | --- |
| intents, approvals, authorizations, nonce claims, broadcasts | `walletd` | reference by immutable identifier |
| policy documents, artifacts, activations | policy registry, consumed by `walletd` | reference by `policy_hash` |
| chain facts used for signing | node adapter, snapshotted by `walletd` | indexer may project them |
| chat and tool presentation | agent runtime / desktop host | cannot grant signing authority |
| plugin manifests and settings candidates | Cordis host | cannot mutate wallet state directly |
| index data | rebuildable indexer | never a settlement authority |

Secrets, opaque credentials, raw FROST material, authenticator private keys, and signing nonces must not enter chat messages, tool results, UI block specifications, or plugin settings patches. An agent can only use an opaque secret reference previously created by the trusted host.

## Compatibility

The existing `/api/v1` semantics and nine MCP wire names remain compatible and additive. Future incompatible wallet capabilities require a new major protocol. A schema digest and permission scope are versioned independently from a wire name.

## Consequences

- Web, desktop, MCP, and executors share one review and intent implementation.
- Durable mode requires serialization through `walletd`; direct SQLite reads by clients are prohibited.
- `walletd` unavailability closes wallet write and signing paths.
- Plugin and executor failures can degrade chat or configuration without silently approving a transaction.

## Rejected alternatives

- Direct database access from Electron or plugins: violates the single-writer and audit boundary.
- Signer or broadcast tools in MCP: converts agent output into custody authority.
- Treating Passkey account login as transaction approval: does not bind the transaction, policy, and chain snapshot.
- Letting an agent apply plugin configuration directly: bypasses human review, migration, health check, and last-good rollback.
