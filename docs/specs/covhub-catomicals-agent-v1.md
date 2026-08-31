# CovHub ↔ Catomicals Agent Contract v1

## Goal

Let a Catomicals agent load or create a CovHub covenant canvas, run bounded tests, confirm the exact generated artifact, and hand the complete unsigned transaction material to the Catomicals wallet for independent review. Agent tools may create a pending intent, but they never approve, sign, or broadcast.

## Trust boundary

- CovHub owns source evidence, canvas semantics, generated artifacts, and test evidence.
- Catomicals treats every CovHub digest and status as untrusted input until it recomputes the relevant digest and re-runs the selected local chain suite over the complete transaction material.
- A `ready_for_wallet_review` proposal is only eligible to become a pending intent. It is not approved and is not ready for signing.
- Passkey approval, signer selection, nonce use, final signature verification, and broadcast stay inside Catomicals.
- The agent-facing surface contains no approval, signing, secret, or broadcast operation.

## Canonical encoding

Contract objects use UTF-8 JSON with unknown fields rejected. Content digests use RFC 8785 JSON Canonicalization Scheme followed by SHA-256 and the lowercase `sha256:<64 hex>` representation. A digest field is omitted from the value being digested. Transaction material uses standard padded Base64 and is limited to 1,000,000 decoded bytes.

## `covhub.canvas/v1`

Required fields:

```json
{
  "schema": "covhub.canvas/v1",
  "canvas_id": "canvas:kaspa:pymatt-vault",
  "item_id": "pymatt-examples-vault-minivault-contracts",
  "mode": "source-derived",
  "chain_scope": {
    "schema_version": 1,
    "chain": "kaspa",
    "network": "kaspa-testnet-11"
  },
  "source": {
    "repository": "owner/repository",
    "revision": "40-hex git commit",
    "path": "path/to/source",
    "sha256": "sha256:<64 hex>"
  },
  "graph": {
    "nodes": [],
    "edges": []
  },
  "portability": {
    "chain_independent_interfaces": [],
    "capability_bound_interfaces": [],
    "chain_native_modules": []
  },
  "semantic_digest": "sha256:<64 hex>"
}
```

The semantic digest covers every field except `semantic_digest`. Source-derived canvases remain complete chain-native graphs; portable and capability-bound modules are visible within the graph and are not collapsed into a smaller generic diagram.

## `covhub.code-confirmation/v1`

```json
{
  "schema": "covhub.code-confirmation/v1",
  "confirmation_id": "confirmation:<stable id>",
  "canvas_digest": "sha256:<64 hex>",
  "artifact": {
    "kind": "unsigned-transaction-material",
    "media_type": "application/vnd.kaspa.transaction-review+binary",
    "sha256": "sha256:<64 hex>",
    "size_bytes": 1234
  },
  "tests": [
    {
      "test_id": "happy-path",
      "runner": "covhub.runner/v0",
      "status": "pass",
      "evidence_digest": "sha256:<64 hex>"
    }
  ],
  "status": "confirmed",
  "confirmed_at": "RFC3339 timestamp",
  "content_digest": "sha256:<64 hex>"
}
```

`status` is `confirmed`, `failed`, or `inconclusive`. CovHub may emit `confirmed` only when the artifact digest and size match the supplied bytes and every required test is `pass`. Source inspection without an executable artifact stays `inconclusive`.

## `covhub.wallet-proposal/v1`

```json
{
  "schema": "covhub.wallet-proposal/v1",
  "proposal_id": "proposal:<stable id>",
  "canvas_digest": "sha256:<64 hex>",
  "code_confirmation_digest": "sha256:<64 hex>",
  "chain_scope": {
    "schema_version": 1,
    "chain": "kaspa",
    "network": "kaspa-testnet-11"
  },
  "transaction": {
    "encoding": "base64",
    "media_type": "application/vnd.kaspa.transaction-review+binary",
    "material_base64": "...",
    "sha256": "sha256:<64 hex>"
  },
  "summary": "Human-readable proposal summary only",
  "created_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp",
  "readiness": {
    "status": "ready_for_wallet_review",
    "blockers": []
  },
  "content_digest": "sha256:<64 hex>"
}
```

`readiness.status` is `ready_for_wallet_review` or `analysis_only`. `analysis_only` requires at least one blocker and cannot create an intent. The proposal deliberately has no trusted signing-message field. Catomicals derives `ReviewArtifact.review_digest` and `ReviewArtifact.signing_message_digest` from the decoded transaction material through its local `ChainSuite`.

## Agent and wallet operations

CovHub exposes these typed operations over HTTP first; an MCP server may map them without changing payloads:

- `GET /v1/agent/canvases/:item_id`
- `POST /v1/agent/code-confirmations`
- `POST /v1/agent/wallet-proposals`

Catomicals exposes:

- MCP `inspect_covhub_wallet_proposal`: strict parse, digest verification, supported test-network lookup, local chain-suite review, and readiness result; no state change.
- MCP `create_covhub_signing_intent`: repeats inspection and may create only a pending intent bound to the locally recomputed review and selected local signer profile.
- HTTP equivalents under `/api/v1/covhub/proposals/inspect` and `/api/v1/covhub/proposals/intents` for the desktop host.

The intent operation must fail closed when the proposal is analysis-only, expired, oversized, has a digest mismatch, selects an unsupported scope, lacks a locally executable chain suite/profile, or cannot reproduce the review. It must never accept a CovHub-provided authorization, signature, signer secret, or broadcast instruction.

## Initial acceptance slice

- CovHub can return every currently collected source-derived native canvas through the agent endpoint with stable semantic digests.
- CovHub can create and reject code confirmations and wallet proposals according to the rules above.
- Catomicals can inspect a Kaspa Testnet11 proposal with a real encoded review fixture, reproduce the Kaspa review artifact, and reject any mutation of the canvas, confirmation, transaction, scope, expiry, or readiness fields.
- When a matching local profile is available, the agent can create a pending intent only; existing Passkey approval remains mandatory before a signing job can exist.
- Both repositories include cross-compatible golden fixtures for all three schemas and independently verify their canonical content digests.
