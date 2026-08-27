# Monochrome web wallet

`web/` is the browser interface for the self-hosted wallet node
(`cargo run -p catomicals -- wallet serve`). It is a React 19 + Vite 7
application using TanStack Router, TanStack Query, Tailwind CSS v4, and local
shadcn-style primitives (`web/src/components/ui/*`) with a strict black/white
Codex-like visual system — no gradients, no color, no crypto-casino styling,
and no platform token.

## Principles

- **Live data only.** Every number, digest, phase, and status on screen is a
  value returned by the wallet-node HTTP API (`http://localhost:18787`, or
  `VITE_WALLET_API_BASE`). There is no fake balance, fake signature, mock
  success path, or client-side fallback data.
- **Real browser WebAuthn.** Registration uses `navigator.credentials.create()`
  and approval uses `navigator.credentials.get()` with the node's one-use
  ceremonies. `web/src/lib/webauthn.ts` converts the node's base64url fields to
  `ArrayBuffer` and back, and sends the credential in the ordinary WebAuthn JSON
  representation the finish endpoints require.
- **Proposal-only chat.** `/chat` stores messages in the wallet-node process
  and may attach one typed Taproot signing proposal. The action card displays
  the node-returned intent digest, exact transaction digest, FROST session,
  signer and expiry, then links to the existing Passkey approval screen. Chat
  has no approval request, authenticator field, verifier hook, or mock path.
  The node caps history at 500 messages; restart clears it.
- **Honest failure states.** The UI renders loading skeletons, wallet-node
  offline, Inquisition-node unreachable, `op_cat` inactive, syncing/last-sync,
  stale (expired) intents, rejected/cancelled approval, ceremony-consumed, and
  threshold-insufficient states instead of pretending success.

## Run

```bash
cd web
pnpm install
pnpm run dev        # http://localhost:5173
pnpm run typecheck  # tsc -b --noEmit
pnpm run build      # tsc -b && vite build -> dist/
```

Start the wallet node with the matching RP origin and CORS origin:

```bash
cargo run -p catomicals -- wallet serve \
  --addr 127.0.0.1:18787 \
  --rp-id localhost \
  --rp-origin http://localhost:5173 \
  --cors-origin http://localhost:5173
```

The UI warns when the browser origin differs from the node's `rp_origin`,
because WebAuthn assertions are signed over the exact origin.

## API surface used

| Endpoint | UI use |
| --- | --- |
| `GET /api/v1/node/status` | wallet-node identity, RP, persistence limits |
| `GET /api/v1/wallet/status` | Inquisition height/OP_CAT, threshold, signers, pending/recent intents, credential count |
| `GET /api/v1/signer/status` | local participant, group key, approved actions |
| `GET /api/v1/chat/state` · `GET /api/v1/chat/messages/{id}` | in-memory messages and current secret-free wallet-action projections |
| `POST /api/v1/chat/messages` | add text and optionally create an immutable pending signing intent |
| `GET /api/v1/intents` · `GET /api/v1/intents/{id}` | intent list and immutable detail |
| `POST /api/v1/intents` | create intent (proposal only — never an approval) |
| `POST /api/v1/intents/{id}/cancel` | cancel pending intent |
| `POST /api/v1/transactions/inspect` | decode and review an unsigned Taproot transaction with ordered prevouts |
| `POST /api/v1/transactions/intents` · `GET /api/v1/transactions/intents/{id}` | create and re-read a wallet-derived transaction intent |
| `POST /api/v1/webauthn/register/start` · `…/finish` | Passkey enrollment ceremony |
| `GET /api/v1/webauthn/credentials` | enrolled credential list |
| `POST /api/v1/intents/{id}/approve/start` · `…/finish` | Passkey-gated approval ceremony |
| `GET /api/v1/signing/{id}/status` | threshold-signing phase |

## UI / agent capability parity

The same provider-neutral intent/status types (crates/wallet-core) serve the
human UI and the local stdio MCP adapter documented in [mcp.md](mcp.md). The
parity rule is: **any actor may propose
and read, but only a verified browser Passkey assertion may release a signer
action.**

| Capability | Human UI | Typed agent clients |
| --- | --- | --- |
| Read node/wallet/signer status | yes | yes |
| Create / read / cancel signing intents | yes | yes |
| Inspect a transaction and create a wallet-derived intent | yes | yes |
| Create / read plain chat messages | yes | yes |
| Enumerate enrolled credentials | yes | no |
| Start + finish Passkey registration | yes (browser) | no — no HTTP override |
| Start + finish Passkey approval | yes (browser) | no — no HTTP override |
| Receive FROST shares / key packages / authorizations | no | no |
| View signing phase / digest bindings | yes | intent binding only |
| Fabricate balances / signatures / successes | never | never |

`docs/security.md` documents why the approval seam is browser-only: the
production crate exports no verifier injection and the HTTP surface refuses
mock approvals.

## State coverage

- Loading — skeleton rows and "starting ceremony…" indicators.
- Chat — empty conversation, offline error, sending state, field validation,
  pending-Passkey count, and live approved/cancelled/expired/signed projections.
- Offline — global banner when the wallet node is unreachable; per-panel
  "no live data" when a poll fails.
- Inquisition down / `op_cat` inactive — banners with exact RPC meaning.
- Sync — header "last sync"/"syncing…" indicator driven by query fetching state.
- Stale intent — pending intent past `expiry` is flagged and cannot be approved.
- Rejected approval — finish errors (`webauthn_rejected`, `state_conflict`,
  `ceremony_consumed_or_missing`, user cancel) render typed alerts; no signer
  action is ever reported as released on failure.
- Threshold insufficient — `min_signers` vs online signer count is shown, and
  the detail page explains that a single local participant cannot complete the
  aggregate signature without authenticated remote signers.
