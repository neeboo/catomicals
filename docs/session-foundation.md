# Catomicals session foundation (backend)

Persistent conversation/session CRUD for the Catomicals desktop shell,
ported from the DeepSeek Harness session architecture. Canonical history is
append-only JSONL under Electron `userData`; search is a derived, rebuildable
SQLite FTS5 index; delete is recoverable through a trash folder.

Ownership: `desktop/src/sessions/**`, `desktop/src/deeplink.ts`,
session IPC/preload contracts, `web/src/lib/session*`,
`web/src/components/sessions/**`. Wallet state is NOT stored here — wallet
actions stay MCP/executor tools and only tool-call/result events are logged.

## Architecture

```
<userData>/sessions/
  --<project-slug>--/           per-cwd project dir (human-readable)
    <encoded-session-id>/       one dir per session (encodeSegment escaping)
      session.jsonl             header line + append-only event lines
  .trash/                       recoverable delete (tombstone + moved log)
  search.sqlite                 derived FTS5 index (rebuildable, never canonical)
```

- **Session id** — UUID, validated `^[a-zA-Z0-9_-]{1,80}$` at IPC boundaries;
  path-encoded with the DSH `encodeSegment` escape before filesystem use.
- **Header line** (immutable): `version, id, createdAt, cwd, parentSession,
  seedLength, provider, model, executor, origin, delegationDepth, agentPreset`.
  Provider/model/executor identity lives here (and in `request/header` events).
- **Events** (append-only, seq contiguous from 0): `turn/start`, `turn/end`
  (reason + durationMs), `user/message`, `assistant/message` (parts incl.
  controlled UI-block references), `assistant/chunk`, `tool/call`,
  `tool/result`, `request/header`, `session/title` (rename, latest wins),
  `session/archive` (latest wins), `todo/write`, `session/end-seed`.
- **Durability**: atomic first write (temp + fsync + `link()` publish),
  fsync'd appends with rollback, revision-stable reads, torn-tail truncation
  repair with synthetic closers on `load` (`inspect` is non-mutating).
- **Search**: `node:sqlite` `DatabaseSync` with FTS5 (`unicode61`), the same
  projection as DSH (`persisted_docs` + `temp.live_docs` overlay), literal
  phrase queries (`quoteFtsData`), cursor pagination (base64url cursor with
  generation staleness), session/event filters, highlight/snippet.

## Main-process integration (wired)

`desktop/src/main.ts` owns the visual-shell process; the session store is
wired after `registerIpc()` (before `createWindow()` so the renderer's initial
list call finds a handler), and the deep-link service is registered after the
window exists so launch-time navigation reaches a live renderer:

```ts
import { SessionManager } from "./sessions/manager.js";
import { registerSessionIpc, createRendererNavigationPusher } from "./sessions/ipc.js";
import { createCatomicalsDeeplinkService, findDeeplinkInArgv } from "./deeplink.js";

const sessionManager = new SessionManager({ root: join(app.getPath("userData"), "sessions") });
registerSessionIpc({
  manager: sessionManager,
  assertSender: assertRenderer,
  pushNavigation: createRendererNavigationPusher(() => window),
});
await createWindow();
createCatomicalsDeeplinkService(
  {
    registerProtocolClient: () => app.setAsDefaultProtocolClient("catomicals"),
    onOpenUrl: (l) => app.on("open-url", (_e, url) => l(url)),
    removeOpenUrlListener: (l) => app.removeListener("open-url", l as never),
    onSecondInstance: (l) => app.on("second-instance", (_e, argv) => l(argv)),
    removeSecondInstanceListener: (l) => app.removeListener("second-instance", l as never),
    currentArgv: [],
  },
  (event) => sessionManager.navigate(
    event.kind === "session-open" ? { kind: "session-open", sessionId: event.sessionId! } : { kind: "session-list" },
    "deeplink",
  ),
);
// Launch-time deep links are honored once the renderer has mounted its
// navigation listener (the service's own argv microtask can race the React
// effect that subscribes):
const launchTarget = findDeeplinkInArgv(process.argv);
if (launchTarget?.ok) setTimeout(() => sessionManager.navigate(/* ... */), 250);
// close: await sessionManager.close() runs in the shutdown coordinator
```

Renderer side: `SessionStoreProvider` (from `web/src/lib/session.tsx`) is
mounted around the router in `web/src/main.tsx`, and the chat shell
(`web/src/components/workbench/WalletWorkbench.tsx`) renders the real
`web/src/components/sessions/SessionList` in the left rail with
create/select/rename/archive/delete/restore and collapsed search. The center
pane is a session-backed conversation: every send appends canonical JSONL
events (turn/start, user/message, request/header, assistant/message or error,
turn/end with duration/status) and reload/reopen reconstructs the transcript
from the SessionManager via `web/src/lib/session-transcript.ts`. The preload
exposes `window.catomicalsDesktop.sessions.*` and `onSessionNavigation`.

## DSH sources ported (MIT)

- `packages/session/session-persistence-jsonl/src/format.ts` → `desktop/src/sessions/format.ts`
  (encodeSegment, projectKey/dir layout, header line, SessionLogScanner, scanLog, parseHeaderMeta)
- `packages/session/session-persistence-jsonl/src/index.ts` → `desktop/src/sessions/jsonl-store.ts`
  (atomic materialize via link-publish, append rollback, revision-stable reads,
  torn-tail repair, header-only listing; Zstandard omitted)
- `packages/session/session-persistence/src/coordinator.ts` → `desktop/src/sessions/coordinator.ts`
  (per-session serialization, create/append/load/inspect/readFrom, synthetic closers;
  Cordis live-session bus replaced by the SessionManager live registry)
- `packages/session-query/session-query-sqlite/src/schema.ts` → `desktop/src/sessions/search-schema.ts`
  (application_id guard, derived reset, persisted + temp live overlay tables, FTS5 unicode61)
- `packages/session-query/session-query-sqlite/src/query.ts` → `desktop/src/sessions/search-query.ts`
  (literal-phrase quoting, sanitize, snippet, predicates, cursor fingerprint)
- `packages/session-query/session-query-sqlite/src/index.ts` → `desktop/src/sessions/search.ts`
  (reconcile-on-search, live-preferred corpus, ranking CTE, cursor pagination, staleness)
- `packages/session-query/session-query/src/{types,documents,extraction}.ts` → search/types
  (filter/request types, surface classification, event text extraction)
- `packages/core/session/src/json.ts` → `desktop/src/sessions/json.ts` (lossless-JSON snapshot)
- `packages/core/session/src/repair.ts` → `interruptedTurnClosers` (adapted to Catomicals events)
- `packages/client/ui-renderer/src/client/session-provider.tsx` → `web/src/lib/session.tsx`
  (renderer session binding + current-session identity + navigation events)

## Tests

- `desktop/src/sessions/format.test.ts` — path escaping, header round-trip, torn scan
- `desktop/src/sessions/jsonl-store.test.ts` — atomic create, reopen, torn-tail recovery, summaries
- `desktop/src/sessions/coordinator.test.ts` — CRUD semantics, contiguity, repair, unknown-type refusal
- `desktop/src/sessions/search.test.ts` — cross-session FTS5, literal phrase, pagination, stale cursor, live overlay
- `desktop/src/sessions/manager.test.ts` — persistence/reopen, archive/delete/restore/purge, navigation, search integration
- `desktop/src/deeplink.test.ts` — parser, argv scan, Electron service contract
- `web/src/lib/session.test.tsx` — bridge contract, store behaviors, navigation events
- `web/src/components/sessions/SessionList.test.tsx` — list/search/actions/trash UI
