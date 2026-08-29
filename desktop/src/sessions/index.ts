/**
 * Catomicals session store — persistent conversation/session CRUD over
 * append-only JSONL under Electron userData, with a derived SQLite FTS5
 * search index and recoverable delete. Architecture ported from DeepSeek
 * Harness packages/session (see the module docs for exact sources).
 *
 * @module catomicals-desktop/sessions
 */

export * from "./types.js";
export { SessionFormatUnsupportedError, SessionPersistenceCorruptionError, SessionCoordinator, interruptedTurnClosers, KNOWN_SESSION_EVENT_TYPES } from "./coordinator.js";
export { JsonlSessionStore, SESSION_ARTIFACT_NAME, type StoredPrefix, type StoredSuffix, type StoreCompression } from "./jsonl-store.js";
export { SessionManager, type CreateSessionInput, type SessionManagerOptions } from "./manager.js";
export { TrashStore, TRASH_TOMBSTONE, parseTrashEntry, type TrashRecord } from "./trash.js";
export {
  SqliteSessionQueryEngine,
  buildSessionEventSearchDocuments,
  classifySurface,
  extractSessionEventText,
  foldSessionMeta,
  SESSION_QUERY_DEFAULT_LIMIT,
  SESSION_QUERY_MAX_LIMIT,
  SESSION_QUERY_SNIPPET_CHARS,
  type SessionSearchSource,
} from "./search.js";
export {
  SESSION_QUERY_SQLITE_APPLICATION_ID,
  SESSION_QUERY_SQLITE_SCHEMA_VERSION,
  openSearchDatabase,
  type JournalMode,
} from "./search-schema.js";
export {
  FTS_HIGHLIGHT_START,
  FTS_HIGHLIGHT_END,
  SQLITE_FTS5_OUTER_PREDICATE_LIMIT,
  SQLITE_MAX_PAGE_LIMIT,
  SQLITE_PORTABLE_VARIABLE_LIMIT,
  makeSnippet,
  quoteFtsData,
  sanitizeFtsText,
} from "./search-query.js";
export { SessionQueryError, type SessionQueryErrorCode } from "./search-errors.js";
export {
  registerSessionIpc,
  createRendererNavigationPusher,
  parseAppendEventsRequest,
  parseCreateSessionRequest,
  parseSearchSessionsRequest,
  parseSearchEventsRequest,
  parseNavigateRequest,
  type SessionIpcDeps,
} from "./ipc.js";
export { snapshotJsonValue, isJsonValue } from "./json.js";
