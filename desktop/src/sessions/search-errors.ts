/**
 * Typed errors for the SQLite FTS5 session search, ported from DeepSeek Harness
 * `packages/session-query/session-query/src/config.ts` (SessionQueryError, MIT).
 *
 * @module catomicals-desktop/sessions/search-errors
 */

/** Stable machine-readable search failure codes. */
export type SessionQueryErrorCode =
  | "SESSION_QUERY_INVALID_QUERY"
  | "SESSION_QUERY_INVALID_FILTER"
  | "SESSION_QUERY_INVALID_CURSOR"
  | "SESSION_QUERY_STALE_CURSOR"
  | "SESSION_QUERY_INVALID_LIMIT"
  | "SESSION_QUERY_SESSION_NOT_FOUND"
  | "SESSION_QUERY_SEARCH_DISABLED"
  | "SESSION_QUERY_INDEX_FAILED"
  | "SESSION_QUERY_ABORTED"
  | "SESSION_QUERY_PERSISTENCE_FAILED"
  | "SESSION_QUERY_INVALID_CONFIG"
  | "SESSION_QUERY_FTS5_UNAVAILABLE";

/** A search failure carrying a stable machine-readable code. */
export class SessionQueryError extends Error {
  readonly code: SessionQueryErrorCode;
  constructor(message: string, code: SessionQueryErrorCode, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionQueryError";
    this.code = code;
  }
}
