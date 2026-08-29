/**
 * Request normalization, parameterized predicates, and result presentation for
 * the SQLite FTS5 session search. Ported from DeepSeek Harness
 * `packages/session-query/session-query-sqlite/src/query.ts` (MIT) and extended
 * with Catomicals session filters (provider/model/executor/archived).
 *
 * @module catomicals-desktop/sessions/search-query
 */

import {
  type SessionEventMetadataFilter,
  type SessionEventSearchRequest,
  type SessionResultFilter,
  type SessionSearchCursor,
  type SessionSearchRequest,
} from "./types.js";
import { SessionId } from "./types.js";
import { SessionQueryError } from "./search-errors.js";

/** Collision-free marker inserted before an FTS5 match by `highlight()`. */
export const FTS_HIGHLIGHT_START = "\uFDD0";
/** Collision-free marker inserted after an FTS5 match by `highlight()`. */
export const FTS_HIGHLIGHT_END = "\uFDD1";

/** Largest page size whose internal lookahead remains an exact SQLite integer binding. */
export const SQLITE_MAX_PAGE_LIMIT = Number.MAX_SAFE_INTEGER - 1;

/** Portable host-parameter ceiling shared by predicate and statement builders. */
export const SQLITE_PORTABLE_VARIABLE_LIMIT = 32_766;

/** Supported outer-predicate budget that keeps SQLite FTS5 MATCH usable. */
export const SQLITE_FTS5_OUTER_PREDICATE_LIMIT = 14;

/** Reject prospective SQLite binding growth beyond the portable ceiling. */
export function assertPortableBindingCount(count: number): void {
  if (count > SQLITE_PORTABLE_VARIABLE_LIMIT) {
    throw new SessionQueryError(
      `session-search request exceeds SQLite's portable ${SQLITE_PORTABLE_VARIABLE_LIMIT}-variable limit; reduce filter values`,
      "SESSION_QUERY_INVALID_FILTER",
    );
  }
}

/** Reject compiled outer predicates beyond the supported FTS5 planner budget. */
export function assertFts5OuterPredicateCount(count: number): void {
  if (count > SQLITE_FTS5_OUTER_PREDICATE_LIMIT) {
    throw new SessionQueryError(
      `session-search request exceeds the supported SQLite FTS5 outer-predicate budget of ${SQLITE_FTS5_OUTER_PREDICATE_LIMIT}; reduce filters`,
      "SESSION_QUERY_INVALID_FILTER",
    );
  }
}

/** Limit defaults needed to normalize a search request. */
export interface QueryLimits {
  defaultLimit: number;
  maxLimit: number;
}

/** Normalized cross-session request. */
export interface NormalizedSessionRequest {
  query: string;
  sessionFilters: readonly SessionResultFilter[];
  eventFilters: readonly SessionEventMetadataFilter[];
  limit: number;
  cursor?: SessionSearchCursor;
}

/** Normalized within-session request. */
export interface NormalizedEventRequest {
  sessionId: SessionId;
  query: string;
  filters: readonly SessionEventMetadataFilter[];
  limit: number;
  cursor?: SessionSearchCursor;
}

/** Parameterized SQL predicate fragment. */
export interface SqlWhere {
  /** SQL without the leading `WHERE`. */
  sql: string;
  /** Bindings in placeholder order. */
  params: Array<string | number>;
  /** Number of compiled predicates in `sql`. */
  predicateCount: number;
}

/** Validate and canonicalize a cross-session request. */
export function normalizeSessionRequest(
  request: SessionSearchRequest,
  limits: QueryLimits,
): NormalizedSessionRequest {
  const sessionFilters = materializeSessionFilters(request.sessionFilters ?? []);
  const eventFilters = materializeMetadataFilters(request.eventFilters ?? []);
  const cursor = materializeCursor(request.cursor);
  return {
    query: normalizeQuery(request.query),
    sessionFilters,
    eventFilters,
    limit: normalizeLimit(request.limit, limits),
    ...cursor === undefined ? {} : { cursor },
  };
}

/** Validate and canonicalize a within-session request. */
export function normalizeEventRequest(
  request: SessionEventSearchRequest,
  limits: QueryLimits,
): NormalizedEventRequest {
  if (typeof request.sessionId !== "string") {
    throw new SessionQueryError("session-search session id must be text", "SESSION_QUERY_INVALID_FILTER");
  }
  const filters = materializeMetadataFilters(request.filters ?? []);
  const cursor = materializeCursor(request.cursor);
  return {
    sessionId: request.sessionId,
    query: normalizeQuery(request.query),
    filters,
    limit: normalizeLimit(request.limit, limits),
    ...cursor === undefined ? {} : { cursor },
  };
}

/** Compile logical-session predicates against selected-document columns. */
export function buildSessionWhere(filters: readonly SessionResultFilter[]): SqlWhere {
  const clauses: string[] = [];
  const params: Array<string | number> = [];
  for (const filter of filters) {
    switch (filter.kind) {
      case "id":
        addList(clauses, params, "session_id", filter.values);
        break;
      case "cwd":
        addNullableList(clauses, params, "cwd", filter.values);
        break;
      case "created-at":
        addRange(clauses, params, "created_at", filter);
        break;
      case "parent":
        addNullableList(clauses, params, "parent_session", filter.values);
        break;
      case "provider":
        addList(clauses, params, "provider", filter.values);
        break;
      case "model":
        addList(clauses, params, "model", filter.values);
        break;
      case "executor":
        addList(clauses, params, "executor", filter.values);
        break;
      case "archived":
        addBooleanList(clauses, params, "archived", filter.values);
        break;
      case "availability": {
        const availability = [...new Set(filter.values)];
        if (availability.length === 0) clauses.push("0");
        else if (availability.length === 1) {
          const value = availability[0];
          if (value === "live") clauses.push("live = 1");
          else if (value === "persisted") clauses.push("persisted = 1");
          else unknownAvailability(value);
        }
        break;
      }
      default:
        unknownFilter(filter);
    }
  }
  assertFts5OuterPredicateCount(clauses.length);
  return { sql: clauses.join(" AND "), params, predicateCount: clauses.length };
}

/** Compile event metadata predicates against selected-document columns. */
export function buildEventWhere(filters: readonly SessionEventMetadataFilter[]): SqlWhere {
  const clauses: string[] = [];
  const params: Array<string | number> = [];
  for (const filter of filters) {
    switch (filter.kind) {
      case "seq":
        addRange(clauses, params, "seq", filter);
        break;
      case "time":
        addRange(clauses, params, "time", filter);
        break;
      case "type":
        addList(clauses, params, "type", filter.values);
        break;
      case "surface":
        addList(clauses, params, "surface", filter.values);
        break;
      default:
        unknownFilter(filter);
    }
  }
  assertFts5OuterPredicateCount(clauses.length);
  return { sql: clauses.join(" AND "), params, predicateCount: clauses.length };
}

/** Quote caller text as one FTS5 phrase so query syntax remains inert data. */
export function quoteFtsData(query: string): string {
  return `"${query.replaceAll('"', '""')}"`;
}

/** Remove reserved marker collisions before text enters FTS5 or MATCH. */
export function sanitizeFtsText(text: string): string {
  return text
    .replaceAll("\0", "\uFFFD")
    .replaceAll(FTS_HIGHLIGHT_START, "\uFFFD")
    .replaceAll(FTS_HIGHLIGHT_END, "\uFFFD");
}

/** Build the stable normalized request identity stored in opaque cursors. */
export function requestFingerprint(request: NormalizedSessionRequest | NormalizedEventRequest): string {
  if ("sessionId" in request) {
    return JSON.stringify({
      scope: "events",
      sessionId: request.sessionId,
      query: request.query,
      filters: canonicalFilters(request.filters),
      limit: request.limit,
    });
  }
  return JSON.stringify({
    scope: "sessions",
    query: request.query,
    sessionFilters: canonicalFilters(request.sessionFilters),
    eventFilters: canonicalFilters(request.eventFilters),
    limit: request.limit,
  });
}

/** Build a whitespace-normalized excerpt no longer than `maxChars`. */
export function makeSnippet(markedText: string, maxChars: number): string {
  const { text: clean, matchStart } = normalizeMarkedText(markedText);
  const characters = Array.from(clean);
  if (characters.length <= maxChars) return clean;
  if (maxChars === 1) return "…";
  const matchedIndex = Math.min(matchStart, characters.length - 1);
  let start = Math.max(0, matchedIndex - Math.floor(maxChars / 3));
  const prefix = start > 0 ? "…" : "";
  let suffix = "…";
  let contentLength = maxChars - prefix.length - suffix.length;
  if (contentLength < 1) {
    start = matchedIndex;
    suffix = "";
    contentLength = maxChars - prefix.length - suffix.length;
  } else if (matchedIndex >= start + contentLength) {
    start = matchedIndex - contentLength + 1;
  }
  let end = Math.min(characters.length, start + contentLength);
  if (end === characters.length) {
    suffix = "";
    contentLength = maxChars - prefix.length;
    start = Math.max(0, end - contentLength);
  }
  end = Math.min(characters.length, start + contentLength);
  return `${prefix}${characters.slice(start, end).join("")}${suffix}`;
}

function normalizeMarkedText(markedText: string): { text: string; matchStart: number } {
  const characters: string[] = [];
  let matchStart: number | undefined;
  for (const character of markedText) {
    if (character === FTS_HIGHLIGHT_START) {
      matchStart ??= characters.length;
      continue;
    }
    if (character === FTS_HIGHLIGHT_END) continue;
    if (/\s/u.test(character)) {
      if (characters.length > 0 && characters.at(-1) !== " ") characters.push(" ");
    } else {
      characters.push(character);
    }
  }
  if (characters.at(-1) === " ") characters.pop();
  return { text: characters.join(""), matchStart: matchStart ?? 0 };
}

function normalizeQuery(value: string): string {
  if (typeof value !== "string") {
    throw new SessionQueryError("session-search query must be text", "SESSION_QUERY_INVALID_QUERY");
  }
  const query = value.trim().replace(/\s+/gu, " ");
  if (query.length === 0) {
    throw new SessionQueryError(
      "session-search query must contain non-whitespace text",
      "SESSION_QUERY_INVALID_QUERY",
    );
  }
  if (query.includes("\0")) {
    throw new SessionQueryError("session-search query must not contain NUL", "SESSION_QUERY_INVALID_QUERY");
  }
  return sanitizeFtsText(query);
}

function materializeCursor(cursor: SessionSearchCursor | undefined): SessionSearchCursor | undefined {
  if (cursor === undefined) return undefined;
  if (typeof cursor !== "string") {
    throw new SessionQueryError("session-search cursor must be text", "SESSION_QUERY_INVALID_CURSOR");
  }
  return cursor;
}

function materializeSessionFilters(filters: readonly SessionResultFilter[]): SessionResultFilter[] {
  const candidates: readonly SessionResultFilter[] = filters;
  for (const filter of candidates) {
    switch (filter.kind) {
      case "id":
      case "cwd":
      case "created-at":
      case "parent":
      case "availability":
      case "provider":
      case "model":
      case "executor":
      case "archived":
        break;
      default:
        unknownFilter(filter);
    }
  }
  return [...candidates];
}

function materializeMetadataFilters(
  filters: readonly SessionEventMetadataFilter[],
): SessionEventMetadataFilter[] {
  const candidates: readonly SessionEventMetadataFilter[] = filters;
  for (const filter of candidates) {
    switch (filter.kind) {
      case "seq":
      case "time":
      case "type":
      case "surface":
        break;
      default:
        unknownFilter(filter);
    }
  }
  return [...candidates];
}

function normalizeLimit(value: number | undefined, limits: QueryLimits): number {
  const limit = value ?? limits.defaultLimit;
  const maxLimit = Math.min(limits.maxLimit, SQLITE_MAX_PAGE_LIMIT);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > maxLimit) {
    throw new SessionQueryError(
      `session-search limit must be an integer between 1 and ${maxLimit}`,
      "SESSION_QUERY_INVALID_LIMIT",
    );
  }
  return limit;
}

function addList(
  clauses: string[],
  params: Array<string | number>,
  column: string,
  values: readonly (string | number)[],
): void {
  if (values.length === 0) {
    clauses.push("0");
    return;
  }
  clauses.push(`${column} IN (${appendListBindings(params, values)})`);
}

function addBooleanList(
  clauses: string[],
  params: Array<string | number>,
  column: string,
  values: readonly boolean[],
): void {
  if (values.length === 0) {
    clauses.push("0");
    return;
  }
  clauses.push(`${column} IN (${appendListBindings(params, values.map(value => (value ? 1 : 0)))})`);
}

function addNullableList(
  clauses: string[],
  params: Array<string | number>,
  column: string,
  values: readonly (string | null)[],
): void {
  if (values.length === 0) {
    clauses.push("0");
    return;
  }
  const concrete = values.filter((value): value is string => value !== null);
  const parts: string[] = [];
  if (concrete.length > 0) {
    parts.push(`${column} IN (${appendListBindings(params, concrete)})`);
  }
  if (values.includes(null)) parts.push(`${column} IS NULL`);
  clauses.push(`(${parts.join(" OR ")})`);
}

function addRange(
  clauses: string[],
  params: Array<string | number>,
  column: string,
  range: { from?: number; to?: number },
): void {
  if (range.from !== undefined) {
    assertPortableBindingCount(params.length + 1);
    clauses.push(`CAST(${column} AS INTEGER) >= ?`);
    params.push(range.from);
  }
  if (range.to !== undefined) {
    assertPortableBindingCount(params.length + 1);
    clauses.push(`CAST(${column} AS INTEGER) <= ?`);
    params.push(range.to);
  }
}

function appendListBindings(
  params: Array<string | number>,
  values: readonly (string | number)[],
): string {
  assertPortableBindingCount(params.length + values.length);
  for (const value of values) params.push(value);
  return values.map(() => "?").join(", ");
}

function canonicalFilters(filters: readonly (SessionResultFilter | SessionEventMetadataFilter)[]): unknown[] {
  return filters.map((filter) => {
    if ("values" in filter) {
      return { ...filter, values: [...filter.values].sort(compareNullable) };
    }
    return { kind: filter.kind, from: filter.from ?? null, to: filter.to ?? null };
  }).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function compareNullable(a: string | null | number | boolean, b: string | null | number | boolean): number {
  const left = a === null ? "" : String(a);
  const right = b === null ? "" : String(b);
  return left.localeCompare(right);
}

function unknownAvailability(value: never): never {
  throw new SessionQueryError(
    `session availability filter contains unknown value "${String(value)}"`,
    "SESSION_QUERY_INVALID_FILTER",
  );
}

function unknownFilter(filter: never): never {
  const kind = (filter as { kind?: unknown }).kind;
  throw new SessionQueryError(
    `session filter contains unknown kind ${typeof kind === "string" ? `"${kind}"` : "(missing)"}`,
    "SESSION_QUERY_INVALID_FILTER",
  );
}
