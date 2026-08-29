/**
 * Concrete session-query engine with SQLite FTS5 over a live-preferred corpus.
 * Ported from DeepSeek Harness
 * `packages/session-query/session-query-sqlite/src/index.ts` (MIT), without the
 * Cordis shell: the persisted/live reconcile, cursor-paginated ranking,
 * literal-phrase matching, and snippet presentation are faithful; the source
 * of live sessions is the SessionManager's live registry instead of
 * `ctx.sessions`.
 *
 * @module catomicals-desktop/sessions/search
 */

import { createHash, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { openSearchDatabase, type JournalMode } from "./search-schema.js";
import {
  type NormalizedEventRequest,
  type NormalizedSessionRequest,
  FTS_HIGHLIGHT_END,
  FTS_HIGHLIGHT_START,
  assertFts5OuterPredicateCount,
  assertPortableBindingCount,
  buildEventWhere,
  buildSessionWhere,
  makeSnippet,
  normalizeEventRequest,
  normalizeSessionRequest,
  quoteFtsData,
  requestFingerprint,
  sanitizeFtsText,
  type QueryLimits,
} from "./search-query.js";
import { SessionQueryError } from "./search-errors.js";
import {
  type SessionEvent,
  type SessionEventSearchDocument,
  type SessionEventSearchHit,
  type SessionEventSearchPage,
  type SessionEventSearchRequest,
  type SessionEventSurface,
  type SessionHeader,
  type SessionId,
  type SessionInspection,
  type SessionMessagePart,
  type SessionPersistenceSnapshot,
  type SessionSearchCursor,
  type SessionSearchHit,
  type SessionSearchPage,
  type SessionSearchRequest,
} from "./types.js";

/** Default result page size. */
export const SESSION_QUERY_DEFAULT_LIMIT = 20;
/** Maximum accepted result page size. */
export const SESSION_QUERY_MAX_LIMIT = 100;
/** Default maximum snippet length in Unicode code points. */
export const SESSION_QUERY_SNIPPET_CHARS = 240;

/** One transient source change gets a retry; repeated churn fails rather than monopolizing the queue. */
const STABLE_OBSERVATION_ATTEMPTS = 2;

/** The session corpus the engine observes: persisted snapshots plus live sessions. */
export interface SessionSearchSource {
  /** List persisted sessions with their stat-derived revisions. */
  listSnapshots(signal?: AbortSignal): Promise<SessionPersistenceSnapshot[]>;
  /** Read one persisted session detached (non-mutating). */
  inspect(id: SessionId, signal?: AbortSignal): Promise<SessionInspection>;
  /** List currently live (open) sessions with their in-memory event buffers. */
  listLive(): Array<{ header: SessionHeader; events: SessionEvent[] }>;
}

/** Options controlling the derived index. */
export interface SessionSearchOptions {
  /** Dedicated derived-index path; `:memory:` is supported for ephemeral indexes. */
  path: string;
  /** SQLite journal mode. Defaults to `wal`. */
  journalMode?: JournalMode;
  /** Page size when a request omits `limit`. Defaults to 20. */
  defaultLimit?: number;
  /** Largest accepted page size. Defaults to 100. */
  maxLimit?: number;
  /** Maximum snippet length in Unicode code points. Defaults to 240. */
  snippetChars?: number;
  /** Disable FTS (openAt "never"): exact reads stay available, search fails cleanly. */
  openAt?: "startup" | "first-search" | "never";
}

interface ResolvedConfig extends QueryLimits {
  path: string;
  journalMode: JournalMode;
  snippetChars: number;
  openAt: "startup" | "first-search" | "never";
}

interface ObservedSession {
  header: SessionHeader;
  documents: SessionEventSearchDocument[];
  fingerprint: string;
  title?: string;
  archived: boolean;
}

interface ObservedPersistedSession {
  header: SessionHeader;
  revision: string;
  loaded?: ObservedSession;
}

interface Observation {
  persisted: Map<SessionId, ObservedPersistedSession>;
  live: Map<SessionId, ObservedSession>;
}

interface IndexedPersistedRow {
  id: string;
  revision: string;
  generation: number;
}

interface IndexedLiveRow {
  id: string;
  fingerprint: string;
  persisted: number;
  generation: number;
}

interface SessionHeaderRow {
  session_id: string;
  version: number;
  created_at: number;
  cwd: string | null;
  parent_session: string | null;
  seed_length: number | null;
  provider: string | null;
  model: string | null;
  executor: string | null;
  agent_preset: string | null;
  title: string | null;
  archived: number;
}

interface SearchRow extends SessionHeaderRow {
  live: number;
  persisted: number;
  seq: number;
  type: string;
  time: number;
  surface: string;
  marked_text: string;
  match_count: number;
  document_length: number;
}

interface CursorPayload {
  version: 1;
  instance: string;
  scope: "sessions" | "events";
  fingerprint: string;
  generation: string;
  offset: number;
}

/**
 * Classify each event's placement in the folded surface: current nodes,
 * shadowed replaced nodes, and log-only (non-surface or never-folded).
 */
export function classifySurface(events: readonly SessionEvent[]): Map<number, SessionEventSurface> {
  const nodes: number[] = [];
  const shadowed = new Set<number>();
  for (const event of events) {
    if (event.type !== "user/message" && event.type !== "assistant/message" && event.type !== "tool/result") continue;
    const op = event.surfaceOp;
    if (op === undefined || op === "append") {
      nodes.push(event.seq);
    } else {
      const { start, end } = op;
      const removed = nodes.splice(start, end - start + 1);
      for (const seq of removed) shadowed.add(seq);
      nodes.push(event.seq);
    }
  }
  const result = new Map<number, SessionEventSurface>();
  for (const seq of nodes) result.set(seq, "current");
  for (const seq of shadowed) result.set(seq, "shadowed");
  return result;
}

/** First-party semantic text for one event; structural events contribute none. */
export function extractSessionEventText(event: SessionEvent): string {
  switch (event.type) {
    case "user/message":
      return joinText([event.data.content, ...partsText(event.data.parts ?? [])]);
    case "assistant/message":
      return joinText([event.data.content, ...partsText(event.data.parts ?? [])]);
    case "tool/call":
      return joinText([event.data.name, event.data.arguments]);
    case "tool/result":
      return joinText([
        event.data.outcome,
        event.data.error?.name ?? "",
        event.data.error?.code ?? "",
        event.data.error?.message ?? "",
        event.data.resultDigest ?? "",
      ]);
    case "todo/write":
      return joinText(event.data.todos.flatMap(todo => [todo.status, todo.content]));
    case "turn/end":
      return turnEndText(event.data.reason);
    case "turn/start":
    case "assistant/chunk":
    case "request/header":
    case "session/title":
    case "session/archive":
    case "session/end-seed":
      return "";
    default:
      return "";
  }
}

function turnEndText(reason: SessionEvent<"turn/end">["data"]["reason"]): string {
  switch (reason.kind) {
    case "error":
      return joinText(["error", reason.error.message, reason.error.code]);
    case "aborted":
      return "aborted";
    case "max-tokens":
    case "interrupted":
      return reason.kind;
    case "completed":
      return "";
    default:
      return "";
  }
}

function partsText(parts: readonly SessionMessagePart[]): string[] {
  return parts.flatMap(part => {
    switch (part.type) {
      case "text":
        return [part.text];
      case "tool_call":
        return [part.tool_name, part.request_digest];
      case "tool_result":
        return [part.outcome, part.result_digest ?? ""];
      case "ui_block":
        return [part.block.component, ...part.block.data_bindings.flatMap(b => [b.reference_kind, b.reference_id])];
      case "review_reference":
        return [part.reference.kind, part.reference.review_digest];
      case "error":
        return [part.message, part.code];
      default:
        return [];
    }
  });
}

function joinText(parts: readonly string[]): string {
  return parts.map(part => part.trim()).filter(Boolean).join("\n");
}

/** Build searchable documents for one complete raw event log (ascending seq). */
export function buildSessionEventSearchDocuments(
  sessionId: SessionId,
  events: readonly SessionEvent[],
): SessionEventSearchDocument[] {
  const surfaceBySeq = classifySurface(events);
  const documents: SessionEventSearchDocument[] = [];
  for (const event of events) {
    const text = extractSessionEventText(event);
    if (text.length === 0) continue;
    documents.push({
      sessionId,
      seq: event.seq,
      type: event.type,
      time: event.time,
      surface: surfaceBySeq.get(event.seq) ?? "log-only",
      text,
    });
  }
  return documents;
}

/** Fold mutable session metadata (title, archive) from the latest events. */
export function foldSessionMeta(events: readonly SessionEvent[]): { title?: string; archived: boolean } {
  let title: string | undefined;
  let archived = false;
  for (const event of events) {
    if (event.type === "session/title") title = event.data.title;
    else if (event.type === "session/archive") archived = event.data.archived;
  }
  return title === undefined ? { archived } : { title, archived };
}

/**
 * SQLite FTS5 owner of the session search index. Opens lazily on first search;
 * reconciles the persisted + live corpus before every query so the derived
 * index always mirrors the canonical JSONL logs.
 */
export class SqliteSessionQueryEngine {
  private readonly config: ResolvedConfig;
  private readonly _instance = randomUUID();
  private _ready: Promise<void> | undefined;
  private _db: DatabaseSync | undefined;
  private _globalGeneration = 0;
  private _localGeneration = 0;
  private _tail: Promise<void> = Promise.resolve();
  private _closed = false;
  private _closePromise: Promise<void> | undefined;

  /** @param source - the session corpus this engine indexes (the SessionManager). */
  constructor(
    private readonly source: SessionSearchSource,
    options: SessionSearchOptions,
  ) {
    this.config = resolveConfig(options);
  }

  /** Open eagerly only when configured to do so. */
  async init(): Promise<void> {
    if (this.config.openAt === "startup") await this._ensureReady();
  }

  /** Whether the search index is available (node:sqlite + FTS5 proved at runtime). */
  static async probeFts5(): Promise<void> {
    try {
      const { DatabaseSync } = await import("node:sqlite");
      const db = new DatabaseSync(":memory:");
      try {
        db.exec('CREATE VIRTUAL TABLE probe USING fts5(text, tokenize = "unicode61")');
        db.exec("INSERT INTO probe (text) VALUES ('catomicals probe')");
        const row = db.prepare("SELECT count(*) AS c FROM probe WHERE probe MATCH ?").get('"catomicals"') as { c: number };
        if (row.c !== 1) throw new Error("FTS5 MATCH did not return the probe row");
      } finally {
        db.close();
      }
    } catch (error: unknown) {
      throw new SessionQueryError(
        `SQLite FTS5 is unavailable in this runtime: ${error instanceof Error ? error.message : String(error)}`,
        "SESSION_QUERY_FTS5_UNAVAILABLE",
        { cause: error },
      );
    }
  }

  /** Close the database after every accepted operation reaches quiescence. */
  close(): Promise<void> {
    this._closePromise ??= this._close();
    return this._closePromise;
  }

  /** Cross-session full-text search over the live-preferred corpus. */
  async searchSessions(request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>> {
    this._assertSearchEnabled();
    const normalized = normalizeSessionRequest(request, this.config);
    return this._serialized(async () => {
      await this._ensureReady();
      await this._reconcile();
      const generation = String(this._globalGeneration);
      const fingerprint = requestFingerprint(normalized);
      const offset = normalized.cursor === undefined
        ? 0
        : decodeCursor(normalized.cursor, this._instance, "sessions", fingerprint, generation);
      const rows = this._querySessions(normalized, offset);
      return page(rows, normalized.limit, row => this._sessionHit(row), cursorOffset => encodeCursor({
        version: 1,
        instance: this._instance,
        scope: "sessions",
        fingerprint,
        generation,
        offset: cursorOffset,
      }), offset);
    });
  }

  /** Within-session full-text search over the live-preferred log. */
  async searchEvents(request: SessionEventSearchRequest): Promise<SessionEventSearchPage> {
    this._assertSearchEnabled();
    const normalized = normalizeEventRequest(request, this.config);
    return this._serialized(async () => {
      await this._ensureReady();
      await this._reconcile();
      const target = this._targetObservation(normalized.sessionId);
      const fingerprint = requestFingerprint(normalized);
      const offset = normalized.cursor === undefined
        ? 0
        : decodeCursor(normalized.cursor, this._instance, "events", fingerprint, target.generation);
      const rows = this._queryEvents(normalized, offset);
      return {
        session: target.header,
        ...page(rows, normalized.limit, row => this._eventHit(row), cursorOffset => encodeCursor({
          version: 1,
          instance: this._instance,
          scope: "events",
          fingerprint,
          generation: target.generation,
          offset: cursorOffset,
        }), offset),
      };
    });
  }

  /** Read the current indexed snapshot of one session's header (for reads after search). */
  private _targetObservation(sessionId: SessionId): { header: SessionHeader; generation: string } {
    const db = this._requireDb();
    const live = db.prepare(
      `SELECT
        id AS session_id, version, created_at, cwd, parent_session, seed_length, provider, model, executor, agent_preset, title, archived, generation
      FROM temp.live_sessions
      WHERE id = ?`,
    ).get(sessionId) as (SessionHeaderRow & { generation: number }) | undefined;
    if (live !== undefined) {
      return { header: rowHeader(live), generation: `live:${live.generation}` };
    }
    const persisted = db.prepare(
      `SELECT
        id AS session_id, version, created_at, cwd, parent_session, seed_length, provider, model, executor, agent_preset, title, archived, generation
      FROM persisted_sessions
      WHERE id = ?`,
    ).get(sessionId) as (SessionHeaderRow & { generation: number }) | undefined;
    if (persisted !== undefined) {
      return { header: rowHeader(persisted), generation: `persisted:${persisted.generation}` };
    }
    throw new SessionQueryError(
      `session "${sessionId}" not found`,
      "SESSION_QUERY_SESSION_NOT_FOUND",
    );
  }

  private async _close(): Promise<void> {
    this._closed = true;
    await this._tail;
    if (this._ready !== undefined) {
      try {
        await this._ready;
      } catch {
        // Opening already closed a partially-created handle; disposal only waits.
      }
    }
    this._db?.close();
    this._db = undefined;
  }

  private async _open(): Promise<void> {
    this._db = await openSearchDatabase(this.config.path, this.config.journalMode);
    const state = this._db.prepare(
      "SELECT global_generation FROM search_state WHERE singleton = 1",
    ).get() as { global_generation: number };
    this._globalGeneration = state.global_generation;
    this._localGeneration = state.global_generation;
  }

  private async _ensureReady(): Promise<void> {
    this._ready ??= this._open();
    try {
      await this._ready;
    } catch (error: unknown) {
      throw new SessionQueryError(
        `session-search SQLite index failed to open: ${errorMessage(error)}`,
        "SESSION_QUERY_INDEX_FAILED",
        { cause: error },
      );
    }
  }

  private async _serialized<T>(operation: () => Promise<T>): Promise<T> {
    if (this._isClosed()) throw indexClosed();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const prior = this._tail;
    this._tail = prior.then(() => gate);
    try {
      await prior;
    } catch {
      release();
      throw indexClosed();
    }
    if (this._isClosed()) {
      release();
      throw indexClosed();
    }
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async _reconcile(): Promise<void> {
    const db = this._requireDb();
    const persistedRows = db.prepare(
      "SELECT id, revision, generation FROM persisted_sessions",
    ).all() as unknown as IndexedPersistedRow[];
    const liveRows = db.prepare(
      "SELECT id, fingerprint, persisted, generation FROM temp.live_sessions",
    ).all() as unknown as IndexedLiveRow[];
    const persistedById = new Map(persistedRows.map(row => [row.id as SessionId, row]));
    const liveById = new Map(liveRows.map(row => [row.id as SessionId, row]));
    const observation = await this._observeStable(persistedById);

    const persistentChanges = [...observation.persisted.values()].filter(entry => entry.loaded !== undefined);
    const persistentDeletes = persistedRows.filter(row => !observation.persisted.has(row.id as SessionId));
    const liveChanges = [...observation.live.values()].filter((entry) => {
      const indexed = liveById.get(entry.header.id);
      const persisted = observation.persisted.has(entry.header.id) ? 1 : 0;
      return indexed?.fingerprint !== entry.fingerprint || indexed.persisted !== persisted;
    });
    const liveDeletes = liveRows.filter(row => !observation.live.has(row.id as SessionId));
    const hasWrites = persistentChanges.length > 0
      || persistentDeletes.length > 0
      || liveChanges.length > 0
      || liveDeletes.length > 0;

    let nextMainGeneration = this._mainGeneration();
    let nextLocalGeneration = this._localGeneration;
    if (persistentChanges.length > 0 || persistentDeletes.length > 0) nextMainGeneration += 1;
    const liveReplacements = liveChanges.map((entry) => {
      nextLocalGeneration = Math.max(nextLocalGeneration, nextMainGeneration) + 1;
      return {
        entry,
        generation: nextLocalGeneration,
        persisted: observation.persisted.has(entry.header.id),
      };
    });

    if (hasWrites) {
      let began = false;
      try {
        db.exec("BEGIN IMMEDIATE");
        began = true;
        for (const row of persistentDeletes) this._deleteSession("persisted", row.id as SessionId);
        for (const entry of persistentChanges) {
          if (entry.loaded === undefined) throw new Error(`missing loaded revision for session "${entry.header.id}"`);
          this._replacePersistedSession(entry.loaded, entry.revision, nextMainGeneration);
        }
        if (persistentChanges.length > 0 || persistentDeletes.length > 0) {
          db.prepare("UPDATE search_state SET global_generation = ? WHERE singleton = 1").run(nextMainGeneration);
        }
        for (const row of liveDeletes) this._deleteSession("live", row.id as SessionId);
        for (const { entry, generation, persisted } of liveReplacements) {
          this._replaceLiveSession(entry, generation, persisted);
        }
        db.exec("COMMIT");
      } catch (error: unknown) {
        if (began) {
          try {
            db.exec("ROLLBACK");
          } catch {
            // The original SQLite failure remains the actionable cause.
          }
        }
        throw new SessionQueryError(
          `session-search reconciliation failed: ${errorMessage(error)}`,
          "SESSION_QUERY_INDEX_FAILED",
          { cause: error },
        );
      }
    }

    if (hasWrites) this._globalGeneration += 1;
    this._localGeneration = nextLocalGeneration;
  }

  private async _observeStable(
    indexed: ReadonlyMap<SessionId, IndexedPersistedRow>,
  ): Promise<Observation> {
    for (let attempt = 0; attempt < STABLE_OBSERVATION_ATTEMPTS; attempt += 1) {
      let persisted = new Map<SessionId, ObservedPersistedSession>();
      const before = await this.source.listSnapshots();
      persisted = materializePersistenceSnapshots(before);
      for (const entry of persisted.values()) {
        if (indexed.get(entry.header.id)?.revision === entry.revision) continue;
        // Skip work already shadowed by a live owner.
        if (this.source.listLive().some(live => live.header.id === entry.header.id)) continue;
        const loaded = await this.source.inspect(entry.header.id);
        assertSessionHeadersCompatible(entry.header, loaded.meta);
        entry.loaded = observeSession(loaded.meta, loaded.events);
      }
      const afterSnapshots = await this.source.listSnapshots();
      const after = materializePersistenceSnapshots(afterSnapshots);
      if (!samePersistenceSnapshots(persisted, after)) continue;

      const live = new Map<SessionId, ObservedSession>();
      for (const session of this.source.listLive()) {
        const observed = observeSession(session.header, session.events);
        const durable = persisted.get(session.header.id);
        if (durable !== undefined) assertSessionHeadersCompatible(observed.header, durable.header);
        live.set(session.header.id, observed);
      }
      return { persisted, live };
    }
    throw new SessionQueryError(
      "session-search persistence observation did not stabilize after one retry",
      "SESSION_QUERY_PERSISTENCE_FAILED",
    );
  }

  private _mainGeneration(): number {
    const row = this._requireDb().prepare(
      "SELECT global_generation FROM search_state WHERE singleton = 1",
    ).get() as { global_generation: number };
    return row.global_generation;
  }

  private _deleteSession(source: "persisted" | "live", id: SessionId): void {
    const db = this._requireDb();
    if (source === "persisted") {
      db.prepare("DELETE FROM persisted_docs WHERE session_id = ?").run(id);
      db.prepare("DELETE FROM persisted_sessions WHERE id = ?").run(id);
    } else {
      db.prepare("DELETE FROM temp.live_docs WHERE session_id = ?").run(id);
      db.prepare("DELETE FROM temp.live_sessions WHERE id = ?").run(id);
    }
  }

  private _replacePersistedSession(
    entry: ObservedSession,
    revision: string,
    generation: number,
  ): void {
    this._deleteSession("persisted", entry.header.id);
    const db = this._requireDb();
    db.prepare(`
      INSERT INTO persisted_sessions
        (id, version, created_at, cwd, parent_session, seed_length, provider, model, executor, agent_preset, title, archived, revision, generation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      ...headerBindings(entry.header),
      entry.title ?? null,
      entry.archived ? 1 : 0,
      revision,
      generation,
    );
    this._insertDocuments(db, "persisted_docs", entry.documents);
  }

  private _replaceLiveSession(entry: ObservedSession, generation: number, persisted: boolean): void {
    this._deleteSession("live", entry.header.id);
    const db = this._requireDb();
    db.prepare(`
      INSERT INTO temp.live_sessions
        (id, version, created_at, cwd, parent_session, seed_length, provider, model, executor, agent_preset, title, archived, fingerprint, persisted, generation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      ...headerBindings(entry.header),
      entry.title ?? null,
      entry.archived ? 1 : 0,
      entry.fingerprint,
      persisted ? 1 : 0,
      generation,
    );
    this._insertDocuments(db, "temp.live_docs", entry.documents);
  }

  private _insertDocuments(db: DatabaseSync, table: string, documents: readonly SessionEventSearchDocument[]): void {
    const insert = db.prepare(`
      INSERT INTO ${table} (text, session_id, seq, type, time, surface, codepoint_length)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    for (const document of documents) {
      const text = sanitizeFtsText(document.text);
      insert.run(
        text,
        document.sessionId,
        document.seq,
        document.type,
        document.time,
        document.surface,
        Array.from(text).length,
      );
    }
  }

  private _querySessions(request: NormalizedSessionRequest, offset: number): SearchRow[] {
    const selected = selectedDocumentsSql();
    const sessionWhere = buildSessionWhere(request.sessionFilters);
    const eventWhere = buildEventWhere(request.eventFilters);
    assertFts5OuterPredicateCount(sessionWhere.predicateCount + eventWhere.predicateCount);
    const where = [sessionWhere.sql, eventWhere.sql].filter(Boolean).join(" AND ");
    const bindings = [
      ...selectedDocumentsParams(request.query),
      ...sessionWhere.params,
      ...eventWhere.params,
      request.limit + 1,
      offset,
    ];
    assertPortableBindingCount(bindings.length);
    return this._requireDb().prepare(`
      ${selected.sql},
      filtered AS (
        SELECT * FROM matched ${where.length === 0 ? "" : `WHERE ${where}`}
      ),
      ranked AS (
        SELECT *, ROW_NUMBER() OVER (
          PARTITION BY session_id
          ORDER BY match_count DESC, document_length ASC, time DESC, seq DESC
        ) AS event_rank
        FROM filtered
      )
      SELECT * FROM ranked
      WHERE event_rank = 1
      ORDER BY match_count DESC, document_length ASC, time DESC, session_id ASC, seq DESC
      LIMIT ? OFFSET ?
    `).all(...bindings) as unknown as SearchRow[];
  }

  private _queryEvents(request: NormalizedEventRequest, offset: number): SearchRow[] {
    const selected = selectedDocumentsSql();
    const eventWhere = buildEventWhere(request.filters);
    assertFts5OuterPredicateCount(1 + eventWhere.predicateCount);
    const where = ["session_id = ?", eventWhere.sql].filter(Boolean).join(" AND ");
    const bindings = [
      ...selectedDocumentsParams(request.query),
      request.sessionId,
      ...eventWhere.params,
      request.limit + 1,
      offset,
    ];
    assertPortableBindingCount(bindings.length);
    return this._requireDb().prepare(`
      ${selected.sql}
      SELECT * FROM matched
      WHERE ${where}
      ORDER BY match_count DESC, document_length ASC, time DESC, seq DESC
      LIMIT ? OFFSET ?
    `).all(...bindings) as unknown as SearchRow[];
  }

  private _sessionHit(row: SearchRow): SessionSearchHit {
    return {
      header: rowHeader(row),
      live: row.live === 1,
      persisted: row.persisted === 1,
      bestMatch: this._eventHit(row),
    };
  }

  private _eventHit(row: SearchRow): SessionEventSearchHit {
    return {
      sessionId: row.session_id as SessionId,
      seq: row.seq,
      type: row.type as SessionEventSearchHit["type"],
      time: row.time,
      surface: row.surface as SessionEventSearchHit["surface"],
      snippet: makeSnippet(row.marked_text, this.config.snippetChars),
    };
  }

  private _requireDb(): DatabaseSync {
    if (this._db === undefined) throw indexClosed();
    return this._db;
  }

  private _isClosed(): boolean {
    return this._closed;
  }

  private _assertSearchEnabled(): void {
    if (this.config.openAt === "never") {
      throw new SessionQueryError(
        "session search is disabled: this deployment configures the session-query index with openAt \"never\"",
        "SESSION_QUERY_SEARCH_DISABLED",
      );
    }
  }
}

function headerBindings(header: SessionHeader): (string | number | null)[] {
  return [
    header.id,
    header.version,
    header.createdAt,
    header.cwd ?? null,
    header.parentSession ?? null,
    header.seedLength ?? null,
    header.provider ?? null,
    header.model ?? null,
    header.executor ?? null,
    header.agentPreset ?? null,
  ];
}

function selectedDocumentsSql(): { sql: string } {
  return {
    sql: `WITH candidates AS (
      SELECT
        pd.session_id AS session_id,
        ps.version AS version,
        ps.created_at AS created_at,
        ps.cwd AS cwd,
        ps.parent_session AS parent_session,
        ps.seed_length AS seed_length,
        ps.provider AS provider,
        ps.model AS model,
        ps.executor AS executor,
        ps.agent_preset AS agent_preset,
        ps.title AS title,
        ps.archived AS archived,
        0 AS live,
        1 AS persisted,
        CAST(pd.seq AS INTEGER) AS seq,
        pd.type AS type,
        CAST(pd.time AS INTEGER) AS time,
        pd.surface AS surface,
        highlight(persisted_docs, 0, ?, ?) AS marked_text,
        CAST(pd.codepoint_length AS INTEGER) AS document_length
      FROM persisted_docs AS pd
      JOIN persisted_sessions AS ps ON ps.id = pd.session_id
      WHERE persisted_docs MATCH ?
        AND NOT EXISTS (SELECT 1 FROM temp.live_sessions AS ls WHERE ls.id = pd.session_id)
      UNION ALL
      SELECT
        ld.session_id AS session_id,
        ls.version AS version,
        ls.created_at AS created_at,
        ls.cwd AS cwd,
        ls.parent_session AS parent_session,
        ls.seed_length AS seed_length,
        ls.provider AS provider,
        ls.model AS model,
        ls.executor AS executor,
        ls.agent_preset AS agent_preset,
        ls.title AS title,
        ls.archived AS archived,
        1 AS live,
        ls.persisted AS persisted,
        CAST(ld.seq AS INTEGER) AS seq,
        ld.type AS type,
        CAST(ld.time AS INTEGER) AS time,
        ld.surface AS surface,
        highlight(live_docs, 0, ?, ?) AS marked_text,
        CAST(ld.codepoint_length AS INTEGER) AS document_length
      FROM temp.live_docs AS ld
      JOIN temp.live_sessions AS ls ON ls.id = ld.session_id
      WHERE live_docs MATCH ?
    ), matched AS (
      SELECT *,
        (
          length(CAST(marked_text AS BLOB))
          - length(CAST(replace(marked_text, ?, '') AS BLOB))
        ) / ? AS match_count
      FROM candidates
    )`,
  };
}

function selectedDocumentsParams(query: string): Array<string | number> {
  const expression = quoteFtsData(query);
  return [
    FTS_HIGHLIGHT_START,
    FTS_HIGHLIGHT_END,
    expression,
    FTS_HIGHLIGHT_START,
    FTS_HIGHLIGHT_END,
    expression,
    FTS_HIGHLIGHT_START,
    Buffer.byteLength(FTS_HIGHLIGHT_START, "utf8"),
  ];
}

function observeSession(header: SessionHeader, events: readonly SessionEvent[]): ObservedSession {
  const detachedHeader = structuredClone(header);
  const detachedEvents = events.map(event => structuredClone(event));
  return {
    header: detachedHeader,
    documents: buildSessionEventSearchDocuments(detachedHeader.id, detachedEvents),
    fingerprint: createHash("sha256")
      .update(JSON.stringify({ header: detachedHeader, events: detachedEvents }))
      .digest("base64url"),
    ...foldSessionMeta(detachedEvents),
  };
}

function materializePersistenceSnapshots(
  snapshots: readonly SessionPersistenceSnapshot[],
): Map<SessionId, ObservedPersistedSession> {
  const result = new Map<SessionId, ObservedPersistedSession>();
  for (const snapshot of snapshots) {
    if (typeof snapshot.revision !== "string") {
      throw new Error("persistence snapshot revision must be a string");
    }
    const header = structuredClone(snapshot.header);
    if (result.has(header.id)) {
      throw new Error(`persistence listed duplicate session "${header.id}"`);
    }
    result.set(header.id, { header, revision: snapshot.revision });
  }
  return result;
}

function samePersistenceSnapshots(
  before: ReadonlyMap<SessionId, ObservedPersistedSession>,
  after: ReadonlyMap<SessionId, ObservedPersistedSession>,
): boolean {
  if (before.size !== after.size) return false;
  for (const [id, first] of before) {
    const second = after.get(id);
    if (
      second === undefined
      || first.revision !== second.revision
      || !sameHeader(first.header, second.header)
    ) return false;
  }
  return true;
}

function sameHeader(a: SessionHeader, b: SessionHeader): boolean {
  return a.version === b.version
    && a.id === b.id
    && a.createdAt === b.createdAt
    && a.cwd === b.cwd
    && a.parentSession === b.parentSession
    && a.seedLength === b.seedLength
    && a.provider === b.provider
    && a.model === b.model
    && a.executor === b.executor
    && (a.delegationDepth ?? 0) === (b.delegationDepth ?? 0)
    && a.agentPreset === b.agentPreset;
}

/** The snapshot and inspection must name the same logical session in every field. */
function assertSessionHeadersCompatible(expected: SessionHeader, actual: SessionHeader): void {
  if (!sameHeader(expected, actual)) {
    throw new Error(
      `session header changed between snapshots and inspection for "${expected.id}"; refusing to index an inconsistent view`,
    );
  }
}

function rowHeader(row: SessionHeaderRow): SessionHeader {
  return {
    version: row.version,
    id: row.session_id as SessionId,
    createdAt: row.created_at,
    ...row.cwd === null ? {} : { cwd: row.cwd },
    ...row.parent_session === null ? {} : { parentSession: row.parent_session as SessionId },
    ...row.seed_length === null ? {} : { seedLength: row.seed_length },
    ...row.provider === null ? {} : { provider: row.provider },
    ...row.model === null ? {} : { model: row.model },
    ...row.executor === null ? {} : { executor: row.executor },
    ...row.agent_preset === null ? {} : { agentPreset: row.agent_preset },
  };
}

function page<Row, Item>(
  rows: readonly Row[],
  limit: number,
  convert: (row: Row) => Item,
  nextCursor: (offset: number) => SessionSearchCursor,
  offset: number,
): SessionSearchPage<Item> {
  const hasMore = rows.length > limit;
  return {
    items: rows.slice(0, limit).map(convert),
    ...hasMore ? { nextCursor: nextCursor(offset + limit) } : {},
  };
}

function encodeCursor(payload: CursorPayload): SessionSearchCursor {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url") as SessionSearchCursor;
}

function decodeCursor(
  cursor: SessionSearchCursor,
  instance: string,
  scope: CursorPayload["scope"],
  fingerprint: string,
  generation: string,
): number {
  let decoded: Partial<CursorPayload>;
  try {
    decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as Partial<CursorPayload>;
  } catch (error: unknown) {
    throw invalidCursor(error);
  }
  if (
    decoded.version !== 1
    || decoded.instance !== instance
    || decoded.scope !== scope
    || decoded.fingerprint !== fingerprint
    || !Number.isSafeInteger(decoded.offset)
    || decoded.offset === undefined
    || decoded.offset < 0
  ) {
    throw invalidCursor(new Error("cursor does not belong to this normalized request"));
  }
  if (decoded.generation !== generation) {
    throw new SessionQueryError(
      "session-search cursor is stale because its relevant corpus changed",
      "SESSION_QUERY_STALE_CURSOR",
    );
  }
  return decoded.offset;
}

function invalidCursor(cause: unknown): SessionQueryError {
  return new SessionQueryError(
    "session-search cursor is invalid",
    "SESSION_QUERY_INVALID_CURSOR",
    { cause },
  );
}

function resolveConfig(options: SessionSearchOptions): ResolvedConfig {
  const resolved: ResolvedConfig = {
    path: options.path,
    openAt: options.openAt ?? "first-search",
    journalMode: options.journalMode ?? "wal",
    defaultLimit: options.defaultLimit ?? SESSION_QUERY_DEFAULT_LIMIT,
    maxLimit: options.maxLimit ?? SESSION_QUERY_MAX_LIMIT,
    snippetChars: options.snippetChars ?? SESSION_QUERY_SNIPPET_CHARS,
  };
  if (typeof resolved.path !== "string" || resolved.path.trim().length === 0) {
    throw invalidConfig("path must not be blank");
  }
  const openPhases: readonly string[] = ["startup", "first-search", "never"];
  if (!openPhases.includes(resolved.openAt)) throw invalidConfig("openAt is not supported");
  assertPageLimit("defaultLimit", resolved.defaultLimit);
  assertPageLimit("maxLimit", resolved.maxLimit);
  assertPositiveInteger("snippetChars", resolved.snippetChars);
  if (resolved.defaultLimit > resolved.maxLimit) {
    throw invalidConfig("defaultLimit must be less than or equal to maxLimit");
  }
  const journalModes: readonly string[] = ["wal", "delete", "truncate", "persist"];
  if (!journalModes.includes(resolved.journalMode)) throw invalidConfig("journalMode is not supported");
  return resolved;
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 1) throw invalidConfig(`${name} must be a positive integer`);
}

function assertPageLimit(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > Number.MAX_SAFE_INTEGER - 1) {
    throw invalidConfig(`${name} must be an integer between 1 and ${Number.MAX_SAFE_INTEGER - 1}`);
  }
}

function invalidConfig(detail: string): SessionQueryError {
  return new SessionQueryError(`session-search SQLite config: ${detail}`, "SESSION_QUERY_INVALID_CONFIG");
}

function indexClosed(): SessionQueryError {
  return new SessionQueryError("session-search SQLite index is closed", "SESSION_QUERY_INDEX_FAILED");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
