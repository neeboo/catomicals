/**
 * SessionManager — the application-facing facade over the JSONL coordinator,
 * the SQLite FTS5 search index, and the recoverable trash. It is the
 * `SessionSearchSource` for the search engine and the navigation-event
 * emitter for the deeplink bridge. Wallet state is never stored here: wallet
 * actions stay MCP/executor tools and only their tool-call/result events are
 * logged like any other conversation event.
 *
 * @module catomicals-desktop/sessions/manager
 */

import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { SessionCoordinator } from "./coordinator.js";
import { JsonlSessionStore } from "./jsonl-store.js";
import { SqliteSessionQueryEngine } from "./search.js";
import { TrashStore, type TrashRecord } from "./trash.js";
import {
  SESSION_FORMAT_VERSION,
  type CatomicalsNavigationEvent,
  type SessionEvent,
  type SessionEventSearchPage,
  type SessionEventSearchRequest,
  type SessionHeader,
  type SessionId,
  type SessionInspection,
  type SessionPersistenceSnapshot,
  type SessionSearchHit,
  type SessionSearchPage,
  type SessionSearchRequest,
  type SessionSummary,
  type TrashEntry,
} from "./types.js";
import { SessionId as brandSessionId } from "./types.js";
import type { JournalMode } from "./search-schema.js";

/** A live (open) session held in the manager's search-overlay registry. */
interface LiveSession {
  header: SessionHeader;
  events: SessionEvent[];
}

/** Inputs accepted by {@link SessionManager.createSession}. */
export interface CreateSessionInput {
  /** Initial title (stored as the first `session/title` event). */
  title?: string;
  provider?: string;
  model?: string;
  executor?: string;
  cwd?: string;
  parentSession?: SessionId;
  origin?: "subagent";
  delegationDepth?: number;
  agentPreset?: string;
  /** Fork/resume seed events; seq numbers are assigned contiguously from 0. */
  seed?: readonly Omit<SessionEvent, "seq">[];
}

/** Options for constructing a {@link SessionManager}. */
export interface SessionManagerOptions {
  /** Canonical JSONL root (normally `<userData>/sessions`). */
  root: string;
  /** Derived search index path (normally `<userData>/sessions/search.sqlite`). */
  searchPath?: string;
  journalMode?: JournalMode;
  defaultLimit?: number;
  maxLimit?: number;
  snippetChars?: number;
  /** When to open the SQLite index; defaults to `first-search`. */
  searchOpenAt?: "startup" | "first-search" | "never";
}

/**
 * Owns one userData session corpus: canonical append-only JSONL logs, a
 * derived SQLite FTS5 search index, and a recoverable trash. All mutating
 * operations are serialized per session by the coordinator.
 */
export class SessionManager {
  private readonly store: JsonlSessionStore;
  private readonly coordinator: SessionCoordinator;
  private readonly trashStore: TrashStore;
  private readonly search: SqliteSessionQueryEngine;
  private readonly live = new Map<SessionId, LiveSession>();
  private readonly navigationListeners = new Set<(event: CatomicalsNavigationEvent) => void>();
  private _closed = false;

  constructor(options: SessionManagerOptions) {
    this.store = new JsonlSessionStore(options.root);
    this.coordinator = new SessionCoordinator(this.store);
    this.trashStore = new TrashStore(this.store);
    this.search = new SqliteSessionQueryEngine(this, {
      path: options.searchPath ?? join(options.root, "search.sqlite"),
      journalMode: options.journalMode,
      defaultLimit: options.defaultLimit,
      maxLimit: options.maxLimit,
      snippetChars: options.snippetChars,
      openAt: options.searchOpenAt,
    });
  }

  /** The JSONL root (for diagnostics). */
  get root(): string {
    return this.store.rootDir;
  }

  // --- CRUD ---

  /** Create a session (lazy: no artifact until the first append). */
  async createSession(input: CreateSessionInput = {}): Promise<SessionSummary> {
    this.assertOpen();
    const id = brandSessionId(randomUUID());
    const now = Date.now();
    const header: SessionHeader = {
      version: SESSION_FORMAT_VERSION,
      id,
      createdAt: now,
      ...input.cwd !== undefined ? { cwd: input.cwd } : {},
      ...input.parentSession !== undefined ? { parentSession: input.parentSession } : {},
      ...input.provider !== undefined ? { provider: input.provider } : {},
      ...input.model !== undefined ? { model: input.model } : {},
      ...input.executor !== undefined ? { executor: input.executor } : {},
      ...input.origin !== undefined ? { origin: input.origin } : {},
      ...input.delegationDepth !== undefined ? { delegationDepth: input.delegationDepth } : {},
      ...input.agentPreset !== undefined ? { agentPreset: input.agentPreset } : {},
    };
    await this.coordinator.create(header);
    const live: LiveSession = { header, events: [] };
    if ((input.seed?.length ?? 0) > 0) {
      const seed = input.seed as readonly Omit<SessionEvent, "seq">[];
      const assigned = await this.coordinator.appendAuto(id, [...seed, { type: "session/end-seed", time: now, data: {} }]);
      live.events = assigned;
    }
    if (input.title !== undefined && input.title.length > 0) {
      const event = await this.coordinator.appendNext(id, {
        type: "session/title",
        time: Date.now(),
        data: { title: input.title },
      });
      live.events = [...live.events, event];
    }
    this.live.set(id, live);
    return this.summaryOf(header, live.events);
  }

  /** Append events to a session; seq numbers are assigned by the coordinator. */
  async appendEvents(id: SessionId, events: readonly Omit<SessionEvent, "seq">[]): Promise<SessionEvent[]> {
    this.assertOpen();
    const assigned = await this.coordinator.appendAuto(id, events);
    const live = this.live.get(id);
    if (live !== undefined) live.events = [...live.events, ...assigned];
    return assigned;
  }

  /** Read (and repair) a session, registering it as live for the search overlay. */
  async readSession(id: SessionId): Promise<SessionInspection> {
    this.assertOpen();
    const inspection = await this.coordinator.load(id);
    this.live.set(id, { header: inspection.meta, events: [...inspection.events] });
    return inspection;
  }

  /** Inspect a session non-mutatingly (no repair, no live registration). */
  async inspectSession(id: SessionId): Promise<SessionInspection> {
    this.assertOpen();
    return this.coordinator.inspect(id);
  }

  /** Read stored events from `fromSeq` onward (non-mutating). */
  readFrom(id: SessionId, fromSeq: number): Promise<{ meta: SessionHeader; events: SessionEvent[] }> {
    this.assertOpen();
    return this.coordinator.readFrom(id, fromSeq);
  }

  /** List session summaries (header + tail-folded metadata), newest first. */
  async listSessions(): Promise<SessionSummary[]> {
    this.assertOpen();
    const summaries = await this.coordinator.listSummaries();
    return summaries.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** Rename a session (appends a `session/title` event; latest wins). */
  async renameSession(id: SessionId, title: string): Promise<SessionSummary> {
    this.assertOpen();
    if (typeof title !== "string" || title.trim().length === 0 || title.length > 500) {
      throw new TypeError("session title must be a non-empty string of at most 500 characters");
    }
    const event = await this.coordinator.appendNext(id, {
      type: "session/title",
      time: Date.now(),
      data: { title: title.trim() },
    });
    const live = this.live.get(id);
    if (live !== undefined) live.events = [...live.events, event];
    return this.getSummary(id);
  }

  /** Archive or unarchive a session (appends a `session/archive` event). */
  async setArchived(id: SessionId, archived: boolean): Promise<SessionSummary> {
    this.assertOpen();
    const event = await this.coordinator.appendNext(id, {
      type: "session/archive",
      time: Date.now(),
      data: { archived },
    });
    const live = this.live.get(id);
    if (live !== undefined) live.events = [...live.events, event];
    return this.getSummary(id);
  }

  /** Recoverably delete a session (moves its directory to trash). */
  async deleteSession(id: SessionId): Promise<TrashEntry> {
    this.assertOpen();
    const inspection = await this.coordinator.inspect(id);
    const deletedAt = Date.now();
    const entry = await this.trashStore.trash(inspection.meta, deletedAt);
    this.live.delete(id);
    this.coordinator.forget(id);
    return entry;
  }

  /** Restore a trashed session to its original project directory. */
  async restoreSession(id: SessionId, deletedAt: number): Promise<SessionSummary> {
    this.assertOpen();
    await this.trashStore.restore(id, deletedAt);
    this.coordinator.forget(id);
    return this.getSummary(id);
  }

  /** Permanently purge a trashed session. */
  async purgeSession(id: SessionId, deletedAt: number): Promise<void> {
    this.assertOpen();
    await this.trashStore.purge(id, deletedAt);
  }

  /** List recoverably deleted sessions. */
  async listTrash(): Promise<TrashEntry[]> {
    this.assertOpen();
    const records: TrashRecord[] = await this.trashStore.list();
    return records.map(record => record.entry).sort((a, b) => b.deletedAt - a.deletedAt);
  }

  /** Open/close a session in the live overlay registry. */
  async openSession(id: SessionId): Promise<void> {
    this.assertOpen();
    if (this.live.has(id)) return;
    const inspection = await this.coordinator.inspect(id);
    this.live.set(id, { header: inspection.meta, events: [...inspection.events] });
  }

  /** Drop a session from the live overlay (it stays durable and searchable). */
  closeSession(id: SessionId): void {
    this.live.delete(id);
  }

  /** Whether a session id is currently registered as live. */
  isLive(id: SessionId): boolean {
    return this.live.has(id);
  }

  // --- search ---

  /** Cross-session full-text search. */
  searchSessions(request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>> {
    this.assertOpen();
    return this.search.searchSessions(request);
  }

  /** Within-session full-text search. */
  searchEvents(request: SessionEventSearchRequest): Promise<SessionEventSearchPage> {
    this.assertOpen();
    return this.search.searchEvents(request);
  }

  /** Prove FTS5 support in the installed runtime (fail-closed gate). */
  static probeFts5(): Promise<void> {
    return SqliteSessionQueryEngine.probeFts5();
  }

  // --- navigation events ---

  /** Emit a navigation event to every listener (deeplink or app-initiated). */
  navigate(target: { kind: "session-open"; sessionId: SessionId } | { kind: "session-list" }, source: "deeplink" | "app"): void {
    const event: CatomicalsNavigationEvent = {
      kind: target.kind,
      ...target.kind === "session-open" ? { sessionId: target.sessionId } : {},
      source,
      at: Date.now(),
    };
    for (const listener of this.navigationListeners) {
      try {
        listener(event);
      } catch {
        // A listener failure must not break navigation for other listeners.
      }
    }
  }

  /** Subscribe to navigation events; returns an unsubscribe function. */
  onNavigate(listener: (event: CatomicalsNavigationEvent) => void): () => void {
    this.navigationListeners.add(listener);
    return () => this.navigationListeners.delete(listener);
  }

  // --- SessionSearchSource (search engine's corpus view) ---

  async listSnapshots(): Promise<SessionPersistenceSnapshot[]> {
    return this.coordinator.listSnapshots();
  }

  async inspect(id: SessionId): Promise<SessionInspection> {
    return this.coordinator.inspect(id);
  }

  listLive(): Array<{ header: SessionHeader; events: SessionEvent[] }> {
    return [...this.live.values()].map(entry => ({ header: entry.header, events: [...entry.events] }));
  }

  // --- lifecycle ---

  /** Flush pending chains and close the search index. */
  async close(): Promise<void> {
    if (this._closed) return;
    this._closed = true;
    await this.coordinator.whenIdle();
    await this.search.close();
  }

  private assertOpen(): void {
    if (this._closed) throw new Error("session manager is closed");
  }

  private async getSummary(id: SessionId): Promise<SessionSummary> {
    const live = this.live.get(id);
    if (live !== undefined) return this.summaryOf(live.header, live.events);
    const inspection = await this.coordinator.inspect(id);
    return this.summaryOf(inspection.meta, inspection.events);
  }

  private summaryOf(header: SessionHeader, events: readonly SessionEvent[]): SessionSummary {
    let title: string | undefined;
    let archived = false;
    let lastError: { message: string; code: string } | undefined;
    let lastTime = header.createdAt;
    for (const event of events) {
      if (event.type === "session/title") title = event.data.title;
      else if (event.type === "session/archive") archived = event.data.archived;
      else if (event.type === "turn/end" && event.data.reason.kind === "error") {
        lastError = { message: event.data.reason.error.message, code: event.data.reason.error.code };
      }
      if (event.time > lastTime) lastTime = event.time;
    }
    return {
      id: header.id,
      ...title !== undefined ? { title } : {},
      archived,
      ...header.provider !== undefined ? { provider: header.provider } : {},
      ...header.model !== undefined ? { model: header.model } : {},
      ...header.executor !== undefined ? { executor: header.executor } : {},
      createdAt: header.createdAt,
      updatedAt: lastTime,
      eventCount: events.length,
      ...lastError !== undefined ? { lastError } : {},
    };
  }
}
