/**
 * Shared serialization, adoption, repair, and read orchestration for the JSONL
 * session backend — a Catomicals port of DeepSeek Harness
 * `packages/session/session-persistence/src/coordinator.ts` (MIT), without the
 * Cordis live-session event bus: per-session write serialization, lazy
 * atomic materialization, seq-contiguity enforcement, torn-tail repair with
 * synthetic closers, and non-mutating inspection are faithful. The live write
 * path (write-behind) is owned by the SessionManager, which feeds this
 * coordinator's `append` with contiguous batches.
 *
 * @module catomicals-desktop/sessions/coordinator
 */

import { snapshotJsonValue } from "./json.js";
import { inspectionFromStored, type JsonlSessionStore } from "./jsonl-store.js";
import {
  SESSION_FORMAT_VERSION,
  type SessionEvent,
  type SessionEventType,
  type SessionHeader,
  type SessionId,
  type SessionInspection,
  type SessionPersistenceSnapshot,
  type SessionSummary,
} from "./types.js";

/** The event types this build can interpret; unknown required events are refused. */
export const KNOWN_SESSION_EVENT_TYPES: ReadonlySet<SessionEventType> = new Set([
  "turn/start",
  "turn/end",
  "user/message",
  "assistant/message",
  "assistant/chunk",
  "tool/call",
  "tool/result",
  "request/header",
  "session/title",
  "session/archive",
  "todo/write",
  "session/end-seed",
]);

/** Per-session write state held by the coordinator's in-memory bookkeeping. */
interface SessionState {
  meta: SessionHeader;
  /** The next seq the backend expects to append (the stored log length). */
  cursor: number;
  /** Whether lazy creation has produced a durable artifact. */
  materialized: boolean;
}

/**
 * Return deterministic synthetic events that close an open tail turn. Unmatched
 * calls receive cancelled results first, followed by an interrupted `turn/end`;
 * sequences continue the log and timestamps reuse the last real event. A
 * balanced or empty log returns no events.
 */
export function interruptedTurnClosers(events: readonly SessionEvent[]): SessionEvent[] {
  let openTurn: number | null = null;
  const pendingCalls = new Map<string, { callSeq?: number }>();
  for (const event of events) {
    switch (event.type) {
      case "turn/start":
        openTurn = event.data.turn;
        pendingCalls.clear();
        break;
      case "turn/end":
        openTurn = null;
        pendingCalls.clear();
        break;
      case "assistant/message":
        for (const part of event.data.parts ?? []) {
          if (part.type === "tool_call" && !pendingCalls.has(part.tool_call_id)) {
            pendingCalls.set(part.tool_call_id, {});
          }
        }
        break;
      case "tool/call": {
        const entry = pendingCalls.get(event.data.callId) ?? {};
        entry.callSeq = event.seq;
        pendingCalls.set(event.data.callId, entry);
        break;
      }
      case "tool/result":
        pendingCalls.delete(event.data.callId);
        break;
      default:
        break;
    }
  }

  const last = events.at(-1);
  if (openTurn === null || last === undefined) return [];

  let seq = last.seq + 1;
  const time = last.time;
  const closers: SessionEvent[] = [];

  for (const [callId, { callSeq }] of pendingCalls) {
    const started = callSeq !== undefined;
    closers.push({
      type: "tool/result",
      seq: seq++,
      time,
      data: {
        callId,
        outcome: "cancelled",
        error: started
          ? { name: "ToolOutcomeUnknownError", code: "TOOL_OUTCOME_UNKNOWN" }
          : { name: "ToolNotStartedError", code: "TOOL_NOT_STARTED" },
      },
      surfaceOp: "append",
      ...(started ? { sourceEventSeqs: [callSeq] } : {}),
    });
  }

  closers.push({ type: "turn/end", seq: seq++, time, data: { turn: openTurn, reason: { kind: "interrupted" } } });
  return closers;
}

/** A format refusal naming the raw artifact when one exists. */
export class SessionFormatUnsupportedError extends Error {
  constructor(message: string, readonly path?: string) {
    super(message);
    this.name = "SessionFormatUnsupportedError";
  }
}

/** The stored log is intact but this runtime cannot faithfully interpret it. */
export class SessionPersistenceCorruptionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SessionPersistenceCorruptionError";
  }
}

/**
 * Orchestrates the JSONL backend: create/append/load/inspect/readFrom/list.
 * All operations for one session id run on a per-id chain so writes never
 * interleave; errors do not poison the chain.
 */
export class SessionCoordinator {
  private readonly states = new Map<SessionId, SessionState>();
  private readonly chains = new Map<SessionId, Promise<unknown>>();

  /** @param store - the JSONL file-bytes backend this coordinator orchestrates. */
  constructor(private readonly store: JsonlSessionStore) {}

  /**
   * Register detached session metadata for lazy creation on the first append.
   * Duplicate tracked or persisted ids are rejected.
   */
  create(meta: SessionHeader): Promise<void> {
    const snapshot = snapshotJsonValue(meta);
    if (snapshot === undefined) {
      return Promise.reject(new TypeError("session metadata must be losslessly JSON-serializable"));
    }
    if (!Number.isSafeInteger(snapshot.createdAt) || snapshot.createdAt < 0) {
      return Promise.reject(new TypeError("session metadata createdAt must be a non-negative safe integer"));
    }
    return this.serialize(snapshot.id, () => this.createCore(snapshot));
  }

  private async createCore(meta: SessionHeader): Promise<void> {
    // Do NOT clobber an existing session: the SessionId IS the identity.
    if (this.states.has(meta.id)) {
      throw new Error(`session "${meta.id}" already exists in this backend`);
    }
    if (await this.store.loadStored(meta.id) !== undefined) {
      throw new Error(`session "${meta.id}" already has a persisted log on disk; load/resume it instead of creating`);
    }
    // Pure lazy: record intent only. No artifact until the first append.
    this.states.set(meta.id, { meta, cursor: 0, materialized: false });
  }

  /**
   * Durably persist a contiguous batch of events. Honors the append-only and
   * contiguous-seq contracts; rejects non-JSON-serializable event data.
   */
  async append(id: SessionId, events: readonly SessionEvent[]): Promise<void> {
    const batch = snapshotJsonValue(events) as SessionEvent[] | undefined;
    if (batch === undefined) {
      throw new TypeError(
        "session event batch is not losslessly JSON-serializable because it contains non-JSON-serializable data",
      );
    }
    return this.serialize(id, () => this.appendCore(id, batch));
  }

  private async appendCore(id: SessionId, events: SessionEvent[]): Promise<void> {
    if (events.length === 0) return;
    let state = this.states.get(id);
    if (state === undefined) state = await this.adopt(id);

    // Contiguity contract: each event's seq must continue the stored log.
    for (const [i, event] of events.entries()) {
      if (event.seq !== state.cursor + i) {
        throw new Error(`append seq mismatch for "${id}": expected ${state.cursor + i} at index ${i}, got ${event.seq}`);
      }
    }

    await this.store.appendBatch(state.meta, events, state.materialized);
    // The durable write is the transaction: mark materialized + advance the cursor.
    state.materialized = true;
    state.cursor += events.length;
  }

  /**
   * Durably persist a batch of events whose seq numbers are assigned here,
   * inside the per-session chain. Used by the manager for renderer-driven
   * appends, where the caller cannot know the next seq.
   * @returns the materialized events (with assigned seqs).
   */
  async appendAuto(id: SessionId, partials: readonly Omit<SessionEvent, "seq">[]): Promise<SessionEvent[]> {
    if (partials.length === 0) return [];
    const snapshot = snapshotJsonValue(partials);
    if (snapshot === undefined) {
      throw new TypeError(
        "session event batch is not losslessly JSON-serializable because it contains non-JSON-serializable data",
      );
    }
    return this.serialize(id, async () => {
      let state = this.states.get(id);
      if (state === undefined) state = await this.adopt(id);
      const events = (partials as readonly Omit<SessionEvent, "seq">[]).map((partial, i) => ({
        ...partial,
        seq: state.cursor + i,
      })) as SessionEvent[];
      await this.store.appendBatch(state.meta, events, state.materialized);
      state.materialized = true;
      state.cursor += events.length;
      return events;
    });
  }

  /**
   * Append one metadata event (title/archive) at the next seq. Assigns seq and
   * time inside the per-session chain.
   * @returns the materialized event.
   */
  async appendNext(id: SessionId, partial: Omit<SessionEvent, "seq">): Promise<SessionEvent> {
    const [event] = await this.appendAuto(id, [partial]);
    return event;
  }

  /** Drop in-memory state for an id (used after delete/restore-purge). */
  forget(id: SessionId): void {
    this.states.delete(id);
  }

  /** Resolve the absolute log path for a header without touching the filesystem. */
  locate(meta: SessionHeader): string {
    return this.store.locate(meta);
  }

  /** Whether an id has been created (or adopted) but not yet closed. */
  has(id: SessionId): boolean {
    return this.states.has(id);
  }

  /**
   * Load a persisted session: repair any torn tail, append synthetic closers,
   * and return the committed immutable view. Mutating — use {@link inspect}
   * for a side-effect-free read.
   */
  async load(id: SessionId): Promise<SessionInspection> {
    return this.serialize(id, async () => {
      const stored = await this.store.loadStored(id);
      if (stored === undefined) throw new Error(`session "${id}" not found`);
      this.assertStoredId(id, stored.meta);
      this.assertVersion(stored.meta);
      const storedEvents = this.adoptStoredEvents(stored.events, id);
      this.assertEventsSupported(stored.meta, storedEvents);

      const closers = interruptedTurnClosers(storedEvents);
      if (stored.tornMarker !== undefined || closers.length > 0) {
        // Repair changes the durable revision; re-read the exact committed graph.
        await this.store.commitRepair(stored.meta, stored.tornMarker, closers);
        const repaired = await this.store.loadStored(id);
        if (repaired === undefined) throw new Error(`session "${id}" lost its log during repair`);
        this.assertStoredId(id, repaired.meta);
        const repairedEvents = this.adoptStoredEvents(repaired.events, id);
        this.assertEventsSupported(repaired.meta, repairedEvents);
        const balanced = [...repairedEvents, ...interruptedTurnClosers(repairedEvents)];
        const state = this.states.get(id);
        if (state !== undefined) {
          state.meta = repaired.meta;
          state.cursor = balanced.length;
          state.materialized = true;
        }
        return Object.freeze({ meta: repaired.meta, events: Object.freeze(balanced) });
      }
      const state = this.states.get(id);
      if (state !== undefined) {
        state.meta = stored.meta;
        state.cursor = storedEvents.length;
        state.materialized = true;
      }
      return Object.freeze({ meta: stored.meta, events: Object.freeze(storedEvents) });
    });
  }

  /**
   * Inspect a persisted session without committing recovery or publishing
   * state. Synthetic closers are included in the returned view (matching what
   * a resumed session would see) but are NOT persisted.
   */
  async inspect(id: SessionId, signal?: AbortSignal): Promise<SessionInspection> {
    signal?.throwIfAborted();
    return this.serialize(id, async () => {
      signal?.throwIfAborted();
      const stored = await this.store.loadStored(id, signal);
      if (stored === undefined) throw new Error(`session "${id}" not found`);
      this.assertStoredId(id, stored.meta);
      this.assertVersion(stored.meta);
      const storedEvents = this.adoptStoredEvents(stored.events, id);
      this.assertEventsSupported(stored.meta, storedEvents);
      const balanced = [...storedEvents, ...interruptedTurnClosers(storedEvents)];
      return Object.freeze({ meta: stored.meta, events: Object.freeze(balanced) });
    });
  }

  /** Read the stored events from `fromSeq` onward, detached and non-mutating. */
  readFrom(id: SessionId, fromSeq: number, signal?: AbortSignal): Promise<{ meta: SessionHeader; events: SessionEvent[] }> {
    if (!Number.isSafeInteger(fromSeq) || fromSeq < 0) {
      return Promise.reject(new TypeError(`readFrom fromSeq must be a non-negative safe integer, got ${String(fromSeq)}`));
    }
    return this.serialize(id, async () => {
      signal?.throwIfAborted();
      const stored = await this.store.loadStored(id, signal);
      if (stored === undefined) throw new Error(`session "${id}" not found`);
      this.assertStoredId(id, stored.meta);
      this.assertVersion(stored.meta);
      const storedEvents = this.adoptStoredEvents(stored.events, id);
      this.assertEventsSupported(stored.meta, storedEvents);
      // Sequential fallback: contiguous seqs from 0 make the suffix an index slice.
      return { meta: stored.meta, events: storedEvents.slice(fromSeq) };
    });
  }

  /** List stored session headers (header line only). */
  list(signal?: AbortSignal): Promise<SessionHeader[]> {
    return this.store.list(signal);
  }

  /** List headers plus stat-derived revisions. */
  listSnapshots(signal?: AbortSignal): Promise<SessionPersistenceSnapshot[]> {
    return this.store.listSnapshots(signal);
  }

  /** List summaries folded from headers + bounded log tails. */
  listSummaries(signal?: AbortSignal): Promise<SessionSummary[]> {
    return this.store.listSummaries(signal);
  }

  /** Wait for every in-flight per-session chain to settle. */
  async whenIdle(): Promise<void> {
    while (this.chains.size > 0) {
      await Promise.allSettled([...this.chains.values()]);
    }
  }

  /** Build a state for a session discovered in storage but not yet in memory. */
  private async adopt(id: SessionId): Promise<SessionState> {
    const stored = await this.store.loadStored(id);
    if (stored === undefined) throw new Error(`session "${id}" not found`);
    this.assertStoredId(id, stored.meta);
    this.assertVersion(stored.meta);
    const storedEvents = this.adoptStoredEvents(stored.events, id);
    this.assertEventsSupported(stored.meta, storedEvents);
    const closers = interruptedTurnClosers(storedEvents);
    if (stored.tornMarker !== undefined || closers.length > 0) {
      await this.store.commitRepair(stored.meta, stored.tornMarker, closers);
      const repaired = await this.store.loadStored(id);
      if (repaired === undefined) throw new Error(`session "${id}" lost its log during adoption`);
      return { meta: repaired.meta, cursor: repaired.events.length, materialized: true };
    }
    return { meta: stored.meta, cursor: storedEvents.length, materialized: true };
  }

  private assertVersion(meta: SessionHeader): void {
    if (meta.version === SESSION_FORMAT_VERSION) return;
    throw new SessionFormatUnsupportedError(
      meta.version > SESSION_FORMAT_VERSION
        ? `session "${meta.id}" uses log format v${meta.version}, but this build reads only v${SESSION_FORMAT_VERSION}: upgrade to open it`
        : `session "${meta.id}" uses log format v${meta.version}, older than the supported v${SESSION_FORMAT_VERSION}`,
      this.store.locate(meta),
    );
  }

  /** Refuse a log containing an event type this build does not know, unless ignorable. */
  private assertEventsSupported(meta: SessionHeader, events: readonly SessionEvent[]): void {
    for (const event of events) {
      if (KNOWN_SESSION_EVENT_TYPES.has(event.type) || event.ignorable === true) continue;
      throw new SessionFormatUnsupportedError(
        `session "${meta.id}" contains event type "${event.type}" (seq ${event.seq}) unknown to this build and not marked ignorable; refusing to interpret the log — it was likely written by a newer harness`,
        this.store.locate(meta),
      );
    }
  }

  private assertStoredId(id: SessionId, meta: SessionHeader): void {
    if (meta.id !== id) {
      throw new Error(`stored session identity mismatch: requested "${id}", header contains "${meta.id}"`);
    }
  }

  /** Detach stored events so the caller owns them (storage never retains graph aliases). */
  private adoptStoredEvents(events: readonly SessionEvent[], id: SessionId): SessionEvent[] {
    const detached = snapshotJsonValue(events) as SessionEvent[] | undefined;
    if (detached === undefined) {
      throw new SessionPersistenceCorruptionError(
        `stored session "${id}" contains non-JSON-serializable event data`,
      );
    }
    return detached;
  }

  /**
   * Run `op` after any in-flight operation for the same session id. NOTE:
   * serialized public methods must NOT call each other (deadlock); they call
   * the unserialized `*Core`/private helpers instead.
   */
  private serialize<T>(id: SessionId, op: () => Promise<T> | T): Promise<T> {
    const prior = this.chains.get(id) ?? Promise.resolve();
    const next = prior.then(op, op);
    // Keep the chain alive but swallow this op's rejection for the NEXT waiter.
    const tail = next.then(() => undefined, () => undefined);
    this.chains.set(id, tail);
    void tail.then(() => {
      if (this.chains.get(id) === tail) this.chains.delete(id);
    });
    return next;
  }
}

/** Convenience: derive an inspection directly from a stored prefix. */
export { inspectionFromStored };
