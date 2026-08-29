/**
 * Typed IPC surface for the session store: channel names, strict request
 * parsers, and `registerSessionIpc` wiring (main → manager → renderer).
 * The main-process integration point is a single call after `registerIpc()`
 * (see the summary); nothing here edits the visual shell.
 *
 * @module catomicals-desktop/sessions/ipc
 */

import { ipcMain, type IpcMainInvokeEvent, type WebContents } from "electron";
import { IPC_CHANNELS } from "../ipc.js";
import { SESSION_ID_PATTERN, type CatomicalsNavigationEvent, type SessionEvent, type SessionId } from "./types.js";
import type { SessionManager } from "./manager.js";
import type { SessionEventSearchRequest, SessionSearchRequest } from "./types.js";

/** Known session-filter kinds accepted at the IPC boundary. */
const SESSION_FILTER_KINDS = new Set([
  "id", "cwd", "created-at", "parent", "availability", "provider", "model", "executor", "archived",
]);
const EVENT_FILTER_KINDS = new Set(["seq", "time", "type", "surface"]);

function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Record<string, unknown>;
}

function exactFields(record: Record<string, unknown>, fields: readonly string[]): void {
  const keys = Object.keys(record).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("unexpected fields");
  }
}

function subsetFields(record: Record<string, unknown>, allowed: readonly string[]): void {
  const keys = Object.keys(record);
  if (keys.some(key => !allowed.includes(key))) throw new Error("unexpected fields");
}

function parseSessionIdValue(value: unknown): SessionId {
  if (typeof value !== "string" || !SESSION_ID_PATTERN.test(value)) throw new Error("invalid session id");
  return value as SessionId;
}

/** Parse the event envelope a renderer may append (seq is assigned by the coordinator). */
export function parseAppendableEvent(value: unknown): Omit<SessionEvent, "seq"> {
  const record = plainRecord(value);
  subsetFields(record, ["type", "time", "data", "ignorable", "sourceEventSeqs", "surfaceOp"]);
  if (typeof record.type !== "string" || record.type.length === 0) throw new Error("invalid event type");
  if (typeof record.time !== "number" || !Number.isSafeInteger(record.time) || record.time < 0) {
    throw new Error("invalid event time");
  }
  if (typeof record.data !== "object" || record.data === null || Array.isArray(record.data)) {
    throw new Error("invalid event data");
  }
  if (record.ignorable !== undefined && record.ignorable !== true) throw new Error("invalid event ignorable");
  return record as unknown as Omit<SessionEvent, "seq">;
}

export function parseCreateSessionRequest(value: unknown): Record<string, unknown> {
  const record = plainRecord(value);
  subsetFields(record, [
    "title", "provider", "model", "executor", "cwd", "parentSession", "origin", "delegationDepth", "agentPreset", "seed",
  ]);
  if (record.title !== undefined && (typeof record.title !== "string" || record.title.trim().length === 0)) {
    throw new Error("invalid title");
  }
  for (const key of ["provider", "model", "executor", "cwd", "agentPreset"] as const) {
    if (record[key] !== undefined && typeof record[key] !== "string") throw new Error(`invalid ${key}`);
  }
  if (record.parentSession !== undefined) record.parentSession = parseSessionIdValue(record.parentSession);
  if (record.origin !== undefined && record.origin !== "subagent") throw new Error("invalid origin");
  if (record.delegationDepth !== undefined
    && (typeof record.delegationDepth !== "number" || !Number.isSafeInteger(record.delegationDepth) || record.delegationDepth < 0)) {
    throw new Error("invalid delegationDepth");
  }
  if (record.seed !== undefined) {
    if (!Array.isArray(record.seed)) throw new Error("invalid seed");
    record.seed = record.seed.map(parseAppendableEvent);
  }
  return record;
}

export function parseAppendEventsRequest(value: unknown): { id: SessionId; events: Omit<SessionEvent, "seq">[] } {
  const record = plainRecord(value);
  exactFields(record, ["id", "events"]);
  const id = parseSessionIdValue(record.id);
  if (!Array.isArray(record.events)) throw new Error("invalid events");
  if (record.events.length > 512) throw new Error("too many events");
  const events = record.events.map(parseAppendableEvent);
  return { id, events };
}

export function parseSessionRequest(value: unknown): { id: SessionId } {
  const record = plainRecord(value);
  exactFields(record, ["id"]);
  return { id: parseSessionIdValue(record.id) };
}

export function parseRenameRequest(value: unknown): { id: SessionId; title: string } {
  const record = plainRecord(value);
  exactFields(record, ["id", "title"]);
  if (typeof record.title !== "string" || record.title.trim().length === 0 || record.title.length > 500) {
    throw new Error("invalid title");
  }
  return { id: parseSessionIdValue(record.id), title: record.title.trim() };
}

export function parseArchiveRequest(value: unknown): { id: SessionId; archived: boolean } {
  const record = plainRecord(value);
  exactFields(record, ["id", "archived"]);
  if (typeof record.archived !== "boolean") throw new Error("invalid archived");
  return { id: parseSessionIdValue(record.id), archived: record.archived };
}

export function parseTrashRequest(value: unknown): { id: SessionId; deletedAt: number } {
  const record = plainRecord(value);
  exactFields(record, ["id", "deletedAt"]);
  if (typeof record.deletedAt !== "number" || !Number.isSafeInteger(record.deletedAt) || record.deletedAt < 0) {
    throw new Error("invalid deletedAt");
  }
  return { id: parseSessionIdValue(record.id), deletedAt: record.deletedAt };
}

export function parseReadFromRequest(value: unknown): { id: SessionId; fromSeq: number } {
  const record = plainRecord(value);
  exactFields(record, ["id", "fromSeq"]);
  if (typeof record.fromSeq !== "number" || !Number.isSafeInteger(record.fromSeq) || record.fromSeq < 0) {
    throw new Error("invalid fromSeq");
  }
  return { id: parseSessionIdValue(record.id), fromSeq: record.fromSeq };
}

function parseFilters(value: unknown, kinds: ReadonlySet<string>): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("invalid filters");
  return value.map((item) => {
    const record = plainRecord(item);
    if (typeof record.kind !== "string" || !kinds.has(record.kind)) throw new Error("invalid filter kind");
    if ("values" in record) {
      if (!Array.isArray(record.values)) throw new Error("invalid filter values");
      if (!record.values.every(v => typeof v === "string" || typeof v === "boolean" || v === null)) {
        throw new Error("invalid filter value");
      }
    } else {
      subsetFields(record, ["kind", "from", "to"]);
      if (record.from !== undefined && (typeof record.from !== "number" || !Number.isSafeInteger(record.from))) {
        throw new Error("invalid filter from");
      }
      if (record.to !== undefined && (typeof record.to !== "number" || !Number.isSafeInteger(record.to))) {
        throw new Error("invalid filter to");
      }
    }
    return item;
  });
}

export function parseSearchSessionsRequest(value: unknown): SessionSearchRequest {
  const record = plainRecord(value);
  subsetFields(record, ["query", "sessionFilters", "eventFilters", "limit", "cursor"]);
  if (typeof record.query !== "string") throw new Error("invalid query");
  const sessionFilters = parseFilters(record.sessionFilters, SESSION_FILTER_KINDS);
  const eventFilters = parseFilters(record.eventFilters, EVENT_FILTER_KINDS);
  const limit = parseOptionalLimit(record.limit);
  const cursor = parseOptionalCursor(record.cursor);
  return {
    query: record.query,
    ...sessionFilters.length > 0 ? { sessionFilters: sessionFilters as SessionSearchRequest["sessionFilters"] } : {},
    ...eventFilters.length > 0 ? { eventFilters: eventFilters as SessionSearchRequest["eventFilters"] } : {},
    ...limit !== undefined ? { limit } : {},
    ...cursor !== undefined ? { cursor } : {},
  };
}

export function parseSearchEventsRequest(value: unknown): SessionEventSearchRequest {
  const record = plainRecord(value);
  subsetFields(record, ["sessionId", "query", "filters", "limit", "cursor"]);
  if (typeof record.query !== "string") throw new Error("invalid query");
  const filters = parseFilters(record.filters, EVENT_FILTER_KINDS);
  const limit = parseOptionalLimit(record.limit);
  const cursor = parseOptionalCursor(record.cursor);
  return {
    sessionId: parseSessionIdValue(record.sessionId),
    query: record.query,
    ...filters.length > 0 ? { filters: filters as SessionEventSearchRequest["filters"] } : {},
    ...limit !== undefined ? { limit } : {},
    ...cursor !== undefined ? { cursor } : {},
  };
}

function parseOptionalLimit(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 100) {
    throw new Error("invalid limit");
  }
  return value;
}

function parseOptionalCursor(value: unknown): SessionSearchRequest["cursor"] | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error("invalid cursor");
  return value as SessionSearchRequest["cursor"];
}

export function parseNavigateRequest(value: unknown): { kind: "session-open"; sessionId: SessionId } | { kind: "session-list" } {
  const record = plainRecord(value);
  subsetFields(record, ["kind", "sessionId"]);
  if (record.kind === "session-open") {
    if (record.sessionId === undefined) throw new Error("missing sessionId");
    return { kind: "session-open", sessionId: parseSessionIdValue(record.sessionId) };
  }
  if (record.kind !== "session-list") throw new Error("invalid navigation kind");
  if (record.sessionId !== undefined) throw new Error("unexpected sessionId");
  return { kind: "session-list" };
}

/** Build a renderer navigation pusher from a window getter (safe when the window is gone). */
export function createRendererNavigationPusher(getWindow: () => { webContents: WebContents; isDestroyed(): boolean } | null) {
  return (event: CatomicalsNavigationEvent): void => {
    const window = getWindow();
    if (window !== null && !window.isDestroyed()) {
      window.webContents.send(IPC_CHANNELS.sessionNavigationPush, event);
    }
  };
}

/** Dependencies for wiring the session IPC surface. */
export interface SessionIpcDeps {
  manager: SessionManager;
  /** Reject untrusted senders (the main process's `assertRenderer`). */
  assertSender: (event: IpcMainInvokeEvent) => void;
  /** Push a navigation event to the renderer. */
  pushNavigation: (event: CatomicalsNavigationEvent) => void;
}

/**
 * Register every session IPC handler and the navigation push subscription.
 * @returns an unregister function that removes all handlers and listeners.
 */
export function registerSessionIpc(deps: SessionIpcDeps): () => void {
  const { manager, assertSender, pushNavigation } = deps;
  const handlers: Array<[string, (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown]> = [
    [IPC_CHANNELS.sessionCreate, (_event, ...args) => manager.createSession(parseCreateSessionRequest(args[0]))],
    [IPC_CHANNELS.sessionAppend, (_event, ...args) => {
      const { id, events } = parseAppendEventsRequest(args[0]);
      return manager.appendEvents(id, events);
    }],
    [IPC_CHANNELS.sessionList, () => manager.listSessions()],
    [IPC_CHANNELS.sessionRead, (_event, ...args) => manager.readSession(parseSessionRequest(args[0]).id)],
    [IPC_CHANNELS.sessionInspect, (_event, ...args) => manager.inspectSession(parseSessionRequest(args[0]).id)],
    [IPC_CHANNELS.sessionRename, (_event, ...args) => {
      const { id, title } = parseRenameRequest(args[0]);
      return manager.renameSession(id, title);
    }],
    [IPC_CHANNELS.sessionArchive, (_event, ...args) => {
      const { id, archived } = parseArchiveRequest(args[0]);
      return manager.setArchived(id, archived);
    }],
    [IPC_CHANNELS.sessionDelete, (_event, ...args) => manager.deleteSession(parseSessionRequest(args[0]).id)],
    [IPC_CHANNELS.sessionRestore, (_event, ...args) => {
      const { id, deletedAt } = parseTrashRequest(args[0]);
      return manager.restoreSession(id, deletedAt);
    }],
    [IPC_CHANNELS.sessionPurge, (_event, ...args) => {
      const { id, deletedAt } = parseTrashRequest(args[0]);
      return manager.purgeSession(id, deletedAt);
    }],
    [IPC_CHANNELS.sessionTrashList, () => manager.listTrash()],
    [IPC_CHANNELS.sessionSearch, (_event, ...args) => manager.searchSessions(parseSearchSessionsRequest(args[0]))],
    [IPC_CHANNELS.sessionSearchEvents, (_event, ...args) => manager.searchEvents(parseSearchEventsRequest(args[0]))],
    [IPC_CHANNELS.sessionReadFrom, (_event, ...args) => {
      const { id, fromSeq } = parseReadFromRequest(args[0]);
      return manager.readFrom(id, fromSeq);
    }],
    [IPC_CHANNELS.sessionNavigate, (_event, ...args) => {
      const target = parseNavigateRequest(args[0]);
      manager.navigate(target, "app");
    }],
  ];
  for (const [channel, handler] of handlers) {
    ipcMain.handle(channel, (event, ...args: unknown[]) => {
      assertSender(event);
      return handler(event, ...args);
    });
  }
  const unsubscribe = manager.onNavigate(pushNavigation);
  return () => {
    for (const [channel] of handlers) ipcMain.removeHandler(channel);
    unsubscribe();
  };
}
