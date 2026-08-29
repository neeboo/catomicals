/**
 * In-memory fake of the desktop session bridge for web tests. Mirrors the
 * SessionManager semantics web code relies on: lazy create, seq-assigned
 * appends, read/inspect, rename/archive/recoverable delete/restore/purge, and
 * a naive content search. Never used at runtime.
 */

import type {
  AppendableSessionEvent,
  CreateSessionInput,
  DesktopBridge,
  SessionBridgeApi,
  SessionEvent,
  SessionHeader,
  SessionInspection,
  SessionSearchHit,
  SessionSearchPage,
  SessionSearchRequest,
  SessionSummary,
  TrashEntry,
} from "./desktop";

export interface FakeSessionRecord {
  header: SessionHeader;
  events: SessionEvent[];
  deletedAt?: number;
}

export interface FakeSessionBridgeState {
  records: FakeSessionRecord[];
  trashed: FakeSessionRecord[];
  navigated: Array<{ kind: "session-open"; sessionId: string } | { kind: "session-list" }>;
}

function now(): number {
  return Date.now();
}

function summaryOf(record: FakeSessionRecord): SessionSummary {
  let title: string | undefined;
  let archived = false;
  let lastTime = record.header.createdAt;
  for (const event of record.events) {
    if (event.type === "session/title") title = (event.data as { title: string }).title;
    else if (event.type === "session/archive") archived = (event.data as { archived: boolean }).archived;
    if (event.time > lastTime) lastTime = event.time;
  }
  return {
    id: record.header.id,
    ...(title !== undefined ? { title } : {}),
    archived,
    ...(record.header.provider ? { provider: record.header.provider } : {}),
    ...(record.header.model ? { model: record.header.model } : {}),
    ...(record.header.executor ? { executor: record.header.executor } : {}),
    createdAt: record.header.createdAt,
    updatedAt: lastTime,
    eventCount: record.events.length,
  };
}

function eventText(event: SessionEvent): string {
  const data = event.data as Record<string, unknown>;
  if (event.type === "user/message" || event.type === "assistant/message") {
    return typeof data.content === "string" ? data.content : "";
  }
  if (event.type === "session/title") return typeof data.title === "string" ? data.title : "";
  return "";
}

/** Build a fake {@link SessionBridgeApi} backed by in-memory records. */
export function createFakeSessionBridge(seed: FakeSessionRecord[] = []): {
  api: SessionBridgeApi;
  state: FakeSessionBridgeState;
} {
  const state: FakeSessionBridgeState = { records: [...seed], trashed: [], navigated: [] };
  let counter = seed.length + 1;

  const find = (id: string): FakeSessionRecord => {
    const record = state.records.find((item) => item.header.id === id);
    if (!record) throw new Error(`session "${id}" not found`);
    return record;
  };

  const api: SessionBridgeApi = {
    async create(input: CreateSessionInput = {}) {
      const id = `s-${counter++}`;
      const createdAt = now();
      const header: SessionHeader = {
        version: 1,
        id,
        createdAt,
        ...(input.provider ? { provider: input.provider } : {}),
        ...(input.model ? { model: input.model } : {}),
        ...(input.executor ? { executor: input.executor } : {}),
        ...(input.cwd ? { cwd: input.cwd } : {}),
      };
      const record: FakeSessionRecord = { header, events: [] };
      if (input.title) {
        record.events.push({
          type: "session/title",
          seq: 0,
          time: createdAt,
          data: { title: input.title },
        });
      }
      state.records.push(record);
      return summaryOf(record);
    },
    async append(id: string, events: AppendableSessionEvent[]) {
      const record = find(id);
      const assigned = events.map((partial, index) => ({
        ...partial,
        seq: record.events.length + index,
      })) as SessionEvent[];
      record.events.push(...assigned);
      return assigned;
    },
    async list() {
      return [...state.records]
        .map(summaryOf)
        .sort((a, b) => b.updatedAt - a.updatedAt);
    },
    async read(id: string): Promise<SessionInspection> {
      const record = find(id);
      return { meta: record.header, events: [...record.events] };
    },
    async inspect(id: string): Promise<SessionInspection> {
      return api.read(id);
    },
    async rename(id: string, title: string) {
      const record = find(id);
      record.events.push({ type: "session/title", seq: record.events.length, time: now(), data: { title } });
      return summaryOf(record);
    },
    async setArchived(id: string, archived: boolean) {
      const record = find(id);
      record.events.push({ type: "session/archive", seq: record.events.length, time: now(), data: { archived } });
      return summaryOf(record);
    },
    async remove(id: string): Promise<TrashEntry> {
      const index = state.records.findIndex((item) => item.header.id === id);
      if (index === -1) throw new Error(`session "${id}" not found`);
      const [record] = state.records.splice(index, 1);
      record.deletedAt = now();
      state.trashed.push(record);
      return { id, deletedAt: record.deletedAt, title: summaryOf(record).title };
    },
    async restore(id: string, deletedAt: number) {
      const index = state.trashed.findIndex((item) => item.header.id === id && item.deletedAt === deletedAt);
      if (index === -1) throw new Error(`trashed session "${id}" not found`);
      const [record] = state.trashed.splice(index, 1);
      delete record.deletedAt;
      state.records.push(record);
      return summaryOf(record);
    },
    async purge(id: string, deletedAt: number) {
      const index = state.trashed.findIndex((item) => item.header.id === id && item.deletedAt === deletedAt);
      if (index === -1) throw new Error(`trashed session "${id}" not found`);
      state.trashed.splice(index, 1);
    },
    async listTrash(): Promise<TrashEntry[]> {
      return state.trashed.map((record) => ({
        id: record.header.id,
        deletedAt: record.deletedAt ?? 0,
        title: summaryOf(record).title,
      }));
    },
    async search(request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>> {
      const term = request.query.trim().toLowerCase();
      const items = state.records
        .map((record) => {
          const match = [...record.events]
            .map((event) => ({ event, text: eventText(event) }))
            .find(({ text }) => term && text.toLowerCase().includes(term));
          if (!match) return null;
          return {
            header: record.header,
            live: true,
            persisted: true,
            bestMatch: {
              sessionId: record.header.id,
              seq: match.event.seq,
              type: match.event.type,
              time: match.event.time,
              surface: "current" as const,
              snippet: match.text,
            },
          };
        })
        .filter((item): item is NonNullable<typeof item> => item !== null);
      return { items };
    },
    async searchEvents() {
      return { items: [], session: { version: 1, id: "", createdAt: 0 } as SessionHeader };
    },
    async readFrom(id: string, fromSeq: number) {
      const record = find(id);
      return { meta: record.header, events: record.events.slice(fromSeq) };
    },
    async navigate(target: { kind: "session-open"; sessionId: string } | { kind: "session-list" }) {
      state.navigated.push(target);
    },
  };

  return { api, state };
}

/** Convenience: a full DesktopBridge with a fake session API. */
export function createFakeSessionBridgeDesktop(overrides: Partial<DesktopBridge> = {}) {
  const { api, state } = createFakeSessionBridge();
  return {
    desktop: {
      sessions: api,
      onSessionNavigation: () => () => undefined,
      ...overrides,
    } as DesktopBridge,
    state,
  };
}
