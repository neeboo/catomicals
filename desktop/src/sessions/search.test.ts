import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SqliteSessionQueryEngine, type SessionSearchSource } from "./search";
import { SessionQueryError } from "./search-errors";
import {
  SESSION_FORMAT_VERSION,
  SessionId,
  type SessionEvent,
  type SessionHeader,
  type SessionInspection,
  type SessionPersistenceSnapshot,
} from "./types";

interface SourceState {
  snapshots: SessionPersistenceSnapshot[];
  inspections: Map<string, SessionInspection>;
  live: Array<{ header: SessionHeader; events: SessionEvent[] }>;
}

function makeSource(initial: Partial<SourceState> = {}): SessionSearchSource & { state: SourceState } {
  const state: SourceState = {
    snapshots: initial.snapshots ?? [],
    inspections: initial.inspections ?? new Map(),
    live: initial.live ?? [],
  };
  return {
    state,
    async listSnapshots() {
      return [...state.snapshots];
    },
    async inspect(id) {
      const inspection = state.inspections.get(id);
      if (inspection === undefined) throw new Error(`session "${id}" not found`);
      return inspection;
    },
    listLive() {
      return state.live.map(entry => ({ header: entry.header, events: [...entry.events] }));
    },
  };
}

function header(id: string, overrides: Partial<SessionHeader> = {}): SessionHeader {
  return { version: SESSION_FORMAT_VERSION, id: SessionId(id), createdAt: 1_700_000_000_000, ...overrides };
}

function user(seq: number, content: string): SessionEvent {
  return { type: "user/message", seq, time: 1_700_000_100_000 + seq, data: { content }, surfaceOp: "append" } as SessionEvent;
}

function persisted(source: SessionSearchSource & { state: SourceState }, h: SessionHeader, events: SessionEvent[], revision: string): void {
  source.state.snapshots.push({ header: h, revision });
  source.state.inspections.set(h.id, { meta: h, events });
}

function engine(source: SessionSearchSource): SqliteSessionQueryEngine {
  return new SqliteSessionQueryEngine(source, { path: ":memory:", openAt: "first-search" });
}

describe("SqliteSessionQueryEngine", () => {
  let source: SessionSearchSource & { state: SourceState };
  let search: SqliteSessionQueryEngine;
  beforeEach(() => {
    source = makeSource();
    search = engine(source);
  });
  afterEach(async () => { await search.close(); });

  it("searches across sessions and groups by the best matching event", async () => {
    persisted(source, header("s1", { provider: "codex" }), [
      user(0, "how do I sign a taproot transaction"),
      { type: "assistant/message", seq: 1, time: 2, data: { content: "use the wallet tool" }, surfaceOp: "append" } as SessionEvent,
    ], "r1");
    persisted(source, header("s2", { provider: "deepseek" }), [
      user(0, "wallet status is fine"),
    ], "r2");

    const page = await search.searchSessions({ query: "wallet", limit: 10 });
    expect(page.items).toHaveLength(2);
    const s1 = page.items.find(item => item.header.id === "s1");
    expect(s1?.bestMatch.snippet).toContain("wallet");
    expect(s1?.persisted).toBe(true);
    expect(s1?.live).toBe(false);
  });

  it("treats the query as a literal phrase, never FTS syntax", async () => {
    persisted(source, header("s1"), [user(0, "bitcoin cat wallet")], "r1");
    persisted(source, header("s2"), [user(0, "bitcoin dog wallet")], "r2");
    // "bitcoin cat" is a phrase: only s1 matches.
    const page = await search.searchSessions({ query: "bitcoin cat", limit: 10 });
    expect(page.items).toHaveLength(1);
    expect(page.items[0].header.id).toBe("s1");
    // FTS operators are inert data: the whole query is one literal phrase.
    expect((await search.searchSessions({ query: "bitcoin OR dog", limit: 10 })).items).toHaveLength(0);
    expect((await search.searchSessions({ query: "bitcoin NEAR dog", limit: 10 })).items).toHaveLength(0);
    // User quotes are data, never syntax: the phrase still matches only s1.
    const quoted = await search.searchSessions({ query: '"bitcoin cat"', limit: 10 });
    expect(quoted.items.map(i => i.header.id)).toEqual(["s1"]);
  });

  it("paginates with opaque cursors and rejects stale cursors", async () => {
    for (let i = 0; i < 25; i++) {
      persisted(source, header(`p${i}`), [user(0, `unique token alpha${i}`)], `r${i}`);
    }
    const first = await search.searchSessions({ query: "unique token", limit: 10 });
    expect(first.items).toHaveLength(10);
    expect(first.nextCursor).toBeDefined();
    const second = await search.searchSessions({ query: "unique token", limit: 10, cursor: first.nextCursor });
    expect(second.items).toHaveLength(10);
    expect(second.nextCursor).toBeDefined();
    const third = await search.searchSessions({ query: "unique token", limit: 10, cursor: second.nextCursor });
    expect(third.items).toHaveLength(5);
    expect(third.nextCursor).toBeUndefined();
    // No overlap between pages.
    const ids = new Set([...first.items, ...second.items, ...third.items].map(i => i.header.id));
    expect(ids.size).toBe(25);
  });

  it("rejects a stale cursor when the corpus changed", async () => {
    for (let i = 0; i < 6; i++) {
      persisted(source, header(`stale${i}`), [user(0, `stale token alpha${i}`)], `r-stale-${i}`);
    }
    const first = await search.searchSessions({ query: "stale token", limit: 5 });
    expect(first.nextCursor).toBeDefined();
    persisted(source, header("s2"), [user(0, "stale token beta")], "r2");
    await expect(
      search.searchSessions({ query: "stale token", limit: 5, cursor: first.nextCursor }),
    ).rejects.toMatchObject({ code: "SESSION_QUERY_STALE_CURSOR" });
  });

  it("rejects cursors that do not belong to the request", async () => {
    for (let i = 0; i < 6; i++) {
      persisted(source, header(`alpha${i}`), [user(0, `alpha token ${i}`)], `r-alpha-${i}`);
    }
    const first = await search.searchSessions({ query: "alpha token", limit: 5 });
    expect(first.nextCursor).toBeDefined();
    await expect(
      search.searchSessions({ query: "different query", limit: 5, cursor: first.nextCursor }),
    ).rejects.toMatchObject({ code: "SESSION_QUERY_INVALID_CURSOR" });
  });

  it("applies session and event filters", async () => {
    persisted(source, header("s1", { provider: "codex" }), [user(0, "approve transaction fee")], "r1");
    persisted(source, header("s2", { provider: "deepseek" }), [user(0, "approve transaction fee")], "r2");
    const page = await search.searchSessions({
      query: "transaction",
      sessionFilters: [{ kind: "provider", values: ["codex"] }],
      limit: 10,
    });
    expect(page.items.map(i => i.header.id)).toEqual(["s1"]);
    const archived = await search.searchSessions({
      query: "transaction",
      sessionFilters: [{ kind: "archived", values: [true] }],
      limit: 10,
    });
    expect(archived.items).toHaveLength(0);
  });

  it("searches within one session (searchEvents)", async () => {
    persisted(source, header("s1"), [
      user(0, "first message about fees"),
      { type: "assistant/message", seq: 1, time: 2, data: { content: "second message about approvals" }, surfaceOp: "append" } as SessionEvent,
    ], "r1");
    const page = await search.searchEvents({ sessionId: "s1", query: "approvals", limit: 10 });
    expect(page.session.id).toBe("s1");
    expect(page.items).toHaveLength(1);
    expect(page.items[0].seq).toBe(1);
    expect(page.items[0].snippet).toContain("approvals");
  });

  it("overlays live sessions on persisted docs (live-preferred)", async () => {
    persisted(source, header("s1"), [user(0, "persisted content")], "r1");
    source.state.live = [{ header: header("s1"), events: [user(0, "live content supersedes")] }];
    const page = await search.searchSessions({ query: "supersedes", limit: 10 });
    expect(page.items).toHaveLength(1);
    expect(page.items[0].live).toBe(true);
    expect(page.items[0].persisted).toBe(true); // also durable
    const stale = await search.searchSessions({ query: "persisted content", limit: 10 });
    expect(stale.items).toHaveLength(0); // the live overlay shadows the persisted doc
  });

  it("normalizes whitespace in queries and bounds snippets", async () => {
    persisted(source, header("s1"), [user(0, "x".repeat(600))], "r1");
    persisted(source, header("s2"), [user(0, "needle in the haystack")], "r2");
    const page = await search.searchSessions({ query: "  needle\n in   the haystack ", limit: 10 });
    expect(page.items).toHaveLength(1);
    expect(page.items[0].bestMatch.snippet.length).toBeLessThanOrEqual(240);
  });

  it("rejects empty, NUL, and oversized-limit queries with typed errors", async () => {
    await expect(search.searchSessions({ query: "   " })).rejects.toMatchObject({ code: "SESSION_QUERY_INVALID_QUERY" });
    await expect(search.searchSessions({ query: "a\0b" })).rejects.toMatchObject({ code: "SESSION_QUERY_INVALID_QUERY" });
    await expect(search.searchSessions({ query: "x", limit: 101 })).rejects.toMatchObject({ code: "SESSION_QUERY_INVALID_LIMIT" });
  });

  it("refuses to index sessions whose header changed between snapshot and inspection", async () => {
    persisted(source, header("s1"), [user(0, "token")], "r1");
    source.state.inspections.set("s1", { meta: header("s1", { provider: "other" }), events: [user(0, "token")] });
    await expect(search.searchSessions({ query: "token", limit: 5 })).rejects.toThrow(/inconsistent/);
  });
});

describe("SqliteSessionQueryEngine config and probe", () => {
  it("proves FTS5 availability in the installed runtime", async () => {
    await expect(SqliteSessionQueryEngine.probeFts5()).resolves.toBeUndefined();
  });

  it("rejects unsupported configuration", () => {
    const source = makeSource();
    expect(() => new SqliteSessionQueryEngine(source, { path: ":memory:", journalMode: "bogus" as never }))
      .toThrow(/journalMode/);
    expect(() => new SqliteSessionQueryEngine(source, { path: ":memory:", defaultLimit: 500, maxLimit: 10 }))
      .toThrow(/defaultLimit/);
  });

  it("fails cleanly when search is disabled (openAt never)", async () => {
    const source = makeSource();
    const disabled = new SqliteSessionQueryEngine(source, { path: ":memory:", openAt: "never" });
    await expect(disabled.searchSessions({ query: "x" })).rejects.toMatchObject({
      code: "SESSION_QUERY_SEARCH_DISABLED",
    });
    await disabled.close();
  });

  it("throws typed SessionQueryError instances", async () => {
    const source = makeSource();
    const engine = new SqliteSessionQueryEngine(source, { path: ":memory:" });
    try {
      await engine.searchSessions({ query: "" });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(SessionQueryError);
    } finally {
      await engine.close();
    }
  });
});
