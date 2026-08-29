import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SessionManager } from "./manager";
import type { SessionEvent, SessionId } from "./types";

let roots: string[] = [];

async function makeManager(): Promise<{ manager: SessionManager; root: string }> {
  const root = await mkdtemp(join(tmpdir(), "catomicals-manager-"));
  roots.push(root);
  const manager = new SessionManager({ root, searchPath: ":memory:" });
  return { manager, root };
}

function message(content: string, time = Date.now()): Omit<SessionEvent, "seq"> {
  return { type: "user/message", time, data: { content } };
}

function reply(content: string, time = Date.now()): Omit<SessionEvent, "seq"> {
  return { type: "assistant/message", time, data: { content } };
}

describe("SessionManager", () => {
  let manager: SessionManager;
  beforeEach(async () => { ({ manager } = await makeManager()); });
  afterEach(async () => {
    await manager.close();
    await Promise.all(roots.map(r => rm(r, { recursive: true, force: true })));
    roots = [];
  });

  it("creates sessions with provider/model/executor metadata and a title", async () => {
    const summary = await manager.createSession({
      title: "Wallet Q&A",
      provider: "codex",
      model: "gpt-5.3-codex",
      executor: "codex",
      cwd: "/tmp/project",
    });
    expect(summary.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(summary.title).toBe("Wallet Q&A");
    expect(summary.provider).toBe("codex");
    expect(summary.model).toBe("gpt-5.3-codex");
    expect(summary.executor).toBe("codex");
    expect(summary.archived).toBe(false);
  });

  it("persists across reopen: messages survive a new manager on the same root", async () => {
    const created = await manager.createSession({ title: "Persistent" });
    const id = created.id;
    await manager.appendEvents(id, [
      message("hello"),
      reply("hi there"),
      { type: "turn/end", time: Date.now(), data: { turn: 0, reason: { kind: "completed" } } },
    ]);
    await manager.close();

    const reopened = new SessionManager({ root: manager.root, searchPath: ":memory:" });
    roots.push(manager.root); // keep cleanup ownership
    const inspection = await reopened.readSession(id);
    expect(inspection.events).toHaveLength(4);
    const list = await reopened.listSessions();
    expect(list[0]).toMatchObject({ id, title: "Persistent", eventCount: 4 });
    await reopened.close();
  });

  it("assigns contiguous seqs across multiple appends", async () => {
    const { id } = await manager.createSession();
    const first = await manager.appendEvents(id, [message("a"), reply("b")]);
    const second = await manager.appendEvents(id, [message("c")]);
    expect(first.map(e => e.seq)).toEqual([0, 1]);
    expect(second.map(e => e.seq)).toEqual([2]);
  });

  it("renames and archives via append-only metadata events", async () => {
    const { id } = await manager.createSession();
    const renamed = await manager.renameSession(id, "New Title");
    expect(renamed.title).toBe("New Title");
    const archived = await manager.setArchived(id, true);
    expect(archived.archived).toBe(true);
    const unarchived = await manager.setArchived(id, false);
    expect(unarchived.archived).toBe(false);
    const list = await manager.listSessions();
    expect(list[0].title).toBe("New Title");
  });

  it("deletes recoverably, restores, and purges", async () => {
    const { id } = await manager.createSession({ title: "Doomed" });
    await manager.appendEvents(id, [message("content")]);
    const entry = await manager.deleteSession(id);
    expect(entry.id).toBe(id);
    expect(await manager.listSessions()).toHaveLength(0);
    expect(await manager.listTrash()).toHaveLength(1);

    const restored = await manager.restoreSession(id, entry.deletedAt);
    expect(restored.id).toBe(id);
    expect(await manager.listTrash()).toHaveLength(0);
    expect(await manager.listSessions()).toHaveLength(1);

    const entry2 = await manager.deleteSession(id);
    await manager.purgeSession(id, entry2.deletedAt);
    expect(await manager.listTrash()).toHaveLength(0);
    await expect(manager.readSession(id)).rejects.toThrow(/not found/);
  });

  it("rejects creating a session id that already exists on disk", async () => {
    const { id } = await manager.createSession();
    await manager.appendEvents(id, [message("x")]);
    await manager.close();
    const reopened = new SessionManager({ root: manager.root, searchPath: ":memory:" });
    roots.push(manager.root);
    await reopened.appendEvents(id, [message("y")]); // adopt path works
    const inspection = await reopened.inspectSession(id);
    expect(inspection.events).toHaveLength(2);
    await reopened.close();
  });

  it("emits navigation events and unsubscribes", async () => {
    const events: Array<{ kind: string; sessionId?: string; source: string }> = [];
    const unsubscribe = manager.onNavigate(event => events.push(event));
    manager.navigate({ kind: "session-list" }, "deeplink");
    manager.navigate({ kind: "session-open", sessionId: "abc-123" as SessionId }, "app");
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ kind: "session-list", source: "deeplink" });
    expect(events[1]).toMatchObject({ kind: "session-open", sessionId: "abc-123", source: "app" });
    unsubscribe();
    manager.navigate({ kind: "session-list" }, "app");
    expect(events).toHaveLength(2);
  });

  it("rejects operations after close", async () => {
    await manager.close();
    await expect(manager.createSession()).rejects.toThrow(/closed/);
  });

  it("keeps the live overlay in sync with appends", async () => {
    const { id } = await manager.createSession();
    expect(manager.isLive(id)).toBe(true);
    await manager.appendEvents(id, [message("live text")]);
    const page = await manager.searchSessions({ query: "live text", limit: 10 });
    expect(page.items[0].live).toBe(true);
    manager.closeSession(id);
    expect(manager.isLive(id)).toBe(false);
    // Still searchable from persisted docs after the live entry is dropped.
    const persisted = await manager.searchSessions({ query: "live text", limit: 10 });
    expect(persisted.items[0].persisted).toBe(true);
    expect(persisted.items[0].live).toBe(false);
  });
});

describe("SessionManager search integration", () => {
  let root: string;
  let manager: SessionManager;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "catomicals-search-int-"));
    roots.push(root);
    manager = new SessionManager({ root, searchPath: ":memory:" });
  });
  afterEach(async () => {
    await manager.close();
    await Promise.all(roots.map(r => rm(r, { recursive: true, force: true })));
    roots = [];
  });

  it("searches across sessions created by the manager", async () => {
    const a = await manager.createSession({ title: "Fees", provider: "codex" });
    await manager.appendEvents(a.id, [
      message("how are transaction fees computed"),
      reply("fees depend on the size of the transaction"),
    ]);
    const b = await manager.createSession({ title: "Status", provider: "deepseek" });
    await manager.appendEvents(b.id, [message("wallet node status check")]);

    const page = await manager.searchSessions({ query: "transaction fees", limit: 10 });
    expect(page.items.map(i => i.header.id)).toEqual([a.id]);

    const both = await manager.searchSessions({ query: "wallet", limit: 10 });
    expect(both.items).toHaveLength(1);
    expect(both.items[0].header.id).toBe(b.id);

    const filtered = await manager.searchSessions({
      query: "fees",
      sessionFilters: [{ kind: "provider", values: ["deepseek"] }],
      limit: 10,
    });
    expect(filtered.items).toHaveLength(0);
  });

  it("searches within a session with cursor pagination", async () => {
    const { id } = await manager.createSession();
    for (let i = 0; i < 15; i++) {
      await manager.appendEvents(id, [message(`needle event number ${i}`)]);
    }
    const first = await manager.searchEvents({ sessionId: id, query: "needle", limit: 10 });
    expect(first.items).toHaveLength(10);
    expect(first.nextCursor).toBeDefined();
    const second = await manager.searchEvents({ sessionId: id, query: "needle", limit: 10, cursor: first.nextCursor });
    expect(second.items).toHaveLength(5);
    expect(second.nextCursor).toBeUndefined();
    // No overlap between pages.
    const seqs = new Set([...first.items, ...second.items].map(item => item.seq));
    expect(seqs.size).toBe(15);
  });
});
