import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SessionCoordinator, interruptedTurnClosers } from "./coordinator";
import { JsonlSessionStore } from "./jsonl-store";
import { SESSION_FORMAT_VERSION, SessionId, type SessionEvent, type SessionHeader } from "./types";

let roots: string[] = [];

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "catomicals-coordinator-"));
  roots.push(root);
  return root;
}

function header(id = "s1", overrides: Partial<SessionHeader> = {}): SessionHeader {
  return { version: SESSION_FORMAT_VERSION, id: SessionId(id), createdAt: 1_700_000_000_000, ...overrides };
}

function event(type: SessionEvent["type"], seq: number, data: Record<string, unknown>, time = 1000): SessionEvent {
  return { type, seq, time, data } as SessionEvent;
}

function user(seq: number, content: string): SessionEvent {
  return { type: "user/message", seq, time: 1000 + seq, data: { content }, surfaceOp: "append" } as SessionEvent;
}

describe("SessionCoordinator", () => {
  let root: string;
  let store: JsonlSessionStore;
  let coordinator: SessionCoordinator;
  beforeEach(async () => {
    root = await makeRoot();
    store = new JsonlSessionStore(root);
    coordinator = new SessionCoordinator(store);
  });
  afterEach(async () => { await Promise.all(roots.map(r => rm(r, { recursive: true, force: true }))); roots = []; });

  it("creates lazily and appends with contiguous seqs", async () => {
    const meta = header("c1");
    await coordinator.create(meta);
    await coordinator.append("c1" as never, [user(0, "hi"), user(1, "there")]);
    const inspection = await coordinator.inspect("c1" as never);
    expect(inspection.meta.id).toBe("c1");
    expect(inspection.events).toHaveLength(2);
    expect(inspection.events.map(e => e.seq)).toEqual([0, 1]);
  });

  it("rejects creating an id that already exists or is persisted", async () => {
    await coordinator.create(header("c2"));
    await expect(coordinator.create(header("c2"))).rejects.toThrow(/exists/);
    await coordinator.append("c2" as never, [user(0, "x")]);
    const fresh = new SessionCoordinator(new JsonlSessionStore(root));
    await expect(fresh.create(header("c2"))).rejects.toThrow(/already has a persisted log/);
  });

  it("rejects appends that break seq contiguity", async () => {
    await coordinator.create(header("c3"));
    await coordinator.append("c3" as never, [user(0, "a")]);
    await expect(coordinator.append("c3" as never, [user(2, "gap")])).rejects.toThrow(/seq mismatch/);
  });

  it("appends with auto-assigned seqs via appendAuto", async () => {
    await coordinator.create(header("c4"));
    const assigned = await coordinator.appendAuto("c4" as never, [
      { type: "user/message", time: 1000, data: { content: "auto" } },
      { type: "assistant/message", time: 1001, data: { content: "reply" } },
    ]);
    expect(assigned.map(e => e.seq)).toEqual([0, 1]);
    const next = await coordinator.appendAuto("c4" as never, [{ type: "user/message", time: 1002, data: { content: "more" } }]);
    expect(next[0].seq).toBe(2);
  });

  it("repairs a torn tail on load and commits synthetic closers", async () => {
    const meta = header("c5");
    await coordinator.create(meta);
    await coordinator.append("c5" as never, [event("turn/start", 0, { turn: 0 }), user(1, "question")]);
    const path = store.locate(meta);
    const complete = await readFile(path);
    // Append a torn (newline-less) assistant message to an open turn tail.
    await writeFile(path, Buffer.concat([
      complete,
      Buffer.from(JSON.stringify({ type: "assistant/message", seq: 2, time: 2000, data: { content: "torn" } })),
    ]));

    // load repairs and returns the balanced log including the synthetic closer.
    const inspection = await coordinator.load("c5" as never);
    expect(inspection.events.map(e => e.type)).toEqual(["turn/start", "user/message", "turn/end"]);
    const tail = inspection.events.slice(-1)[0];
    expect(tail.type).toBe("turn/end");
    expect((tail as SessionEvent<"turn/end">).data.reason).toEqual({ kind: "interrupted" });
    // The torn line was dropped and the closer committed: the log is now balanced.
    const after = await coordinator.inspect("c5" as never);
    expect(after.events.map(e => e.type)).toEqual(["turn/start", "user/message", "turn/end"]);
  });

  it("inspect is non-mutating: it never commits repair", async () => {
    const meta = header("c6");
    await coordinator.create(meta);
    await coordinator.append("c6" as never, [user(0, "x")]);
    const path = store.locate(meta);
    const complete = await readFile(path);
    await writeFile(path, Buffer.concat([complete, Buffer.from("{\"type\":\"assistant/message\",\"seq\":1,\"time\":1,\"data\":{\"content\":\"torn\"}}")]));

    const inspection = await coordinator.inspect("c6" as never);
    expect(inspection.events).toHaveLength(1);
    const bytes = await readFile(path);
    expect(bytes.byteLength).toBeGreaterThan(complete.byteLength); // still torn on disk
  });

  it("reads suffixes via readFrom", async () => {
    await coordinator.create(header("c7"));
    await coordinator.append("c7" as never, [user(0, "a"), user(1, "b"), user(2, "c")]);
    const { events } = await coordinator.readFrom("c7" as never, 1);
    expect(events.map(e => e.seq)).toEqual([1, 2]);
  });

  it("folds rename and archive events into summaries", async () => {
    const meta = header("c8");
    await coordinator.create(meta);
    await coordinator.append("c8" as never, [user(0, "hi")]);
    await coordinator.appendNext("c8" as never, { type: "session/title", time: 2000, data: { title: "Renamed" } });
    await coordinator.appendNext("c8" as never, { type: "session/archive", time: 2001, data: { archived: true } });
    const summaries = await coordinator.listSummaries();
    expect(summaries[0]).toMatchObject({ id: "c8", title: "Renamed", archived: true, eventCount: 3 });
  });

  it("refuses unknown required event types on load but honors ignorable ones", async () => {
    const meta = header("c9");
    await coordinator.create(meta);
    await coordinator.append("c9" as never, [user(0, "x")]);
    const path = store.locate(meta);
    // Append a complete committed line with an unknown required event type.
    await writeFile(path, (await readFile(path, "utf8")) + JSON.stringify({ type: "future/event", seq: 1, time: 1, data: { v: 1 } }) + "\n");
    await expect(coordinator.inspect("c9" as never)).rejects.toThrow(/future\/event/);

    // With ignorable: true the same log loads.
    const meta10 = header("c10");
    const fresh = new SessionCoordinator(new JsonlSessionStore(root));
    await fresh.create(meta10);
    await fresh.append("c10" as never, [user(0, "x")]);
    const path10 = fresh.locate(meta10);
    await writeFile(
      path10,
      (await readFile(path10, "utf8")) + JSON.stringify({ type: "future/event", seq: 1, time: 1, data: { v: 1 }, ignorable: true }) + "\n",
    );
    const inspection = await fresh.inspect("c10" as never);
    expect(inspection.events).toHaveLength(2);
  });

  it("rejects non-JSON-serializable event data", async () => {
    await coordinator.create(header("c11"));
    const bad = { type: "user/message", seq: 0, time: 1, data: { content: () => "nope" } } as unknown as SessionEvent;
    await expect(coordinator.append("c11" as never, [bad])).rejects.toThrow(/JSON-serializable/);
  });

  it("forget drops in-memory state so the id can be re-created once its log is gone", async () => {
    const meta = header("c12");
    await coordinator.create(meta);
    await coordinator.append("c12" as never, [user(0, "x")]);
    coordinator.forget("c12" as never);
    // Without forget, createCore would reject on the stale in-memory state.
    // After the durable log is removed (as deleteSession does via trash), the
    // id becomes creatable again and appends start a fresh artifact.
    await rm(store.locate(meta), { force: true });
    await coordinator.create(header("c12"));
    expect(coordinator.has("c12" as never)).toBe(true);
    await coordinator.append("c12" as never, [user(0, "fresh")]);
    const inspection = await coordinator.inspect("c12" as never);
    expect(inspection.events).toHaveLength(1);
  });
});

describe("interruptedTurnClosers", () => {
  it("returns no closers for a balanced log", () => {
    const events = [
      event("turn/start", 0, { turn: 0 }),
      user(1, "hi"),
      event("turn/end", 2, { turn: 0, reason: { kind: "completed" } }),
    ];
    expect(interruptedTurnClosers(events)).toEqual([]);
  });

  it("synthesizes cancelled tool results and an interrupted turn/end for an open turn", () => {
    const events = [
      event("turn/start", 0, { turn: 0 }),
      user(1, "hi"),
      { type: "tool/call", seq: 2, time: 1002, data: { callId: "call-1", name: "wallet_status", arguments: "{}" } } as SessionEvent,
    ];
    const closers = interruptedTurnClosers(events);
    expect(closers).toHaveLength(2);
    expect(closers[0].type).toBe("tool/result");
    expect((closers[0] as SessionEvent<"tool/result">).data).toMatchObject({
      callId: "call-1",
      outcome: "cancelled",
      error: { name: "ToolOutcomeUnknownError", code: "TOOL_OUTCOME_UNKNOWN" },
    });
    expect(closers[1].type).toBe("turn/end");
    expect((closers[1] as SessionEvent<"turn/end">).data.reason).toEqual({ kind: "interrupted" });
    expect(closers.map(c => c.seq)).toEqual([3, 4]);
  });

  it("returns no closers for an empty log", () => {
    expect(interruptedTurnClosers([])).toEqual([]);
  });
});
