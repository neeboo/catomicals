// @vitest-environment jsdom

import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  SessionStoreProvider,
  formatSessionTime,
  parseSessionDeeplink,
  sessionBridge,
  sessionDisplayTitle,
  useCurrentSessionId,
  useSessionNavigation,
  useSessionStore,
  type SessionStoreValue,
} from "./session";
import type { DesktopBridge, SessionBridgeApi, SessionEvent, SessionSummary } from "./desktop";

function fakeBridge(overrides: Partial<SessionBridgeApi> = {}): DesktopBridge {
  const summaries: SessionSummary[] = [
    { id: "s-1", archived: false, createdAt: 1000, updatedAt: 2000, eventCount: 2, provider: "codex", title: "First" },
    { id: "s-2", archived: true, createdAt: 1001, updatedAt: 1001, eventCount: 0 },
  ];
  const sessions: SessionBridgeApi = {
    create: vi.fn(async (input) => ({
      id: "s-new",
      archived: false,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      eventCount: 0,
      ...input?.title !== undefined ? { title: input.title } : {},
    })),
    append: vi.fn(async () => [] as SessionEvent[]),
    list: vi.fn(async () => summaries),
    read: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    inspect: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    rename: vi.fn(async (id, title) => ({ ...summaries[0], id, title })),
    setArchived: vi.fn(async (id, archived) => ({ ...summaries[0], id, archived })),
    remove: vi.fn(async (id) => ({ id, deletedAt: Date.now() })),
    restore: vi.fn(async (id) => ({ ...summaries[0], id })),
    purge: vi.fn(async () => undefined),
    listTrash: vi.fn(async () => []),
    search: vi.fn(async () => ({ items: [] })),
    searchEvents: vi.fn(async () => ({ items: [], session: { version: 1, id: "s-1", createdAt: 1000 } })),
    readFrom: vi.fn(async () => ({ meta: { version: 1, id: "s-1", createdAt: 1000 }, events: [] })),
    navigate: vi.fn(async () => undefined),
    ...overrides,
  } as SessionBridgeApi;
  return {
    sessions,
    onSessionNavigation: vi.fn(() => () => undefined),
  } as unknown as DesktopBridge;
}

function StoreProbe() {
  const store = useSessionStore();
  const current = useCurrentSessionId();
  const last = useSessionNavigation();
  return (
    <div>
      <span data-testid="count">{store.sessions?.length ?? "none"}</span>
      <span data-testid="current">{current ?? "none"}</span>
      <span data-testid="nav">{last ? `${last.kind}:${last.sessionId ?? ""}` : "none"}</span>
      <span data-testid="loading">{store.loading ? "loading" : "idle"}</span>
    </div>
  );
}

function renderStore(bridge: DesktopBridge) {
  let store!: SessionStoreValue;
  function Capture() {
    store = useSessionStore();
    return null;
  }
  render(
    <SessionStoreProvider bridge={bridge}>
      <Capture />
      <StoreProbe />
    </SessionStoreProvider>,
  );
  return { getStore: () => store };
}

describe("sessionBridge resolution", () => {
  it("returns the passed bridge and fails closed without one", () => {
    const bridge = { list: async () => [] } as unknown as SessionBridgeApi;
    expect(sessionBridge(bridge)).toBe(bridge);
    expect(() => sessionBridge()).toThrow("session store unavailable");
  });
});

describe("session helpers", () => {
  it("derives display titles", () => {
    expect(sessionDisplayTitle({ id: "abc-123", title: "Wallet Q&A" })).toBe("Wallet Q&A");
    expect(sessionDisplayTitle({ id: "abc-123", title: "  " })).toBe("会话 abc-123");
  });

  it("formats relative times", () => {
    const now = 10 * 60_000;
    expect(formatSessionTime(now - 30_000, now)).toBe("刚刚");
    expect(formatSessionTime(now - 5 * 60_000, now)).toBe("5 分钟前");
    expect(formatSessionTime(now - 3 * 3_600_000, now)).toBe("3 小时前");
    expect(formatSessionTime(now - 4 * 86_400_000, now)).toBe("4 天前");
  });
});

describe("parseSessionDeeplink (renderer mirror)", () => {
  it("parses session-open and session-list targets", () => {
    expect(parseSessionDeeplink("catomicals://session/abc-123")).toEqual({ kind: "session-open", sessionId: "abc-123" });
    expect(parseSessionDeeplink("catomicals://sessions")).toEqual({ kind: "session-list" });
  });

  it("returns undefined for malformed or foreign links", () => {
    expect(parseSessionDeeplink("catomicals://session/../x")).toBeUndefined();
    expect(parseSessionDeeplink("https://session/x")).toBeUndefined();
    expect(parseSessionDeeplink("catomicals://wallet/sign")).toBeUndefined();
  });
});

describe("SessionStoreProvider", () => {
  let bridge: DesktopBridge;
  beforeEach(() => { bridge = fakeBridge(); });
  afterEach(() => cleanup());

  it("loads the session list on mount and exposes actions", async () => {
    renderStore(bridge);
    expect(screen.getByTestId("count").textContent).toBe("none");
    await waitFor(() => expect(screen.getByTestId("count").textContent).toBe("2"));
    expect(screen.getByTestId("loading").textContent).toBe("idle");
  });

  it("updates the current session from desktop navigation events", async () => {
    renderStore(bridge);
    await waitFor(() => expect(screen.getByTestId("count").textContent).toBe("2"));
    const subscribe = bridge.onSessionNavigation as (cb: (event: { kind: string; sessionId?: string; source: string; at: number }) => void) => () => void;
    const callback = vi.mocked(subscribe).mock.calls[0][0];
    await act(async () => {
      callback({ kind: "session-open", sessionId: "s-2", source: "deeplink", at: 5 });
    });
    expect(screen.getByTestId("current").textContent).toBe("s-2");
    expect(screen.getByTestId("nav").textContent).toBe("session-open:s-2");
    await act(async () => {
      callback({ kind: "session-list", source: "deeplink", at: 6 });
    });
    expect(screen.getByTestId("current").textContent).toBe("none");
  });

  it("opens, renames, and removes sessions through the store", async () => {
    const { getStore } = renderStore(bridge);
    await waitFor(() => expect(screen.getByTestId("count").textContent).toBe("2"));
    const store = getStore();
    await act(async () => { await store.openSession("s-1"); });
    expect(screen.getByTestId("current").textContent).toBe("s-1");
    await act(async () => { await store.rename("s-1", "Renamed"); });
    expect(bridge.sessions.rename).toHaveBeenCalledWith("s-1", "Renamed");
    await act(async () => { await store.remove("s-1"); });
    expect(bridge.sessions.remove).toHaveBeenCalledWith("s-1");
    expect(screen.getByTestId("current").textContent).toBe("none");
  });

  it("passes search requests through to the bridge", async () => {
    const { getStore } = renderStore(bridge);
    await waitFor(() => expect(screen.getByTestId("count").textContent).toBe("2"));
    await act(async () => { await getStore().search({ query: "fees", limit: 5 }); });
    expect(bridge.sessions.search).toHaveBeenCalledWith({ query: "fees", limit: 5 });
  });
});
