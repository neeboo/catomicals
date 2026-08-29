import { describe, expect, it } from "vitest";
import {
  CATOMICALS_SCHEME,
  createCatomicalsDeeplinkService,
  findDeeplinkInArgv,
  navigationEventFromTarget,
  parseCatomicalsDeeplink,
  type CatomicalsDeeplinkServiceDeps,
} from "./deeplink";

describe("parseCatomicalsDeeplink", () => {
  it("parses a canonical session deep link", () => {
    const result = parseCatomicalsDeeplink("catomicals://session/abc-123");
    expect(result).toEqual({ ok: true, target: { kind: "session", sessionId: "abc-123" }, url: "catomicals://session/abc-123" });
  });

  it("is case-insensitive about the scheme and tolerant of slashes", () => {
    expect(parseCatomicalsDeeplink("CATOMICALS://session/abc-123").ok).toBe(true);
    expect(parseCatomicalsDeeplink("catomicals:///session/abc-123").ok).toBe(true);
    expect(parseCatomicalsDeeplink("catomicals://session/abc-123/").ok).toBe(true);
  });

  it("parses the session list target", () => {
    expect(parseCatomicalsDeeplink("catomicals://sessions")).toEqual({
      ok: true,
      target: { kind: "sessions" },
      url: "catomicals://sessions",
    });
  });

  it("rejects unsupported schemes, malformed ids, and unknown targets", () => {
    expect(parseCatomicalsDeeplink("https://session/abc")).toEqual({
      ok: false,
      reason: "unsupported-scheme",
      url: "https://session/abc",
    });
    expect(parseCatomicalsDeeplink("catomicals://session/../etc/passwd").reason).toBe("malformed");
    expect(parseCatomicalsDeeplink("catomicals://session/").reason).toBe("malformed");
    expect(parseCatomicalsDeeplink("catomicals://wallet/sign").reason).toBe("unknown-target");
    expect(parseCatomicalsDeeplink("").reason).toBe("malformed");
  });

  it("ignores query strings on session ids", () => {
    const result = parseCatomicalsDeeplink("catomicals://session/abc-123?ref=sidebar");
    expect(result.ok && result.target).toEqual({ kind: "session", sessionId: "abc-123" });
  });
});

describe("navigationEventFromTarget", () => {
  it("maps targets to the navigation event contract", () => {
    expect(navigationEventFromTarget({ kind: "session", sessionId: "abc-123" as never }, "deeplink", 42)).toEqual({
      kind: "session-open",
      sessionId: "abc-123",
      source: "deeplink",
      at: 42,
    });
    expect(navigationEventFromTarget({ kind: "sessions" }, "app", 7)).toEqual({
      kind: "session-list",
      source: "app",
      at: 7,
    });
  });
});

describe("findDeeplinkInArgv", () => {
  it("finds the first deep link in an argv list", () => {
    const parsed = findDeeplinkInArgv(["/Applications/Catomicals.app", "--flag", "catomicals://session/zzz-99"]);
    expect(parsed?.ok).toBe(true);
    expect(parsed?.ok && parsed.target).toEqual({ kind: "session", sessionId: "zzz-99" });
  });

  it("returns undefined when no deep link is present", () => {
    expect(findDeeplinkInArgv(["/Applications/Catomicals.app", "--renderer-url=http://localhost:5173"])).toBeUndefined();
  });
});

describe("createCatomicalsDeeplinkService", () => {
  function fakeDeps(argv: readonly string[] = []): CatomicalsDeeplinkServiceDeps & {
    emitOpenUrl(url: string): void;
    emitSecondInstance(argv: readonly string[]): void;
    openUrlListeners: Array<(url: string) => void>;
    secondInstanceListeners: Array<(argv: readonly string[]) => void>;
  } {
    const openUrlListeners: Array<(url: string) => void> = [];
    const secondInstanceListeners: Array<(argv: readonly string[]) => void> = [];
    return {
      currentArgv: argv,
      registerProtocolClient: () => true,
      onOpenUrl: (listener) => openUrlListeners.push(listener),
      removeOpenUrlListener: (listener) => {
        const index = openUrlListeners.indexOf(listener);
        if (index !== -1) openUrlListeners.splice(index, 1);
      },
      onSecondInstance: (listener) => secondInstanceListeners.push(listener),
      removeSecondInstanceListener: (listener) => {
        const index = secondInstanceListeners.indexOf(listener);
        if (index !== -1) secondInstanceListeners.splice(index, 1);
      },
      emitOpenUrl: (url) => { for (const listener of [...openUrlListeners]) listener(url); },
      emitSecondInstance: (argv) => { for (const listener of [...secondInstanceListeners]) listener(argv); },
      openUrlListeners,
      secondInstanceListeners,
    };
  }

  it("forwards open-url and second-instance deep links as navigation events", () => {
    const deps = fakeDeps();
    const events: unknown[] = [];
    const service = createCatomicalsDeeplinkService(deps, (event) => events.push(event));
    deps.emitOpenUrl("catomicals://session/abc-123");
    deps.emitSecondInstance(["/Applications/Catomicals.app", "catomicals://sessions"]);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ kind: "session-open", sessionId: "abc-123", source: "deeplink" });
    expect(events[1]).toMatchObject({ kind: "session-list", source: "deeplink" });
    service.dispose();
    deps.emitOpenUrl("catomicals://session/other");
    expect(events).toHaveLength(2);
  });

  it("honors a launch-time deep link on a microtask", async () => {
    const deps = fakeDeps(["/Applications/Catomicals.app", "catomicals://session/launch-1"]);
    const events: unknown[] = [];
    createCatomicalsDeeplinkService(deps, (event) => events.push(event));
    await Promise.resolve();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ kind: "session-open", sessionId: "launch-1", source: "deeplink" });
  });

  it("registers the protocol client on creation", () => {
    const deps = fakeDeps();
    let registered = 0;
    deps.registerProtocolClient = () => { registered += 1; return true; };
    createCatomicalsDeeplinkService(deps, () => undefined);
    expect(registered).toBe(1);
    expect(CATOMICALS_SCHEME).toBe("catomicals");
  });
});
