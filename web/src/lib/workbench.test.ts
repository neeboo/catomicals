import { describe, expect, it, vi } from "vitest";
import {
  INSPECTOR_MODES,
  createToolAreaBridgeQueue,
  DEFAULT_TOOL_AREA,
  TOOL_TABS,
  starterActions,
  mountBrowserPane,
  resolveExecutorProbeProvider,
  transitionDrawer,
  transitionToolArea,
  type InspectorMode,
} from "./workbench";

describe("wallet workbench model", () => {
  it("exposes the four contextual inspector modes", () => {
    expect(INSPECTOR_MODES).toEqual([
      "transaction",
      "intents",
      "security",
      "issuance",
    ] satisfies InspectorMode[]);
  });

  it("maps each starter action to a real inspector mode", () => {
    expect(starterActions.map((action) => action.mode)).toEqual([
      "transaction",
      "intents",
      "security",
      "issuance",
    ]);
  });

  it("keeps issuance honest about its current implementation boundary", () => {
    const issuance = starterActions.find((action) => action.mode === "issuance");

    expect(issuance?.available).toBe(false);
    expect(issuance?.description).toContain("尚未实现");
  });

  it("uses one drawer state so opening one side always closes the other", () => {
    expect(transitionDrawer(null, "open-left")).toBe("left");
    expect(transitionDrawer("left", "open-right")).toBe("right");
    expect(transitionDrawer("right", "open-left")).toBe("left");
    expect(transitionDrawer("left", "close")).toBeNull();
  });

  it("moves from the left drawer to the right drawer when a tool is selected", () => {
    expect(transitionDrawer("left", "select-tool")).toBe("right");
  });

  it("keeps the right tool area collapsed until its corner control is used", () => {
    expect(DEFAULT_TOOL_AREA).toEqual({ open: false, activeTab: null });
    const expanded = transitionToolArea(DEFAULT_TOOL_AREA, { type: "expand" });
    expect(expanded).toEqual({ open: true, activeTab: null });
    const selected = transitionToolArea(expanded, { type: "select", tab: "security" });
    expect(selected).toEqual({ open: true, activeTab: "security" });
    expect(transitionToolArea(selected, { type: "back" })).toEqual({ open: true, activeTab: null });
    expect(transitionToolArea(selected, { type: "close" })).toEqual(DEFAULT_TOOL_AREA);
  });

  it("models the real Electron browser as a first-class tool tab", () => {
    expect(TOOL_TABS).toEqual([
      "browser",
      "transaction",
      "intents",
      "security",
      "issuance",
    ]);
    expect(transitionToolArea(DEFAULT_TOOL_AREA, { type: "select", tab: "browser" }))
      .toEqual({ open: true, activeTab: "browser" });
  });

  it("waits for persisted settings before probing an executor", () => {
    expect(resolveExecutorProbeProvider(false, "codex")).toBeNull();
    expect(resolveExecutorProbeProvider(true, "deepseek")).toBe("deepseek");
  });

  it("does not select or close host tabs when the browser surface mounts and unmounts", async () => {
    const calls: string[] = [];
    let resize: (() => void) | undefined;
    const bridge = {
      selectTab: async (tab: string) => { calls.push(`select:${tab}`); },
      setPaneBounds: async () => { calls.push("bounds"); },
      closeTools: async () => { calls.push("close"); },
    };
    const surface = {
      getBoundingClientRect: () => ({ x: 10, y: 20, width: 300, height: 400 }),
    };
    const frames: Array<() => void> = [];
    const cleanup = mountBrowserPane(bridge, surface, {
      createObserver: (callback) => {
        resize = callback;
        return { observe: () => undefined, disconnect: () => calls.push("disconnect") };
      },
      scheduleFrame: (callback) => { frames.push(callback); return frames.length; },
      cancelFrame: () => undefined,
    });

    frames.shift()?.();
    resize?.();
    resize?.();
    frames.shift()?.();
    await bridge.selectTab("transaction");
    cleanup();

    expect(calls).toEqual([
      "bounds",
      "bounds",
      "select:transaction",
      "disconnect",
    ]);
    expect(calls).not.toContain("close");
  });

  it("serializes host tab changes so the latest user selection cannot be overtaken", async () => {
    const calls: string[] = [];
    let releaseBrowser: (() => void) | undefined;
    const browserPending = new Promise<void>((resolve) => { releaseBrowser = resolve; });
    const queue = createToolAreaBridgeQueue({
      selectTab: async (tab) => {
        calls.push(`select:${tab}`);
        if (tab === "browser") await browserPending;
        return {};
      },
      closeTools: async () => { calls.push("close"); return {}; },
    }, (cause) => { throw cause; });

    const browser = queue.selectTab("browser");
    const transaction = queue.selectTab("transaction");
    await Promise.resolve();
    expect(calls).toEqual(["select:browser"]);

    releaseBrowser?.();
    await Promise.all([browser, transaction]);
    expect(calls).toEqual(["select:browser", "select:transaction"]);
  });

  it("reports a failed host change and continues with the next queued selection", async () => {
    const calls: string[] = [];
    const errors: string[] = [];
    let releaseRecovery: (() => void) | undefined;
    const recoveryPending = new Promise<void>((resolve) => { releaseRecovery = resolve; });
    const queue = createToolAreaBridgeQueue({
      selectTab: async (tab) => {
        calls.push(`select:${tab}`);
        if (tab === "browser") throw new Error("browser failed");
        return {};
      },
      closeTools: async () => { calls.push("close"); return {}; },
    }, async (cause) => {
      errors.push(cause instanceof Error ? cause.message : "unknown");
      await recoveryPending;
    });

    const browser = queue.selectTab("browser");
    const security = queue.selectTab("security");
    await vi.waitFor(() => expect(errors).toEqual(["browser failed"]));
    expect(calls).toEqual(["select:browser"]);
    releaseRecovery?.();
    await Promise.all([browser, security]);
    expect(calls).toEqual(["select:browser", "select:security"]);
  });
});
