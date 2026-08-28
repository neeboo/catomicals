// @vitest-environment jsdom

import type { ReactNode } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONVERSATION_STARTERS,
  MessagePart,
  WalletWorkbench,
  runConversationStarter,
} from "./WalletWorkbench";

const testState = vi.hoisted(() => ({
  desktopBridge: null as Record<string, unknown> | null,
  walletSend: vi.fn(),
}));

// Node 25 exposes a broken empty `globalThis.localStorage` (experimental
// webstorage without a backing file) that shadows jsdom's real Storage in the
// vitest environment, so tests stub a working in-memory Storage instead.
function createMemoryStorage(): Storage {
  const entries = new Map<string, string>();
  return {
    get length() { return entries.size; },
    clear: () => { entries.clear(); },
    getItem: (key: string) => entries.get(key) ?? null,
    key: (index: number) => Array.from(entries.keys())[index] ?? null,
    removeItem: (key: string) => { entries.delete(key); },
    setItem: (key: string, value: string) => { entries.set(key, String(value)); },
  } as Storage;
}

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="#settings">{children}</a>,
}));

vi.mock("@/lib/desktop", () => ({
  optionalDesktopBridge: () => testState.desktopBridge,
  requireDesktopBridge: () => {
    if (!testState.desktopBridge) throw new Error("desktop unavailable");
    return testState.desktopBridge;
  },
}));

vi.mock("@/lib/hooks", () => ({
  useChatStateQuery: () => ({
    data: undefined,
    error: new Error("offline"),
    isError: true,
    isFetching: false,
    isPending: false,
    isSuccess: false,
  }),
  useCreateChatMessageMutation: () => ({ isPending: false, mutate: testState.walletSend }),
  useCredentialsQuery: () => ({ data: [] }),
  useInspectTransactionMutation: () => ({ data: undefined, isPending: false, mutate: vi.fn(), reset: vi.fn() }),
  useIntentsQuery: () => ({ data: [], isError: false, isFetching: false, isPending: false, refetch: vi.fn() }),
  useNodeStatusQuery: () => ({ data: undefined, isSuccess: false }),
  useRetryWalletQueries: () => vi.fn(),
  useSignerStatusQuery: () => ({ data: undefined }),
  useWalletStatusQuery: () => ({ data: undefined, isSuccess: false }),
}));

beforeEach(() => {
  vi.stubGlobal("localStorage", createMemoryStorage());
  testState.desktopBridge = null;
  testState.walletSend.mockReset();
  Object.defineProperty(HTMLElement.prototype, "scrollTo", {
    configurable: true,
    value: vi.fn(),
  });
  vi.stubGlobal("matchMedia", vi.fn((query: string) => ({
    matches: query === "(max-width: 1180px)",
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  })));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("wallet workbench protocol message rendering", () => {
  it("renders text, tool activity, and errors from typed parts", () => {
    expect(renderToStaticMarkup(<MessagePart part={{ type: "text", text: "检查完成" }} />))
      .toContain("检查完成");
    expect(renderToStaticMarkup(<MessagePart part={{
      type: "tool_call",
      tool_call_id: "call-1",
      tool_name: "read_plugin_health",
      request_digest: `sha256:${"1".repeat(64)}`,
      permission_scope: "plugin.health.read",
    }} />)).toContain("read_plugin_health");
    expect(renderToStaticMarkup(<MessagePart part={{
      type: "error",
      code: "health_unavailable",
      message: "健康状态不可用",
      retriable: true,
    }} />)).toContain("健康状态不可用");
  });

  it("rejects an invalid review reference at the render boundary", () => {
    const markup = renderToStaticMarkup(<MessagePart part={{
      type: "review_reference",
      reference: {
        schema_version: 1,
        review_id: "review-1",
        kind: "plugin_settings",
        source: "desktop_host",
        review_digest: `sha256:${"2".repeat(64)}`,
        intent_id: "60675e8d-b7a2-4602-b744-4c85d6dc0206",
        plugin_id: "@catomicals/plugin-walletd",
        plugin_version: "1.0.0",
        created_at: "2026-08-27T09:00:00Z",
        state: "current",
      },
    }} />);

    expect(markup).toContain("invalid review id");
    expect(markup).not.toContain("审查引用</span>");
  });

  it("routes starter actions to real tools and only drafts the unimplemented mint flow", () => {
    const openTool = vi.fn();
    const setDraft = vi.fn();

    runConversationStarter("transaction", { openTool, setDraft });
    runConversationStarter("issuance", { openTool, setDraft });
    runConversationStarter("intents", { openTool, setDraft });

    expect(openTool.mock.calls).toEqual([["transaction"], ["intents"]]);
    expect(setDraft).toHaveBeenCalledOnce();
    expect(setDraft).toHaveBeenCalledWith(expect.stringContaining("尚未实现"));
    expect(CONVERSATION_STARTERS.map((action) => action.label)).toEqual([
      "检查交易",
      "发起铸造",
      "查看签名意图",
    ]);
  });

  it("sends ordinary conversation to the selected desktop agent while the wallet node is offline", async () => {
    const createExecutorSession = vi.fn().mockResolvedValue({
      sessionId: "wallet-main-codex",
      provider: "codex",
      state: "idle",
    });
    const sendExecutorMessage = vi.fn().mockResolvedValue({
      sessionId: "wallet-main-codex",
      provider: "codex",
      state: "completed",
      output: [
        JSON.stringify({ type: "thread.started", thread_id: "native-1" }),
        JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "我在。" } }),
      ].join("\n"),
    });
    testState.desktopBridge = {
      getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
      getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
      probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
      readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
      createExecutorSession,
      sendExecutorMessage,
    };

    const user = userEvent.setup();
    render(<WalletWorkbench />);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("我在。")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();
    expect(createExecutorSession).toHaveBeenCalledWith("codex", "wallet-main-codex");
    expect(sendExecutorMessage).toHaveBeenCalledWith("wallet-main-codex", "在不在");
    expect(testState.walletSend).not.toHaveBeenCalled();
  });

  it("renders user turns as right-aligned dark bubbles and agent turns as plain left content", async () => {
    const sendExecutorMessage = vi.fn().mockResolvedValue({
      sessionId: "wallet-main-codex",
      provider: "codex",
      state: "completed",
      output: [
        JSON.stringify({ type: "thread.started", thread_id: "native-1" }),
        JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "我在。" } }),
      ].join("\n"),
    });
    testState.desktopBridge = {
      getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
      getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
      probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
      readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
      createExecutorSession: vi.fn().mockResolvedValue({
        sessionId: "wallet-main-codex",
        provider: "codex",
        state: "idle",
      }),
      sendExecutorMessage,
    };

    const user = userEvent.setup();
    render(<WalletWorkbench />);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    await screen.findByText("我在。");

    const userArticle = screen.getByText("在不在").closest("article");
    expect(userArticle?.getAttribute("data-role")).toBe("user");
    expect(userArticle?.querySelector(".user-bubble")).not.toBeNull();

    const agentArticle = screen.getByText("我在。").closest("article");
    expect(agentArticle?.getAttribute("data-role")).toBe("agent");
    expect(agentArticle?.querySelector(".user-bubble")).toBeNull();
    expect(agentArticle?.querySelector(".turn-duration")).not.toBeNull();
  });

  it("shows a live processing status with per-second elapsed time and then the real round duration", async () => {
    vi.useFakeTimers();
    try {
      let resolveSend!: (value: unknown) => void;
      const sendExecutorMessage = vi.fn().mockImplementation(
        () => new Promise((resolve) => { resolveSend = resolve; }),
      );
      testState.desktopBridge = {
        getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
        getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
        probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
        readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
        getExecutorStatus: vi.fn().mockRejectedValue(new Error("session not found")),
        createExecutorSession: vi.fn().mockResolvedValue({
          sessionId: "wallet-main-codex",
          provider: "codex",
          state: "idle",
        }),
        sendExecutorMessage,
      };

      // fireEvent keeps the send flow synchronous up to the executor await,
      // so the per-second ticker is driven entirely by fake timers.
      render(<WalletWorkbench />);
      fireEvent.change(screen.getByPlaceholderText(/向所选代理/), { target: { value: "在不在" } });
      fireEvent.click(screen.getByRole("button", { name: "发送消息" }));

      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByText(/正在处理/)).toBeTruthy();
      expect(screen.getByText("0s")).toBeTruthy();

      await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
      expect(screen.getByText("2s")).toBeTruthy();
      expect(screen.queryByText("1s")).toBeNull();

      await act(async () => {
        resolveSend({
          sessionId: "wallet-main-codex",
          provider: "codex",
          state: "completed",
          output: [
            JSON.stringify({ type: "thread.started", thread_id: "native-1" }),
            JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "我在。" } }),
          ].join("\n"),
        });
        await vi.advanceTimersByTimeAsync(0);
      });

      expect(screen.getByText("我在。")).toBeTruthy();
      expect(screen.getByText("2s")).toBeTruthy();
      expect(screen.queryByText(/正在处理/)).toBeNull();
      const agentArticle = screen.getByText("我在。").closest("article");
      expect(agentArticle?.querySelector(".turn-duration")?.textContent).toBe("2s");
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the user message and shows a clear failure state when the executor round fails", async () => {
    testState.desktopBridge = {
      getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
      getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
      probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
      readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
      createExecutorSession: vi.fn().mockResolvedValue({
        sessionId: "wallet-main-codex",
        provider: "codex",
        state: "idle",
      }),
      sendExecutorMessage: vi.fn().mockRejectedValue(new Error("执行器进程退出")),
    };

    const user = userEvent.setup();
    render(<WalletWorkbench />);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("处理失败")).toBeTruthy();
    expect(screen.getByText("执行器进程退出")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();
    expect(screen.getByText("在不在").closest("article")?.getAttribute("data-role")).toBe("user");
    expect(screen.queryByText(/正在处理/)).toBeNull();
  });

  it("treats a non-completed executor result as a failure with the real error code", async () => {
    testState.desktopBridge = {
      getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
      getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
      probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
      readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
      createExecutorSession: vi.fn().mockResolvedValue({
        sessionId: "wallet-main-codex",
        provider: "codex",
        state: "idle",
      }),
      sendExecutorMessage: vi.fn().mockResolvedValue({
        sessionId: "wallet-main-codex",
        provider: "codex",
        state: "failed",
        lastError: "process-failed",
        output: "",
      }),
    };

    const user = userEvent.setup();
    render(<WalletWorkbench />);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("处理失败")).toBeTruthy();
    expect(screen.getByText("process-failed")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();
  });

  it("traps focus in the overlay, closes with Escape, and returns focus to its trigger", async () => {
    const user = userEvent.setup();
    render(<WalletWorkbench />);

    const discovery = screen.getByRole("complementary", { name: "工具区" });
    const discoveryButton = within(discovery).getByRole("button", { name: "打开工具区" });
    await user.click(discoveryButton);

    const dialog = await screen.findByRole("dialog");
    const closeButton = within(dialog).getByRole("button", { name: "关闭工具区" });
    await waitFor(() => expect(document.activeElement).toBe(closeButton));

    await user.tab({ shift: true });
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: /资产发行/ }));
    await user.tab();
    expect(document.activeElement).toBe(closeButton);

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(within(screen.getByRole("complementary", { name: "工具区" }))
      .getByRole("button", { name: "打开工具区" })));

    const transactionStarter = screen.getByRole("button", { name: /检查交易/ });
    await user.click(transactionStarter);
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(document.activeElement).toBe(transactionStarter));
  });
});

describe("resizable workbench panes", () => {
  function stubDesktopMatchMedia() {
    // Desktop mode: neither pane is an overlay, so both separators are live.
    vi.stubGlobal("matchMedia", vi.fn(() => ({
      matches: false,
      media: "",
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })));
  }

  function stubOverlayMatchMedia(matches: (query: string) => boolean) {
    vi.stubGlobal("matchMedia", vi.fn((query: string) => ({
      matches: matches(query),
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })));
  }

  function railVar(name: "--left-rail" | "--right-rail"): string {
    const shell = document.querySelector<HTMLElement>(".workbench-shell");
    if (!shell) throw new Error("workbench shell not found");
    return shell.style.getPropertyValue(name);
  }

  function openTools() {
    // The header also carries a hidden mobile "打开工具区" toggle, so scope to
    // the discovery rail (or the open dialog's close path) explicitly.
    const discovery = screen.getByRole("complementary", { name: "工具区" });
    fireEvent.click(within(discovery).getByRole("button", { name: "打开工具区" }));
  }

  it("restores persisted pane widths from localStorage", () => {
    stubDesktopMatchMedia();
    localStorage.setItem("catomicals:workbench:leftWidth", "360");
    localStorage.setItem("catomicals:workbench:rightWidth", "520");

    render(<WalletWorkbench />);

    expect(railVar("--left-rail")).toBe("360px");
    expect(railVar("--right-rail")).toBe("520px");
  });

  it("falls back to safe defaults when stored widths are invalid or out of range", () => {
    stubDesktopMatchMedia();
    for (const badLeft of ["abc", "9999", "-40", "NaN", ""]) {
      localStorage.setItem("catomicals:workbench:leftWidth", badLeft);
      const { unmount } = render(<WalletWorkbench />);
      expect(railVar("--left-rail")).toBe("312px");
      unmount();
    }
    for (const badRight of ["319", "720.1", "not-a-number"]) {
      localStorage.setItem("catomicals:workbench:rightWidth", badRight);
      const { unmount } = render(<WalletWorkbench />);
      expect(railVar("--right-rail")).toBe("384px");
      unmount();
    }
  });

  it("adjusts the left pane with keyboard arrows and persists the width", () => {
    stubDesktopMatchMedia();
    render(<WalletWorkbench />);

    const resizer = screen.getByRole("separator", { name: "调整左侧栏宽度" });
    expect(resizer.getAttribute("aria-orientation")).toBe("vertical");
    expect(resizer.getAttribute("aria-valuemin")).toBe("240");
    expect(resizer.getAttribute("aria-valuemax")).toBe("480");
    expect(resizer.getAttribute("aria-valuenow")).toBe("312");

    fireEvent.keyDown(resizer, { key: "ArrowRight" });
    expect(railVar("--left-rail")).toBe("328px");
    expect(localStorage.getItem("catomicals:workbench:leftWidth")).toBe("328");

    fireEvent.keyDown(resizer, { key: "ArrowLeft" });
    fireEvent.keyDown(resizer, { key: "ArrowLeft" });
    expect(railVar("--left-rail")).toBe("296px");
    expect(localStorage.getItem("catomicals:workbench:leftWidth")).toBe("296");
  });

  it("clamps pane widths to the documented bounds", () => {
    stubDesktopMatchMedia();
    render(<WalletWorkbench />);

    const left = screen.getByRole("separator", { name: "调整左侧栏宽度" });
    for (let i = 0; i < 30; i += 1) fireEvent.keyDown(left, { key: "ArrowRight" });
    expect(railVar("--left-rail")).toBe("480px");
    for (let i = 0; i < 40; i += 1) fireEvent.keyDown(left, { key: "ArrowLeft" });
    expect(railVar("--left-rail")).toBe("240px");

    openTools();
    const right = screen.getByRole("separator", { name: "调整工具区宽度" });
    for (let i = 0; i < 40; i += 1) fireEvent.keyDown(right, { key: "ArrowLeft" });
    expect(railVar("--right-rail")).toBe("720px");
    for (let i = 0; i < 50; i += 1) fireEvent.keyDown(right, { key: "ArrowRight" });
    expect(railVar("--right-rail")).toBe("320px");
  });

  it("shows the right separator only when tools are open on desktop and mirrors the keyboard direction", () => {
    stubDesktopMatchMedia();
    render(<WalletWorkbench />);

    expect(screen.queryByRole("separator", { name: "调整工具区宽度" })).toBeNull();

    openTools();
    const right = screen.getByRole("separator", { name: "调整工具区宽度" });
    expect(right.getAttribute("aria-valuemin")).toBe("320");
    expect(right.getAttribute("aria-valuemax")).toBe("720");

    // ArrowLeft moves the boundary left, widening the right pane.
    fireEvent.keyDown(right, { key: "ArrowLeft" });
    expect(railVar("--right-rail")).toBe("400px");
    fireEvent.keyDown(right, { key: "ArrowRight" });
    expect(railVar("--right-rail")).toBe("384px");
  });

  it("drags the left separator with the pointer and persists the result", () => {
    stubDesktopMatchMedia();
    render(<WalletWorkbench />);

    const left = screen.getByRole("separator", { name: "调整左侧栏宽度" });
    fireEvent.pointerDown(left, { button: 0, clientX: 100, pointerId: 1 });
    fireEvent.pointerMove(left, { clientX: 140, pointerId: 1 });
    expect(railVar("--left-rail")).toBe("352px");
    fireEvent.pointerUp(left, { pointerId: 1 });

    expect(localStorage.getItem("catomicals:workbench:leftWidth")).toBe("352");
  });

  it("drags the right separator in the mirror direction", () => {
    stubDesktopMatchMedia();
    render(<WalletWorkbench />);

    openTools();
    const right = screen.getByRole("separator", { name: "调整工具区宽度" });
    fireEvent.pointerDown(right, { button: 0, clientX: 200, pointerId: 1 });
    fireEvent.pointerMove(right, { clientX: 160, pointerId: 1 });
    expect(railVar("--right-rail")).toBe("424px");
    fireEvent.pointerUp(right, { pointerId: 1 });

    expect(localStorage.getItem("catomicals:workbench:rightWidth")).toBe("424");
  });

  it("keeps the resizers out of small-screen drawer modes", () => {
    // Both panes are overlays below their breakpoints: no separators at all.
    stubOverlayMatchMedia((query) => query === "(max-width: 760px)" || query === "(max-width: 1180px)");
    render(<WalletWorkbench />);
    expect(screen.queryByRole("separator")).toBeNull();
  });

  it("hides only the right separator while the right pane is in overlay mode", () => {
    // Default stub: only the 1180px query matches, so the right pane is a drawer.
    render(<WalletWorkbench />);
    expect(screen.getByRole("separator", { name: "调整左侧栏宽度" })).toBeTruthy();

    openTools();
    expect(screen.queryByRole("separator", { name: "调整工具区宽度" })).toBeNull();
  });
});
