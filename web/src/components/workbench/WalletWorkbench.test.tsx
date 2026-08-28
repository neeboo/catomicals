// @vitest-environment jsdom

import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
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
