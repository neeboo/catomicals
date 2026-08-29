// @vitest-environment jsdom

import type { ReactNode } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MessagePart, WalletWorkbench } from "./WalletWorkbench";
import { SessionStoreProvider } from "@/lib/session";
import { createFakeSessionBridge } from "@/lib/session-fake";
import type { DesktopBridge, SessionBridgeApi } from "@/lib/desktop";

const testState = vi.hoisted(() => ({
  desktopBridge: null as DesktopBridge | null,
  executor: {
    createExecutorSession: vi.fn(),
    disposeExecutorSession: vi.fn(),
    getExecutorStatus: vi.fn(),
    resumeExecutorSession: vi.fn(),
    sendExecutorMessage: vi.fn(),
  },
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
  useCredentialsQuery: () => ({ data: [] }),
  useInspectTransactionMutation: () => ({ data: undefined, isPending: false, mutate: vi.fn(), reset: vi.fn() }),
  useIntentsQuery: () => ({ data: [], isError: false, isFetching: false, isPending: false, refetch: vi.fn() }),
  useNodeStatusQuery: () => ({ data: undefined, isSuccess: false }),
  useSignerStatusQuery: () => ({ data: undefined }),
  useWalletStatusQuery: () => ({ data: undefined, isSuccess: false }),
}));

beforeEach(() => {
  vi.stubGlobal("localStorage", createMemoryStorage());
  testState.desktopBridge = null;
  for (const mock of Object.values(testState.executor)) mock.mockReset();
  testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
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

/** Build a desktop bridge with a fake session store and reset executor mocks. */
function baseBridge(): { bridge: DesktopBridge; api: SessionBridgeApi; sessionState: ReturnType<typeof createFakeSessionBridge>["state"] } {
  const { api, state } = createFakeSessionBridge();
  const bridge = {
    getState: vi.fn().mockResolvedValue({ desktop: true, toolsOpen: false, activeTab: null }),
    getSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
    updateSettings: vi.fn().mockResolvedValue({ version: 2, defaultHarness: "codex" }),
    getIdentityState: vi.fn().mockResolvedValue({ available: true, session: null }),
    loginIdentity: vi.fn(),
    logoutIdentity: vi.fn(),
    recoverIdentity: vi.fn(),
    probeExecutor: vi.fn().mockRejectedValue(new Error("probe omitted in test")),
    readPluginSettings: vi.fn().mockRejectedValue(new Error("settings omitted in test")),
    createExecutorSession: testState.executor.createExecutorSession,
    disposeExecutorSession: testState.executor.disposeExecutorSession,
    getExecutorStatus: testState.executor.getExecutorStatus,
    resumeExecutorSession: testState.executor.resumeExecutorSession,
    sendExecutorMessage: testState.executor.sendExecutorMessage,
    sessions: api,
    onSessionNavigation: () => () => undefined,
  } as unknown as DesktopBridge;
  return { bridge, api, sessionState: state };
}

function renderWorkbench(bridge?: DesktopBridge) {
  return render(
    <SessionStoreProvider bridge={bridge}>
      <WalletWorkbench />
    </SessionStoreProvider>,
  );
}

function completedExecutorOutput(text: string, nativeSessionId = "native-1"): string {
  return [
    JSON.stringify({ type: "thread.started", thread_id: nativeSessionId }),
    JSON.stringify({ type: "item.completed", item: { type: "agent_message", text } }),
  ].join("\n");
}

async function findAgentMessage(text: string): Promise<HTMLElement> {
  let match: HTMLElement | undefined;
  await waitFor(() => {
    match = Array.from(document.querySelectorAll<HTMLElement>('article[data-role="agent"]'))
      .find((article) => article.textContent?.includes(text));
    expect(match).toBeDefined();
  });
  return match as HTMLElement;
}

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
});

describe("session-backed conversation", () => {
  it("shows lightweight starter prompts only while the transcript is empty", async () => {
    const { bridge } = baseBridge();
    testState.desktopBridge = bridge;
    const user = userEvent.setup();
    renderWorkbench(bridge);

    expect(await screen.findByRole("heading", { name: "从一项钱包任务开始" })).toBeTruthy();
    expect(screen.getByText("直接描述目标，或从一个常用任务开始。")).toBeTruthy();
    expect(screen.getByRole("button", { name: "检查一笔交易" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "查看钱包状态" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "设计一个 covenant 发行方案" })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "检查一笔交易" }));
    const composer = screen.getByPlaceholderText(/向所选代理/);
    expect((composer as HTMLTextAreaElement).value).toBe("检查一笔交易");
    expect(document.activeElement).toBe(composer);
    expect(testState.executor.sendExecutorMessage).not.toHaveBeenCalled();

    testState.executor.sendExecutorMessage.mockResolvedValue({
      sessionId: "s-1",
      provider: "codex",
      state: "completed",
      nativeSessionId: "native-1",
      output: completedExecutorOutput("交易内容已读取。"),
    });
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({
      sessionId,
      provider,
      state: "idle",
    }));
    testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await findAgentMessage("交易内容已读取。")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "从一项钱包任务开始" })).toBeNull();
  });

  it("generates the first successful turn title in an isolated executor session", async () => {
    const { bridge, api, sessionState } = baseBridge();
    const rename = vi.spyOn(api, "rename");
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({
      sessionId,
      provider,
      state: "idle",
    }));
    testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
    testState.executor.sendExecutorMessage.mockImplementation(async (sessionId, prompt) => {
      if (sessionId === "s-1") {
        return {
          sessionId,
          provider: "codex",
          state: "completed",
          nativeSessionId: "native-main",
          output: completedExecutorOutput("可以先检查输入输出。", "native-main"),
        };
      }
      expect(sessionId).toMatch(/^s-1-title-/);
      expect(prompt).toContain("只输出一行自然语言标题");
      return {
        sessionId,
        provider: "codex",
        state: "completed",
        output: completedExecutorOutput("**“检查 Bitcoin 交易”**", "native-title"),
      };
    });

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "帮我检查这笔 Bitcoin 交易");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("可以先检查输入输出。")).toBeTruthy();
    await waitFor(() => expect(rename).toHaveBeenCalledWith("s-1", "检查 Bitcoin 交易"));
    const auxiliaryId = testState.executor.createExecutorSession.mock.calls
      .map((call) => call[1] as string)
      .find((id) => id.startsWith("s-1-title-"));
    expect(auxiliaryId).toBeDefined();
    expect(testState.executor.disposeExecutorSession).toHaveBeenCalledWith(auxiliaryId);

    const visibleContents = sessionState.records[0].events
      .filter((event) => event.type === "user/message" || event.type === "assistant/message")
      .map((event) => (event.data as { content: string }).content);
    expect(visibleContents).toEqual(["帮我检查这笔 Bitcoin 交易", "可以先检查输入输出。"]);
  });

  it("keeps a manual rename made while title generation is running", async () => {
    const { bridge, api } = baseBridge();
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({ sessionId, provider, state: "idle" }));
    testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
    let resolveTitle!: (value: unknown) => void;
    testState.executor.sendExecutorMessage.mockImplementation((sessionId) => {
      if (sessionId === "s-1") {
        return Promise.resolve({
          sessionId,
          provider: "codex",
          state: "completed",
          nativeSessionId: "native-main",
          output: completedExecutorOutput("回答", "native-main"),
        });
      }
      return new Promise((resolve) => { resolveTitle = resolve; });
    });

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "初始问题");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    await screen.findByText("回答");
    await waitFor(() => expect(resolveTitle).toBeDefined());

    await api.rename("s-1", "人工标题");
    resolveTitle({
      sessionId: "s-1-title-1",
      provider: "codex",
      state: "completed",
      output: completedExecutorOutput("自动标题", "native-title"),
    });

    await waitFor(() => expect(testState.executor.disposeExecutorSession).toHaveBeenCalled());
    const summaries = await api.list();
    expect(summaries[0].title).toBe("人工标题");
  });

  it("falls back to the first user message when auxiliary title generation fails", async () => {
    const { bridge, api } = baseBridge();
    const rename = vi.spyOn(api, "rename");
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({ sessionId, provider, state: "idle" }));
    testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
    testState.executor.sendExecutorMessage.mockImplementation(async (sessionId) => {
      if (sessionId === "s-1") {
        return {
          sessionId,
          provider: "codex",
          state: "completed",
          nativeSessionId: "native-main",
          output: completedExecutorOutput("回答", "native-main"),
        };
      }
      throw new Error("title executor unavailable");
    });

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "设计 covenant 发行与挖矿规则");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("回答")).toBeTruthy();
    await waitFor(() => expect(rename).toHaveBeenCalledWith("s-1", "设计 covenant 发行与挖矿规则"));
  });

  it("uses the first user message to title the first successful turn after an earlier failure", async () => {
    const { bridge, api } = baseBridge();
    const rename = vi.spyOn(api, "rename");
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({ sessionId, provider, state: "idle" }));
    testState.executor.disposeExecutorSession.mockResolvedValue({ state: "disposed" });
    let mainTurn = 0;
    testState.executor.sendExecutorMessage.mockImplementation(async (sessionId, prompt) => {
      if (sessionId === "s-1") {
        mainTurn += 1;
        if (mainTurn === 1) {
          return {
            sessionId,
            provider: "codex",
            state: "failed",
            lastError: "first-turn-failed",
            output: "",
          };
        }
        return {
          sessionId,
          provider: "codex",
          state: "completed",
          nativeSessionId: "native-main",
          output: completedExecutorOutput("第二轮成功回答", "native-main"),
        };
      }
      expect(sessionId).toMatch(/^s-1-title-/);
      expect(prompt).toContain(JSON.stringify(["首轮失败问题"]));
      expect(prompt).not.toContain("第二轮成功问题");
      expect(prompt).not.toContain("first-turn-failed");
      return {
        sessionId,
        provider: "codex",
        state: "completed",
        output: completedExecutorOutput("首轮问题处理", "native-title"),
      };
    });

    const user = userEvent.setup();
    renderWorkbench(bridge);
    const composer = screen.getByPlaceholderText(/向所选代理/);
    await user.type(composer, "首轮失败问题");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    expect(await screen.findByText("first-turn-failed")).toBeTruthy();

    await user.type(composer, "第二轮成功问题");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    expect(await screen.findByText("第二轮成功回答")).toBeTruthy();

    await waitFor(() => expect(rename).toHaveBeenCalledWith("s-1", "首轮问题处理"));
  });

  it("opens account login in place without navigating to the Passkey management route", async () => {
    const user = userEvent.setup();
    window.location.hash = "";
    renderWorkbench();

    const login = screen.getByRole("button", { name: "登录" });
    await user.click(login);

    expect(screen.getByRole("dialog", { name: "登录 Catomicals" })).toBeTruthy();
    expect(window.location.hash).toBe("");

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "登录 Catomicals" })).toBeNull();
    expect(document.activeElement).toBe(login);
  });

  it("restores the local identity label in the sidebar", async () => {
    const { bridge } = baseBridge();
    bridge.getIdentityState = vi.fn().mockResolvedValue({
      available: true,
      session: {
        version: 1,
        provider: "local-device",
        accountId: "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
        sessionId: "c1f66ac1-3b46-4c93-afdb-38c301a97732",
        displayName: "本机用户",
        createdAt: 1_775_000_000_000,
        authenticatedAt: 1_775_000_000_000,
      },
    });
    testState.desktopBridge = bridge;

    renderWorkbench(bridge);

    expect(await screen.findByRole("button", { name: "本机用户" })).toBeTruthy();
  });

  it("auto-creates a session, appends canonical JSONL events, and renders the transcript", async () => {
    const { bridge, sessionState } = baseBridge();
    testState.executor.sendExecutorMessage.mockResolvedValue({
      sessionId: "s-1",
      provider: "codex",
      state: "completed",
      nativeSessionId: "native-1",
      output: completedExecutorOutput("我在。"),
    });
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockResolvedValue({ sessionId: "s-1", provider: "codex", state: "idle" });
    testState.desktopBridge = bridge;

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await findAgentMessage("我在。")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();

    // The session is created with provider/executor metadata and bound to the
    // native executor session (its id is the persistent session id).
    expect(sessionState.records[0].header).toMatchObject({ provider: "codex", executor: "codex" });
    expect(testState.executor.createExecutorSession).toHaveBeenCalledWith("codex", "s-1");
    expect(testState.executor.sendExecutorMessage).toHaveBeenCalledWith("s-1", "在不在");

    // The canonical log holds the full turn: start, user message, request
    // header (initial + native-session resume), assistant message, turn end.
    const record = sessionState.records[0];
    expect(record.events.map((event) => event.type)).toEqual([
      "session/title",
      "turn/start",
      "user/message",
      "request/header",
      "request/header",
      "assistant/message",
      "turn/end",
      "session/title",
    ]);
    const userEvent_ = record.events.find((event) => event.type === "user/message");
    expect((userEvent_?.data as { content: string }).content).toBe("在不在");
    const assistantEvent = record.events.find((event) => event.type === "assistant/message");
    expect((assistantEvent?.data as { content: string }).content).toBe("我在。");
    const headers = record.events.filter((event) => event.type === "request/header");
    expect((headers[0].data as { header: { provider: string } }).header.provider).toBe("codex");
    expect((headers[1].data as { header: { nativeSessionId: string } }).header.nativeSessionId).toBe("native-1");
    const turnEnd = record.events.find((event) => event.type === "turn/end");
    expect((turnEnd?.data as { reason: { kind: string } }).reason.kind).toBe("completed");
  });

  it("keeps an in-flight response in its original session when the user switches sessions", async () => {
    const { bridge, sessionState } = baseBridge();
    const createdAt = Date.now();
    sessionState.records.push(
      {
        header: { version: 1, id: "s-old", createdAt, provider: "codex", executor: "codex" },
        events: [{ type: "session/title", seq: 0, time: createdAt, data: { title: "旧会话" } }],
      },
      {
        header: { version: 1, id: "s-new", createdAt: createdAt + 1, provider: "codex", executor: "codex" },
        events: [
          { type: "session/title", seq: 0, time: createdAt + 1, data: { title: "新目标会话" } },
          { type: "turn/start", seq: 1, time: createdAt + 2, data: { turn: 1 } },
          { type: "user/message", seq: 2, time: createdAt + 2, data: { content: "新会话问题" } },
          { type: "assistant/message", seq: 3, time: createdAt + 3, data: { content: "新会话回答" } },
          { type: "turn/end", seq: 4, time: createdAt + 3, data: { turn: 1, reason: { kind: "completed" } } },
        ],
      },
    );
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockImplementation(async (provider, sessionId) => ({ sessionId, provider, state: "idle" }));
    let resolveOldRequest!: (value: unknown) => void;
    testState.executor.sendExecutorMessage.mockImplementation(() => new Promise((resolve) => { resolveOldRequest = resolve; }));

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await screen.findByText("旧会话");
    await user.click(within(screen.getByTestId("session-row-s-old")).getByRole("button", { name: "旧会话" }));
    await waitFor(() => expect(screen.getByTestId("conversation-title").textContent).toContain("旧会话"));
    await user.type(screen.getByPlaceholderText(/向所选代理/), "旧会话请求");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    await waitFor(() => expect(testState.executor.sendExecutorMessage).toHaveBeenCalledWith("s-old", "旧会话请求"));

    await user.click(within(screen.getByTestId("session-row-s-new")).getByRole("button", { name: "新目标会话" }));
    expect(await screen.findByText("新会话回答")).toBeTruthy();
    expect(screen.queryByText(/正在处理/)).toBeNull();

    await act(async () => {
      resolveOldRequest({
        sessionId: "s-old",
        provider: "codex",
        state: "completed",
        nativeSessionId: "native-old",
        output: completedExecutorOutput("旧会话完成", "native-old"),
      });
    });

    await waitFor(() => {
      const oldRecord = sessionState.records.find((record) => record.header.id === "s-old");
      expect(oldRecord?.events.some((event) => event.type === "assistant/message"
        && event.data.content === "旧会话完成")).toBe(true);
    });
    expect(screen.getByTestId("conversation-title").textContent).toContain("新目标会话");
    expect(screen.getByText("新会话回答")).toBeTruthy();
    expect(screen.queryByText("旧会话完成")).toBeNull();
    expect(screen.queryByText("旧会话请求")).toBeNull();
  });

  it("binds executor readiness to both provider and persistent session", async () => {
    const { bridge, sessionState } = baseBridge();
    const createdAt = Date.now();
    sessionState.records.push({
      header: { version: 1, id: "s-shared", createdAt, provider: "codex", executor: "codex" },
      events: [{ type: "session/title", seq: 0, time: createdAt, data: { title: "共享会话" } }],
    });
    testState.desktopBridge = bridge;
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.resumeExecutorSession.mockResolvedValue(undefined);
    testState.executor.createExecutorSession.mockImplementation(async (selectedProvider, sessionId) => ({
      sessionId,
      provider: selectedProvider,
      state: "idle",
    }));
    let responseCount = 0;
    testState.executor.sendExecutorMessage.mockImplementation(async (sessionId) => {
      responseCount += 1;
      return {
        sessionId,
        provider: responseCount === 1 ? "codex" : "deepseek",
        state: "completed",
        nativeSessionId: `native-${responseCount}`,
        output: responseCount === 1
          ? completedExecutorOutput("回答 1", "native-1")
          : "回答 2",
      };
    });

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await screen.findByText("共享会话");
    await user.click(within(screen.getByTestId("session-row-s-shared")).getByRole("button", { name: "共享会话" }));
    const composer = screen.getByPlaceholderText(/向所选代理/);
    await user.type(composer, "Codex 请求");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    expect(await screen.findByText("回答 1")).toBeTruthy();
    expect(testState.executor.createExecutorSession).toHaveBeenCalledWith("codex", "s-shared");

    await user.selectOptions(screen.getByRole("combobox", { name: "执行器" }), "deepseek");
    await user.type(composer, "DeepSeek 请求");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    expect(await screen.findByText("回答 2")).toBeTruthy();

    expect(testState.executor.createExecutorSession).toHaveBeenCalledWith("deepseek", "s-shared");
  });

  it("renders user turns as right-aligned dark bubbles and agent turns as plain left content", async () => {
    const { bridge } = baseBridge();
    testState.executor.sendExecutorMessage.mockResolvedValue({
      sessionId: "s-1",
      provider: "codex",
      state: "completed",
      nativeSessionId: "native-1",
      output: completedExecutorOutput("我在。"),
    });
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockResolvedValue({ sessionId: "s-1", provider: "codex", state: "idle" });
    testState.desktopBridge = bridge;

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));
    const agentArticle = await findAgentMessage("我在。");

    const userArticle = screen.getByText("在不在").closest("article");
    expect(userArticle?.getAttribute("data-role")).toBe("user");
    expect(userArticle?.querySelector(".user-bubble")).not.toBeNull();

    expect(agentArticle?.getAttribute("data-role")).toBe("agent");
    expect(agentArticle?.querySelector(".user-bubble")).toBeNull();
    expect(agentArticle?.querySelector(".turn-duration")).not.toBeNull();
  });

  it("shows a live processing status with per-second elapsed time and then the real round duration", async () => {
    vi.useFakeTimers();
    try {
      const { bridge } = baseBridge();
      let resolveSend!: (value: unknown) => void;
      testState.executor.sendExecutorMessage.mockImplementation(
        () => new Promise((resolve) => { resolveSend = resolve; }),
      );
      testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
      testState.executor.createExecutorSession.mockResolvedValue({ sessionId: "s-1", provider: "codex", state: "idle" });
      testState.desktopBridge = bridge;

      // fireEvent keeps the send flow synchronous up to the executor await,
      // so the per-second ticker is driven entirely by fake timers.
      renderWorkbench(bridge);
      fireEvent.change(screen.getByPlaceholderText(/向所选代理/), { target: { value: "在不在" } });
      fireEvent.click(screen.getByRole("button", { name: "发送消息" }));

      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByText("在不在")).toBeTruthy();
      expect(screen.getByText(/正在处理/)).toBeTruthy();
      expect(screen.getByText("0s")).toBeTruthy();

      await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
      expect(screen.getByText("2s")).toBeTruthy();
      expect(screen.queryByText("1s")).toBeNull();

      await act(async () => {
        resolveSend({
          sessionId: "s-1",
          provider: "codex",
          state: "completed",
          nativeSessionId: "native-1",
          output: completedExecutorOutput("我在。"),
        });
        await vi.advanceTimersByTimeAsync(0);
      });

      const agentArticle = Array.from(document.querySelectorAll<HTMLElement>('article[data-role="agent"]'))
        .find((article) => article.textContent?.includes("我在。"));
      expect(agentArticle).toBeDefined();
      expect(screen.getByText("2s")).toBeTruthy();
      expect(screen.queryByText(/正在处理/)).toBeNull();
      expect(agentArticle?.querySelector(".turn-duration")?.textContent).toBe("2s");
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the user message and stores an error turn when the executor round fails", async () => {
    const { bridge, sessionState } = baseBridge();
    testState.executor.sendExecutorMessage.mockRejectedValue(new Error("执行器进程退出"));
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockResolvedValue({ sessionId: "s-1", provider: "codex", state: "idle" });
    testState.desktopBridge = bridge;

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("处理失败")).toBeTruthy();
    expect(screen.getByText("执行器进程退出")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();
    expect(screen.getByText("在不在").closest("article")?.getAttribute("data-role")).toBe("user");
    expect(screen.queryByText(/正在处理/)).toBeNull();

    const record = sessionState.records[0];
    const turnEnd = record.events.find((event) => event.type === "turn/end");
    expect((turnEnd?.data as { reason: { kind: string; error: { message: string } } }).reason).toMatchObject({
      kind: "error",
      error: { message: "执行器进程退出" },
    });
  });

  it("treats a non-completed executor result as a failure with the real error code", async () => {
    const { bridge } = baseBridge();
    testState.executor.sendExecutorMessage.mockResolvedValue({
      sessionId: "s-1",
      provider: "codex",
      state: "failed",
      lastError: "process-failed",
      output: "",
    });
    testState.executor.getExecutorStatus.mockRejectedValue(new Error("session not found"));
    testState.executor.createExecutorSession.mockResolvedValue({ sessionId: "s-1", provider: "codex", state: "idle" });
    testState.desktopBridge = bridge;

    const user = userEvent.setup();
    renderWorkbench(bridge);
    await user.type(screen.getByPlaceholderText(/向所选代理/), "在不在");
    await user.click(screen.getByRole("button", { name: "发送消息" }));

    expect(await screen.findByText("处理失败")).toBeTruthy();
    expect(screen.getByText("process-failed")).toBeTruthy();
    expect(screen.getByText("在不在")).toBeTruthy();
  });

  it("reconstructs the transcript from persisted history when a session is selected", async () => {
    const { bridge, sessionState } = baseBridge();
    const id = "hist-1";
    const createdAt = Date.now();
    sessionState.records.push({
      header: { version: 1, id, createdAt, provider: "codex", model: "gpt-5.3-codex" },
      events: [
        { type: "session/title", seq: 0, time: createdAt, data: { title: "历史会话" } },
        { type: "turn/start", seq: 1, time: createdAt, data: { turn: 1 } },
        { type: "user/message", seq: 2, time: createdAt, data: { content: "上次的问题" } },
        { type: "request/header", seq: 3, time: createdAt, data: { header: { provider: "codex", model: "gpt-5.3-codex" }, reason: "initial" } },
        { type: "assistant/message", seq: 4, time: createdAt, data: { content: "上次的回答", durationMs: 500 } },
        { type: "turn/end", seq: 5, time: createdAt, data: { turn: 1, reason: { kind: "completed" }, durationMs: 500 } },
      ],
    });
    testState.desktopBridge = bridge;

    renderWorkbench(bridge);
    await waitFor(() => expect(screen.getByText("历史会话")).toBeTruthy());

    // Selecting the session loads full history from the store.
    fireEvent.click(screen.getByText("历史会话"));
    expect(await screen.findByText("上次的问题")).toBeTruthy();
    expect(screen.getByText("上次的回答")).toBeTruthy();
    expect(screen.getByTestId("conversation-title").textContent).toContain("历史会话");
  });

  it("traps focus in the overlay, closes with Escape, and returns focus to its trigger", async () => {
    const user = userEvent.setup();
    renderWorkbench();

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

    // Reopen the tool area (the discovery rail remounts after closing) and
    // select a tool from the chooser; Escape closes and restores focus.
    const rediscovered = screen.getByRole("complementary", { name: "工具区" });
    const rediscoveredButton = within(rediscovered).getByRole("button", { name: "打开工具区" });
    await user.click(rediscoveredButton);
    const secondDialog = await screen.findByRole("dialog");
    const transactionStarter = within(secondDialog).getByRole("button", { name: /交易检查/ });
    await user.click(transactionStarter);
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByText("交易检查")).toBeTruthy());
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(
      within(screen.getByRole("complementary", { name: "工具区" })).getByRole("button", { name: "打开工具区" }),
    ));
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
    const discovery = screen.getByRole("complementary", { name: "工具区" });
    fireEvent.click(within(discovery).getByRole("button", { name: "打开工具区" }));
  }

  it("restores persisted pane widths from localStorage", () => {
    stubDesktopMatchMedia();
    localStorage.setItem("catomicals:workbench:leftWidth", "360");
    localStorage.setItem("catomicals:workbench:rightWidth", "520");

    renderWorkbench();

    expect(railVar("--left-rail")).toBe("360px");
    expect(railVar("--right-rail")).toBe("520px");
  });

  it("falls back to safe defaults when stored widths are invalid or out of range", () => {
    stubDesktopMatchMedia();
    for (const badLeft of ["abc", "9999", "-40", "NaN", ""]) {
      localStorage.setItem("catomicals:workbench:leftWidth", badLeft);
      const { unmount } = renderWorkbench();
      expect(railVar("--left-rail")).toBe("312px");
      unmount();
    }
    for (const badRight of ["319", "720.1", "not-a-number"]) {
      localStorage.setItem("catomicals:workbench:rightWidth", badRight);
      const { unmount } = renderWorkbench();
      expect(railVar("--right-rail")).toBe("384px");
      unmount();
    }
  });

  it("adjusts the left pane with keyboard arrows and persists the width", () => {
    stubDesktopMatchMedia();
    renderWorkbench();

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
    renderWorkbench();

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
    renderWorkbench();

    expect(screen.queryByRole("separator", { name: "调整工具区宽度" })).toBeNull();

    openTools();
    const right = screen.getByRole("separator", { name: "调整工具区宽度" });
    expect(right.getAttribute("aria-valuemin")).toBe("320");
    expect(right.getAttribute("aria-valuemax")).toBe("720");

    fireEvent.keyDown(right, { key: "ArrowLeft" });
    expect(railVar("--right-rail")).toBe("400px");
    fireEvent.keyDown(right, { key: "ArrowRight" });
    expect(railVar("--right-rail")).toBe("384px");
  });

  it("drags the left separator with the pointer and persists the result", () => {
    stubDesktopMatchMedia();
    renderWorkbench();

    const left = screen.getByRole("separator", { name: "调整左侧栏宽度" });
    fireEvent.pointerDown(left, { button: 0, clientX: 100, pointerId: 1 });
    fireEvent.pointerMove(left, { clientX: 140, pointerId: 1 });
    expect(railVar("--left-rail")).toBe("352px");
    fireEvent.pointerUp(left, { pointerId: 1 });

    expect(localStorage.getItem("catomicals:workbench:leftWidth")).toBe("352");
  });

  it("drags the right separator in the mirror direction", () => {
    stubDesktopMatchMedia();
    renderWorkbench();

    openTools();
    const right = screen.getByRole("separator", { name: "调整工具区宽度" });
    fireEvent.pointerDown(right, { button: 0, clientX: 200, pointerId: 1 });
    fireEvent.pointerMove(right, { clientX: 160, pointerId: 1 });
    expect(railVar("--right-rail")).toBe("424px");
    fireEvent.pointerUp(right, { pointerId: 1 });

    expect(localStorage.getItem("catomicals:workbench:rightWidth")).toBe("424");
  });

  it("keeps the resizers out of small-screen drawer modes", () => {
    stubOverlayMatchMedia((query) => query === "(max-width: 760px)" || query === "(max-width: 1180px)");
    renderWorkbench();
    expect(screen.queryByRole("separator")).toBeNull();
  });

  it("hides only the right separator while the right pane is in overlay mode", () => {
    // Default stub: only the 1180px query matches, so the right pane is a drawer.
    renderWorkbench();
    expect(screen.getByRole("separator", { name: "调整左侧栏宽度" })).toBeTruthy();

    openTools();
    expect(screen.queryByRole("separator", { name: "调整工具区宽度" })).toBeNull();
  });
});
