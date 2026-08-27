import { describe, expect, it, vi } from "vitest";
import type { DesktopSettings } from "../contracts";
import type {
  ProcessHost,
  ProcessResult,
  RunningProcess,
} from "./process-manager";
import { ExecutorRegistry } from "./registry";

const settings: DesktopSettings = {
  version: 1,
  defaultHarness: "codex",
  adapters: {
    codex: { command: "codex", defaultModel: "gpt-test", reasoningEffort: "high", workingDirectory: "/work" },
    deepseek: { command: "dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "/work" },
    "claude-code": { command: "claude", defaultModel: "sonnet", reasoningEffort: "high", workingDirectory: "/work" },
  },
  mcpEnabled: true,
  walletNodeUrl: "http://127.0.0.1:18787",
  browserHome: "https://mempool.space/signet",
};

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolver) => { resolve = resolver; });
  return { promise, resolve };
}

function fakeProcessHost(probeResult: ProcessResult = { exitCode: 0, signal: null, stdout: "codex 1.2.3", stderr: "" }) {
  const completion = deferred<ProcessResult>();
  const running: RunningProcess = {
    completion: completion.promise,
    interrupt: vi.fn(() => true),
  };
  const host: ProcessHost = {
    probe: vi.fn().mockResolvedValue(probeResult),
    start: vi.fn(() => running),
    dispose: vi.fn().mockResolvedValue(undefined),
  };
  return { host, running, completion };
}

describe("executor registry", () => {
  it("marks a provider unavailable when capability probing fails", async () => {
    const { host } = fakeProcessHost({ exitCode: null, signal: null, stdout: "", stderr: "", error: "ENOENT" });
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });

    await expect(registry.probe("codex")).resolves.toMatchObject({
      provider: "codex",
      availability: "unavailable",
      capabilities: { walletApproval: false, signing: false, broadcast: false },
    });
    await expect(registry.create({ provider: "codex", sessionId: "local-1" }))
      .rejects.toThrow("unavailable");
  });

  it("creates, runs, and completes a provider session using the main-owned profile", async () => {
    const { host, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });
    await expect(registry.create({ provider: "codex", sessionId: "local-1" }))
      .resolves.toMatchObject({ state: "idle", provider: "codex", sessionId: "local-1" });

    const send = registry.send({ sessionId: "local-1", prompt: "hello; $(whoami)" });
    await expect(registry.status("local-1")).resolves.toMatchObject({ state: "running" });
    expect(host.start).toHaveBeenCalledWith(expect.objectContaining({
      executable: "codex",
      args: expect.arrayContaining(["hello; $(whoami)"]),
      cwd: "/work",
    }));

    completion.resolve({
      exitCode: 0,
      signal: null,
      stdout: '{"type":"thread.started","thread_id":"native-1"}\n{"type":"result","text":"done"}',
      stderr: "",
    });
    await expect(send).resolves.toMatchObject({ state: "completed", nativeSessionId: "native-1" });
    await expect(registry.status("local-1")).resolves.toMatchObject({ state: "completed", nativeSessionId: "native-1" });
  });

  it("interrupts only a running process and preserves the interrupted state", async () => {
    const { host, running, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });
    await registry.create({ provider: "claude-code", sessionId: "local-2" });
    const send = registry.send({ sessionId: "local-2", prompt: "wait" });

    await expect(registry.interrupt("local-2")).resolves.toMatchObject({ state: "running" });
    expect(running.interrupt).toHaveBeenCalledOnce();
    completion.resolve({ exitCode: null, signal: "SIGTERM", stdout: "", stderr: "" });

    await expect(send).resolves.toMatchObject({ state: "interrupted" });
    await expect(registry.interrupt("local-2")).rejects.toThrow("not running");
  });

  it("rejects unsupported resume instead of inventing a DeepSeek session", async () => {
    const { host } = fakeProcessHost({ exitCode: 0, signal: null, stdout: "dsh 0.1.1", stderr: "" });
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });

    await expect(registry.resume({ provider: "deepseek", sessionId: "local-3", nativeSessionId: "maybe" }))
      .rejects.toThrow("does not support resume");
  });

  it("disposes all processes during host shutdown", async () => {
    const { host } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });
    await registry.create({ provider: "codex", sessionId: "local-4" });

    await registry.disposeAll();

    expect(host.dispose).toHaveBeenCalledOnce();
    await expect(registry.status("local-4")).resolves.toMatchObject({ state: "disposed" });
  });

  it("keeps a disposed session terminal when its process exits later", async () => {
    const { host, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readSettings: async () => settings });
    await registry.create({ provider: "codex", sessionId: "local-5" });
    const send = registry.send({ sessionId: "local-5", prompt: "wait" });

    await expect(registry.dispose("local-5")).resolves.toMatchObject({ state: "disposed" });
    completion.resolve({ exitCode: null, signal: "SIGTERM", stdout: "", stderr: "" });

    await expect(send).resolves.toMatchObject({ state: "disposed" });
    await expect(registry.status("local-5")).resolves.toMatchObject({ state: "disposed" });
  });
});
