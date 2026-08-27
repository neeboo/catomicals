import { describe, expect, it, vi } from "vitest";
import type { HarnessId, HarnessSettings } from "../contracts";
import type {
  ProcessHost,
  ProcessResult,
  RunningProcess,
} from "./process-manager";
import { ExecutorRegistry } from "./registry";

const profiles: Record<HarnessId, HarnessSettings> = {
  codex: { command: "codex", defaultModel: "gpt-test", reasoningEffort: "high", workingDirectory: "/work" },
  deepseek: { command: "dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "/work" },
  "claude-code": { command: "claude", defaultModel: "sonnet", reasoningEffort: "high", workingDirectory: "/work" },
};

const readProfile = async (provider: HarnessId): Promise<HarnessSettings> => structuredClone(profiles[provider]);

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
    probe: vi.fn(async (command) => {
      if (probeResult.exitCode !== 0 || probeResult.error) return probeResult;
      if (!command.args.includes("--help")) return probeResult;
      return {
        exitCode: 0,
        signal: null,
        stdout: "--json --ignore-user-config --color --sandbox Usage: dsh --profile headless task --print --verbose --output-format --input-format --safe-mode --permission-mode --tools --resume",
        stderr: "",
      };
    }),
    start: vi.fn(() => running),
    dispose: vi.fn().mockResolvedValue(undefined),
  };
  return { host, running, completion };
}

describe("executor registry", () => {
  it("marks a provider unavailable when capability probing fails", async () => {
    const { host } = fakeProcessHost({ exitCode: null, signal: null, stdout: "", stderr: "", error: "ENOENT" });
    const registry = new ExecutorRegistry({ host, readProfile });

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
    const registry = new ExecutorRegistry({ host, readProfile });
    const created = await registry.create({ provider: "codex", sessionId: "local-1" });
    expect(created).toMatchObject({
        state: "idle", provider: "codex", sessionId: "local-1",
        model: "gpt-test", reasoningEffort: "high", workingDirectory: "/work", restartImpact: "none",
      });
    expect(created.protocolSessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    const send = registry.send({ sessionId: "local-1", prompt: "hello; $(whoami)" });
    await expect(registry.status("local-1")).resolves.toMatchObject({
      state: "running",
      sessionId: "local-1",
      protocolSessionId: created.protocolSessionId,
    });
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
    await expect(send).resolves.toMatchObject({
      state: "completed",
      nativeSessionId: "native-1",
      protocolSessionId: created.protocolSessionId,
    });
    await expect(registry.status("local-1")).resolves.toMatchObject({
      state: "completed",
      nativeSessionId: "native-1",
      protocolSessionId: created.protocolSessionId,
    });
  });

  it("creates a new host-owned protocol UUID when a compatible local session id is reused", async () => {
    const { host } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readProfile });
    const first = await registry.create({ provider: "codex", sessionId: "legacy-local-session" });
    await registry.dispose("legacy-local-session");
    const second = await registry.create({ provider: "codex", sessionId: "legacy-local-session" });

    expect(first.sessionId).toBe("legacy-local-session");
    expect(second.sessionId).toBe("legacy-local-session");
    expect(second.protocolSessionId).not.toBe(first.protocolSessionId);
  });

  it("interrupts only a running process and preserves the interrupted state", async () => {
    const { host, running, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readProfile });
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
    const registry = new ExecutorRegistry({ host, readProfile });

    await expect(registry.resume({ provider: "deepseek", sessionId: "local-3", nativeSessionId: "maybe" }))
      .rejects.toThrow("does not support resume");
  });

  it("disposes all processes during host shutdown", async () => {
    const { host } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readProfile });
    await registry.create({ provider: "codex", sessionId: "local-4" });

    await registry.disposeAll();

    expect(host.dispose).toHaveBeenCalledOnce();
    await expect(registry.status("local-4")).rejects.toThrow("not found");
  });

  it("keeps a disposed session terminal when its process exits later", async () => {
    const { host, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readProfile });
    await registry.create({ provider: "codex", sessionId: "local-5" });
    const send = registry.send({ sessionId: "local-5", prompt: "wait" });

    await expect(registry.dispose("local-5")).resolves.toMatchObject({ state: "disposed" });
    completion.resolve({ exitCode: null, signal: "SIGTERM", stdout: "", stderr: "" });

    await expect(send).resolves.toMatchObject({ state: "disposed" });
    await expect(registry.status("local-5")).rejects.toThrow("not found");
    await expect(registry.create({ provider: "codex", sessionId: "local-5" }))
      .resolves.toMatchObject({ state: "idle" });
  });

  it("marks an installed command unavailable when its protocol surface is incompatible", async () => {
    const { host } = fakeProcessHost();
    vi.mocked(host.probe)
      .mockResolvedValueOnce({ exitCode: 0, signal: null, stdout: "claude 1", stderr: "" })
      .mockResolvedValueOnce({ exitCode: 0, signal: null, stdout: "old help", stderr: "" });
    const registry = new ExecutorRegistry({ host, readProfile });

    await expect(registry.probe("claude-code")).resolves.toMatchObject({
      availability: "unavailable",
      reason: "capability-mismatch",
    });
  });

  it("runs the exact profile that passed probing even if settings change concurrently", async () => {
    const { host, completion } = fakeProcessHost();
    const changed = structuredClone(profiles.codex);
    changed.command = "unprobed-command";
    let reads = 0;
    const registry = new ExecutorRegistry({
      host,
      readProfile: async () => reads++ === 0 ? profiles.codex : changed,
    });
    await registry.create({ provider: "codex", sessionId: "local-6" });

    const send = registry.send({ sessionId: "local-6", prompt: "hello" });
    expect(host.start).toHaveBeenCalledWith(expect.objectContaining({ executable: "codex" }));
    completion.resolve({ exitCode: 0, signal: null, stdout: "", stderr: "" });
    await send;
  });

  it("reports an external termination as a provider failure", async () => {
    const { host, completion } = fakeProcessHost();
    const registry = new ExecutorRegistry({ host, readProfile });
    await registry.create({ provider: "codex", sessionId: "local-7" });
    const send = registry.send({ sessionId: "local-7", prompt: "hello" });

    completion.resolve({ exitCode: null, signal: "SIGTERM", stdout: "", stderr: "" });

    await expect(send).resolves.toMatchObject({ state: "failed", lastError: "process-failed" });
  });

  it("omits model and reasoning metadata that DeepSeek does not apply", async () => {
    const { host } = fakeProcessHost({ exitCode: 0, signal: null, stdout: "dsh 0.1.1", stderr: "" });
    const registry = new ExecutorRegistry({ host, readProfile });

    const session = await registry.create({ provider: "deepseek", sessionId: "deepseek-actual" });

    expect(session).not.toHaveProperty("model");
    expect(session).not.toHaveProperty("reasoningEffort");
    expect(session.workingDirectory).toBe("/work");
  });

  it("marks existing sessions with plugin restart impact while new sessions read the new profile", async () => {
    const { host } = fakeProcessHost();
    let current = structuredClone(profiles.codex);
    const registry = new ExecutorRegistry({ host, readProfile: async () => structuredClone(current) });
    await registry.create({ provider: "codex", sessionId: "old-session" });

    current = { ...current, command: "codex-next", defaultModel: "gpt-next" };
    registry.noteConfigurationChange("codex", "plugin");

    await expect(registry.status("old-session")).resolves.toMatchObject({
      model: "gpt-test",
      restartImpact: "plugin",
    });
    await registry.create({ provider: "codex", sessionId: "new-session" });
    await expect(registry.status("new-session")).resolves.toMatchObject({
      model: "gpt-next",
      restartImpact: "none",
    });
  });
});
