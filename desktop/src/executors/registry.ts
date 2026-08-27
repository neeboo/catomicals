import type { DesktopSettings, HarnessSettings } from "../contracts.js";
import { claudeCodeAdapter } from "./claude-code.js";
import { codexAdapter } from "./codex.js";
import { deepseekAdapter } from "./deepseek.js";
import type { ProcessHost, RunningProcess } from "./process-manager.js";
import type { ExecutorAdapter, ExecutorCapabilities, ExecutorProviderId } from "./types.js";

const adapters: Readonly<Record<ExecutorProviderId, ExecutorAdapter>> = Object.freeze({
  codex: codexAdapter,
  deepseek: deepseekAdapter,
  "claude-code": claudeCodeAdapter,
});

export type ExecutorSessionState = "idle" | "running" | "completed" | "interrupted" | "failed" | "disposed";

export interface ExecutorProbe {
  readonly provider: ExecutorProviderId;
  readonly availability: "available" | "unavailable";
  readonly version?: string;
  readonly reason?: "not-configured" | "not-found" | "probe-timeout" | "probe-failed" | "capability-mismatch";
  readonly capabilities: ExecutorCapabilities;
}

export interface ExecutorSessionView {
  readonly sessionId: string;
  readonly provider: ExecutorProviderId;
  readonly nativeSessionId?: string;
  readonly state: ExecutorSessionState;
  readonly capabilities: ExecutorCapabilities;
  readonly lastError?: "interrupted" | "process-failed" | "spawn-failed" | "output-limit";
}

export interface ExecutorSendResult extends ExecutorSessionView {
  readonly output: string;
}

interface SessionRecord {
  sessionId: string;
  provider: ExecutorProviderId;
  nativeSessionId?: string;
  state: ExecutorSessionState;
  profile: HarnessSettings;
  running?: RunningProcess;
  interruptRequested: boolean;
  disposed: boolean;
  lastError?: ExecutorSessionView["lastError"];
}

interface RegistryOptions {
  readonly host: ProcessHost;
  readonly readSettings: () => Promise<DesktopSettings>;
}

function assertSessionId(sessionId: string): void {
  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(sessionId)) throw new Error("invalid executor session id");
}

function assertNativeSessionId(nativeSessionId: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}$/.test(nativeSessionId)) {
    throw new Error("invalid native session id");
  }
}

function assertProfile(profile: HarnessSettings): void {
  if (profile.command.trim() === "" || /[\0\r\n]/.test(profile.command)) {
    throw new Error("executor command is not configured");
  }
  if (profile.workingDirectory.includes("\0")) throw new Error("invalid executor working directory");
}

function probeFailureReason(error?: string): ExecutorProbe["reason"] {
  if (error === "ENOENT") return "not-found";
  if (error === "probe-timeout") return "probe-timeout";
  return "probe-failed";
}

function outputVersion(stdout: string): string | undefined {
  const firstLine = stdout.split(/\r?\n/, 1)[0]?.trim();
  return firstLine && firstLine.length <= 256 ? firstLine : undefined;
}

function view(record: SessionRecord): ExecutorSessionView {
  return {
    sessionId: record.sessionId,
    provider: record.provider,
    ...(record.nativeSessionId ? { nativeSessionId: record.nativeSessionId } : {}),
    state: record.state,
    capabilities: adapters[record.provider].capabilities,
    ...(record.lastError ? { lastError: record.lastError } : {}),
  };
}

export class ExecutorRegistry {
  private readonly sessions = new Map<string, SessionRecord>();

  constructor(private readonly options: RegistryOptions) {}

  async probe(provider: ExecutorProviderId): Promise<ExecutorProbe> {
    const profile = (await this.options.readSettings()).adapters[provider];
    return this.probeProfile(provider, profile);
  }

  private async probeProfile(provider: ExecutorProviderId, profile: HarnessSettings): Promise<ExecutorProbe> {
    const adapter = adapters[provider];
    try {
      assertProfile(profile);
    } catch {
      return { provider, availability: "unavailable", reason: "not-configured", capabilities: adapter.capabilities };
    }
    const result = await this.options.host.probe(adapter.buildProbeCommand(profile));
    if (result.exitCode !== 0 || result.error) {
      return {
        provider,
        availability: "unavailable",
        reason: probeFailureReason(result.error),
        capabilities: adapter.capabilities,
      };
    }
    const capabilityResult = await this.options.host.probe(adapter.buildCapabilityProbeCommand(profile));
    if (capabilityResult.exitCode !== 0 || capabilityResult.error) {
      return {
        provider,
        availability: "unavailable",
        reason: probeFailureReason(capabilityResult.error),
        capabilities: adapter.capabilities,
      };
    }
    if (!adapter.acceptsCapabilityProbe(capabilityResult.stdout)) {
      return { provider, availability: "unavailable", reason: "capability-mismatch", capabilities: adapter.capabilities };
    }
    const version = outputVersion(result.stdout);
    return {
      provider,
      availability: "available",
      ...(version ? { version } : {}),
      capabilities: adapter.capabilities,
    };
  }

  async create(input: { provider: ExecutorProviderId; sessionId: string }): Promise<ExecutorSessionView> {
    assertSessionId(input.sessionId);
    if (this.sessions.has(input.sessionId)) throw new Error("executor session already exists");
    const profile = (await this.options.readSettings()).adapters[input.provider];
    const availability = await this.probeProfile(input.provider, profile);
    if (availability.availability !== "available") throw new Error(`executor provider unavailable: ${availability.reason}`);
    const record: SessionRecord = {
      sessionId: input.sessionId,
      provider: input.provider,
      state: "idle",
      profile: structuredClone(profile),
      interruptRequested: false,
      disposed: false,
    };
    this.sessions.set(input.sessionId, record);
    return view(record);
  }

  async resume(input: {
    provider: ExecutorProviderId;
    sessionId: string;
    nativeSessionId: string;
  }): Promise<ExecutorSessionView> {
    assertNativeSessionId(input.nativeSessionId);
    const adapter = adapters[input.provider];
    if (!adapter.capabilities.resume) throw new Error(`executor provider ${input.provider} does not support resume`);
    const created = await this.create({ provider: input.provider, sessionId: input.sessionId });
    const record = this.requiredSession(created.sessionId);
    record.nativeSessionId = input.nativeSessionId;
    return view(record);
  }

  async send(input: { sessionId: string; prompt: string }): Promise<ExecutorSendResult> {
    const record = this.requiredSession(input.sessionId);
    if (record.state === "disposed") throw new Error("executor session disposed");
    if (record.state === "running") throw new Error("executor session already running");
    if (typeof input.prompt !== "string" || input.prompt.trim() === "" || input.prompt.length > 20_000 || input.prompt.includes("\0")) {
      throw new Error("invalid executor prompt");
    }
    const adapter = adapters[record.provider];
    if (record.nativeSessionId && !adapter.capabilities.resume) {
      throw new Error(`executor provider ${record.provider} does not support resume`);
    }
    record.interruptRequested = false;
    record.lastError = undefined;
    record.state = "running";
    const running = this.options.host.start(adapter.buildSendCommand({
      profile: record.profile,
      ...(record.nativeSessionId ? { nativeSessionId: record.nativeSessionId } : {}),
      prompt: input.prompt,
    }));
    record.running = running;
    const result = await running.completion;
    record.running = undefined;

    if (record.disposed) {
      return { ...view(record), output: result.stdout };
    }
    if (record.interruptRequested) {
      record.state = "interrupted";
      record.lastError = "interrupted";
    } else if (result.exitCode !== 0 || result.signal !== null || result.error) {
      record.state = "failed";
      record.lastError = result.error === "output-limit"
        ? "output-limit"
        : result.error ? "spawn-failed" : "process-failed";
    } else {
      record.state = "completed";
      record.nativeSessionId ??= adapter.extractNativeSessionId(result.stdout);
    }
    return { ...view(record), output: result.stdout };
  }

  async interrupt(sessionId: string): Promise<ExecutorSessionView> {
    const record = this.requiredSession(sessionId);
    if (record.state !== "running" || !record.running) throw new Error("executor session is not running");
    record.interruptRequested = true;
    record.running.interrupt();
    return view(record);
  }

  async status(sessionId: string): Promise<ExecutorSessionView> {
    return view(this.requiredSession(sessionId));
  }

  async dispose(sessionId: string): Promise<ExecutorSessionView> {
    const record = this.requiredSession(sessionId);
    if (record.running) {
      record.interruptRequested = true;
      record.running.interrupt();
    }
    record.state = "disposed";
    record.disposed = true;
    record.running = undefined;
    const disposed = view(record);
    this.sessions.delete(sessionId);
    return disposed;
  }

  async disposeAll(): Promise<void> {
    for (const record of this.sessions.values()) {
      record.state = "disposed";
      record.disposed = true;
      record.running = undefined;
    }
    this.sessions.clear();
    await this.options.host.dispose();
  }

  private requiredSession(sessionId: string): SessionRecord {
    assertSessionId(sessionId);
    const record = this.sessions.get(sessionId);
    if (!record) throw new Error("executor session not found");
    return record;
  }
}
