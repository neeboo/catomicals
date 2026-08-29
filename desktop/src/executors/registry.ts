import { randomUUID } from "node:crypto";
import type { CordisRestartImpact, HarnessSettings } from "../contracts.js";
import type { CordisAgentBridge, CordisAgentSessionIdentity } from "../cordis/agent-bridge.js";
import { claudeCodeAdapter } from "./claude-code.js";
import { codexAdapter } from "./codex.js";
import { deepseekAdapter } from "./deepseek.js";
import type { ProcessHost, RunningProcess } from "./process-manager.js";
import type { ExecutorAdapter, ExecutorCapabilities, ExecutorProviderId } from "./types.js";
import {
  buildCordisMcpCapabilityProbe,
  prepareExecutorMcpProbe,
  prepareExecutorMcpSession,
  prepareDeepseekSessionIsolation,
  type DeepseekSessionIsolation,
  type ExecutorMcpSessionAssembly,
} from "./mcp.js";

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
  readonly protocolSessionId: string;
  readonly provider: ExecutorProviderId;
  readonly nativeSessionId?: string;
  readonly state: ExecutorSessionState;
  readonly capabilities: ExecutorCapabilities;
  readonly model?: string;
  readonly reasoningEffort?: HarnessSettings["reasoningEffort"];
  readonly workingDirectory: string;
  readonly restartImpact: CordisRestartImpact;
  readonly lastError?: "interrupted" | "process-failed" | "spawn-failed" | "output-limit";
}

export interface ExecutorSendResult extends ExecutorSessionView {
  readonly output: string;
}

interface SessionRecord {
  sessionId: string;
  protocolSessionId: string;
  provider: ExecutorProviderId;
  nativeSessionId?: string;
  state: ExecutorSessionState;
  profile: HarnessSettings;
  running?: RunningProcess;
  interruptRequested: boolean;
  disposed: boolean;
  restartImpact: CordisRestartImpact;
  capabilities: ExecutorCapabilities;
  cordisIdentity?: CordisAgentSessionIdentity;
  mcpAssembly?: ExecutorMcpSessionAssembly;
  deepseekIsolation?: DeepseekSessionIsolation;
  lastError?: ExecutorSessionView["lastError"];
}

interface RegistryOptions {
  readonly host: ProcessHost;
  readonly readProfile: (provider: ExecutorProviderId) => Promise<HarnessSettings>;
  readonly cordisAgentBridge: CordisAgentBridge | (() => CordisAgentBridge);
  readonly cordisMcpCommand: string;
  readonly mcpEnabled: () => Promise<boolean>;
  readonly walletEndpoint: () => Promise<string>;
  readonly preparePrompt?: (provider: ExecutorProviderId, prompt: string) => Promise<string>;
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
  const capabilities = record.capabilities;
  return {
    sessionId: record.sessionId,
    protocolSessionId: record.protocolSessionId,
    provider: record.provider,
    ...(record.nativeSessionId ? { nativeSessionId: record.nativeSessionId } : {}),
    state: record.state,
    capabilities,
    ...(capabilities.modelSelection && record.profile.defaultModel ? { model: record.profile.defaultModel } : {}),
    ...(capabilities.reasoningEffort ? { reasoningEffort: record.profile.reasoningEffort } : {}),
    workingDirectory: record.profile.workingDirectory,
    restartImpact: record.restartImpact,
    ...(record.lastError ? { lastError: record.lastError } : {}),
  };
}

export class ExecutorRegistry {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly pendingSessionIds = new Set<string>();

  constructor(private readonly options: RegistryOptions) {}

  async probe(provider: ExecutorProviderId): Promise<ExecutorProbe> {
    return this.probeConfigured(provider, await this.options.readProfile(provider));
  }

  async probeConfigured(provider: ExecutorProviderId, profile: HarnessSettings): Promise<ExecutorProbe> {
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
    let mcp = false;
    const enabled = await this.options.mcpEnabled().catch(() => false);
    const mcpCapabilityResult = enabled
      ? await this.options.host.probe(adapter.buildMcpCapabilityProbeCommand(profile))
      : undefined;
    if (mcpCapabilityResult?.exitCode === 0 && !mcpCapabilityResult.error
      && adapter.acceptsMcpCapabilityProbe(mcpCapabilityResult.stdout)) {
      let probeAssembly: Awaited<ReturnType<typeof prepareExecutorMcpProbe>> | undefined;
      try {
        probeAssembly = await prepareExecutorMcpProbe(
          provider,
          this.options.cordisMcpCommand,
          await this.options.walletEndpoint(),
        );
        const assemblyResult = await this.options.host.probe(
          adapter.buildMcpAssemblyProbeCommand(profile, probeAssembly.configuration),
        );
        if (assemblyResult.exitCode === 0 && assemblyResult.signal === null && !assemblyResult.error) {
          const mcpResult = await this.options.host.probe(buildCordisMcpCapabilityProbe(this.options.cordisMcpCommand));
          mcp = mcpResult.exitCode === 0 && mcpResult.signal === null && !mcpResult.error;
        }
      } catch {
        mcp = false;
      } finally {
        await probeAssembly?.dispose().catch(() => undefined);
      }
    }
    const capabilities = Object.freeze({ ...adapter.capabilities, mcp });
    const version = outputVersion(result.stdout);
    return {
      provider,
      availability: "available",
      ...(version ? { version } : {}),
      capabilities,
    };
  }

  async create(input: { provider: ExecutorProviderId; sessionId: string }): Promise<ExecutorSessionView> {
    assertSessionId(input.sessionId);
    if (this.sessions.has(input.sessionId) || this.pendingSessionIds.has(input.sessionId)) {
      throw new Error("executor session already exists");
    }
    this.pendingSessionIds.add(input.sessionId);
    try {
      const profile = await this.options.readProfile(input.provider);
      const availability = await this.probeConfigured(input.provider, profile);
      if (availability.availability !== "available") throw new Error(`executor provider unavailable: ${availability.reason}`);
      const protocolSessionId = randomUUID();
      let cordisIdentity: CordisAgentSessionIdentity | undefined;
      let bridge: CordisAgentBridge | undefined;
      let mcpAssembly: ExecutorMcpSessionAssembly | undefined;
      let deepseekIsolation: DeepseekSessionIsolation | undefined;
      try {
        if (availability.capabilities.mcp) {
          cordisIdentity = { executorSessionId: input.sessionId, protocolSessionId };
          bridge = this.cordisAgentBridge();
          const credential = bridge.issueSessionToken(cordisIdentity);
          mcpAssembly = await prepareExecutorMcpSession(
            input.provider,
            credential,
            this.options.cordisMcpCommand,
            await this.options.walletEndpoint(),
          );
        } else if (input.provider === "deepseek") {
          deepseekIsolation = await prepareDeepseekSessionIsolation();
        }
        const record: SessionRecord = {
          sessionId: input.sessionId,
          protocolSessionId,
          provider: input.provider,
          state: "idle",
          profile: structuredClone(profile),
          interruptRequested: false,
          disposed: false,
          restartImpact: "none",
          capabilities: availability.capabilities,
          ...(cordisIdentity ? { cordisIdentity } : {}),
          ...(mcpAssembly ? { mcpAssembly } : {}),
          ...(deepseekIsolation ? { deepseekIsolation } : {}),
        };
        this.sessions.set(input.sessionId, record);
        return view(record);
      } catch (error) {
        await mcpAssembly?.dispose().catch(() => undefined);
        await deepseekIsolation?.dispose().catch(() => undefined);
        if (bridge && cordisIdentity) bridge.revokeSession(cordisIdentity);
        throw error;
      }
    } finally {
      this.pendingSessionIds.delete(input.sessionId);
    }
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
    const preparedPrompt = this.options.preparePrompt
      ? await this.options.preparePrompt(record.provider, input.prompt)
      : input.prompt;
    if (preparedPrompt.trim() === "" || preparedPrompt.includes("\0") || preparedPrompt.length > 32_000) {
      throw new Error("invalid prepared executor prompt");
    }
    record.state = "running";
    const running = this.options.host.start(adapter.buildSendCommand({
      profile: record.profile,
      ...(record.nativeSessionId ? { nativeSessionId: record.nativeSessionId } : {}),
      ...(record.mcpAssembly ? { mcp: record.mcpAssembly.configuration } : {}),
      ...(record.deepseekIsolation ? { deepseekPatchPath: record.deepseekIsolation.patchPath } : {}),
      prompt: preparedPrompt,
    }), record.mcpAssembly?.environment);
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
    await this.disposeSessionResources(record);
    return disposed;
  }

  async disposeAll(): Promise<void> {
    const records = [...this.sessions.values()];
    for (const record of records) {
      record.state = "disposed";
      record.disposed = true;
      record.running = undefined;
    }
    this.sessions.clear();
    const failures: unknown[] = [];
    const cleanupResults = await Promise.allSettled(records.map((record) => this.disposeSessionResources(record)));
    for (const result of cleanupResults) {
      if (result.status === "rejected") failures.push(result.reason);
    }
    try {
      await this.options.host.dispose();
    } catch (error) {
      failures.push(error);
    }
    if (failures.length > 0) throw new AggregateError(failures, "executor cleanup failed");
  }

  noteConfigurationChange(provider: ExecutorProviderId, restartImpact: CordisRestartImpact): void {
    if (restartImpact === "none") return;
    for (const record of this.sessions.values()) {
      if (record.provider === provider) record.restartImpact = restartImpact;
    }
  }

  private requiredSession(sessionId: string): SessionRecord {
    assertSessionId(sessionId);
    const record = this.sessions.get(sessionId);
    if (!record) throw new Error("executor session not found");
    return record;
  }

  private cordisAgentBridge(): CordisAgentBridge {
    return typeof this.options.cordisAgentBridge === "function"
      ? this.options.cordisAgentBridge()
      : this.options.cordisAgentBridge;
  }

  private async disposeSessionResources(record: SessionRecord): Promise<void> {
    if (record.cordisIdentity) this.cordisAgentBridge().revokeSession(record.cordisIdentity);
    await record.mcpAssembly?.dispose();
    await record.deepseekIsolation?.dispose();
    record.mcpAssembly = undefined;
    record.deepseekIsolation = undefined;
  }
}
