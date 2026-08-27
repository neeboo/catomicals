import type { HarnessId, HarnessSettings } from "../contracts.js";

export type ExecutorProviderId = HarnessId;

export interface ExecutorCapabilities {
  readonly create: true;
  readonly send: true;
  readonly interrupt: true;
  readonly status: true;
  readonly dispose: true;
  readonly resume: boolean;
  readonly modelSelection: boolean;
  readonly reasoningEffort: boolean;
  readonly mcp: false;
  readonly walletApproval: false;
  readonly signing: false;
  readonly broadcast: false;
}

export interface ExecutorCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
}

export interface BuildSendCommandInput {
  readonly profile: HarnessSettings;
  readonly nativeSessionId?: string;
  readonly prompt: string;
}

export interface ExecutorAdapter {
  readonly id: ExecutorProviderId;
  readonly capabilities: ExecutorCapabilities;
  buildProbeCommand(profile: HarnessSettings): ExecutorCommand;
  buildSendCommand(input: BuildSendCommandInput): ExecutorCommand;
  extractNativeSessionId(stdout: string): string | undefined;
}

export function commandWorkingDirectory(profile: HarnessSettings): string | undefined {
  return profile.workingDirectory || undefined;
}

export function jsonLineSessionId(
  stdout: string,
  select: (record: Record<string, unknown>) => unknown,
): string | undefined {
  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    try {
      const parsed = JSON.parse(line) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
      const value = select(parsed as Record<string, unknown>);
      if (typeof value === "string" && value.length > 0 && value.length <= 256) return value;
    } catch {
      // Provider output may include non-JSON diagnostics. Only explicit JSON ids count.
    }
  }
  return undefined;
}

export const CHAT_ONLY_CAPABILITIES = Object.freeze({
  create: true,
  send: true,
  interrupt: true,
  status: true,
  dispose: true,
  mcp: false,
  walletApproval: false,
  signing: false,
  broadcast: false,
} as const);
