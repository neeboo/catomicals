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
  readonly mcp: boolean;
  readonly walletApproval: false;
  readonly signing: false;
  readonly broadcast: false;
}

export interface ExecutorCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly environmentKeys: readonly string[];
}

export interface BuildSendCommandInput {
  readonly profile: HarnessSettings;
  readonly nativeSessionId?: string;
  readonly prompt: string;
  readonly mcp?: ExecutorMcpConfiguration;
  readonly deepseekPatchPath?: string;
}

export interface ExecutorMcpConfiguration {
  readonly command: string;
  readonly walletUrl: string;
  readonly deepseekPatchPath?: string;
}

export interface ExecutorAdapter {
  readonly id: ExecutorProviderId;
  readonly capabilities: ExecutorCapabilities;
  buildProbeCommand(profile: HarnessSettings): ExecutorCommand;
  buildCapabilityProbeCommand(profile: HarnessSettings): ExecutorCommand;
  buildMcpCapabilityProbeCommand(profile: HarnessSettings): ExecutorCommand;
  /**
   * Builds an offline smoke probe for the provider's native MCP configuration path.
   * It must parse the same injected configuration as a real session without starting
   * an MCP child or requiring a model request; the server command is probed separately.
   */
  buildMcpAssemblyProbeCommand(profile: HarnessSettings, mcp: ExecutorMcpConfiguration): ExecutorCommand;
  acceptsCapabilityProbe(stdout: string): boolean;
  acceptsMcpCapabilityProbe(stdout: string): boolean;
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

export const CORDIS_MCP_TOOL_NAMES = Object.freeze([
  "list_plugins",
  "read_plugin_manifest",
  "read_plugin_settings_schema",
  "read_plugin_health",
  "validate_plugin_settings_patch",
  "create_plugin_settings_intent",
] as const);

export const CORDIS_MCP_PUBLIC_TOOL_NAMES = Object.freeze(
  CORDIS_MCP_TOOL_NAMES.map((name) => `mcp__catomicals__${name}`),
);

export const WALLET_MCP_TOOL_NAMES = Object.freeze([
  "add_chat_message",
  "cancel_signing_intent",
  "check_protected_trade",
  "create_transaction_intent",
  "get_chat_state",
  "get_wallet_status",
  "inspect_transaction",
  "list_signing_intents",
  "read_signing_intent",
] as const);

export const WALLET_MCP_PUBLIC_TOOL_NAMES = Object.freeze(
  WALLET_MCP_TOOL_NAMES.map((name) => `mcp__catomicals_wallet__${name}`),
);

export type ExecutorMcpToolName =
  | (typeof CORDIS_MCP_TOOL_NAMES)[number]
  | (typeof WALLET_MCP_TOOL_NAMES)[number];

const BASE_ENVIRONMENT_KEYS = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
] as const;

export function executorEnvironmentKeys(providerKeys: readonly string[]): readonly string[] {
  return Object.freeze([...new Set([...BASE_ENVIRONMENT_KEYS, ...providerKeys])]);
}

export function containsProbeTokens(stdout: string, tokens: readonly string[]): boolean {
  return tokens.every((token) => stdout.includes(token));
}
