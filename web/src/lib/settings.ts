import {
  DEFAULT_HARNESS_ID,
  HARNESS_IDS,
  isHarnessId,
  type HarnessId,
} from "./harness";

export const REASONING_EFFORTS = ["low", "medium", "high", "xhigh"] as const;
export type ReasoningEffort = (typeof REASONING_EFFORTS)[number];

export interface HarnessSettings {
  command: string;
  defaultModel: string;
  reasoningEffort: ReasoningEffort;
  workingDirectory: string;
}

export interface DesktopSettings {
  version: 1;
  defaultHarness: HarnessId;
  adapters: Record<HarnessId, HarnessSettings>;
  mcpEnabled: boolean;
  walletNodeUrl: string;
  browserHome: string;
}

const DEFAULT_ADAPTERS: Record<HarnessId, HarnessSettings> = {
  codex: { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  deepseek: { command: "deepseek-harness", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  "claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
};

export const DEFAULT_DESKTOP_SETTINGS: DesktopSettings = {
  version: 1,
  defaultHarness: DEFAULT_HARNESS_ID,
  adapters: DEFAULT_ADAPTERS,
  mcpEnabled: true,
  walletNodeUrl: "http://127.0.0.1:18787",
  browserHome: "https://mempool.space/signet",
};

function text(value: unknown, fallback: string, maxLength = 512): string {
  return typeof value === "string" && value.length <= maxLength ? value : fallback;
}

function effort(value: unknown, fallback: ReasoningEffort): ReasoningEffort {
  return typeof value === "string" && REASONING_EFFORTS.includes(value as ReasoningEffort)
    ? value as ReasoningEffort
    : fallback;
}

function adapterSettings(value: unknown, fallback: HarnessSettings): HarnessSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  const record = value as Record<string, unknown>;
  return {
    command: text(record.command, fallback.command, 256),
    defaultModel: text(record.defaultModel, fallback.defaultModel, 256),
    reasoningEffort: effort(record.reasoningEffort, fallback.reasoningEffort),
    workingDirectory: text(record.workingDirectory, fallback.workingDirectory, 1024),
  };
}

export function parseDesktopSettings(value: unknown): DesktopSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return DEFAULT_DESKTOP_SETTINGS;
  const record = value as Record<string, unknown>;
  if (!record.adapters || typeof record.adapters !== "object" || Array.isArray(record.adapters)) {
    return DEFAULT_DESKTOP_SETTINGS;
  }
  const adapters = record.adapters as Record<string, unknown>;
  return {
    version: 1,
    defaultHarness: isHarnessId(record.defaultHarness) ? record.defaultHarness : DEFAULT_HARNESS_ID,
    adapters: Object.fromEntries(HARNESS_IDS.map((id) => [
      id,
      adapterSettings(adapters[id], DEFAULT_ADAPTERS[id]),
    ])) as Record<HarnessId, HarnessSettings>,
    mcpEnabled: typeof record.mcpEnabled === "boolean" ? record.mcpEnabled : true,
    walletNodeUrl: text(record.walletNodeUrl, DEFAULT_DESKTOP_SETTINGS.walletNodeUrl),
    browserHome: text(record.browserHome, DEFAULT_DESKTOP_SETTINGS.browserHome),
  };
}

export function serializeDesktopSettings(settings: DesktopSettings): string {
  return JSON.stringify(parseDesktopSettings(settings), null, 2);
}
