export const HARNESS_IDS = ["codex", "deepseek", "claude-code"] as const;
export type HarnessId = (typeof HARNESS_IDS)[number];
export type HarnessStatus = "ready" | "not-connected" | "unavailable";
export type HarnessCapability = "chat" | "mcp" | "workspace";

export interface HarnessAdapterDefinition {
  id: HarnessId;
  label: string;
  command: string;
  status: HarnessStatus;
  statusLabel: string;
  capabilities: readonly HarnessCapability[];
}

export const HARNESS_ADAPTERS: readonly HarnessAdapterDefinition[] = [
  {
    id: "codex",
    label: "Codex",
    command: "codex",
    status: "not-connected",
    statusLabel: "桌面适配器尚未接通",
    capabilities: ["chat", "mcp", "workspace"],
  },
  {
    id: "deepseek",
    label: "DeepSeek Harness",
    command: "deepseek-harness",
    status: "not-connected",
    statusLabel: "桌面适配器尚未接通",
    capabilities: ["chat", "mcp", "workspace"],
  },
  {
    id: "claude-code",
    label: "Claude Code",
    command: "claude",
    status: "not-connected",
    statusLabel: "桌面适配器尚未接通",
    capabilities: ["chat", "mcp", "workspace"],
  },
] as const;

export const DEFAULT_HARNESS_ID: HarnessId = "codex";

export function isHarnessId(value: unknown): value is HarnessId {
  return typeof value === "string" && HARNESS_IDS.includes(value as HarnessId);
}

export function parseHarnessId(value: unknown): HarnessId {
  return isHarnessId(value) ? value : DEFAULT_HARNESS_ID;
}

export function selectedHarnessStorageKey(sessionId: string): string {
  return `catomicals:harness:${sessionId.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

export function harnessAdapter(id: HarnessId): HarnessAdapterDefinition {
  return HARNESS_ADAPTERS.find((adapter) => adapter.id === id) ?? HARNESS_ADAPTERS[0];
}
