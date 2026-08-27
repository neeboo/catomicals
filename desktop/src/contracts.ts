export const TOOL_TAB_IDS = [
  "browser",
  "transaction",
  "intents",
  "security",
  "issuance",
] as const;
export type ToolTabId = (typeof TOOL_TAB_IDS)[number];

export const HARNESS_IDS = ["codex", "deepseek", "claude-code"] as const;
export type HarnessId = (typeof HARNESS_IDS)[number];
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

export interface DesktopState {
  desktop: true;
  toolsOpen: boolean;
  activeTab: ToolTabId | null;
  safeStorageAvailable: boolean;
}

export interface HarnessRequest {
  harnessId: HarnessId;
  sessionId: string;
  prompt: string;
}

export interface HarnessResult {
  ok: false;
  status: "not-connected";
  message: string;
}

export interface PaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}
