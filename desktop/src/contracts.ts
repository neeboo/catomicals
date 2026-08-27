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
  version: 2;
  defaultHarness: HarnessId;
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

export interface ExecutorProbeRequest {
  provider: HarnessId;
}

export interface ExecutorCreateRequest extends ExecutorProbeRequest {
  sessionId: string;
}

export interface ExecutorResumeRequest extends ExecutorCreateRequest {
  nativeSessionId: string;
}

export interface ExecutorSendRequest {
  sessionId: string;
  prompt: string;
}

export interface ExecutorSessionRequest {
  sessionId: string;
}

export interface PaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export type CordisSettingValue = string | boolean | number | null;
export type CordisRestartImpact = "none" | "plugin" | "desktop";

export interface PluginSettingsFieldMetadata {
  id: string;
  label: string;
  type: "string" | "boolean" | "integer";
  required: boolean;
  restart: CordisRestartImpact;
  default?: Exclude<CordisSettingValue, null>;
  secretReference?: true;
  choices?: readonly string[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

export interface PluginSettingsView {
  pluginId: string;
  pluginVersion: string;
  status: "ready" | "isolated";
  errorCode?: "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";
  settingsSchemaVersion: number;
  settingsDigest: string;
  settings: Readonly<Record<string, CordisSettingValue>>;
  secretStates: Readonly<Record<string, "unset" | "set">>;
  schema: { version: number; fields: readonly PluginSettingsFieldMetadata[] };
}

export interface SettingsPermissionDelta {
  added: readonly string[];
  removed: readonly string[];
}

export type SettingsReviewChange = {
  id: string;
  label: string;
  type: "string" | "boolean" | "integer";
  restart: CordisRestartImpact;
  before: CordisSettingValue;
  after: CordisSettingValue;
} | {
  id: string;
  label: string;
  type: "string";
  restart: CordisRestartImpact;
  secretState: "unset" | "set" | "changed";
};

export interface PluginSettingsReview {
  intentId: string;
  reviewId: string;
  pluginId: string;
  pluginVersion: string;
  baseSettingsDigest: string;
  candidateSettingsDigest: string;
  patchDigest: string;
  review_digest: string;
  restartImpact: CordisRestartImpact;
  permissionDelta: SettingsPermissionDelta;
  changes: readonly SettingsReviewChange[];
  state: "current" | "stale";
  createdAt: string;
  expiresAt: string;
}
