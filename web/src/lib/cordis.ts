import type { ExecutorProbe } from "./desktop";
import type { HarnessId } from "./harness";

export type CordisSettingValue = string | boolean | number | null;
export type CordisRestartImpact = "none" | "plugin" | "desktop";

export interface PluginListEntry {
  pluginId: string;
  pluginVersion?: string;
  status: "ready" | "isolated";
  errorCode?: "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";
}

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
  control?: "text" | "textarea";
}

export interface PluginSettingsView extends PluginListEntry {
  pluginVersion: string;
  settingsSchemaVersion: number;
  settingsDigest: string;
  settings: Readonly<Record<string, CordisSettingValue>>;
  secretStates: Readonly<Record<string, "unset" | "set">>;
  schema: { version: number; fields: readonly PluginSettingsFieldMetadata[] };
}

export interface CordisSettingsPatch {
  schemaVersion: number;
  changes: Array<{ id: string; value: CordisSettingValue }>;
}

export interface SettingsValidationResult {
  valid: boolean;
  settingsDigest?: string;
  restartImpact?: CordisRestartImpact;
  error?: string;
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
  restartImpact: CordisRestartImpact;
  permissionDelta: { added: readonly string[]; removed: readonly string[] };
  changes: readonly SettingsReviewChange[];
  state: "current" | "stale";
  createdAt: string;
  expiresAt: string;
}

export interface PluginHealthReport {
  status: "healthy" | "degraded" | "unhealthy" | "isolated";
  code?: string;
  message?: string;
  checkedAt?: string;
}

const pluginNames: Readonly<Record<string, string>> = Object.freeze({
  "@catomicals/plugin-walletd": "钱包节点",
  "@catomicals/plugin-bitcoin-node": "比特币节点",
  "@catomicals/plugin-indexer": "索引器",
  "@catomicals/plugin-mcp": "MCP",
  "@catomicals/plugin-executor-codex": "Codex",
  "@catomicals/plugin-executor-deepseek": "DeepSeek Harness",
  "@catomicals/plugin-executor-claude-code": "Claude Code",
  "@catomicals/plugin-generative-ui": "生成式界面",
  "@catomicals/plugin-backup": "备份",
  "@catomicals/plugin-browser": "浏览器",
});

export const pluginCategories = [
  { id: "wallet-security", label: "钱包与安全" },
  { id: "network-data", label: "网络与数据" },
  { id: "agents", label: "代理" },
  { id: "interface-tools", label: "界面与工具" },
] as const;

export type PluginCategoryId = (typeof pluginCategories)[number]["id"];

const pluginCategoryIds: Readonly<Record<string, PluginCategoryId>> = Object.freeze({
  "@catomicals/plugin-walletd": "wallet-security",
  "@catomicals/plugin-backup": "wallet-security",
  "@catomicals/plugin-bitcoin-node": "network-data",
  "@catomicals/plugin-indexer": "network-data",
  "@catomicals/plugin-mcp": "agents",
  "@catomicals/plugin-executor-codex": "agents",
  "@catomicals/plugin-executor-deepseek": "agents",
  "@catomicals/plugin-executor-claude-code": "agents",
  "@catomicals/plugin-generative-ui": "interface-tools",
  "@catomicals/plugin-browser": "interface-tools",
});

export function pluginCategory(pluginId: string): PluginCategoryId {
  return pluginCategoryIds[pluginId] ?? "interface-tools";
}

const settingChoiceLabels: Readonly<Record<string, string>> = Object.freeze({
  prefer: "优先生成组件",
  automatic: "自动判断",
  off: "仅使用 Markdown",
});

export function settingChoiceLabel(choice: string): string {
  return settingChoiceLabels[choice] ?? choice;
}

const executorPluginIds: Readonly<Record<HarnessId, string>> = Object.freeze({
  codex: "@catomicals/plugin-executor-codex",
  deepseek: "@catomicals/plugin-executor-deepseek",
  "claude-code": "@catomicals/plugin-executor-claude-code",
});

export function pluginDisplayName(pluginId: string): string {
  return pluginNames[pluginId] ?? pluginId.replace(/^@catomicals\/plugin-/, "").replaceAll("-", " ");
}

export function executorPluginId(provider: HarnessId): string {
  return executorPluginIds[provider];
}

export function settingsDraft(view: PluginSettingsView): Record<string, CordisSettingValue | ""> {
  return Object.fromEntries(view.schema.fields.map((field) => [
    field.id,
    field.secretReference ? "" : (view.settings[field.id] ?? null),
  ]));
}

export function buildSettingsPatch(
  view: PluginSettingsView,
  draft: Readonly<Record<string, CordisSettingValue | "">>,
): CordisSettingsPatch {
  const changes: CordisSettingsPatch["changes"] = [];
  for (const field of view.schema.fields) {
    const next = draft[field.id];
    if (field.secretReference && next === "") continue;
    const current = field.secretReference
      ? (view.secretStates[field.id] === "set" ? undefined : null)
      : (view.settings[field.id] ?? null);
    if (field.secretReference || !Object.is(current, next)) {
      changes.push({ id: field.id, value: next === undefined ? null : next });
    }
  }
  return { schemaVersion: view.settingsSchemaVersion, changes };
}

const unavailableLabels: Readonly<Record<NonNullable<ExecutorProbe["reason"]>, string>> = Object.freeze({
  "not-configured": "尚未配置",
  "not-found": "未找到命令",
  "probe-timeout": "检查超时",
  "probe-failed": "检查失败",
  "capability-mismatch": "版本不兼容",
});

export interface ExecutorPresentation {
  provider: HarnessId;
  label: string;
  availabilityLabel: string;
  version?: string;
  model?: string;
  reasoningEffort?: string;
}

export function executorPresentation(
  provider: HarnessId,
  probe: ExecutorProbe,
  settings: PluginSettingsView,
): ExecutorPresentation {
  const model = settings.settings.defaultModel;
  const effort = settings.settings.reasoningEffort;
  return {
    provider,
    label: pluginDisplayName(executorPluginId(provider)),
    availabilityLabel: probe.availability === "available"
      ? "可用"
      : unavailableLabels[probe.reason ?? "probe-failed"],
    ...(probe.version ? { version: probe.version } : {}),
    ...(probe.capabilities.modelSelection && typeof model === "string" && model ? { model } : {}),
    ...(probe.capabilities.reasoningEffort && typeof effort === "string" && effort ? { reasoningEffort: effort } : {}),
  };
}
