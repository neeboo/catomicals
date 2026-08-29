import type { ExecutorProbe } from "./desktop";
import type { HarnessId } from "./harness";

export type CordisSettingValue = string | boolean | number | null;
export type CordisRestartImpact = "none" | "plugin" | "desktop";
export type PluginHostCategory = "system" | "wallet" | "chain" | "data" | "agent" | "interface" | "storage";
export type PluginCapability =
  | "wallet"
  | "chain.rpc"
  | "chain.address"
  | "indexer"
  | "agent.mcp"
  | "agent.executor"
  | "ui.generative"
  | "browser"
  | "backup";

export const supportedChains = [
  { id: "bitcoin", label: "Bitcoin", pluginId: "@catomicals/plugin-chain-bitcoin" },
  { id: "bitcoin-cash", label: "Bitcoin Cash", pluginId: "@catomicals/plugin-chain-bitcoin-cash" },
  { id: "bsv", label: "BSV", pluginId: "@catomicals/plugin-chain-bsv" },
  { id: "fractal-bitcoin", label: "Fractal Bitcoin", pluginId: "@catomicals/plugin-chain-fractal-bitcoin" },
  { id: "kaspa", label: "Kaspa", pluginId: "@catomicals/plugin-chain-kaspa" },
  { id: "chia", label: "Chia", pluginId: "@catomicals/plugin-chain-chia" },
  { id: "ergo", label: "Ergo", pluginId: "@catomicals/plugin-chain-ergo" },
] as const;

export type SupportedChainId = (typeof supportedChains)[number]["id"];

export interface PluginListEntry {
  pluginId: string;
  pluginVersion?: string;
  status: "ready" | "disabled" | "isolated";
  errorCode?: "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";
  /** Optional host metadata; old Cordis hosts remain source-compatible. */
  enabled?: boolean;
  category?: PluginHostCategory;
  capabilities?: readonly PluginCapability[];
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
  format?: "rpc-endpoint";
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
  status: "healthy" | "degraded" | "unhealthy" | "isolated" | "disabled";
  code?: string;
  message?: string;
  checkedAt?: string;
}

const pluginNames: Readonly<Record<string, string>> = Object.freeze({
  "@catomicals/plugin-walletd": "钱包节点",
  "@catomicals/plugin-bitcoin-node": "Bitcoin",
  "@catomicals/plugin-chain-bitcoin": "Bitcoin",
  "@catomicals/plugin-chain-kaspa": "Kaspa",
  "@catomicals/plugin-chain-bitcoin-cash": "Bitcoin Cash",
  "@catomicals/plugin-chain-bsv": "BSV",
  "@catomicals/plugin-chain-fractal-bitcoin": "Fractal Bitcoin",
  "@catomicals/plugin-chain-chia": "Chia",
  "@catomicals/plugin-chain-ergo": "Ergo",
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
  { id: "chain-plugins", label: "链插件" },
] as const;

export type PluginCategoryId = (typeof pluginCategories)[number]["id"];

const pluginCategoryIds: Readonly<Record<string, PluginCategoryId>> = Object.freeze({
  ...Object.fromEntries(supportedChains.map((chain) => [chain.pluginId, "chain-plugins" as const])),
});

const productPluginIds: ReadonlySet<string> = new Set(supportedChains.map((chain) => chain.pluginId));

export function productPlugins(plugins: readonly PluginListEntry[]): PluginListEntry[] {
  const byId = new Map(plugins.filter((plugin) => productPluginIds.has(plugin.pluginId)).map((plugin) => [plugin.pluginId, plugin]));
  return supportedChains.flatMap((chain) => {
    const plugin = byId.get(chain.pluginId);
    return plugin ? [plugin] : [];
  });
}

export function pluginCategory(plugin: string | Pick<PluginListEntry, "pluginId" | "category">): PluginCategoryId {
  const pluginId = typeof plugin === "string" ? plugin : plugin.pluginId;
  const fixedCategory = pluginCategoryIds[pluginId];
  if (fixedCategory) return fixedCategory;
  return "chain-plugins";
}

export function pluginSurfaces(
  plugin: string | Pick<PluginListEntry, "pluginId" | "category" | "capabilities">,
): readonly PluginCategoryId[] {
  const pluginId = typeof plugin === "string" ? plugin : plugin.pluginId;
  return productPluginIds.has(pluginId) ? ["chain-plugins"] : [];
}

const chainByPluginId = new Map<string, (typeof supportedChains)[number]>(
  supportedChains.map((chain) => [chain.pluginId, chain]),
);

export interface PluginCapabilitySummary {
  chainId?: SupportedChainId;
  chainLabel?: string;
  network?: string;
  capabilityLabel: string;
  permissionLabel: string;
  networkAccessLabel?: string;
  endpoint?: string;
  verificationLabel: string;
}

function safeEndpointSummary(endpoint: string | undefined): string | undefined {
  if (!endpoint) return undefined;
  try {
    const url = new URL(endpoint);
    return url.origin;
  } catch {
    return endpoint.length > 52 ? `${endpoint.slice(0, 49)}…` : endpoint;
  }
}

export function pluginCapabilitySummary(
  plugin: PluginListEntry,
  settingsView?: Pick<PluginSettingsView, "settings">,
): PluginCapabilitySummary {
  const catalogChain = chainByPluginId.get(plugin.pluginId);
  const chainId = catalogChain?.id;
  const chainLabel = supportedChains.find((chain) => chain.id === chainId)?.label;
  const access = settingsView?.settings.access;
  const networkAccess = settingsView?.settings.networkAccess;
  const network = settingsView?.settings.networkId ?? settingsView?.settings.network ?? settingsView?.settings.profile;
  const endpoint = settingsView?.settings.endpoint;
  const preset = settingsView?.settings.nodeSource === "preset";
  const hasRpc = plugin.capabilities?.includes("chain.rpc") ?? Boolean(chainId);
  const hasAddress = plugin.capabilities?.includes("chain.address") ?? Boolean(chainId);
  const capabilityLabel = [hasAddress ? "地址" : null, hasRpc ? "RPC" : null].filter(Boolean).join(" · ") || "通用";
  const permissionLabel = access === "broadcast" ? "可广播" : "只读";
  const verificationLabel = plugin.pluginId === "@catomicals/plugin-bitcoin-node"
    ? "节点验证"
    : hasRpc ? "RPC 验证" : "本机配置";
  return {
    ...(chainId ? { chainId } : {}),
    ...(chainLabel ? { chainLabel } : {}),
    ...(typeof network === "string" && network ? { network } : {}),
    capabilityLabel,
    permissionLabel,
    ...(typeof networkAccess === "string" && networkAccess
      ? { networkAccessLabel: settingChoiceLabel(networkAccess) }
      : {}),
    ...(preset
      ? { endpoint: "默认节点" }
      : safeEndpointSummary(typeof endpoint === "string" ? endpoint : undefined)
        ? { endpoint: safeEndpointSummary(typeof endpoint === "string" ? endpoint : undefined) }
        : {}),
    verificationLabel,
  };
}

const settingChoiceLabels: Readonly<Record<string, string>> = Object.freeze({
  prefer: "优先生成组件",
  automatic: "自动判断",
  off: "仅使用 Markdown",
  local: "仅本机",
  "private-network": "私有网络",
  public: "公网",
  read: "只读",
  broadcast: "可广播",
  preset: "默认节点",
  custom: "自建节点",
  strict: "严格校验",
  "bitcoin-inquisition": "Bitcoin Inquisition",
  "bitcoin-mainnet": "Bitcoin 主网",
  "bitcoin-testnet3": "Bitcoin Testnet3",
  "bitcoin-testnet4": "Bitcoin Testnet4",
  "bitcoin-signet": "Bitcoin Signet",
  "bitcoin-regtest": "Bitcoin Regtest",
  "bitcoin-cash-mainnet": "Bitcoin Cash 主网",
  "bitcoin-cash-testnet3": "Bitcoin Cash Testnet3",
  "bitcoin-cash-testnet4": "Bitcoin Cash Testnet4",
  "bitcoin-cash-chipnet": "Bitcoin Cash Chipnet",
  "bitcoin-cash-regtest": "Bitcoin Cash Regtest",
  "bsv-mainnet": "BSV 主网",
  "bsv-testnet": "BSV 测试网",
  "bsv-regtest": "BSV Regtest",
  "fractal-bitcoin-mainnet": "Fractal Bitcoin 主网",
  "fractal-bitcoin-testnet3": "Fractal Bitcoin Testnet3",
  "fractal-bitcoin-testnet4": "Fractal Bitcoin Testnet4",
  "fractal-bitcoin-signet": "Fractal Bitcoin Signet",
  "fractal-bitcoin-regtest": "Fractal Bitcoin Regtest",
  "kaspa-mainnet": "Kaspa 主网",
  "kaspa-testnet-10": "Kaspa Testnet 10",
  "kaspa-testnet-11": "Kaspa Testnet 11",
  "chia-mainnet": "Chia 主网",
  "chia-testnet11": "Chia Testnet11",
  "ergo-mainnet": "Ergo 主网",
  "ergo-testnet": "Ergo 测试网",
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
