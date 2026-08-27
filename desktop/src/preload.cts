import { contextBridge, ipcRenderer } from "electron";

type ToolTabId = "browser" | "transaction" | "intents" | "security" | "issuance";
type HarnessId = "codex" | "deepseek" | "claude-code";
type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

interface PaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface DesktopSettings {
  version: 2;
  defaultHarness: HarnessId;
}

interface WalletProxyRequest {
  path: string;
  method: "GET" | "POST";
  body?: string;
}

interface WalletProxyResponse {
  status: number;
  body: string;
  contentType: string;
}

interface DesktopState {
  desktop: true;
  toolsOpen: boolean;
  activeTab: ToolTabId | null;
  safeStorageAvailable: boolean;
}

interface HarnessRequest {
  harnessId: HarnessId;
  sessionId: string;
  prompt: string;
}

interface HarnessResult {
  ok: false;
  status: "not-connected";
  message: string;
}

interface ExecutorCapabilities {
  create: true;
  send: true;
  interrupt: true;
  status: true;
  dispose: true;
  resume: boolean;
  modelSelection: boolean;
  reasoningEffort: boolean;
  mcp: false;
  walletApproval: false;
  signing: false;
  broadcast: false;
}

interface ExecutorProbe {
  provider: HarnessId;
  availability: "available" | "unavailable";
  version?: string;
  reason?: "not-configured" | "not-found" | "probe-timeout" | "probe-failed" | "capability-mismatch";
  capabilities: ExecutorCapabilities;
}

interface ExecutorSession {
  sessionId: string;
  provider: HarnessId;
  nativeSessionId?: string;
  state: "idle" | "running" | "completed" | "interrupted" | "failed" | "disposed";
  capabilities: ExecutorCapabilities;
  model?: string;
  reasoningEffort?: ReasoningEffort;
  workingDirectory: string;
  restartImpact: "none" | "plugin" | "desktop";
  lastError?: "interrupted" | "process-failed" | "spawn-failed" | "output-limit";
}

interface ExecutorSendResult extends ExecutorSession {
  output: string;
}

interface PluginListEntry {
  pluginId: string;
  pluginVersion?: string;
  status: "ready" | "isolated";
  errorCode?: "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";
}

type CordisSettingValue = string | boolean | number | null;

interface CordisSettingsPatch {
  schemaVersion: number;
  changes: Array<{ id: string; value: CordisSettingValue }>;
}

interface SettingsValidationResult {
  valid: boolean;
  settingsDigest?: string;
  restartImpact?: "none" | "plugin" | "desktop";
  error?: string;
}

interface PluginSettingsView {
  pluginId: string;
  pluginVersion: string;
  status: "ready" | "isolated";
  settingsSchemaVersion: number;
  settingsDigest: string;
  settings: Record<string, CordisSettingValue>;
  secretStates: Record<string, "unset" | "set">;
  schema: unknown;
}

interface SettingsReview {
  intentId: string;
  reviewId: string;
  pluginId: string;
  pluginVersion: string;
  baseSettingsDigest: string;
  candidateSettingsDigest: string;
  patchDigest: string;
  restartImpact: "none" | "plugin" | "desktop";
  permissionDelta: { added: string[]; removed: string[] };
  changes: Array<Record<string, unknown>>;
  state: "current" | "stale";
  createdAt: string;
  expiresAt: string;
}

const api = Object.freeze({
  getState: (): Promise<DesktopState> => ipcRenderer.invoke("catomicals:state:get"),
  selectTab: (tab: ToolTabId): Promise<DesktopState> => ipcRenderer.invoke("catomicals:tab:select", tab),
  closeTools: (): Promise<DesktopState> => ipcRenderer.invoke("catomicals:tools:close"),
  setPaneBounds: (bounds: PaneBounds): Promise<void> => ipcRenderer.invoke("catomicals:pane:set-bounds", bounds),
  navigateBrowser: (url: string): Promise<string> => ipcRenderer.invoke("catomicals:browser:navigate", url),
  browserBack: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:back"),
  browserForward: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:forward"),
  browserReload: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:reload"),
  getSettings: (): Promise<DesktopSettings> => ipcRenderer.invoke("catomicals:settings:get"),
  updateSettings: (settings: DesktopSettings): Promise<DesktopSettings> => ipcRenderer.invoke("catomicals:settings:update", settings),
  requestWallet: (request: WalletProxyRequest): Promise<WalletProxyResponse> => ipcRenderer.invoke("catomicals:wallet:request", request),
  getMcpEnabled: (): Promise<boolean> => ipcRenderer.invoke("catomicals:mcp:enabled-get"),
  invokeHarness: (request: HarnessRequest): Promise<HarnessResult> => ipcRenderer.invoke("catomicals:harness:invoke", request),
  probeExecutor: (provider: HarnessId): Promise<ExecutorProbe> => ipcRenderer.invoke("catomicals:executor:probe", { provider }),
  createExecutorSession: (provider: HarnessId, sessionId: string): Promise<ExecutorSession> => ipcRenderer.invoke("catomicals:executor:create", { provider, sessionId }),
  resumeExecutorSession: (provider: HarnessId, sessionId: string, nativeSessionId: string): Promise<ExecutorSession> => ipcRenderer.invoke("catomicals:executor:resume", { provider, sessionId, nativeSessionId }),
  sendExecutorMessage: (sessionId: string, prompt: string): Promise<ExecutorSendResult> => ipcRenderer.invoke("catomicals:executor:send", { sessionId, prompt }),
  interruptExecutorSession: (sessionId: string): Promise<ExecutorSession> => ipcRenderer.invoke("catomicals:executor:interrupt", { sessionId }),
  getExecutorStatus: (sessionId: string): Promise<ExecutorSession> => ipcRenderer.invoke("catomicals:executor:status", { sessionId }),
  disposeExecutorSession: (sessionId: string): Promise<ExecutorSession> => ipcRenderer.invoke("catomicals:executor:dispose", { sessionId }),
  listPlugins: (): Promise<PluginListEntry[]> => ipcRenderer.invoke("catomicals:plugin:list"),
  readPluginManifest: (pluginId: string): Promise<unknown> => ipcRenderer.invoke("catomicals:plugin:manifest", { pluginId }),
  readPluginSettingsSchema: (pluginId: string): Promise<unknown> => ipcRenderer.invoke("catomicals:plugin:settings-schema", { pluginId }),
  readPluginSettings: (pluginId: string): Promise<PluginSettingsView> => ipcRenderer.invoke("catomicals:plugin:settings-read", { pluginId }),
  readPluginHealth: (pluginId: string): Promise<unknown> => ipcRenderer.invoke("catomicals:plugin:health", { pluginId }),
  validatePluginSettings: (pluginId: string, patch: CordisSettingsPatch): Promise<SettingsValidationResult> => ipcRenderer.invoke("catomicals:plugin:settings-validate", { pluginId, patch }),
  createPluginSettingsIntent: (pluginId: string, patch: CordisSettingsPatch): Promise<SettingsReview> => ipcRenderer.invoke("catomicals:plugin:settings-intent-create", { pluginId, patch }),
  readPluginSettingsReview: (reviewId: string): Promise<SettingsReview> => ipcRenderer.invoke("catomicals:plugin:settings-review", { reviewId }),
  confirmPluginSettingsIntent: (reviewId: string): Promise<PluginSettingsView> => ipcRenderer.invoke("catomicals:plugin:settings-intent-confirm", { reviewId }),
});

contextBridge.exposeInMainWorld("catomicalsDesktop", api);
