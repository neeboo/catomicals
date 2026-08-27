import type {
  CordisSettingsPatch,
  PluginHealthReport,
  PluginListEntry,
  PluginSettingsReview,
  PluginSettingsView,
  SettingsValidationResult,
} from "./cordis";
import type { HarnessId } from "./harness";
import type { ToolTab } from "./workbench";

export type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

export interface PaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface DesktopSettings {
  version: 2;
  defaultHarness: HarnessId;
}

export interface DesktopState {
  desktop: true;
  toolsOpen: boolean;
  activeTab: ToolTab | null;
  safeStorageAvailable: boolean;
}

export interface WalletProxyRequest {
  path: string;
  method: "GET" | "POST";
  body?: string;
}

export interface WalletProxyResponse {
  status: number;
  body: string;
  contentType: string;
}

export interface ExecutorCapabilities {
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

export interface ExecutorProbe {
  provider: HarnessId;
  availability: "available" | "unavailable";
  version?: string;
  reason?: "not-configured" | "not-found" | "probe-timeout" | "probe-failed" | "capability-mismatch";
  capabilities: ExecutorCapabilities;
}

export interface ExecutorSession {
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

export interface ExecutorSendResult extends ExecutorSession {
  output: string;
}

export interface DesktopBridge {
  getState(): Promise<DesktopState>;
  selectTab(tab: ToolTab): Promise<DesktopState>;
  closeTools(): Promise<DesktopState>;
  setPaneBounds(bounds: PaneBounds): Promise<void>;
  navigateBrowser(url: string): Promise<string>;
  browserBack(): Promise<void>;
  browserForward(): Promise<void>;
  browserReload(): Promise<void>;
  getSettings(): Promise<DesktopSettings>;
  updateSettings(settings: DesktopSettings): Promise<DesktopSettings>;
  requestWallet(request: WalletProxyRequest): Promise<WalletProxyResponse>;
  getMcpEnabled(): Promise<boolean>;
  probeExecutor(provider: HarnessId): Promise<ExecutorProbe>;
  createExecutorSession(provider: HarnessId, sessionId: string): Promise<ExecutorSession>;
  resumeExecutorSession(provider: HarnessId, sessionId: string, nativeSessionId: string): Promise<ExecutorSession>;
  sendExecutorMessage(sessionId: string, prompt: string): Promise<ExecutorSendResult>;
  interruptExecutorSession(sessionId: string): Promise<ExecutorSession>;
  getExecutorStatus(sessionId: string): Promise<ExecutorSession>;
  disposeExecutorSession(sessionId: string): Promise<ExecutorSession>;
  listPlugins(): Promise<PluginListEntry[]>;
  readPluginManifest(pluginId: string): Promise<unknown>;
  readPluginSettingsSchema(pluginId: string): Promise<unknown>;
  readPluginSettings(pluginId: string): Promise<PluginSettingsView>;
  readPluginHealth(pluginId: string): Promise<PluginHealthReport>;
  validatePluginSettings(pluginId: string, patch: CordisSettingsPatch): Promise<SettingsValidationResult>;
  createPluginSettingsIntent(pluginId: string, patch: CordisSettingsPatch): Promise<PluginSettingsReview>;
  readPluginSettingsReview(reviewId: string): Promise<PluginSettingsReview>;
  confirmPluginSettingsIntent(reviewId: string): Promise<PluginSettingsView>;
}

export function requireDesktopBridge(value?: DesktopBridge): DesktopBridge {
  const candidate = value ?? (typeof window === "undefined" ? undefined : window.catomicalsDesktop);
  if (!candidate) throw new Error("desktop runtime unavailable");
  return candidate;
}

export function optionalDesktopBridge(): DesktopBridge | undefined {
  return typeof window === "undefined" ? undefined : window.catomicalsDesktop;
}
