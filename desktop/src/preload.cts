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

interface IdentitySession {
  version: 1;
  provider: "local-device";
  accountId: string;
  sessionId: string;
  displayName: string;
  createdAt: number;
  authenticatedAt: number;
}

interface IdentityState {
  available: boolean;
  session: IdentitySession | null;
  issue?: "identity-data-corrupt";
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
  mcp: boolean;
  walletApproval: false;
  signing: false;
  broadcast: false;
}

type ExecutorMcpService = "catomicals-config" | "catomicals-wallet";
type ExecutorMcpToolName =
  | "list_plugins"
  | "read_plugin_manifest"
  | "read_plugin_settings_schema"
  | "read_plugin_health"
  | "validate_plugin_settings_patch"
  | "create_plugin_settings_intent"
  | "add_chat_message"
  | "cancel_signing_intent"
  | "check_protected_trade"
  | "create_transaction_intent"
  | "get_chat_state"
  | "get_wallet_status"
  | "inspect_transaction"
  | "list_signing_intents"
  | "read_signing_intent";
type ExecutorPermissionScope =
  | "wallet.status.read"
  | "wallet.intent.read"
  | "wallet.intent.create"
  | "wallet.intent.cancel"
  | "wallet.chat.read"
  | "wallet.chat.append"
  | "wallet.transaction.inspect"
  | "wallet.trade.verify"
  | "plugin.catalog.read"
  | "plugin.manifest.read"
  | "plugin.settings_schema.read"
  | "plugin.health.read"
  | "plugin.settings.validate"
  | "plugin.settings_intent.create";

interface ExecutorMcpMetadata {
  enabled: boolean;
  transport: "stdio" | "http-oauth";
  services: readonly ExecutorMcpService[];
  toolNames: readonly ExecutorMcpToolName[];
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
  protocolSessionId: string;
  provider: HarnessId;
  nativeSessionId?: string;
  state: "idle" | "running" | "completed" | "interrupted" | "failed" | "disposed";
  capabilities: ExecutorCapabilities;
  mcp: ExecutorMcpMetadata;
  allowedScopes: readonly ExecutorPermissionScope[];
  model?: string;
  reasoningEffort?: ReasoningEffort;
  workingDirectory: string;
  restartImpact: "none" | "plugin" | "desktop";
  lastError?: "interrupted" | "process-failed" | "spawn-failed" | "output-limit";
}

type ExecutorMessagePart =
  | { type: "text"; text: string }
  | { type: "error"; code: string; message: string; retriable: boolean };

interface ExecutorFinalMessage {
  schema_version: 1;
  message_id: string;
  session_id: string;
  role: "assistant";
  content_digest: string;
  created_at: string;
  parts: readonly ExecutorMessagePart[];
}

type ExecutorSendResult =
  | (ExecutorSession & { state: "completed"; output: string; message: ExecutorFinalMessage })
  | (ExecutorSession & {
    state: Exclude<ExecutorSession["state"], "completed">;
    output: string;
    message?: never;
  });

interface PluginListEntry {
  pluginId: string;
  pluginVersion?: string;
  status: "ready" | "disabled" | "isolated";
  errorCode?: "package_invalid" | "missing_service" | "state_invalid" | "migration_failed" | "health_failed";
  enabled: boolean;
  category: "system" | "wallet" | "chain" | "data" | "agent" | "interface" | "storage";
  capabilities: Array<"wallet" | "chain.rpc" | "chain.address" | "indexer" | "agent.mcp" | "agent.executor" | "ui.generative" | "browser" | "backup">;
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

interface PluginSettingsView extends PluginListEntry {
  pluginVersion: string;
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
  review_digest: string;
  restartImpact: "none" | "plugin" | "desktop";
  permissionDelta: { added: string[]; removed: string[] };
  changes: Array<Record<string, unknown>>;
  state: "current" | "stale";
  createdAt: string;
  expiresAt: string;
}

// --- Session store contract (mirrors desktop/src/sessions/types.ts over IPC) ---

interface SessionHeader {
  version: number;
  id: string;
  createdAt: number;
  cwd?: string;
  parentSession?: string;
  seedLength?: number;
  provider?: string;
  model?: string;
  executor?: string;
  origin?: "subagent";
  delegationDepth?: number;
  agentPreset?: string;
}

interface SessionEventData {
  [key: string]: unknown;
}

interface AppendableSessionEvent {
  type: string;
  time: number;
  data: SessionEventData;
  ignorable?: true;
  sourceEventSeqs?: number[];
  surfaceOp?: "append" | { op: "replace"; start: number; end: number };
}

interface SessionEvent extends AppendableSessionEvent {
  seq: number;
}

interface SessionInspection {
  meta: SessionHeader;
  events: SessionEvent[];
}

interface SessionSummary {
  id: string;
  title?: string;
  archived: boolean;
  provider?: string;
  model?: string;
  executor?: string;
  createdAt: number;
  updatedAt: number;
  eventCount: number;
  lastError?: { message: string; code: string };
}

interface TrashEntry {
  id: string;
  deletedAt: number;
  originalCwd?: string;
  title?: string;
}

interface SessionSearchPage<T> {
  items: T[];
  nextCursor?: string;
}

interface SessionEventSearchHit {
  sessionId: string;
  seq: number;
  type: string;
  time: number;
  surface: "current" | "shadowed" | "log-only";
  snippet: string;
}

interface SessionSearchHit {
  header: SessionHeader;
  live: boolean;
  persisted: boolean;
  bestMatch: SessionEventSearchHit;
}

interface SessionSearchRequest {
  query: string;
  sessionFilters?: Array<Record<string, unknown>>;
  eventFilters?: Array<Record<string, unknown>>;
  limit?: number;
  cursor?: string;
}

interface SessionEventSearchRequest {
  sessionId: string;
  query: string;
  filters?: Array<Record<string, unknown>>;
  limit?: number;
  cursor?: string;
}

interface CatomicalsNavigationEvent {
  kind: "session-open" | "session-list";
  sessionId?: string;
  source: "deeplink" | "app";
  at: number;
}

interface CreateSessionInput {
  title?: string;
  provider?: string;
  model?: string;
  executor?: string;
  cwd?: string;
  parentSession?: string;
  origin?: "subagent";
  delegationDepth?: number;
  agentPreset?: string;
  seed?: AppendableSessionEvent[];
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
  getIdentityState: (): Promise<IdentityState> => ipcRenderer.invoke("catomicals:identity:state"),
  loginIdentity: (): Promise<IdentitySession> => ipcRenderer.invoke("catomicals:identity:login", { provider: "local-device" }),
  logoutIdentity: (): Promise<void> => ipcRenderer.invoke("catomicals:identity:logout"),
  recoverIdentity: (): Promise<void> => ipcRenderer.invoke("catomicals:identity:recover"),
  sessions: {
    create: (input: CreateSessionInput): Promise<SessionSummary> => ipcRenderer.invoke("catomicals:session:create", input),
    append: (id: string, events: AppendableSessionEvent[]): Promise<SessionEvent[]> => ipcRenderer.invoke("catomicals:session:append", { id, events }),
    list: (): Promise<SessionSummary[]> => ipcRenderer.invoke("catomicals:session:list"),
    read: (id: string): Promise<SessionInspection> => ipcRenderer.invoke("catomicals:session:read", { id }),
    inspect: (id: string): Promise<SessionInspection> => ipcRenderer.invoke("catomicals:session:inspect", { id }),
    rename: (id: string, title: string): Promise<SessionSummary> => ipcRenderer.invoke("catomicals:session:rename", { id, title }),
    setArchived: (id: string, archived: boolean): Promise<SessionSummary> => ipcRenderer.invoke("catomicals:session:archive", { id, archived }),
    remove: (id: string): Promise<TrashEntry> => ipcRenderer.invoke("catomicals:session:delete", { id }),
    restore: (id: string, deletedAt: number): Promise<SessionSummary> => ipcRenderer.invoke("catomicals:session:restore", { id, deletedAt }),
    purge: (id: string, deletedAt: number): Promise<void> => ipcRenderer.invoke("catomicals:session:purge", { id, deletedAt }),
    listTrash: (): Promise<TrashEntry[]> => ipcRenderer.invoke("catomicals:session:trash-list"),
    search: (request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>> => ipcRenderer.invoke("catomicals:session:search", request),
    searchEvents: (request: SessionEventSearchRequest): Promise<SessionSearchPage<SessionEventSearchHit> & { session: SessionHeader }> => ipcRenderer.invoke("catomicals:session:search-events", request),
    readFrom: (id: string, fromSeq: number): Promise<{ meta: SessionHeader; events: SessionEvent[] }> => ipcRenderer.invoke("catomicals:session:read-from", { id, fromSeq }),
    navigate: (target: { kind: "session-open"; sessionId: string } | { kind: "session-list" }): Promise<void> => ipcRenderer.invoke("catomicals:session:navigate", target),
  },
  onSessionNavigation: (callback: (event: CatomicalsNavigationEvent) => void): (() => void) => {
    const listener = (_event: unknown, value: CatomicalsNavigationEvent): void => callback(value);
    ipcRenderer.on("catomicals:session:navigation", listener);
    return () => {
      ipcRenderer.removeListener("catomicals:session:navigation", listener);
    };
  },
});

contextBridge.exposeInMainWorld("catomicalsDesktop", api);
