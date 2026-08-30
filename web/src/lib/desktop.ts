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

export interface IdentitySession {
  version: 1;
  provider: "local-device";
  accountId: string;
  sessionId: string;
  displayName: string;
  createdAt: number;
  authenticatedAt: number;
}

export interface IdentityState {
  available: boolean;
  session: IdentitySession | null;
  issue?: "identity-data-corrupt";
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
  mcp: boolean;
  walletApproval: false;
  signing: false;
  broadcast: false;
}

export type ExecutorMcpService = "catomicals-config" | "catomicals-wallet";
export type ExecutorMcpToolName =
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
export type ExecutorPermissionScope =
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

export interface ExecutorMcpMetadata {
  enabled: boolean;
  transport: "stdio" | "http-oauth";
  services: readonly ExecutorMcpService[];
  toolNames: readonly ExecutorMcpToolName[];
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

export interface ExecutorSendResult extends ExecutorSession {
  output: string;
}

// --- Session store contract (mirrors desktop/src/sessions/types.ts over IPC) ---

export interface SessionHeader {
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

export interface SessionEventData {
  [key: string]: unknown;
}

export interface AppendableSessionEvent {
  type: string;
  time: number;
  data: SessionEventData;
  ignorable?: true;
  sourceEventSeqs?: number[];
  surfaceOp?: "append" | { op: "replace"; start: number; end: number };
}

export interface SessionEvent extends AppendableSessionEvent {
  seq: number;
}

// --- Message parts stored inside session events (mirror of desktop session
// --- types over IPC). The event `data` field itself stays loosely typed; these
// --- are the structured shapes the transcript builder understands.

/** Controlled UI reference stored with a session message (schema 1). */
export interface SessionUiBlockReference {
  schema_version: 1;
  block_id: string;
  component: string;
  data_bindings: ReadonlyArray<{
    slot: string;
    source: string;
    reference_kind: string;
    reference_id: string;
  }>;
  action_bindings: readonly unknown[];
}

/** Review reference stored with a session message (schema 1). */
export interface SessionReviewReference {
  schema_version: 1;
  review_id: string;
  kind: string;
  source: string;
  review_digest: string;
  created_at: string;
  state: string;
  valid_until?: string;
  intent_id?: string;
  policy_hash?: string;
  node_snapshot_id?: string;
  plugin_id?: string;
  plugin_version?: string;
}

export type SessionMessagePart =
  | { type: "text"; text: string }
  | {
    type: "tool_call";
    tool_call_id: string;
    tool_name: string;
    request_digest: string;
    permission_scope: string;
    intent_id?: string;
    review_id?: string;
  }
  | {
    type: "tool_result";
    tool_call_id: string;
    outcome: "succeeded" | "failed" | "cancelled";
    result_digest?: string;
    intent_id?: string;
    review_id?: string;
  }
  | { type: "ui_block"; block: SessionUiBlockReference }
  | { type: "review_reference"; reference: SessionReviewReference }
  | { type: "error"; code: string; message: string; retriable: boolean };

export interface SessionInspection {
  meta: SessionHeader;
  events: SessionEvent[];
}

export interface SessionSummary {
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

export interface TrashEntry {
  id: string;
  deletedAt: number;
  originalCwd?: string;
  title?: string;
}

export interface SessionSearchPage<T> {
  items: T[];
  nextCursor?: string;
}

export interface SessionEventSearchHit {
  sessionId: string;
  seq: number;
  type: string;
  time: number;
  surface: "current" | "shadowed" | "log-only";
  snippet: string;
}

export interface SessionSearchHit {
  header: SessionHeader;
  live: boolean;
  persisted: boolean;
  bestMatch: SessionEventSearchHit;
}

export interface SessionSearchRequest {
  query: string;
  sessionFilters?: Array<Record<string, unknown>>;
  eventFilters?: Array<Record<string, unknown>>;
  limit?: number;
  cursor?: string;
}

export interface SessionEventSearchRequest {
  sessionId: string;
  query: string;
  filters?: Array<Record<string, unknown>>;
  limit?: number;
  cursor?: string;
}

export interface CatomicalsNavigationEvent {
  kind: "session-open" | "session-list";
  sessionId?: string;
  source: "deeplink" | "app";
  at: number;
}

export interface CreateSessionInput {
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

export interface SessionBridgeApi {
  create(input: CreateSessionInput): Promise<SessionSummary>;
  append(id: string, events: AppendableSessionEvent[]): Promise<SessionEvent[]>;
  list(): Promise<SessionSummary[]>;
  read(id: string): Promise<SessionInspection>;
  inspect(id: string): Promise<SessionInspection>;
  rename(id: string, title: string): Promise<SessionSummary>;
  setArchived(id: string, archived: boolean): Promise<SessionSummary>;
  remove(id: string): Promise<TrashEntry>;
  restore(id: string, deletedAt: number): Promise<SessionSummary>;
  purge(id: string, deletedAt: number): Promise<void>;
  listTrash(): Promise<TrashEntry[]>;
  search(request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>>;
  searchEvents(request: SessionEventSearchRequest): Promise<SessionSearchPage<SessionEventSearchHit> & { session: SessionHeader }>;
  readFrom(id: string, fromSeq: number): Promise<{ meta: SessionHeader; events: SessionEvent[] }>;
  navigate(target: { kind: "session-open"; sessionId: string } | { kind: "session-list" }): Promise<void>;
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
  getIdentityState(): Promise<IdentityState>;
  loginIdentity(): Promise<IdentitySession>;
  logoutIdentity(): Promise<void>;
  recoverIdentity(): Promise<void>;
  sessions: SessionBridgeApi;
  onSessionNavigation(callback: (event: CatomicalsNavigationEvent) => void): () => void;
}

export function requireDesktopBridge(value?: DesktopBridge): DesktopBridge {
  const candidate = value ?? (typeof window === "undefined" ? undefined : window.catomicalsDesktop);
  if (!candidate) throw new Error("desktop runtime unavailable");
  return candidate;
}

export function optionalDesktopBridge(): DesktopBridge | undefined {
  return typeof window === "undefined" ? undefined : window.catomicalsDesktop;
}
