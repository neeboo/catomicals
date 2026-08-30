import type { CordisRestartImpact, HarnessSettings } from "../contracts.js";
import type { CordisPermissionScope } from "../cordis/permissions.js";
import {
  CORDIS_MCP_TOOL_NAMES,
  WALLET_MCP_TOOL_NAMES,
  type ExecutorCapabilities,
  type ExecutorMcpToolName,
  type ExecutorProviderId,
} from "./types.js";

export const EXECUTOR_MCP_SERVICES = Object.freeze([
  "catomicals-config",
  "catomicals-wallet",
] as const);

export type ExecutorMcpService = (typeof EXECUTOR_MCP_SERVICES)[number];
export type ExecutorMcpTransport = "stdio" | "http-oauth";

export interface ExecutorMcpMetadata {
  readonly enabled: boolean;
  readonly transport: ExecutorMcpTransport;
  readonly services: readonly ExecutorMcpService[];
  readonly toolNames: readonly ExecutorMcpToolName[];
}

export const EXECUTOR_MCP_PERMISSION_SCOPES: readonly CordisPermissionScope[] = Object.freeze([
  "wallet.status.read",
  "wallet.intent.read",
  "wallet.intent.create",
  "wallet.intent.cancel",
  "wallet.chat.read",
  "wallet.chat.append",
  "wallet.transaction.inspect",
  "wallet.trade.verify",
  "plugin.catalog.read",
  "plugin.manifest.read",
  "plugin.settings_schema.read",
  "plugin.health.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
]);

const ENABLED_MCP_METADATA: ExecutorMcpMetadata = Object.freeze({
  enabled: true,
  transport: "stdio",
  services: EXECUTOR_MCP_SERVICES,
  toolNames: Object.freeze([...CORDIS_MCP_TOOL_NAMES, ...WALLET_MCP_TOOL_NAMES]),
});

const DISABLED_MCP_METADATA: ExecutorMcpMetadata = Object.freeze({
  enabled: false,
  transport: "stdio",
  services: Object.freeze([]),
  toolNames: Object.freeze([]),
});

export function executorMcpMetadata(enabled: boolean): ExecutorMcpMetadata {
  return enabled ? ENABLED_MCP_METADATA : DISABLED_MCP_METADATA;
}

export type ExecutorSessionState = "idle" | "running" | "completed" | "interrupted" | "failed" | "disposed";
export type ExecutorSessionLastError = "interrupted" | "process-failed" | "spawn-failed" | "output-limit";

export interface ExecutorSessionView {
  readonly sessionId: string;
  readonly protocolSessionId: string;
  readonly provider: ExecutorProviderId;
  readonly nativeSessionId?: string;
  readonly state: ExecutorSessionState;
  readonly capabilities: ExecutorCapabilities;
  readonly mcp: ExecutorMcpMetadata;
  readonly allowedScopes: readonly CordisPermissionScope[];
  readonly model?: string;
  readonly reasoningEffort?: HarnessSettings["reasoningEffort"];
  readonly workingDirectory: string;
  readonly restartImpact: CordisRestartImpact;
  readonly lastError?: ExecutorSessionLastError;
}

export interface ExecutorSessionDocumentV2 {
  readonly schema_version: 2;
  readonly session_id: string;
  readonly protocol_session_id: string;
  readonly native_session_id?: string;
  readonly provider: ExecutorProviderId;
  readonly state: ExecutorSessionState;
  readonly capabilities: {
    readonly create: true;
    readonly send: true;
    readonly interrupt: true;
    readonly status: true;
    readonly dispose: true;
    readonly resume: boolean;
    readonly model_selection: boolean;
    readonly reasoning_effort: boolean;
    readonly mcp: boolean;
    readonly wallet_approval: false;
    readonly signing: false;
    readonly broadcast: false;
  };
  readonly mcp: {
    readonly enabled: boolean;
    readonly transport: ExecutorMcpTransport;
    readonly services: readonly ExecutorMcpService[];
    readonly tool_names: readonly ExecutorMcpToolName[];
  };
  readonly permission_scopes: readonly CordisPermissionScope[];
  readonly model?: string;
  readonly reasoning_effort?: HarnessSettings["reasoningEffort"];
  readonly working_directory: string;
  readonly restart_impact: CordisRestartImpact;
  readonly last_error?: ExecutorSessionLastError;
}

export function serializeExecutorSession(session: ExecutorSessionView): ExecutorSessionDocumentV2 {
  return {
    schema_version: 2,
    session_id: session.sessionId,
    protocol_session_id: session.protocolSessionId,
    ...(session.nativeSessionId ? { native_session_id: session.nativeSessionId } : {}),
    provider: session.provider,
    state: session.state,
    capabilities: {
      create: session.capabilities.create,
      send: session.capabilities.send,
      interrupt: session.capabilities.interrupt,
      status: session.capabilities.status,
      dispose: session.capabilities.dispose,
      resume: session.capabilities.resume,
      model_selection: session.capabilities.modelSelection,
      reasoning_effort: session.capabilities.reasoningEffort,
      mcp: session.capabilities.mcp,
      wallet_approval: session.capabilities.walletApproval,
      signing: session.capabilities.signing,
      broadcast: session.capabilities.broadcast,
    },
    mcp: {
      enabled: session.mcp.enabled,
      transport: session.mcp.transport,
      services: [...session.mcp.services],
      tool_names: [...session.mcp.toolNames],
    },
    permission_scopes: [...session.allowedScopes],
    ...(session.model ? { model: session.model } : {}),
    ...(session.reasoningEffort ? { reasoning_effort: session.reasoningEffort } : {}),
    working_directory: session.workingDirectory,
    restart_impact: session.restartImpact,
    ...(session.lastError ? { last_error: session.lastError } : {}),
  };
}
