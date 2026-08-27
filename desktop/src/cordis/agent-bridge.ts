import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { parsePluginId } from "./manifest.js";
import { cordisAccess, type CordisAccessContext, type CordisPermissionScope } from "./permissions.js";
import { parseSettingsPatch, type CordisSettingValue, type CordisSettingsPatch } from "./settings.js";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_REQUEST_DEPTH = 8;
const MAX_REQUEST_NODES = 512;
const DEFAULT_TOKEN_LIFETIME_MS = 15 * 60 * 1000;
const DEFAULT_DRAIN_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_SESSION_TOKENS = 256;
const MAX_IN_FLIGHT_REQUESTS = 64;
const ROUTE_PREFIX = "/v1/cordis/";

export const CORDIS_AGENT_PERMISSION_SCOPES = Object.freeze([
  "plugin.catalog.read",
  "plugin.manifest.read",
  "plugin.settings_schema.read",
  "plugin.health.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
] as const satisfies readonly CordisPermissionScope[]);

type CordisAgentPermissionScope = (typeof CORDIS_AGENT_PERMISSION_SCOPES)[number];

export interface CordisAgentBridgeHost {
  listPlugins(access: CordisAccessContext): unknown;
  readManifest(pluginId: unknown, access: CordisAccessContext): unknown;
  readSettingsSchema(pluginId: unknown, access: CordisAccessContext): unknown;
  readHealth(pluginId: unknown, access: CordisAccessContext): Promise<unknown>;
  validateSettingsPatch(pluginId: unknown, patch: unknown, access: CordisAccessContext): unknown;
  createSettingsIntent(pluginId: unknown, patch: unknown, access: CordisAccessContext): Promise<unknown>;
}

export interface CordisAgentSessionIdentity {
  readonly executorSessionId: string;
  readonly protocolSessionId: string;
}

export interface CordisAgentSessionCredential {
  readonly endpoint: string;
  readonly token: string;
  readonly expiresAt: string;
}

export interface CordisAgentBridge {
  readonly endpoint: string;
  issueSessionToken(identity: CordisAgentSessionIdentity): CordisAgentSessionCredential;
  revokeSession(identity: CordisAgentSessionIdentity): void;
  close(): Promise<void>;
}

export interface ExternalSettingsPatch {
  readonly schema_version: number;
  readonly changes: Readonly<Record<string, CordisSettingValue>>;
}

interface TokenRecord extends CordisAgentSessionIdentity {
  readonly scopes: readonly CordisAgentPermissionScope[];
  readonly expiresAtMs: number;
}

interface RouteDefinition {
  readonly scope: CordisAgentPermissionScope;
  readonly invoke: (
    host: CordisAgentBridgeHost,
    body: unknown,
    access: CordisAccessContext,
  ) => unknown | Promise<unknown>;
}

interface StartCordisAgentBridgeOptions {
  readonly host: CordisAgentBridgeHost;
  readonly now?: () => Date;
  readonly tokenLifetimeMs?: number;
  readonly drainTimeoutMs?: number;
  readonly maxSessionTokens?: number;
}

class RequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
}

function inspectClosedValue(value: unknown): void {
  let nodes = 0;
  const visit = (item: unknown, depth: number): void => {
    nodes += 1;
    if (nodes > MAX_REQUEST_NODES || depth > MAX_REQUEST_DEPTH) {
      throw new RequestError(400, "invalid_request", "invalid request");
    }
    if (item === null || typeof item === "string" || typeof item === "boolean"
      || (typeof item === "number" && Number.isSafeInteger(item))) return;
    if (Array.isArray(item)) {
      for (const child of item) visit(child, depth + 1);
      return;
    }
    const input = plainRecord(item);
    for (const [key, child] of Object.entries(input)) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") {
        throw new RequestError(400, "invalid_request", "invalid request");
      }
      visit(child, depth + 1);
    }
  };
  visit(value, 0);
}

function parseEmptyArguments(value: unknown): Record<string, never> {
  const input = plainRecord(value);
  exactFields(input, []);
  return {};
}

function parsePluginArguments(value: unknown): { pluginId: string } {
  const input = plainRecord(value);
  exactFields(input, ["plugin_id"]);
  try {
    return { pluginId: parsePluginId(input.plugin_id) };
  } catch {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
}

function parsePatchArguments(value: unknown): { pluginId: string; patch: CordisSettingsPatch } {
  const input = plainRecord(value);
  exactFields(input, ["plugin_id", "patch"]);
  let patch: CordisSettingsPatch;
  try {
    patch = externalPatchToCordis(input.patch);
  } catch {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
  try {
    return { pluginId: parsePluginId(input.plugin_id), patch };
  } catch {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
}

export function externalPatchToCordis(value: unknown): CordisSettingsPatch {
  inspectClosedValue(value);
  const input = plainRecord(value);
  exactFields(input, ["schema_version", "changes"]);
  const changes = plainRecord(input.changes);
  if (Object.keys(changes).length === 0) throw new Error("invalid settings changes");
  return parseSettingsPatch({
    schemaVersion: input.schema_version,
    changes: Object.entries(changes).map(([id, settingValue]) => ({ id, value: settingValue })),
  });
}

export function cordisPatchToExternal(value: unknown): ExternalSettingsPatch {
  const patch = parseSettingsPatch(value);
  return {
    schema_version: patch.schemaVersion,
    changes: Object.fromEntries(patch.changes.map((change) => [change.id, change.value])),
  };
}

const routes: Readonly<Record<string, RouteDefinition>> = Object.freeze({
  list_plugins: {
    scope: "plugin.catalog.read",
    invoke: (host, body, access) => {
      parseEmptyArguments(body);
      return host.listPlugins(access);
    },
  },
  read_plugin_manifest: {
    scope: "plugin.manifest.read",
    invoke: (host, body, access) => host.readManifest(parsePluginArguments(body).pluginId, access),
  },
  read_plugin_settings_schema: {
    scope: "plugin.settings_schema.read",
    invoke: (host, body, access) => host.readSettingsSchema(parsePluginArguments(body).pluginId, access),
  },
  read_plugin_health: {
    scope: "plugin.health.read",
    invoke: (host, body, access) => host.readHealth(parsePluginArguments(body).pluginId, access),
  },
  validate_plugin_settings_patch: {
    scope: "plugin.settings.validate",
    invoke: (host, body, access) => {
      const input = parsePatchArguments(body);
      return host.validateSettingsPatch(input.pluginId, input.patch, access);
    },
  },
  create_plugin_settings_intent: {
    scope: "plugin.settings_intent.create",
    invoke: (host, body, access) => {
      const input = parsePatchArguments(body);
      return host.createSettingsIntent(input.pluginId, input.patch, access);
    },
  },
});

function digestToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function assertExecutorSessionId(value: string): void {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(value)) throw new Error("invalid executor session id");
}

function assertProtocolSessionId(value: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error("invalid protocol session id");
  }
}

function assertSessionIdentity(identity: CordisAgentSessionIdentity): void {
  if (!identity || typeof identity !== "object") throw new Error("invalid agent session identity");
  assertExecutorSessionId(identity.executorSessionId);
  assertProtocolSessionId(identity.protocolSessionId);
}

function sessionKey(identity: CordisAgentSessionIdentity): string {
  return `${identity.executorSessionId}\0${identity.protocolSessionId}`;
}

export function isLoopbackAddress(address: string | undefined): boolean {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function baseHeaders(): Readonly<Record<string, string>> {
  return {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
  };
}

function writeJson(response: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) {
    const fallback = JSON.stringify({
      ok: false,
      error: { code: "response_too_large", message: "Cordis response too large" },
    });
    response.writeHead(502, { ...baseHeaders(), "Content-Length": String(Buffer.byteLength(fallback, "utf8")) });
    response.end(fallback);
    return;
  }
  response.writeHead(status, { ...baseHeaders(), "Content-Length": String(Buffer.byteLength(body, "utf8")) });
  response.end(body);
}

function writeError(response: ServerResponse, error: RequestError): void {
  writeJson(response, error.status, { ok: false, error: { code: error.code, message: error.message } });
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  const declaredLength = request.headers["content-length"];
  if (declaredLength !== undefined) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new RequestError(400, "invalid_request", "invalid request");
    }
    if (length > MAX_REQUEST_BYTES) {
      request.resume();
      throw new RequestError(413, "request_too_large", "request too large");
    }
  }
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const rawChunk of request) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk as Uint8Array);
    bytes += chunk.byteLength;
    if (bytes > MAX_REQUEST_BYTES) {
      request.resume();
      throw new RequestError(413, "request_too_large", "request too large");
    }
    chunks.push(chunk);
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8")) as unknown;
  } catch {
    throw new RequestError(400, "invalid_request", "invalid request");
  }
  inspectClosedValue(value);
  return value;
}

function routeFromRequest(request: IncomingMessage): RouteDefinition {
  let parsed: URL;
  try {
    parsed = new URL(request.url ?? "", "http://127.0.0.1");
  } catch {
    throw new RequestError(404, "route_not_found", "route not found");
  }
  if (parsed.search !== "" || parsed.hash !== "" || !parsed.pathname.startsWith(ROUTE_PREFIX)) {
    throw new RequestError(404, "route_not_found", "route not found");
  }
  const routeName = parsed.pathname.slice(ROUTE_PREFIX.length);
  const route = routes[routeName];
  if (!route || routeName.includes("/")) throw new RequestError(404, "route_not_found", "route not found");
  return route;
}

function tokenFromRequest(request: IncomingMessage): string {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string") throw new RequestError(401, "unauthorized", "unauthorized");
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization);
  if (!match) throw new RequestError(401, "unauthorized", "unauthorized");
  return match[1]!;
}

function beginServerClose(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeIdleConnections();
  });
}

async function drainRequests(inFlight: ReadonlySet<Promise<void>>, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (inFlight.size > 0) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return false;
    const drained = await new Promise<boolean>((resolve) => {
      const timeout = setTimeout(() => resolve(false), remaining);
      void Promise.allSettled([...inFlight]).then(() => {
        clearTimeout(timeout);
        resolve(true);
      });
    });
    if (!drained) return false;
  }
  return true;
}

export async function startCordisAgentBridge(options: StartCordisAgentBridgeOptions): Promise<CordisAgentBridge> {
  const now = options.now ?? (() => new Date());
  const tokenLifetimeMs = options.tokenLifetimeMs ?? DEFAULT_TOKEN_LIFETIME_MS;
  const drainTimeoutMs = options.drainTimeoutMs ?? DEFAULT_DRAIN_TIMEOUT_MS;
  const maxSessionTokens = options.maxSessionTokens ?? DEFAULT_MAX_SESSION_TOKENS;
  if (!Number.isSafeInteger(tokenLifetimeMs) || tokenLifetimeMs <= 0 || tokenLifetimeMs > 24 * 60 * 60 * 1000) {
    throw new Error("invalid agent token lifetime");
  }
  if (!Number.isSafeInteger(drainTimeoutMs) || drainTimeoutMs <= 0 || drainTimeoutMs > 30_000) {
    throw new Error("invalid agent bridge drain timeout");
  }
  if (!Number.isSafeInteger(maxSessionTokens) || maxSessionTokens <= 0 || maxSessionTokens > 4_096) {
    throw new Error("invalid agent session limit");
  }
  const tokens = new Map<string, TokenRecord>();
  const sessionTokens = new Map<string, string>();
  const inFlight = new Set<Promise<void>>();
  const access = cordisAccess(...CORDIS_AGENT_PERMISSION_SCOPES);
  const sweepIntervalMs = Math.min(tokenLifetimeMs, 60_000);
  let nextTokenSweepAtMs = 0;
  let endpoint = "";
  let closed = false;
  let closePromise: Promise<void> | null = null;

  const deleteToken = (tokenDigest: string, record: TokenRecord): void => {
    tokens.delete(tokenDigest);
    const key = sessionKey(record);
    if (sessionTokens.get(key) === tokenDigest) sessionTokens.delete(key);
  };
  const sweepExpiredTokens = (currentTimeMs: number): void => {
    if (currentTimeMs < nextTokenSweepAtMs) return;
    for (const [tokenDigest, record] of tokens) {
      if (record.expiresAtMs <= currentTimeMs) deleteToken(tokenDigest, record);
    }
    nextTokenSweepAtMs = currentTimeMs + sweepIntervalMs;
  };

  const handleRequest = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    try {
      if (closed) throw new RequestError(503, "bridge_unavailable", "bridge unavailable");
      if (!isLoopbackAddress(request.socket.remoteAddress)) {
        throw new RequestError(403, "forbidden_request", "forbidden request");
      }
      if (request.headers.origin !== undefined || request.headers.cookie !== undefined) {
        throw new RequestError(403, "forbidden_request", "forbidden request");
      }
      if (request.method !== "POST") {
        request.resume();
        throw new RequestError(405, "method_not_allowed", "method not allowed");
      }
      const route = routeFromRequest(request);
      const token = tokenFromRequest(request);
      const tokenDigest = digestToken(token);
      const record = tokens.get(tokenDigest);
      if (!record || record.expiresAtMs <= now().getTime()) {
        if (record) deleteToken(tokenDigest, record);
        request.resume();
        throw new RequestError(401, "unauthorized", "unauthorized");
      }
      if (!record.scopes.includes(route.scope)) {
        request.resume();
        throw new RequestError(403, "forbidden_request", "forbidden request");
      }
      if (request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
        request.resume();
        throw new RequestError(415, "unsupported_media_type", "content type must be application/json");
      }
      const body = await readBody(request);
      const result = await route.invoke(options.host, body, access);
      writeJson(response, 200, { ok: true, result });
    } catch (error) {
      if (response.headersSent || response.destroyed) return;
      if (error instanceof RequestError) {
        writeError(response, error);
      } else {
        writeError(response, new RequestError(502, "cordis_request_failed", "Cordis request failed"));
      }
    }
  };

  const server = createServer((request, response) => {
    if (inFlight.size >= MAX_IN_FLIGHT_REQUESTS) {
      request.resume();
      writeError(response, new RequestError(503, "bridge_busy", "bridge busy"));
      return;
    }
    let work: Promise<void>;
    work = handleRequest(request, response).finally(() => { inFlight.delete(work); });
    inFlight.add(work);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("agent bridge address unavailable"));
        return;
      }
      endpoint = `http://127.0.0.1:${(address as AddressInfo).port}`;
      resolve();
    });
  });

  return {
    get endpoint() { return endpoint; },
    issueSessionToken(identity) {
      if (closed) throw new Error("agent bridge closed");
      assertSessionIdentity(identity);
      const currentTimeMs = now().getTime();
      sweepExpiredTokens(currentTimeMs);
      const key = sessionKey(identity);
      const previousTokenDigest = sessionTokens.get(key);
      if (previousTokenDigest) tokens.delete(previousTokenDigest);
      if (tokens.size >= maxSessionTokens) throw new Error("too many active agent sessions");
      let token: string;
      let tokenDigest: string;
      do {
        token = randomBytes(32).toString("base64url");
        tokenDigest = digestToken(token);
      } while (tokens.has(tokenDigest));
      const expiresAtMs = currentTimeMs + tokenLifetimeMs;
      tokens.set(tokenDigest, {
        executorSessionId: identity.executorSessionId,
        protocolSessionId: identity.protocolSessionId,
        scopes: CORDIS_AGENT_PERMISSION_SCOPES,
        expiresAtMs,
      });
      sessionTokens.set(key, tokenDigest);
      return { endpoint, token, expiresAt: new Date(expiresAtMs).toISOString() };
    },
    revokeSession(identity) {
      assertSessionIdentity(identity);
      const key = sessionKey(identity);
      const tokenDigest = sessionTokens.get(key);
      if (tokenDigest) tokens.delete(tokenDigest);
      sessionTokens.delete(key);
    },
    close() {
      if (closePromise) return closePromise;
      closed = true;
      tokens.clear();
      sessionTokens.clear();
      const serverClosed = beginServerClose(server);
      closePromise = (async () => {
        const drained = await drainRequests(inFlight, drainTimeoutMs);
        if (!drained) server.closeAllConnections();
        else server.closeIdleConnections();
        await serverClosed;
        if (!drained) throw new Error("agent bridge drain timeout");
      })().finally(() => { tokens.clear(); sessionTokens.clear(); });
      return closePromise;
    },
  };
}
