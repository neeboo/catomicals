import { ChainRpcError } from "./errors.js";
import type { ChainId, ChainRpcAdapterOptions, ChainRpcConfig } from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TIMEOUT_MS = 120_000;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const SECRET_REFERENCE = /^secret-ref:[A-Za-z0-9_-]{16,128}$/;
const SAFE_HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_SECRET_HEADERS = new Set(["connection", "content-length", "host", "transfer-encoding"]);

export interface ValidatedRpcConfig {
  readonly endpoint: URL;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

interface RpcHttpClientOptions {
  readonly chain: ChainId;
  readonly config: ChainRpcConfig;
  readonly validated: ValidatedRpcConfig;
  readonly options: ChainRpcAdapterOptions;
}

function boundedInteger(value: number | undefined, fallback: number, maximum: number, field: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new ChainRpcError("invalid_config", `invalid ${field}`);
  }
  return resolved;
}

export function validateRpcConfig(config: ChainRpcConfig): ValidatedRpcConfig {
  let endpoint: URL;
  try {
    endpoint = new URL(config.endpoint);
  } catch {
    throw new ChainRpcError("invalid_config", "invalid RPC endpoint");
  }
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:") {
    throw new ChainRpcError("invalid_config", "RPC endpoint must use http or https");
  }
  if (endpoint.username !== "" || endpoint.password !== "") {
    throw new ChainRpcError("invalid_config", "RPC endpoint must not include userinfo");
  }
  if (endpoint.hash !== "" || endpoint.search !== "") {
    throw new ChainRpcError("invalid_config", "RPC endpoint must not include query or fragment data");
  }
  if (config.auth && !SECRET_REFERENCE.test(config.auth.credentialRef)) {
    throw new ChainRpcError("invalid_config", "invalid RPC credential reference");
  }
  return {
    endpoint,
    timeoutMs: boundedInteger(config.timeoutMs, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, "RPC timeout"),
    maxResponseBytes: boundedInteger(config.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES, "RPC response limit"),
  };
}

function validateSecretHeaders(headers: Readonly<Record<string, string>>): Headers {
  const validated = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    const normalized = name.toLowerCase();
    if (!SAFE_HEADER_NAME.test(name) || FORBIDDEN_SECRET_HEADERS.has(normalized) || /[\0\r\n]/.test(value)) {
      throw new ChainRpcError("credential_unavailable", "credential resolver returned invalid headers");
    }
    validated.set(name, value);
  }
  return validated;
}

async function readBoundedBody(response: Response, maximum: number): Promise<Uint8Array> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximum) {
    await response.body?.cancel().catch(() => undefined);
    throw new ChainRpcError("response_too_large", "RPC response exceeded configured limit");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel().catch(() => undefined);
        throw new ChainRpcError("response_too_large", "RPC response exceeded configured limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ChainRpcError("invalid_response", "RPC returned invalid JSON");
  }
}

export class RpcHttpClient {
  readonly #chain: ChainId;
  readonly #config: ChainRpcConfig;
  readonly #endpoint: URL;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #options: ChainRpcAdapterOptions;

  constructor(options: RpcHttpClientOptions) {
    this.#chain = options.chain;
    this.#config = options.config;
    this.#endpoint = options.validated.endpoint;
    this.#timeoutMs = options.validated.timeoutMs;
    this.#maxResponseBytes = options.validated.maxResponseBytes;
    this.#options = options.options;
  }

  endpoint(): URL {
    return new URL(this.#endpoint.toString());
  }

  async request(path: string | undefined, method: "GET" | "POST", body?: unknown): Promise<unknown> {
    const endpoint = path === undefined ? this.endpoint() : this.#pathUrl(path);
    const headers = await this.#headers();
    if (body !== undefined) headers.set("content-type", "application/json");
    let response: Response;
    try {
      response = await (this.#options.fetcher ?? fetch)(endpoint, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        redirect: "manual",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      if (error instanceof ChainRpcError) throw error;
      if (error instanceof DOMException && (error.name === "TimeoutError" || error.name === "AbortError")) {
        throw new ChainRpcError("timeout", "RPC request timed out");
      }
      throw new ChainRpcError("remote_error", "RPC request failed");
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel().catch(() => undefined);
      throw new ChainRpcError("redirect_rejected", "RPC redirect rejected");
    }
    try {
      const bytes = await readBoundedBody(response, this.#maxResponseBytes);
      if (!response.ok) throw new ChainRpcError("remote_error", `RPC returned HTTP ${response.status}`);
      return parseJson(bytes);
    } catch (error) {
      if (error instanceof ChainRpcError) throw error;
      if (error instanceof DOMException && (error.name === "TimeoutError" || error.name === "AbortError")) {
        throw new ChainRpcError("timeout", "RPC request timed out");
      }
      throw new ChainRpcError("remote_error", "RPC response failed");
    }
  }

  #pathUrl(path: string): URL {
    if (!path.startsWith("/") || path.includes("\\") || path.includes("\0")) {
      throw new ChainRpcError("invalid_request", "invalid RPC path");
    }
    const endpoint = this.endpoint();
    const basePath = endpoint.pathname.endsWith("/") ? endpoint.pathname.slice(0, -1) : endpoint.pathname;
    endpoint.pathname = `${basePath}${path}`;
    return endpoint;
  }

  async #headers(): Promise<Headers> {
    if (!this.#config.auth) return new Headers();
    if (!this.#options.resolveSecretHeaders) {
      throw new ChainRpcError("credential_unavailable", "RPC credentials are unavailable");
    }
    let resolved: Readonly<Record<string, string>>;
    try {
      resolved = await this.#options.resolveSecretHeaders(this.#config.auth.credentialRef, {
        chain: this.#chain,
        endpointOrigin: this.#endpoint.origin,
      });
    } catch {
      throw new ChainRpcError("credential_unavailable", "RPC credentials are unavailable");
    }
    return validateSecretHeaders(resolved);
  }
}

export function requireIdentifier(value: string, field: string): string {
  if (value.length < 1 || value.length > 256 || !/^[A-Za-z0-9:_-]+$/.test(value)) {
    throw new ChainRpcError("invalid_request", `invalid ${field}`);
  }
  return value;
}

export function requireRecord(value: unknown, message = "RPC returned an invalid response"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ChainRpcError("invalid_response", message);
  }
  return value as Record<string, unknown>;
}

export function requireHeight(value: unknown): number {
  const height = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (typeof height !== "number" || !Number.isSafeInteger(height) || height < 0) {
    throw new ChainRpcError("invalid_response", "RPC returned an invalid chain height");
  }
  return height;
}

export function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= 512 ? value : undefined;
}
