export interface WalletProxyRequest {
  readonly path: string;
  readonly method: "GET" | "POST";
  readonly body?: string;
}

export interface WalletProxyResponse {
  readonly status: number;
  readonly body: string;
  readonly contentType: string;
}

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

interface WalletProxyOptions {
  readonly walletEndpoint: () => Promise<string>;
  readonly fetcher?: Fetcher;
}

const identifier = "[0-9A-Za-z][0-9A-Za-z._:-]{0,127}";
const allowedRoutes: readonly { method: WalletProxyRequest["method"]; path: RegExp }[] = [
  { method: "GET", path: /^\/api\/v1\/(?:node|wallet|signer)\/status$/ },
  { method: "GET", path: /^\/api\/v1\/chains\/(?:status|config)$/ },
  { method: "GET", path: /^\/api\/v1\/webauthn\/credentials$/ },
  { method: "GET", path: /^\/api\/v1\/intents$/ },
  { method: "GET", path: new RegExp(`^/api/v1/intents/${identifier}$`) },
  { method: "GET", path: new RegExp(`^/api/v1/transactions/intents/${identifier}$`) },
  { method: "GET", path: new RegExp(`^/api/v1/signing/${identifier}/status$`) },
  { method: "GET", path: new RegExp(`^/api/v1/signing/jobs/${identifier}$`) },
  { method: "GET", path: /^\/api\/v1\/chat\/state$/ },
  { method: "GET", path: new RegExp(`^/api/v1/chat/messages/${identifier}$`) },
  { method: "POST", path: /^\/api\/v1\/intents$/ },
  { method: "POST", path: /^\/api\/v1\/chains\/config$/ },
  { method: "POST", path: /^\/api\/v1\/signing\/jobs$/ },
  { method: "POST", path: new RegExp(`^/api/v1/signing/jobs/${identifier}/execute$`) },
  { method: "POST", path: new RegExp(`^/api/v1/intents/${identifier}/cancel$`) },
  { method: "POST", path: /^\/api\/v1\/transactions\/inspect$/ },
  { method: "POST", path: /^\/api\/v1\/transactions\/intents$/ },
  { method: "POST", path: /^\/api\/v1\/webauthn\/register\/(?:start|finish)$/ },
  { method: "POST", path: new RegExp(`^/api/v1/intents/${identifier}/approve/(?:start|finish)$`) },
  { method: "POST", path: /^\/api\/v1\/chat\/messages$/ },
] as const;

const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function parseRequest(value: unknown): WalletProxyRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid wallet proxy request");
  const input = value as Record<string, unknown>;
  const keys = Object.keys(input).sort().join(",");
  if (keys !== "method,path" && keys !== "body,method,path") throw new Error("invalid wallet proxy fields");
  if (input.method !== "GET" && input.method !== "POST") throw new Error("invalid wallet API method");
  if (typeof input.path !== "string" || input.path.length > 256) {
    throw new Error("invalid wallet API path");
  }
  const method = input.method;
  const path = input.path;
  if (!allowedRoutes.some((route) => route.method === method && route.path.test(path))) {
    throw new Error("invalid wallet API path");
  }
  if (input.method === "GET" && input.body !== undefined) throw new Error("wallet GET request cannot include a body");
  if (input.body !== undefined && (typeof input.body !== "string" || Buffer.byteLength(input.body, "utf8") > MAX_REQUEST_BYTES)) {
    throw new Error("invalid wallet API body");
  }
  return {
    path,
    method,
    ...(typeof input.body === "string" ? { body: input.body } : {}),
  };
}

export function createWalletProxy(options: WalletProxyOptions): (value: unknown) => Promise<WalletProxyResponse> {
  return async (value) => {
    const request = parseRequest(value);
    const endpoint = await options.walletEndpoint();
    const response = await (options.fetcher ?? fetch)(`${endpoint}${request.path}`, {
      method: request.method,
      credentials: "omit",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      ...(request.body === undefined ? {} : {
        headers: { "Content-Type": "application/json" },
        body: request.body,
      }),
    });
    const declaredLength = Number(response.headers.get("Content-Length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) throw new Error("wallet response too large");
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) throw new Error("wallet response too large");
    const contentType = response.headers.get("Content-Type") ?? "application/octet-stream";
    return { status: response.status, body, contentType: contentType.slice(0, 128) };
  };
}
