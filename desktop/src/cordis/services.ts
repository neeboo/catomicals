import type { CordisService } from "./health.js";

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

interface DesktopServiceOptions {
  readonly fetcher?: Fetcher;
}

function httpService(
  name: string,
  path: string,
  options: DesktopServiceOptions,
): CordisService {
  return {
    name,
    health: async ({ settings }) => {
      const configuredEndpoint = settings.endpoint;
      if (typeof configuredEndpoint !== "string") return { status: "unhealthy", message: "endpoint unavailable" };
      const endpoint = new URL(path, `${configuredEndpoint.replace(/\/$/, "")}/`).toString();
      try {
        const response = await (options.fetcher ?? fetch)(endpoint, {
          method: "GET",
          credentials: "omit",
          redirect: "error",
          signal: AbortSignal.timeout(2_000),
        });
        return response.ok
          ? { status: "healthy" as const }
          : { status: "unhealthy" as const, message: `HTTP ${response.status}` };
      } catch {
        return { status: "unhealthy" as const, message: "service unavailable" };
      }
    },
  };
}

export function createDesktopCordisServices(options: DesktopServiceOptions): readonly CordisService[] {
  return [
    httpService("walletd.health", "/api/v1/wallet/status", options),
    httpService("bitcoin.node.health", "/api/v1/node/status", options),
    {
      name: "indexer.health",
      health: async () => ({ status: "unhealthy", message: "indexer runtime unavailable" }),
    },
    {
      name: "mcp.health",
      health: async ({ settings }) => settings.enabled === true
        ? { status: "unhealthy", message: "MCP runtime unavailable" }
        : { status: "unhealthy", message: "MCP runtime disabled" },
    },
  ];
}
