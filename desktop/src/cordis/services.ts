import type { CordisService } from "./health.js";

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

interface DesktopServiceSettings {
  readonly walletNodeUrl: string;
  readonly mcpEnabled: boolean;
}

interface DesktopServiceOptions {
  readonly readSettings: () => Promise<DesktopServiceSettings>;
  readonly fetcher?: Fetcher;
}

function httpService(
  name: string,
  path: string,
  options: DesktopServiceOptions,
): CordisService {
  return {
    name,
    health: async () => {
      const settings = await options.readSettings();
      const endpoint = new URL(path, `${settings.walletNodeUrl.replace(/\/$/, "")}/`).toString();
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
      health: async () => (await options.readSettings()).mcpEnabled
        ? { status: "healthy" }
        : { status: "unhealthy", message: "MCP runtime disabled" },
    },
  ];
}
