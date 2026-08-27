import type { CordisService } from "./health.js";
import type { HarnessId, HarnessSettings } from "../contracts.js";
import type { ExecutorProbe } from "../executors/registry.js";
import { parseExecutorRuntimeProfile, parseLoopbackWalletEndpoint } from "./runtime-config.js";

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

interface DesktopServiceOptions {
  readonly fetcher?: Fetcher;
  readonly executorProbe?: (provider: HarnessId, profile: HarnessSettings) => Promise<Pick<ExecutorProbe, "availability" | "version" | "reason">>;
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
      let endpoint: string;
      try {
        endpoint = new URL(path, `${parseLoopbackWalletEndpoint(configuredEndpoint)}/`).toString();
      } catch (error) {
        return { status: "unhealthy", message: error instanceof Error ? error.message : "invalid loopback endpoint" };
      }
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

function executorService(provider: HarnessId, name: string, options: DesktopServiceOptions): CordisService {
  return {
    name,
    health: async ({ settings }) => {
      if (!options.executorProbe) return { status: "degraded", message: "executor runtime unavailable" };
      try {
        const probe = await options.executorProbe(provider, parseExecutorRuntimeProfile(settings));
        return probe.availability === "available"
          ? { status: "healthy", ...(probe.version ? { message: probe.version } : {}) }
          : { status: "degraded", message: probe.reason ?? "executor unavailable" };
      } catch {
        return { status: "degraded", message: "executor probe failed" };
      }
    },
  };
}

export function createDesktopCordisServices(options: DesktopServiceOptions): readonly CordisService[] {
  return [
    httpService("walletd.health", "/api/v1/wallet/status", options),
    httpService("bitcoin.node.health", "/api/v1/node/status", options),
    executorService("codex", "executor.codex.health", options),
    executorService("deepseek", "executor.deepseek.health", options),
    executorService("claude-code", "executor.claude.code.health", options),
    {
      name: "indexer.health",
      health: async () => ({ status: "unhealthy", message: "indexer runtime unavailable" }),
    },
    {
      name: "mcp.health",
      health: async ({ settings }) => settings.enabled === true
        ? { status: "degraded", message: "MCP runtime unavailable" }
        : { status: "healthy", message: "MCP runtime disabled" },
    },
    { name: "browser.health", health: async () => ({ status: "degraded", message: "browser runtime status unavailable" }) },
    { name: "backup.health", health: async () => ({ status: "degraded", message: "backup runtime unavailable" }) },
  ];
}
