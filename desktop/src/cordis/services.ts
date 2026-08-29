import type { CordisService } from "./health.js";
import type { HarnessId, HarnessSettings } from "../contracts.js";
import {
  ChainRpcError,
  createChainRpcAdapter,
  chainHealthServiceName,
  type ChainId,
  type ChainRpcAdapter,
  type ChainRpcConfig,
  type SecretHeaderResolver,
  resolveChainRpcPreset,
} from "../chains/rpc/index.js";
import type { ExecutorProbe } from "../executors/registry.js";
import { digestJson } from "./manifest.js";
import {
  assertRpcEndpointAccess,
  type ResolveHostAddresses,
  type RpcNetworkAccess,
} from "./network-policy.js";
import { parseExecutorRuntimeProfile, parseLoopbackWalletEndpoint } from "./runtime-config.js";

export interface DesktopServiceOptions {
  readonly fetcher?: typeof fetch;
  readonly resolveSecretHeaders?: SecretHeaderResolver;
  readonly resolveHostAddresses?: ResolveHostAddresses;
  readonly now?: () => number;
  readonly chainHealthTtlMs?: number;
  readonly executorProbe?: (provider: HarnessId, profile: HarnessSettings) => Promise<Pick<ExecutorProbe, "availability" | "version" | "reason">>;
  readonly mcpProbe?: () => Promise<boolean>;
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

function requiredString(settings: Readonly<Record<string, unknown>>, field: string): string {
  const value = settings[field];
  if (typeof value !== "string" || value.length === 0) throw new ChainRpcError("invalid_config", `invalid ${field}`);
  return value;
}

function rpcNetworkAccess(settings: Readonly<Record<string, unknown>>): RpcNetworkAccess {
  const value = settings.networkAccess;
  if (value !== "local" && value !== "private-network" && value !== "public") {
    throw new ChainRpcError("invalid_config", "invalid RPC network access");
  }
  return value;
}

export function chainRpcConfigFromSettings(chain: ChainId, settings: Readonly<Record<string, unknown>>): ChainRpcConfig {
  const rpcPresetId = requiredString(settings, "networkId");
  const usePreset = settings.nodeSource === "preset"
    || (settings.nodeSource === undefined && (typeof settings.endpoint !== "string" || settings.endpoint.length === 0));
  const preset = resolveChainRpcPreset(chain, rpcPresetId);
  const endpoint = usePreset ? preset.endpoint : requiredString(settings, "endpoint");
  const transport = usePreset ? preset.transport : requiredString(settings, "transport");
  const common = {
    endpoint,
    enabled: true,
    chainNetwork: preset.chainNetwork,
    rpcPresetId: preset.id,
    ...(typeof settings.credentialRef === "string" ? { credentialRef: settings.credentialRef } : {}),
    broadcastEnabled: settings.access === "broadcast",
    access: usePreset ? preset.access : rpcNetworkAccess(settings),
  };
  switch (chain) {
    case "bitcoin":
    case "fractal-bitcoin":
    case "bitcoin-cash":
    case "bsv":
      if (transport !== "json-rpc") throw new ChainRpcError("unsupported_transport", "unsupported Bitcoin-family RPC transport");
      return { ...common, chain, transport };
    case "kaspa":
      if (transport !== "https-api" && transport !== "json-rpc" && transport !== "wrpc") {
        throw new ChainRpcError("unsupported_transport", "unsupported Kaspa RPC transport");
      }
      return { ...common, chain, transport };
    case "chia":
      if (transport !== "https-rpc") throw new ChainRpcError("unsupported_transport", "unsupported Chia RPC transport");
      return { ...common, chain, transport };
    case "ergo":
      if (transport !== "rest") throw new ChainRpcError("unsupported_transport", "unsupported Ergo RPC transport");
      return { ...common, chain, transport };
  }
}

export async function createConfiguredChainRpcAdapter(
  chain: ChainId,
  settings: Readonly<Record<string, unknown>>,
  options: DesktopServiceOptions,
): Promise<ChainRpcAdapter> {
  const config = chainRpcConfigFromSettings(chain, settings);
  if (config.credentialRef && config.access !== "local" && new URL(config.endpoint).protocol !== "https:") {
    throw new ChainRpcError("invalid_config", "credentialed remote RPC endpoints require HTTPS");
  }
  await assertRpcEndpointAccess(config.endpoint, config.access ?? "public", options.resolveHostAddresses);
  return createChainRpcAdapter(config, {
    ...(options.fetcher ? { fetcher: options.fetcher } : {}),
    ...(options.resolveSecretHeaders ? { resolveSecretHeaders: options.resolveSecretHeaders } : {}),
  });
}

function chainRpcService(chain: ChainId, options: DesktopServiceOptions): CordisService {
  const walletGateway = httpService(chainHealthServiceName(chain), "/api/v1/node/status", options);
  const now = options.now ?? Date.now;
  const ttlMs = options.chainHealthTtlMs ?? 5_000;
  let cached: { readonly key: string; readonly expiresAt: number; readonly result: { status: "healthy" | "unhealthy"; message: string } } | undefined;
  let pending: { readonly key: string; readonly result: Promise<{ status: "healthy" | "unhealthy"; message: string }> } | undefined;
  let generation = 0;
  return {
    name: chainHealthServiceName(chain),
    health: async ({ settings }) => {
      if (settings.enabled === false) {
        generation += 1;
        cached = undefined;
        pending = undefined;
        return { status: "healthy", message: "chain RPC disabled" };
      }
      if (chain === "bitcoin" && (settings.transport === undefined || settings.transport === "wallet-gateway")) {
        return walletGateway.health({ settings });
      }
      const key = digestJson(settings);
      if (cached?.key === key && cached.expiresAt > now()) return cached.result;
      if (pending?.key === key) return pending.result;
      const result = (async (): Promise<{ status: "healthy" | "unhealthy"; message: string }> => {
        try {
          const health = await (await createConfiguredChainRpcAdapter(chain, settings, options)).health();
          return { status: "healthy", message: `${health.latencyMs}ms` };
        } catch (error) {
          return {
            status: "unhealthy",
            message: error instanceof ChainRpcError ? error.code : "RPC health unavailable",
          };
        }
      })();
      const currentGeneration = generation;
      pending = { key, result };
      const settled = await result;
      if (pending?.key === key) pending = undefined;
      if (generation === currentGeneration) cached = { key, expiresAt: now() + ttlMs, result: settled };
      return settled;
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
    chainRpcService("bitcoin", options),
    chainRpcService("fractal-bitcoin", options),
    chainRpcService("bitcoin-cash", options),
    chainRpcService("bsv", options),
    chainRpcService("kaspa", options),
    chainRpcService("chia", options),
    chainRpcService("ergo", options),
    executorService("codex", "executor.codex.health", options),
    executorService("deepseek", "executor.deepseek.health", options),
    executorService("claude-code", "executor.claude.code.health", options),
    {
      name: "indexer.health",
      health: async () => ({ status: "unhealthy", message: "indexer runtime unavailable" }),
    },
    {
      name: "mcp.health",
      health: async ({ settings }) => {
        if (settings.enabled !== true) return { status: "healthy", message: "MCP runtime disabled" };
        const available = await options.mcpProbe?.().catch(() => false) ?? false;
        return available
          ? { status: "healthy", message: "wallet MCP stdio available" }
          : { status: "degraded", message: "MCP runtime unavailable" };
      },
    },
    { name: "browser.health", health: async () => ({ status: "degraded", message: "browser runtime status unavailable" }) },
    { name: "backup.health", health: async () => ({ status: "degraded", message: "backup runtime unavailable" }) },
  ];
}
