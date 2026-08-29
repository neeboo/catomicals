import { BitcoinFamilyRpcAdapter } from "./bitcoin-family.js";
import { ChiaRpcAdapter } from "./chia.js";
import { ChainRpcError } from "./errors.js";
import { ErgoRpcAdapter } from "./ergo.js";
import { KaspaRpcAdapter } from "./kaspa.js";
import { chainHealthServiceName } from "./types.js";
import type { ChainRpcAdapter, ChainRpcAdapterOptions, ChainRpcConfig, RpcHealth } from "./types.js";

export { ChainRpcError } from "./errors.js";
export type { ChainRpcErrorCode } from "./errors.js";
export { CHAIN_RPC_PRESETS, chainRpcNetworkIds, resolveChainRpcPreset } from "./presets.js";
export type { ChainRpcPreset, ChainRpcPresetAccess, ChainRpcPresetTransport } from "./presets.js";
export {
  CHAIN_IDS,
  CHAIN_RPC_PERMISSIONS,
  chainHealthServiceName,
} from "./types.js";
export type {
  BitcoinFamilyChainId,
  BroadcastResult,
  ChainId,
  ChainRpcAdapter,
  ChainRpcAdapterOptions,
  ChainRpcConfig,
  ChainTip,
  KaspaTransport,
  RawChainObject,
  RpcHealth,
  SecretHeaderContext,
  SecretHeaderResolver,
} from "./types.js";

export function createChainRpcAdapter(
  config: ChainRpcConfig,
  options: ChainRpcAdapterOptions = {},
): ChainRpcAdapter {
  switch (config.chain) {
    case "bitcoin":
    case "fractal-bitcoin":
    case "bitcoin-cash":
    case "bsv":
      if (config.transport !== undefined && config.transport !== "json-rpc") {
        throw new ChainRpcError("unsupported_transport", "unsupported Bitcoin-family RPC transport");
      }
      return new BitcoinFamilyRpcAdapter(config, options);
    case "kaspa":
      return new KaspaRpcAdapter(config, options);
    case "chia":
      if (config.transport !== undefined && config.transport !== "https-rpc") {
        throw new ChainRpcError("unsupported_transport", "unsupported Chia RPC transport");
      }
      return new ChiaRpcAdapter(config, options);
    case "ergo":
      if (config.transport !== undefined && config.transport !== "rest") {
        throw new ChainRpcError("unsupported_transport", "unsupported Ergo RPC transport");
      }
      return new ErgoRpcAdapter(config, options);
    default: {
      const exhaustive: never = config;
      throw new ChainRpcError("invalid_config", `unsupported chain: ${String(exhaustive)}`);
    }
  }
}

export class ChainRpcRegistry {
  readonly #adapters: ReadonlyMap<string, ChainRpcAdapter>;

  constructor(configs: readonly ChainRpcConfig[], options: ChainRpcAdapterOptions = {}) {
    const adapters = new Map<string, ChainRpcAdapter>();
    for (const config of configs) {
      if (config.enabled === false) continue;
      if (adapters.has(config.chain)) throw new ChainRpcError("invalid_config", "duplicate chain RPC configuration");
      adapters.set(config.chain, createChainRpcAdapter(config, options));
    }
    this.#adapters = adapters;
  }

  list(): readonly ChainRpcAdapter[] {
    return [...this.#adapters.values()];
  }

  healthBindings(): readonly { readonly name: string; health(): Promise<RpcHealth> }[] {
    return this.list().map((adapter) => ({
      name: chainHealthServiceName(adapter.chain),
      health: () => adapter.health(),
    }));
  }

  get(chain: string): ChainRpcAdapter {
    const adapter = this.#adapters.get(chain);
    if (!adapter) throw new ChainRpcError("invalid_config", "chain RPC adapter is not enabled");
    return adapter;
  }
}
