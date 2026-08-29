import { ChainRpcError } from "./errors.js";
import type { ChainId, ChainRpcAdapterOptions, ChainRpcConfig, RpcHealth } from "./types.js";

export abstract class BaseChainRpcAdapter {
  abstract readonly chain: ChainId;
  protected readonly config: ChainRpcConfig;
  readonly #now: () => number;

  protected constructor(config: ChainRpcConfig, options: ChainRpcAdapterOptions) {
    this.config = config;
    this.#now = options.now ?? Date.now;
  }

  protected async measureHealth(probe: () => Promise<unknown>): Promise<RpcHealth> {
    const startedAt = this.#now();
    await probe();
    return {
      chain: this.chain,
      ok: true,
      latencyMs: Math.max(0, this.#now() - startedAt),
    };
  }

  protected requireBroadcastEnabled(): void {
    if (this.config.broadcastEnabled !== true) {
      throw new ChainRpcError("broadcast_disabled", "RPC broadcast is disabled");
    }
  }
}
