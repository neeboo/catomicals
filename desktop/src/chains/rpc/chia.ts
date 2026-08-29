import { BaseChainRpcAdapter } from "./base.js";
import { ChainRpcError } from "./errors.js";
import { optionalString, requireHeight, requireIdentifier, requireRecord, RpcHttpClient, validateRpcConfig } from "./http.js";
import type {
  BroadcastResult,
  ChainRpcAdapter,
  ChainRpcAdapterOptions,
  ChainRpcConfig,
  ChainTip,
  RawChainObject,
  RpcHealth,
} from "./types.js";

type ChiaRpcConfig = Extract<ChainRpcConfig, { chain: "chia" }>;

function requireChiaSuccess(value: unknown): Record<string, unknown> {
  const response = requireRecord(value);
  if (response.success !== true) throw new ChainRpcError("remote_error", "Chia RPC method failed");
  return response;
}

function parseJsonObject(raw: string, field: string): Record<string, unknown> {
  if (raw.length < 2 || raw.length > 8 * 1024 * 1024) throw new ChainRpcError("invalid_request", `invalid ${field}`);
  try {
    return requireRecord(JSON.parse(raw), `invalid ${field}`);
  } catch (error) {
    if (error instanceof ChainRpcError) throw error;
    throw new ChainRpcError("invalid_request", `invalid ${field}`);
  }
}

export class ChiaRpcAdapter extends BaseChainRpcAdapter implements ChainRpcAdapter {
  readonly chain = "chia" as const;
  readonly #http: RpcHttpClient;

  constructor(config: ChiaRpcConfig, options: ChainRpcAdapterOptions = {}) {
    super(config, options);
    this.#http = new RpcHttpClient({ chain: this.chain, config, validated: validateRpcConfig(config), options });
  }

  health(): Promise<RpcHealth> {
    return this.measureHealth(async () => requireChiaSuccess(await this.#http.request("/healthz", "POST", {})));
  }

  async getTip(): Promise<ChainTip> {
    const response = requireChiaSuccess(await this.#http.request("/get_blockchain_state", "POST", {}));
    const state = requireRecord(response.blockchain_state);
    const peak = requireRecord(state.peak);
    const hash = optionalString(peak.header_hash);
    return { height: requireHeight(peak.height), ...(hash ? { hash } : {}) };
  }

  async getTransaction(transactionId: string): Promise<RawChainObject> {
    const id = requireIdentifier(transactionId, "transaction identifier");
    const response = requireChiaSuccess(await this.#http.request("/get_mempool_item_by_tx_id", "POST", { tx_id: id }));
    return { chain: this.chain, id, raw: response.mempool_item };
  }

  async broadcast(rawTransaction: string): Promise<BroadcastResult> {
    this.requireBroadcastEnabled();
    const spendBundle = parseJsonObject(rawTransaction, "Chia spend bundle");
    const response = requireChiaSuccess(await this.#http.request("/push_tx", "POST", { spend_bundle: spendBundle }));
    const transactionId = optionalString(response.transaction_id);
    return { accepted: true, ...(transactionId ? { transactionId } : {}) };
  }
}
