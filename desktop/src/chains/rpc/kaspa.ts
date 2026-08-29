import { BaseChainRpcAdapter } from "./base.js";
import { ChainRpcError } from "./errors.js";
import { optionalString, requireHeight, requireIdentifier, requireRecord, RpcHttpClient, validateRpcConfig } from "./http.js";
import { JsonRpcClient } from "./json-rpc.js";
import type {
  BroadcastResult,
  ChainRpcAdapter,
  ChainRpcAdapterOptions,
  ChainRpcConfig,
  ChainTip,
  RawChainObject,
  RpcHealth,
} from "./types.js";

type KaspaRpcConfig = Extract<ChainRpcConfig, { chain: "kaspa" }>;

function kaspaTip(value: unknown): ChainTip {
  const result = requireRecord(value);
  const hashes = Array.isArray(result.tipHashes) ? result.tipHashes : [];
  const hash = optionalString(hashes[0]);
  return {
    height: requireHeight(result.virtualDaaScore),
    ...(hash ? { hash } : {}),
  };
}

function kaspaTransactionId(value: unknown): string | undefined {
  const direct = optionalString(value);
  if (direct) return direct;
  const result = requireRecord(value);
  return optionalString(result.transactionId);
}

export class KaspaRpcAdapter extends BaseChainRpcAdapter implements ChainRpcAdapter {
  readonly chain = "kaspa" as const;
  readonly #transport: KaspaRpcConfig["transport"];
  readonly #http: RpcHttpClient;
  readonly #rpc: JsonRpcClient;

  constructor(config: KaspaRpcConfig, options: ChainRpcAdapterOptions = {}) {
    super(config, options);
    this.#transport = config.transport;
    this.#http = new RpcHttpClient({
      chain: this.chain,
      config,
      validated: validateRpcConfig(config),
      options,
    });
    this.#rpc = new JsonRpcClient(this.#http);
  }

  async health(): Promise<RpcHealth> {
    this.#requireImplementedTransport();
    return await this.measureHealth(async () => requireRecord(this.#transport === "json-rpc"
      ? await this.#rpc.call("getBlockDagInfo")
      : await this.#http.request("/info/health", "GET")));
  }

  async getTip(): Promise<ChainTip> {
    this.#requireImplementedTransport();
    const result = this.#transport === "json-rpc"
      ? await this.#rpc.call("getBlockDagInfo")
      : await this.#http.request("/info/blockdag", "GET");
    return kaspaTip(result);
  }

  async getTransaction(transactionId: string): Promise<RawChainObject> {
    this.#requireImplementedTransport();
    const id = requireIdentifier(transactionId, "transaction identifier");
    const raw = this.#transport === "json-rpc"
      ? await this.#rpc.call("getMempoolEntry", [{ txId: id, includeOrphanPool: true, filterTransactionPool: false }])
      : await this.#http.request(`/transactions/${encodeURIComponent(id)}`, "GET");
    return { chain: this.chain, id, raw };
  }

  async broadcast(rawTransaction: string): Promise<BroadcastResult> {
    this.requireBroadcastEnabled();
    this.#requireImplementedTransport();
    if (rawTransaction.length < 1 || rawTransaction.length > 8 * 1024 * 1024 || /[\0\r\n]/.test(rawTransaction)) {
      throw new ChainRpcError("invalid_request", "invalid raw transaction");
    }
    const result = this.#transport === "json-rpc"
      ? await this.#rpc.call("submitTransaction", [{ transaction: rawTransaction, allowOrphan: false }])
      : await this.#http.request("/transactions", "POST", { transaction: rawTransaction });
    const transactionId = kaspaTransactionId(result);
    return { accepted: true, ...(transactionId ? { transactionId } : {}) };
  }

  #requireImplementedTransport(): void {
    if (this.#transport === "wrpc") {
      throw new ChainRpcError("unsupported_transport", "Kaspa wRPC transport is not available in this build");
    }
  }
}
