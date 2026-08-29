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

type ErgoRpcConfig = Extract<ChainRpcConfig, { chain: "ergo" }>;

function parseSignedTransaction(raw: string): Record<string, unknown> {
  if (raw.length < 2 || raw.length > 8 * 1024 * 1024) throw new ChainRpcError("invalid_request", "invalid Ergo transaction");
  try {
    return requireRecord(JSON.parse(raw), "invalid Ergo transaction");
  } catch (error) {
    if (error instanceof ChainRpcError) throw error;
    throw new ChainRpcError("invalid_request", "invalid Ergo transaction");
  }
}

export class ErgoRpcAdapter extends BaseChainRpcAdapter implements ChainRpcAdapter {
  readonly chain = "ergo" as const;
  readonly #http: RpcHttpClient;

  constructor(config: ErgoRpcConfig, options: ChainRpcAdapterOptions = {}) {
    super(config, options);
    this.#http = new RpcHttpClient({ chain: this.chain, config, validated: validateRpcConfig(config), options });
  }

  health(): Promise<RpcHealth> {
    return this.measureHealth(async () => requireRecord(await this.#http.request("/info", "GET")));
  }

  async getTip(): Promise<ChainTip> {
    const info = requireRecord(await this.#http.request("/info", "GET"));
    const hash = optionalString(info.bestFullHeaderId);
    return { height: requireHeight(info.fullHeight), ...(hash ? { hash } : {}) };
  }

  async getTransaction(transactionId: string): Promise<RawChainObject> {
    const id = requireIdentifier(transactionId, "transaction identifier");
    const raw = await this.#http.request(`/transactions/unconfirmed/byTransactionId/${encodeURIComponent(id)}`, "GET");
    return { chain: this.chain, id, raw };
  }

  async broadcast(rawTransaction: string): Promise<BroadcastResult> {
    this.requireBroadcastEnabled();
    const signedTransaction = parseSignedTransaction(rawTransaction);
    const response = await this.#http.request("/transactions", "POST", signedTransaction);
    const transactionId = optionalString(response) ?? optionalString(requireRecord(response).id);
    return { accepted: true, ...(transactionId ? { transactionId } : {}) };
  }
}
