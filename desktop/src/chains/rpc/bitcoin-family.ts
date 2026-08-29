import { BaseChainRpcAdapter } from "./base.js";
import { ChainRpcError } from "./errors.js";
import { optionalString, requireHeight, requireIdentifier, requireRecord, RpcHttpClient, validateRpcConfig } from "./http.js";
import { JsonRpcClient } from "./json-rpc.js";
import type {
  BitcoinFamilyChainId,
  BroadcastResult,
  ChainRpcAdapter,
  ChainRpcAdapterOptions,
  ChainRpcConfig,
  ChainTip,
  RawChainObject,
  RpcHealth,
} from "./types.js";

type BitcoinRpcConfig = Extract<ChainRpcConfig, { chain: BitcoinFamilyChainId }>;

export class BitcoinFamilyRpcAdapter extends BaseChainRpcAdapter implements ChainRpcAdapter {
  readonly chain: BitcoinFamilyChainId;
  readonly #rpc: JsonRpcClient;

  constructor(config: BitcoinRpcConfig, options: ChainRpcAdapterOptions = {}) {
    super(config, options);
    this.chain = config.chain;
    this.#rpc = new JsonRpcClient(new RpcHttpClient({
      chain: config.chain,
      config,
      validated: validateRpcConfig(config),
      options,
    }));
  }

  health(): Promise<RpcHealth> {
    return this.measureHealth(async () => requireRecord(await this.#rpc.call("getblockchaininfo")));
  }

  async getTip(): Promise<ChainTip> {
    const result = requireRecord(await this.#rpc.call("getblockchaininfo"));
    const hash = optionalString(result.bestblockhash);
    return { height: requireHeight(result.blocks), ...(hash ? { hash } : {}) };
  }

  async getTransaction(transactionId: string): Promise<RawChainObject> {
    const id = requireIdentifier(transactionId, "transaction identifier");
    const raw = await this.#rpc.call("getrawtransaction", [id, true]);
    return { chain: this.chain, id, raw };
  }

  async broadcast(rawTransaction: string): Promise<BroadcastResult> {
    this.requireBroadcastEnabled();
    if (rawTransaction.length < 2 || rawTransaction.length > 8 * 1024 * 1024 || !/^[0-9a-fA-F]+$/.test(rawTransaction)) {
      throw new ChainRpcError("invalid_request", "invalid raw transaction");
    }
    const transactionId = optionalString(await this.#rpc.call("sendrawtransaction", [rawTransaction]));
    return { accepted: true, ...(transactionId ? { transactionId } : {}) };
  }
}
