import { ChainRpcError } from "./errors.js";
import { requireRecord, RpcHttpClient } from "./http.js";

export class JsonRpcClient {
  readonly #http: RpcHttpClient;
  #nextId = 1;

  constructor(http: RpcHttpClient) {
    this.#http = http;
  }

  async call(method: string, params: readonly unknown[] | Readonly<Record<string, unknown>> = []): Promise<unknown> {
    const id = this.#nextId++;
    const raw = await this.#http.request(undefined, "POST", { jsonrpc: "2.0", id, method, params });
    const response = requireRecord(raw);
    if (response.id !== id) throw new ChainRpcError("invalid_response", "RPC returned a mismatched request identifier");
    if (response.error !== undefined && response.error !== null) {
      throw new ChainRpcError("remote_error", "RPC method failed");
    }
    if (!("result" in response)) throw new ChainRpcError("invalid_response", "RPC response is missing a result");
    return response.result;
  }
}
