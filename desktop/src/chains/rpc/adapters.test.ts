import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  ChainRpcError,
  ChainRpcRegistry,
  createChainRpcAdapter,
  type ChainRpcConfig,
  type SecretHeaderResolver,
} from "./index.js";

interface CapturedRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: IncomingMessage["headers"];
  readonly body: string;
}

interface MockServer {
  readonly endpoint: string;
  readonly requests: CapturedRequest[];
  close(): Promise<void>;
}

const servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function mockServer(
  reply: (request: CapturedRequest, response: ServerResponse) => void | Promise<void>,
): Promise<MockServer> {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const captured: CapturedRequest = {
      method: request.method ?? "",
      path: request.url ?? "",
      headers: request.headers,
      body: Buffer.concat(chunks).toString("utf8"),
    };
    requests.push(captured);
    await reply(captured, response);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("mock server failed to bind");
  const mock: MockServer = {
    endpoint: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
  servers.push(mock);
  return mock;
}

function json(response: ServerResponse, value: unknown, status = 200): void {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  response.end(body);
}

describe("chain RPC adapters", () => {
  it("exposes enabled adapters as Cordis health bindings with stable service names", async () => {
    const server = await mockServer((request, response) => {
      const envelope = JSON.parse(request.body) as { id: number };
      json(response, { jsonrpc: "2.0", id: envelope.id, result: { blocks: 1, bestblockhash: "tip" } });
    });
    const registry = new ChainRpcRegistry([
      { chain: "bitcoin", endpoint: server.endpoint },
      { chain: "bsv", endpoint: server.endpoint, enabled: false },
    ]);

    expect(registry.list().map((adapter) => adapter.chain)).toEqual(["bitcoin"]);
    expect(registry.healthBindings().map((binding) => binding.name)).toEqual(["bitcoin.node.health"]);
    await expect(registry.healthBindings()[0]!.health()).resolves.toMatchObject({ ok: true, chain: "bitcoin" });
    expect(() => registry.get("bsv")).toThrow("not enabled");
  });

  it.each(["bitcoin", "fractal-bitcoin", "bitcoin-cash", "bsv"] as const)(
    "uses Bitcoin-family JSON-RPC request shapes for %s",
    async (chain) => {
      let nextId = 0;
      const server = await mockServer((request, response) => {
        const envelope = JSON.parse(request.body) as { id: number; method: string };
        nextId = envelope.id;
        const result = envelope.method === "getblockchaininfo"
          ? { blocks: 101, bestblockhash: "ab" }
          : envelope.method === "getrawtransaction"
            ? { txid: "tx-1", hex: "00" }
            : "broadcast-txid";
        json(response, { jsonrpc: "2.0", id: envelope.id, result, error: null });
      });
      const config: ChainRpcConfig = {
        chain,
        endpoint: server.endpoint,
        auth: { credentialRef: "secret-ref:abcdefghijklmnop" },
        broadcastEnabled: true,
      };
      const resolveSecretHeaders: SecretHeaderResolver = async () => ({ authorization: "Basic opaque-value" });
      const adapter = createChainRpcAdapter(config, { resolveSecretHeaders });

      await expect(adapter.health()).resolves.toMatchObject({ ok: true, chain });
      await expect(adapter.getTip()).resolves.toEqual({ height: 101, hash: "ab" });
      await expect(adapter.getTransaction("tx-1")).resolves.toMatchObject({ id: "tx-1", raw: { txid: "tx-1" } });
      await expect(adapter.broadcast("deadbeef")).resolves.toEqual({ accepted: true, transactionId: "broadcast-txid" });

      expect(nextId).toBeGreaterThan(0);
      expect(server.requests.map((request) => JSON.parse(request.body).method)).toEqual([
        "getblockchaininfo",
        "getblockchaininfo",
        "getrawtransaction",
        "sendrawtransaction",
      ]);
      expect(server.requests.every((request) => request.headers.authorization === "Basic opaque-value")).toBe(true);
      expect(JSON.parse(server.requests[2]!.body).params).toEqual(["tx-1", true]);
      expect(JSON.parse(server.requests[3]!.body).params).toEqual(["deadbeef"]);
    },
  );

  it("supports Kaspa JSON-RPC and rejects native wRPC explicitly", async () => {
    const server = await mockServer((request, response) => {
      const envelope = JSON.parse(request.body) as { id: number; method: string };
      const result = envelope.method === "getBlockDagInfo"
        ? { virtualDaaScore: "42", tipHashes: ["tip-hash"] }
        : envelope.method === "getMempoolEntry"
          ? { entry: { transaction: { verboseData: { transactionId: "kaspa-tx" } } } }
          : { transactionId: "kaspa-broadcast" };
      json(response, { jsonrpc: "2.0", id: envelope.id, result });
    });
    const adapter = createChainRpcAdapter({
      chain: "kaspa",
      endpoint: server.endpoint,
      transport: "json-rpc",
      broadcastEnabled: true,
    });

    await expect(adapter.getTip()).resolves.toEqual({ height: 42, hash: "tip-hash" });
    await expect(adapter.getTransaction("kaspa-tx")).resolves.toMatchObject({ id: "kaspa-tx" });
    await expect(adapter.broadcast("raw-kaspa-transaction")).resolves.toEqual({
      accepted: true,
      transactionId: "kaspa-broadcast",
    });
    expect(server.requests.map((request) => JSON.parse(request.body).method)).toEqual([
      "getBlockDagInfo",
      "getMempoolEntry",
      "submitTransaction",
    ]);

    const wrpc = createChainRpcAdapter({ chain: "kaspa", endpoint: server.endpoint, transport: "wrpc" });
    await expect(wrpc.health()).rejects.toMatchObject({ code: "unsupported_transport" });
  });

  it("uses Kaspa HTTPS API routes when explicitly selected", async () => {
    const server = await mockServer((request, response) => {
      if (request.path === "/info/health") return json(response, { status: "ready" });
      if (request.path === "/info/blockdag") return json(response, { virtualDaaScore: "77", tipHashes: ["k-tip"] });
      if (request.path === "/transactions/k-tx") return json(response, { transactionId: "k-tx" });
      return json(response, { transactionId: "k-new" });
    });
    const adapter = createChainRpcAdapter({
      chain: "kaspa",
      endpoint: server.endpoint,
      transport: "https-api",
      broadcastEnabled: true,
    });

    await expect(adapter.health()).resolves.toMatchObject({ ok: true });
    await expect(adapter.getTip()).resolves.toEqual({ height: 77, hash: "k-tip" });
    await adapter.getTransaction("k-tx");
    await adapter.broadcast("raw-kaspa-transaction");

    expect(server.requests.map(({ method, path }) => `${method} ${path}`)).toEqual([
      "GET /info/health",
      "GET /info/blockdag",
      "GET /transactions/k-tx",
      "POST /transactions",
    ]);
    expect(JSON.parse(server.requests[3]!.body)).toEqual({ transaction: "raw-kaspa-transaction" });
  });

  it("uses Chia HTTPS RPC routes and object payloads", async () => {
    const server = await mockServer((request, response) => {
      const body = JSON.parse(request.body || "{}") as Record<string, unknown>;
      if (request.path === "/healthz") return json(response, { success: true });
      if (request.path === "/get_blockchain_state") return json(response, { success: true, blockchain_state: { peak: { height: 9, header_hash: "chia-tip" } } });
      if (request.path === "/get_mempool_item_by_tx_id") return json(response, { success: true, mempool_item: { name: body.tx_id } });
      return json(response, { success: true, transaction_id: "chia-new" });
    });
    const adapter = createChainRpcAdapter({
      chain: "chia",
      endpoint: server.endpoint,
      broadcastEnabled: true,
    });

    await expect(adapter.health()).resolves.toMatchObject({ ok: true, chain: "chia" });
    await expect(adapter.getTip()).resolves.toEqual({ height: 9, hash: "chia-tip" });
    await adapter.getTransaction("chia-tx");
    await adapter.broadcast('{"aggregated_signature":"sig","coin_spends":[]}');

    expect(server.requests.map((request) => request.path)).toEqual([
      "/healthz",
      "/get_blockchain_state",
      "/get_mempool_item_by_tx_id",
      "/push_tx",
    ]);
    expect(JSON.parse(server.requests[2]!.body)).toEqual({ tx_id: "chia-tx" });
    expect(JSON.parse(server.requests[3]!.body)).toEqual({ spend_bundle: { aggregated_signature: "sig", coin_spends: [] } });
  });

  it("uses Ergo REST routes and signed transaction payloads", async () => {
    const server = await mockServer((request, response) => {
      if (request.path === "/info") return json(response, { fullHeight: 88, bestFullHeaderId: "ergo-tip" });
      if (request.method === "GET") return json(response, { id: "ergo-tx" });
      return json(response, "ergo-new");
    });
    const adapter = createChainRpcAdapter({
      chain: "ergo",
      endpoint: server.endpoint,
      broadcastEnabled: true,
    });

    await expect(adapter.health()).resolves.toMatchObject({ ok: true });
    await expect(adapter.getTip()).resolves.toEqual({ height: 88, hash: "ergo-tip" });
    await adapter.getTransaction("ergo-tx");
    await adapter.broadcast('{"id":"ergo-new","inputs":[],"outputs":[]}');

    expect(server.requests.map(({ method, path }) => `${method} ${path}`)).toEqual([
      "GET /info",
      "GET /info",
      "GET /transactions/unconfirmed/byTransactionId/ergo-tx",
      "POST /transactions",
    ]);
    expect(JSON.parse(server.requests[3]!.body)).toEqual({ id: "ergo-new", inputs: [], outputs: [] });
  });

  it("keeps broadcast disabled unless explicitly enabled", async () => {
    const server = await mockServer((_request, response) => json(response, { result: "unexpected" }));
    const adapter = createChainRpcAdapter({ chain: "bitcoin", endpoint: server.endpoint });

    await expect(adapter.broadcast("deadbeef")).rejects.toMatchObject({ code: "broadcast_disabled" });
    expect(server.requests).toHaveLength(0);
  });

  it("rechecks the broadcast switch at call time", async () => {
    const server = await mockServer((_request, response) => json(response, { result: "unexpected" }));
    const config = { chain: "bitcoin" as const, endpoint: server.endpoint, broadcastEnabled: true };
    const adapter = createChainRpcAdapter(config);
    config.broadcastEnabled = false;

    await expect(adapter.broadcast("deadbeef")).rejects.toMatchObject({ code: "broadcast_disabled" });
    expect(server.requests).toHaveLength(0);
  });

  it("rejects endpoint credentials and unsupported protocols before network access", () => {
    expect(() => createChainRpcAdapter({ chain: "bitcoin", endpoint: "ftp://node.example" }))
      .toThrow("http or https");
    expect(() => createChainRpcAdapter({ chain: "bitcoin", endpoint: "http://user:pass@node.example" }))
      .toThrow("userinfo");
  });

  it("fails closed when authentication is configured without a secret resolver", async () => {
    const server = await mockServer((_request, response) => json(response, {}));
    const adapter = createChainRpcAdapter({
      chain: "bitcoin",
      endpoint: server.endpoint,
      auth: { credentialRef: "secret-ref:abcdefghijklmnop" },
    });

    await expect(adapter.health()).rejects.toMatchObject({ code: "credential_unavailable" });
    expect(server.requests).toHaveLength(0);
  });

  it("rejects redirects, oversized bodies, and slow responses with structured errors", async () => {
    const redirect = await mockServer((_request, response) => {
      response.writeHead(302, { location: "http://127.0.0.1:1/private" });
      response.end();
    });
    const oversized = await mockServer((_request, response) => json(response, { data: "x".repeat(4096) }));
    const slow = await mockServer(async (_request, response) => {
      await new Promise((resolve) => setTimeout(resolve, 80));
      json(response, { result: {} });
    });
    const slowBody = await mockServer(async (_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.write('{"result":');
      await new Promise((resolve) => setTimeout(resolve, 80));
      response.end("{}}");
    });

    await expect(createChainRpcAdapter({ chain: "bitcoin", endpoint: redirect.endpoint }).health())
      .rejects.toMatchObject({ code: "redirect_rejected" });
    await expect(createChainRpcAdapter({ chain: "bitcoin", endpoint: oversized.endpoint, maxResponseBytes: 128 }).health())
      .rejects.toMatchObject({ code: "response_too_large" });
    await expect(createChainRpcAdapter({ chain: "bitcoin", endpoint: slow.endpoint, timeoutMs: 20 }).health())
      .rejects.toMatchObject({ code: "timeout" });
    await expect(createChainRpcAdapter({ chain: "bitcoin", endpoint: slowBody.endpoint, timeoutMs: 20 }).health())
      .rejects.toMatchObject({ code: "timeout" });
  });

  it("never includes credential references in structured error messages", async () => {
    const secretRef = "secret-ref:abcdefghijklmnop";
    const server = await mockServer((_request, response) => json(response, { error: { code: -1, message: "denied" } }, 401));
    const adapter = createChainRpcAdapter({
      chain: "bitcoin",
      endpoint: server.endpoint,
      auth: { credentialRef: secretRef },
    }, {
      resolveSecretHeaders: async () => ({ authorization: "Bearer private-token" }),
    });

    let error: unknown;
    try {
      await adapter.health();
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ChainRpcError);
    expect(String(error)).not.toContain(secretRef);
    expect(String(error)).not.toContain("private-token");
    expect(String(error)).not.toContain("denied");
  });

  it("does not report health when an RPC returns a malformed success payload", async () => {
    const server = await mockServer((request, response) => {
      const envelope = JSON.parse(request.body) as { id: number };
      json(response, { jsonrpc: "2.0", id: envelope.id, result: null });
    });
    const adapter = createChainRpcAdapter({ chain: "bitcoin", endpoint: server.endpoint });

    await expect(adapter.health()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
