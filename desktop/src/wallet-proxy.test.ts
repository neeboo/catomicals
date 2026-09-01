import { describe, expect, it, vi } from "vitest";
import { createBuiltinCordisHost } from "./cordis/builtins.js";
import { CordisRuntimeConfig } from "./cordis/runtime-config.js";
import { InMemoryCordisStateStore } from "./cordis/store.js";
import { createWalletProxy } from "./wallet-proxy.js";

describe("wallet IPC proxy", () => {
  it("reads the current Cordis endpoint for every request and returns a bounded response", async () => {
    const walletEndpoint = vi.fn()
      .mockResolvedValueOnce("http://127.0.0.1:18787")
      .mockResolvedValueOnce("http://127.0.0.1:28787");
    const fetcher = vi.fn(async () => new Response('{"ok":true}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({ walletEndpoint, fetcher });

    await expect(proxy({ path: "/api/v1/node/status", method: "GET" }))
      .resolves.toEqual({ status: 200, body: '{"ok":true}', contentType: "application/json" });
    await proxy({ path: "/api/v1/chat/messages", method: "POST", body: "{}" });

    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "http://127.0.0.1:18787/api/v1/node/status",
      "http://127.0.0.1:28787/api/v1/chat/messages",
    ]);
  });

  it("rejects unknown paths, invalid methods, and bodies on GET before network access", async () => {
    const fetcher = vi.fn();
    const proxy = createWalletProxy({ walletEndpoint: async () => "http://127.0.0.1:18787", fetcher });

    await expect(proxy({ path: "/api/v1/../../etc/passwd", method: "GET" })).rejects.toThrow("wallet API path");
    await expect(proxy({ path: "/api/v1/intents/..", method: "GET" })).rejects.toThrow("wallet API path");
    await expect(proxy({ path: "/api/v1/node/status", method: "DELETE" })).rejects.toThrow("method");
    await expect(proxy({ path: "/api/v1/node/status", method: "GET", body: "{}" })).rejects.toThrow("body");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects oversized response bodies", async () => {
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher: async () => new Response("x".repeat(2 * 1024 * 1024 + 1), { status: 200 }),
    });
    await expect(proxy({ path: "/api/v1/node/status", method: "GET" })).rejects.toThrow("response too large");
  });

  it("allows only the typed multichain query and configuration routes", async () => {
    const fetcher = vi.fn(async () => new Response('{"schema_version":1,"chains":[]}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher,
    });

    await expect(proxy({ path: "/api/v1/chains/status", method: "GET" })).resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: "/api/v1/chains/config", method: "GET" })).resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: "/api/v1/chains/config", method: "POST", body: "{}" })).resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: "/api/v1/chains/sign", method: "POST", body: "{}" })).rejects.toThrow("wallet API path");
  });

  it("exposes signing job creation and lookup without exposing backend round APIs", async () => {
    const fetcher = vi.fn(async () => new Response('{"status":"signing"}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher,
    });
    const jobId = "11111111-1111-4111-8111-111111111111";

    await expect(proxy({ path: "/api/v1/signing/jobs", method: "POST", body: "{}" }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: `/api/v1/signing/jobs/${jobId}`, method: "GET" }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: `/api/v1/signing/jobs/${jobId}/execute`, method: "POST", body: "{}" }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: `/api/v1/signing/jobs/${jobId}/round-one`, method: "POST", body: "{}" }))
      .rejects.toThrow("wallet API path");
  });

  it("allows only the bounded CovHub proposal inspect and pending-intent routes", async () => {
    const fetcher = vi.fn(async () => new Response('{"intent":{"status":"pending"}}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher,
    });

    await expect(proxy({ path: "/api/v1/covhub/proposals/inspect", method: "POST", body: "{}" }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: "/api/v1/covhub/proposals/intents", method: "POST", body: "{}" }))
      .resolves.toMatchObject({ status: 200 });
    // The bridge exposes no approval, signing, passkey capture, or broadcast.
    for (const path of [
      "/api/v1/covhub/proposals/approve",
      "/api/v1/covhub/proposals/sign",
      "/api/v1/covhub/proposals/broadcast",
      "/api/v1/covhub/proposals/intents/61616161-6161-4161-8161-616161616161/approve",
      "/api/v1/covhub/passkey/assertion",
    ]) {
      await expect(proxy({ path, method: "POST", body: "{}" })).rejects.toThrow("wallet API path");
    }
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("accepts a max-size CovHub proposal request body and rejects anything larger", async () => {
    const fetcher = vi.fn(async () => new Response('{"eligible":true}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher,
    });
    const big = JSON.stringify({ proposal: { material_base64: "A".repeat(1_350_000) } });
    await expect(proxy({ path: "/api/v1/covhub/proposals/inspect", method: "POST", body: big }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({
      path: "/api/v1/covhub/proposals/inspect",
      method: "POST",
      body: "A".repeat(2 * 1024 * 1024 + 1),
    })).rejects.toThrow("wallet API body");
  });

  it("keeps unrelated routes at the 1 MiB limit while CovHub routes use the bounded larger limit", async () => {
    const fetcher = vi.fn(async () => new Response('{"eligible":true}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    const proxy = createWalletProxy({
      walletEndpoint: async () => "http://127.0.0.1:18787",
      fetcher,
    });
    const big = "A".repeat(1024 * 1024 + 1024);
    // Above the general 1 MiB limit: rejected on a non-CovHub route.
    await expect(proxy({ path: "/api/v1/intents", method: "POST", body: big }))
      .rejects.toThrow("wallet API body");
    expect(fetcher).not.toHaveBeenCalled();
    // Same body is accepted on the bounded CovHub routes.
    await expect(proxy({ path: "/api/v1/covhub/proposals/inspect", method: "POST", body: big }))
      .resolves.toMatchObject({ status: 200 });
    await expect(proxy({ path: "/api/v1/covhub/proposals/intents", method: "POST", body: big }))
      .resolves.toMatchObject({ status: 200 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("reaches the wallet network boundary with first-run defaults while walletd is offline", async () => {
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), [{
      name: "walletd.health",
      health: async () => ({ status: "unhealthy", message: "wallet offline" }),
    }]);
    await host.initialize();
    const runtimeConfig = new CordisRuntimeConfig(host);
    const fetcher = vi.fn(async () => {
      throw new TypeError("fetch failed: ECONNREFUSED");
    });
    const proxy = createWalletProxy({ walletEndpoint: () => runtimeConfig.walletEndpoint(), fetcher });

    await expect(proxy({ path: "/api/v1/node/status", method: "GET" })).rejects.toThrow("ECONNREFUSED");
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
