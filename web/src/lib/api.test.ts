import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readWalletRuntimeEndpoint } from "./runtime";

vi.mock("./runtime", () => ({ readWalletRuntimeEndpoint: vi.fn() }));

describe("wallet API runtime routing", () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

  it("reads the current desktop endpoint for every new request", async () => {
    vi.mocked(readWalletRuntimeEndpoint)
      .mockResolvedValueOnce("http://127.0.0.1:18787")
      .mockResolvedValueOnce("http://127.0.0.1:28787");
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetcher);
    const { api } = await import("./api");

    await api.nodeStatus();
    await api.walletStatus();

    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "http://127.0.0.1:18787/api/v1/node/status",
      "http://127.0.0.1:28787/api/v1/wallet/status",
    ]);
  });

  it("contains no Vite or fixed wallet endpoint fallback", () => {
    const source = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
    expect(source).not.toContain("VITE_WALLET_API_BASE");
    expect(source).not.toContain("http://localhost:18787");
  });
});
