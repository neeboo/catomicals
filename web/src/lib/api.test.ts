import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { requestWallet } from "./runtime";

vi.mock("./runtime", () => ({ requestWallet: vi.fn() }));

describe("wallet API runtime routing", () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

  it("sends every new request through the desktop wallet proxy", async () => {
    vi.mocked(requestWallet).mockResolvedValue({ status: 200, body: "{}", contentType: "application/json" });
    const { api } = await import("./api");

    await api.nodeStatus();
    await api.walletStatus();

    expect(vi.mocked(requestWallet).mock.calls.map(([request]) => request)).toEqual([
      { path: "/api/v1/node/status", method: "GET" },
      { path: "/api/v1/wallet/status", method: "GET" },
    ]);
  });

  it("contains no renderer fetch, Vite, or fixed wallet endpoint fallback", () => {
    const source = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
    expect(source).not.toContain("VITE_WALLET_API_BASE");
    expect(source).not.toContain("http://localhost:18787");
    expect(source).not.toMatch(/\bfetch\s*\(/);
  });
});
