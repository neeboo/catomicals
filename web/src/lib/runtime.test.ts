import { afterEach, describe, expect, it, vi } from "vitest";
import { readMcpEnabled, requestWallet } from "./runtime";

describe("desktop runtime bridge", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("routes wallet requests through Electron without exposing an endpoint", async () => {
    const request = vi.fn(async () => ({ status: 200, body: "{}", contentType: "application/json" }));
    vi.stubGlobal("window", { catomicalsDesktop: { requestWallet: request, getMcpEnabled: async () => true } });

    await expect(requestWallet({ path: "/api/v1/node/status", method: "GET" }))
      .resolves.toMatchObject({ status: 200 });
    await expect(readMcpEnabled()).resolves.toBe(true);
    expect(request).toHaveBeenCalledOnce();
  });

  it("fails closed when the desktop bridge is unavailable", async () => {
    vi.stubGlobal("window", {});
    await expect(requestWallet({ path: "/api/v1/node/status", method: "GET" }))
      .rejects.toThrow("desktop runtime unavailable");
  });
});
