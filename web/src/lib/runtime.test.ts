import { afterEach, describe, expect, it, vi } from "vitest";
import { readWalletRuntimeEndpoint } from "./runtime";

describe("desktop runtime bridge", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("reads the current validated wallet endpoint from Electron", async () => {
    const getRuntimeConfig = vi.fn(async () => ({ walletEndpoint: "http://127.0.0.1:28787", mcpEnabled: true }));
    vi.stubGlobal("window", { catomicalsDesktop: { getRuntimeConfig } });

    await expect(readWalletRuntimeEndpoint()).resolves.toBe("http://127.0.0.1:28787");
    expect(getRuntimeConfig).toHaveBeenCalledOnce();
  });

  it("fails closed when the desktop bridge is unavailable", async () => {
    vi.stubGlobal("window", {});
    await expect(readWalletRuntimeEndpoint()).rejects.toThrow("desktop runtime unavailable");
  });
});
