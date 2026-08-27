import { describe, expect, it, vi } from "vitest";
import { createDesktopCordisServices } from "./services.js";

describe("desktop Cordis service registrations", () => {
  it("probes wallet services without credentials and reports disabled runtimes", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 200 }));
    const services = createDesktopCordisServices({
      readSettings: async () => ({ walletNodeUrl: "http://127.0.0.1:18787", mcpEnabled: false }),
      fetcher,
    });
    const byName = new Map(services.map((service) => [service.name, service]));

    await expect(byName.get("walletd.health")?.health()).resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("bitcoin.node.health")?.health()).resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("mcp.health")?.health()).resolves.toMatchObject({ status: "unhealthy" });
    await expect(byName.get("indexer.health")?.health()).resolves.toMatchObject({ status: "unhealthy" });
    expect(fetcher).toHaveBeenNthCalledWith(1, "http://127.0.0.1:18787/api/v1/wallet/status", expect.objectContaining({
      method: "GET",
      credentials: "omit",
      redirect: "error",
    }));
    expect(fetcher).toHaveBeenNthCalledWith(2, "http://127.0.0.1:18787/api/v1/node/status", expect.any(Object));
  });

  it("treats a failed or non-success HTTP probe as unavailable", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 503 }));
    const [walletd] = createDesktopCordisServices({
      readSettings: async () => ({ walletNodeUrl: "http://127.0.0.1:18787", mcpEnabled: true }),
      fetcher,
    });

    await expect(walletd?.health()).resolves.toMatchObject({ status: "unhealthy" });
  });
});
