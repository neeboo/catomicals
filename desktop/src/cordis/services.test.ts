import { describe, expect, it, vi } from "vitest";
import { createDesktopCordisServices } from "./services.js";

describe("desktop Cordis service registrations", () => {
  it("probes wallet services without credentials and reports disabled runtimes", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 200 }));
    const services = createDesktopCordisServices({
      fetcher,
      executorProbe: async (provider) => ({ provider, availability: "unavailable", reason: "not-found" }),
    });
    const byName = new Map(services.map((service) => [service.name, service]));

    await expect(byName.get("walletd.health")?.health({ settings: { endpoint: "http://127.0.0.1:18787" } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("bitcoin.node.health")?.health({ settings: { endpoint: "http://127.0.0.1:28787" } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("mcp.health")?.health({ settings: { enabled: false } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("mcp.health")?.health({ settings: { enabled: true } }))
      .resolves.toMatchObject({ status: "degraded", message: "MCP runtime unavailable" });
    await expect(byName.get("indexer.health")?.health({ settings: { enabled: true } }))
      .resolves.toMatchObject({ status: "unhealthy" });
    expect(fetcher).toHaveBeenNthCalledWith(1, "http://127.0.0.1:18787/api/v1/wallet/status", expect.objectContaining({
      method: "GET",
      credentials: "omit",
      redirect: "error",
    }));
    expect(fetcher).toHaveBeenNthCalledWith(2, "http://127.0.0.1:28787/api/v1/node/status", expect.any(Object));
    await expect(byName.get("executor.codex.health")?.health({ settings: {
      command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "",
    } })).resolves.toMatchObject({ status: "degraded", message: "not-found" });
    await expect(byName.get("browser.health")?.health({ settings: { home: "https://example.com" } }))
      .resolves.toMatchObject({ status: "degraded", message: "browser runtime status unavailable" });
    await expect(byName.get("backup.health")?.health({ settings: {} }))
      .resolves.toMatchObject({ status: "degraded", message: "backup runtime unavailable" });
  });

  it("treats a failed or non-success HTTP probe as unavailable", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 503 }));
    const [walletd] = createDesktopCordisServices({ fetcher });

    await expect(walletd?.health({ settings: { endpoint: "http://127.0.0.1:18787" } }))
      .resolves.toMatchObject({ status: "unhealthy" });
  });

  it("rejects remote wallet service endpoints without making a request", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 200 }));
    const [walletd] = createDesktopCordisServices({ fetcher });

    await expect(walletd?.health({ settings: { endpoint: "https://wallet.example" } }))
      .resolves.toMatchObject({ status: "unhealthy", message: expect.stringContaining("loopback") });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("reports the real executor version and capabilities through the registry probe", async () => {
    const executorProbe = vi.fn(async (provider) => ({
      provider,
      availability: "available" as const,
      version: "codex 5.6",
      capabilities: { resume: true },
    }));
    const services = createDesktopCordisServices({ executorProbe });
    const service = services.find((candidate) => candidate.name === "executor.codex.health");

    await expect(service?.health({ settings: {
      command: "codex", defaultModel: "gpt-5.6", reasoningEffort: "high", workingDirectory: "/work",
    } })).resolves.toMatchObject({ status: "healthy", message: "codex 5.6" });
    expect(executorProbe).toHaveBeenCalledWith("codex", {
      command: "codex", defaultModel: "gpt-5.6", reasoningEffort: "high", workingDirectory: "/work",
    });
  });
});
