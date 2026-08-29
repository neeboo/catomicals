import { describe, expect, it, vi } from "vitest";
import { builtinPackages } from "./builtins.js";
import { CordisHost } from "./host.js";
import { cordisAccess, cordisDesktopAccess } from "./permissions.js";
import { chainRpcConfigFromSettings, createConfiguredChainRpcAdapter, createDesktopCordisServices } from "./services.js";
import { InMemoryCordisStateStore } from "./store.js";

describe("desktop Cordis service registrations", () => {
  it("probes wallet services without credentials and reports disabled runtimes", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 200 }));
    const services = createDesktopCordisServices({
      fetcher,
      executorProbe: async (provider) => ({ provider, availability: "unavailable", reason: "not-found" }),
      mcpProbe: async () => true,
    });
    const byName = new Map(services.map((service) => [service.name, service]));

    await expect(byName.get("walletd.health")?.health({ settings: { endpoint: "http://127.0.0.1:18787" } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("bitcoin.node.health")?.health({ settings: { endpoint: "http://127.0.0.1:28787" } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("mcp.health")?.health({ settings: { enabled: false } }))
      .resolves.toMatchObject({ status: "healthy" });
    await expect(byName.get("mcp.health")?.health({ settings: { enabled: true } }))
      .resolves.toMatchObject({ status: "healthy", message: "wallet MCP stdio available" });
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

  it("reports enabled MCP as degraded when its stdio adapter cannot launch", async () => {
    const services = createDesktopCordisServices({ mcpProbe: async () => false });
    const service = services.find((candidate) => candidate.name === "mcp.health");

    await expect(service?.health({ settings: { enabled: true } }))
      .resolves.toMatchObject({ status: "degraded", message: "MCP runtime unavailable" });
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

  it("registers a health service for every supported chain", () => {
    const names = createDesktopCordisServices({}).map(({ name }) => name);

    expect(names).toEqual(expect.arrayContaining([
      "bitcoin.node.health",
      "chain.fractal-bitcoin.health",
      "chain.bitcoin-cash.health",
      "chain.bsv.health",
      "chain.kaspa.health",
      "chain.chia.health",
      "chain.ergo.health",
    ]));
  });

  it("promotes a disabled chain through review into adapter health and stops all I/O after disabling", async () => {
    const plugin = builtinPackages().find(({ registration }) => registration.id === "@catomicals/plugin-chain-kaspa");
    if (!plugin) throw new Error("Kaspa plugin fixture unavailable");
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://kaspa.example/info/health");
      expect(init).toMatchObject({ method: "GET", credentials: "omit", redirect: "manual" });
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer opaque");
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const resolveSecretHeaders = vi.fn(async () => ({ authorization: "Bearer opaque" }));
    const resolveHostAddresses = vi.fn(async () => ["93.184.216.34"]);
    const secretExists = vi.fn(async () => true);
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({
      registrations: [plugin.registration],
      trust: [plugin.trust],
      stateStore: store,
      services: createDesktopCordisServices({ fetcher, resolveSecretHeaders, resolveHostAddresses }),
      secretReferences: { exists: secretExists },
    });
    const intentAccess = cordisAccess("plugin.settings_intent.create");
    const healthAccess = cordisAccess("plugin.health.read");
    const schemaVersion = plugin.registration.settingsSchema.version;

    await host.initialize();
    expect(fetcher).not.toHaveBeenCalled();
    expect(resolveSecretHeaders).not.toHaveBeenCalled();
    expect(secretExists).not.toHaveBeenCalled();

    const enable = await host.createSettingsIntent(plugin.registration.id, {
      schemaVersion,
      changes: [
        { id: "enabled", value: true },
        { id: "nodeSource", value: "custom" },
        { id: "endpoint", value: "https://kaspa.example" },
        { id: "access", value: "broadcast" },
        { id: "credentialRef", value: "secret-ref:abcdefghijklmnop" },
      ],
    }, intentAccess);
    await expect(host.confirmSettingsIntent(enable.reviewId, cordisDesktopAccess))
      .resolves.toMatchObject({ enabled: true, status: "ready" });
    expect(enable.permissionDelta).toEqual({ added: ["chain.rpc.broadcast"], removed: [] });
    expect(secretExists).toHaveBeenCalledTimes(1);
    expect(resolveSecretHeaders).toHaveBeenCalledWith("secret-ref:abcdefghijklmnop", {
      chain: "kaspa",
      endpointOrigin: "https://kaspa.example",
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    const persisted = JSON.stringify(await store.load(plugin.registration.id));
    expect(persisted).toContain("secret-ref:abcdefghijklmnop");
    expect(persisted).not.toContain("Bearer opaque");
    expect(persisted).not.toContain("authorization");

    const readOnly = await host.createSettingsIntent(plugin.registration.id, {
      schemaVersion,
      changes: [{ id: "access", value: "read" }],
    }, intentAccess);
    expect(readOnly.permissionDelta).toEqual({ added: [], removed: ["chain.rpc.broadcast"] });
    await host.confirmSettingsIntent(readOnly.reviewId, cordisDesktopAccess);
    expect(fetcher).toHaveBeenCalledTimes(2);

    const disable = await host.createSettingsIntent(plugin.registration.id, {
      schemaVersion,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);
    await expect(host.confirmSettingsIntent(disable.reviewId, cordisDesktopAccess))
      .resolves.toMatchObject({ enabled: false, status: "disabled" });
    await expect(host.readHealth(plugin.registration.id, healthAccess))
      .resolves.toMatchObject({ status: "disabled", code: "disabled" });
    expect(secretExists).toHaveBeenCalledTimes(2);
    expect(resolveSecretHeaders).toHaveBeenCalledTimes(2);
    expect(resolveHostAddresses).toHaveBeenCalledTimes(2);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("maps read access to adapter-enforced broadcast denial", async () => {
    const fetcher = vi.fn(async () => new Response("{}", { status: 200 }));
    const settings = {
      enabled: true,
      endpoint: "https://rpc.example",
      networkAccess: "public",
      networkId: "bitcoin-mainnet",
      transport: "json-rpc",
      access: "read",
    };

    expect(chainRpcConfigFromSettings("bitcoin", settings)).toMatchObject({ broadcastEnabled: false, access: "public" });
    const adapter = await createConfiguredChainRpcAdapter("bitcoin", settings, {
      fetcher,
      resolveHostAddresses: async () => ["93.184.216.34"],
    });
    await expect(adapter.broadcast("00")).rejects.toMatchObject({ code: "broadcast_disabled" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("resolves built-in mainnet and testnet RPC presets without a user-entered endpoint", () => {
    const cases = [
      ["bitcoin", "bitcoin-mainnet", "http://127.0.0.1:8332", "json-rpc", "local"],
      ["bitcoin", "bitcoin-testnet4", "http://127.0.0.1:48332", "json-rpc", "local"],
      ["fractal-bitcoin", "fractal-bitcoin-testnet4", "http://127.0.0.1:48332", "json-rpc", "local"],
      ["bitcoin-cash", "bitcoin-cash-chipnet", "http://127.0.0.1:48332", "json-rpc", "local"],
      ["bsv", "bsv-testnet", "http://127.0.0.1:18332", "json-rpc", "local"],
      ["kaspa", "kaspa-testnet-10", "https://api-tn10.kaspa.org", "https-api", "public"],
      ["chia", "chia-testnet11", "https://127.0.0.1:8555", "https-rpc", "local"],
      ["ergo", "ergo-testnet", "http://127.0.0.1:9052", "rest", "local"],
    ] as const;

    for (const [chain, networkId, endpoint, transport, access] of cases) {
      expect(chainRpcConfigFromSettings(chain, {
        enabled: true,
        nodeSource: "preset",
        networkId,
        access: "read",
      })).toMatchObject({ chain, networkId, endpoint, transport, access });
    }
  });

  it("rejects a preset from another chain and keeps explicit custom endpoints", () => {
    expect(() => chainRpcConfigFromSettings("kaspa", {
      nodeSource: "preset",
      networkId: "bitcoin-mainnet",
      access: "read",
    })).toThrowError(expect.objectContaining({ code: "invalid_config" }));

    expect(chainRpcConfigFromSettings("kaspa", {
      nodeSource: "custom",
      networkId: "kaspa-mainnet",
      endpoint: "https://rpc.example",
      transport: "https-api",
      networkAccess: "public",
      access: "read",
    })).toMatchObject({ endpoint: "https://rpc.example", transport: "https-api", access: "public" });
  });

  it("does not fetch when the credential resolver rejects the endpoint origin", async () => {
    const fetcher = vi.fn(async () => new Response("{}", { status: 200 }));
    const resolveSecretHeaders = vi.fn(async (_reference, context) => {
      if (context.endpointOrigin !== "https://allowed.example") throw new Error("origin denied");
      return { authorization: "Bearer opaque" };
    });
    const service = createDesktopCordisServices({
      fetcher,
      resolveSecretHeaders,
      resolveHostAddresses: async () => ["93.184.216.34"],
    }).find(({ name }) => name === "chain.kaspa.health");

    await expect(service?.health({ settings: {
      enabled: true,
      endpoint: "https://wrong.example",
      networkAccess: "public",
      networkId: "kaspa-mainnet",
      transport: "https-api",
      credentialRef: "secret-ref:abcdefghijklmnop",
      access: "read",
    } })).resolves.toMatchObject({ status: "unhealthy", message: "credential_unavailable" });
    expect(resolveSecretHeaders).toHaveBeenCalledWith("secret-ref:abcdefghijklmnop", {
      chain: "kaspa",
      endpointOrigin: "https://wrong.example",
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("requires HTTPS for credentialed private and public RPC endpoints", async () => {
    const common = {
      enabled: true,
      networkId: "kaspa-mainnet",
      transport: "https-api",
      credentialRef: "secret-ref:abcdefghijklmnop",
      access: "read",
    };
    await expect(createConfiguredChainRpcAdapter("kaspa", {
      ...common,
      endpoint: "http://10.0.0.2",
      networkAccess: "private-network",
    }, {})).rejects.toMatchObject({ code: "invalid_config" });
    await expect(createConfiguredChainRpcAdapter("kaspa", {
      ...common,
      endpoint: "http://93.184.216.34",
      networkAccess: "public",
    }, {})).rejects.toMatchObject({ code: "invalid_config" });
    await expect(createConfiguredChainRpcAdapter("kaspa", {
      ...common,
      endpoint: "http://127.0.0.1:16110",
      networkAccess: "local",
    }, {})).resolves.toBeDefined();
  });

  it("coalesces and briefly caches chain health probes without persisting resolved headers", async () => {
    let now = 100;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const fetcher = vi.fn(async () => {
      await gate;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    const service = createDesktopCordisServices({
      fetcher,
      now: () => now,
      chainHealthTtlMs: 50,
      resolveHostAddresses: async () => ["93.184.216.34"],
    }).find(({ name }) => name === "chain.ergo.health");
    const settings = {
      enabled: true,
      endpoint: "https://ergo.example",
      networkAccess: "public",
      networkId: "ergo-mainnet",
      transport: "rest",
      access: "read",
    };

    const first = service?.health({ settings });
    const concurrent = service?.health({ settings });
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    release();
    await expect(Promise.all([first, concurrent])).resolves.toEqual([
      expect.objectContaining({ status: "healthy" }),
      expect.objectContaining({ status: "healthy" }),
    ]);
    await service?.health({ settings });
    expect(fetcher).toHaveBeenCalledTimes(1);
    now = 151;
    await service?.health({ settings });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
