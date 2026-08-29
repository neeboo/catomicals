import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { builtinPackages, createBuiltinCordisHost, FIXED_PLUGIN_IDS } from "./builtins.js";
import type { CordisService } from "./health.js";
import { digestJson } from "./manifest.js";
import { cordisAccess } from "./permissions.js";
import { InMemoryCordisStateStore } from "./store.js";

describe("built-in Cordis catalog", () => {
  const catalogAccess = cordisAccess("plugin.catalog.read");
  const healthAccess = cordisAccess("plugin.health.read");

  it("ships the seven chain adapters as fixed signed plugins with separate RPC and address capabilities", async () => {
    const expectedChainPlugins = [
      "@catomicals/plugin-bitcoin-node",
      "@catomicals/plugin-chain-fractal-bitcoin",
      "@catomicals/plugin-chain-bitcoin-cash",
      "@catomicals/plugin-chain-bsv",
      "@catomicals/plugin-chain-kaspa",
      "@catomicals/plugin-chain-chia",
      "@catomicals/plugin-chain-ergo",
    ];
    const packages = builtinPackages().filter(({ registration }) => expectedChainPlugins.includes(registration.id));

    expect(packages.map(({ registration }) => registration.id)).toEqual(expectedChainPlugins);
    for (const { registration, trust } of packages) {
      expect(registration.manifest).toMatchObject({
        catalog: { category: "chain", capabilities: ["chain.rpc", "chain.address"] },
        permission_scopes: expect.arrayContaining(["chain.rpc.read", "chain.rpc.broadcast", "chain.address.read"]),
      });
      expect(trust.publicKey).toContain("BEGIN PUBLIC KEY");
    }

    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), [
      { name: "bitcoin.node.health", health: async () => ({ status: "healthy" }) },
    ]);
    await host.initialize();
    const chains = host.listPlugins(catalogAccess).filter(({ category }) => category === "chain");
    expect(chains).toHaveLength(7);
    expect(chains.find(({ pluginId }) => pluginId === "@catomicals/plugin-bitcoin-node"))
      .toMatchObject({ enabled: true, capabilities: ["chain.rpc", "chain.address"] });
    expect(chains.filter(({ pluginId }) => pluginId !== "@catomicals/plugin-bitcoin-node"))
      .toEqual(expect.arrayContaining(expectedChainPlugins.slice(1).map((pluginId) => expect.objectContaining({
        pluginId,
        enabled: false,
        status: "ready",
      }))));
  });

  it("uses a common non-secret chain configuration and reports plugin restart impact", () => {
    for (const { registration } of builtinPackages().filter(({ registration }) =>
      registration.id === "@catomicals/plugin-bitcoin-node" || registration.id.includes("plugin-chain-"))) {
      expect(registration.settingsSchema.fields.map(({ id }) => id)).toEqual([
        "enabled", "networkId", "transport", "endpoint", "networkAccess", "credentialRef", "access",
      ]);
      expect(registration.settingsSchema.fields.find(({ id }) => id === "enabled")?.restart).toBe("plugin");
      expect(registration.settingsSchema.fields.find(({ id }) => id === "endpoint"))
        .toMatchObject({ required: false, format: "rpc-endpoint", restart: "plugin" });
      expect(registration.settingsSchema.fields.find(({ id }) => id === "credentialRef"))
        .toMatchObject({ required: false, secretReference: true, restart: "plugin" });
      expect(registration.settingsSchema.fields.find(({ id }) => id === "networkAccess"))
        .toMatchObject({ required: true, choices: ["local", "private-network", "public"], restart: "plugin" });
      expect(registration.settingsSchema.fields.find(({ id }) => id === "access"))
        .toMatchObject({ default: "read", choices: ["read", "broadcast"], restart: "plugin" });
    }
  });

  it("uses only transports implemented by each chain adapter", () => {
    const byId = new Map(builtinPackages().map(({ registration }) => [registration.id, registration.settingsSchema]));
    const transport = (pluginId: string) => byId.get(pluginId)?.fields.find(({ id }) => id === "transport");

    expect(transport("@catomicals/plugin-bitcoin-node"))
      .toMatchObject({ default: "wallet-gateway", choices: ["wallet-gateway", "json-rpc"] });
    for (const pluginId of [
      "@catomicals/plugin-chain-fractal-bitcoin",
      "@catomicals/plugin-chain-bitcoin-cash",
      "@catomicals/plugin-chain-bsv",
    ]) {
      expect(transport(pluginId)).toMatchObject({ default: "json-rpc", choices: ["json-rpc"] });
    }
    expect(transport("@catomicals/plugin-chain-kaspa"))
      .toMatchObject({ default: "https-api", choices: ["https-api", "json-rpc", "wrpc"] });
    expect(transport("@catomicals/plugin-chain-chia"))
      .toMatchObject({ default: "https-rpc", choices: ["https-rpc"] });
    expect(transport("@catomicals/plugin-chain-ergo"))
      .toMatchObject({ default: "rest", choices: ["rest"] });
  });

  it("migrates the prior Bitcoin node profile into the chain plugin without exposing credentials", async () => {
    const store = new InMemoryCordisStateStore();
    const pluginId = "@catomicals/plugin-bitcoin-node";
    const oldSettings = { profile: "inquisition", endpoint: "http://127.0.0.1:18787" };
    await store.save(pluginId, {
      storageVersion: 1,
      pluginId,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings: oldSettings,
        settingsDigest: digestJson(oldSettings),
      },
      pendingSettingsReviews: [],
    });
    const host = createBuiltinCordisHost(store, [
      { name: "bitcoin.node.health", health: async () => ({ status: "healthy" }) },
    ]);
    await host.initialize();

    await expect(host.readPluginSettings(pluginId, cordisAccess("plugin.settings.read"))).resolves.toMatchObject({
      pluginVersion: "1.2.0",
      settingsSchemaVersion: 3,
      enabled: true,
      settings: {
        enabled: true,
        networkId: "bitcoin-inquisition",
        transport: "wallet-gateway",
        endpoint: "http://127.0.0.1:18787",
        networkAccess: "local",
        access: "read",
      },
      secretStates: { credentialRef: "unset" },
    });
  });

  it("migrates the prior disabled chain settings to the implemented transport and network policy", async () => {
    const store = new InMemoryCordisStateStore();
    const pluginId = "@catomicals/plugin-chain-kaspa";
    const oldSettings = { enabled: false, networkId: "kaspa-mainnet", transport: "grpc", access: "read" };
    await store.save(pluginId, {
      storageVersion: 1,
      pluginId,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings: oldSettings,
        settingsDigest: digestJson(oldSettings),
      },
      pendingSettingsReviews: [],
    });
    const host = createBuiltinCordisHost(store);
    await host.initialize();

    await expect(host.readPluginSettings(pluginId, cordisAccess("plugin.settings.read"))).resolves.toMatchObject({
      pluginVersion: "1.1.0",
      settingsSchemaVersion: 2,
      enabled: false,
      settings: {
        enabled: false,
        networkId: "kaspa-mainnet",
        transport: "https-api",
        networkAccess: "public",
        access: "read",
      },
    });
  });

  it("isolates core plugins until their required services are registered", async () => {
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore());

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toEqual(FIXED_PLUGIN_IDS.map((pluginId, index) => expect.objectContaining({
      pluginId,
      status: index < 4 ? "isolated" : "ready",
      ...(index < 4 ? { errorCode: "missing_service" } : {}),
    })));
  });

  it("refreshes built-in health against registered backend services", async () => {
    const statuses = new Map<string, "healthy" | "unhealthy">([
      ["walletd.health", "healthy"],
      ["bitcoin.node.health", "healthy"],
      ["indexer.health", "healthy"],
      ["mcp.health", "healthy"],
    ]);
    const services: CordisService[] = [...statuses.keys()].map((name) => ({
      name,
      health: async () => ({ status: statuses.get(name) ?? "unhealthy" }),
    }));
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), services);

    await host.initialize();
    expect(host.listPlugins(catalogAccess)).toEqual(FIXED_PLUGIN_IDS.map((pluginId) => expect.objectContaining({
      pluginId,
      status: "ready",
    })));

    statuses.set("walletd.health", "unhealthy");
    expect(await host.readHealth("@catomicals/plugin-walletd", healthAccess)).toMatchObject({ status: "isolated", code: "health_failed" });
    statuses.set("walletd.health", "healthy");
    expect(await host.readHealth("@catomicals/plugin-walletd", healthAccess)).toMatchObject({ status: "healthy" });
  });

  it("contains no dynamic package, code, shell, or secret-loading path", () => {
    const sources = ["builtins.ts", "host.ts", "manifest.ts", "settings.ts"]
      .map((file) => readFileSync(new URL(file, import.meta.url), "utf8"))
      .join("\n");

    expect(sources).not.toMatch(/child_process|\bspawn\s*\(|\bexec(?:File)?\s*\(|\beval\s*\(|new Function|import\s*\(/);
    expect(sources).not.toContain("privateKey");
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(createBuiltinCordisHost(new InMemoryCordisStateStore()))))
      .not.toEqual(expect.arrayContaining(["install", "loadPackage", "runShell", "readSecret", "approve", "sign", "broadcast"]));
  });

  it("does not report optional executor, browser, or backup runtimes as healthy when unavailable", async () => {
    const services: CordisService[] = [
      "executor.codex.health", "executor.deepseek.health", "executor.claude.code.health", "browser.health", "backup.health",
    ].map((name) => ({ name, health: async () => ({ status: "degraded", message: "runtime unavailable" }) }));
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), services);
    await host.initialize();

    await expect(host.readHealth("@catomicals/plugin-executor-codex", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
    await expect(host.readHealth("@catomicals/plugin-browser", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
    await expect(host.readHealth("@catomicals/plugin-backup", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
  });
});
