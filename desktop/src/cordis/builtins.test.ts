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
  const schemaAccess = cordisAccess("plugin.settings_schema.read");

  const chainPluginIds = [
    "@catomicals/plugin-chain-bitcoin",
    "@catomicals/plugin-chain-bitcoin-cash",
    "@catomicals/plugin-chain-bsv",
    "@catomicals/plugin-chain-fractal-bitcoin",
    "@catomicals/plugin-chain-kaspa",
    "@catomicals/plugin-chain-chia",
    "@catomicals/plugin-chain-ergo",
  ] as const;

  it("contains exactly the seven CovHub chain plugins with product settings", async () => {
    expect(FIXED_PLUGIN_IDS.filter((pluginId) => pluginId.startsWith("@catomicals/plugin-chain-")))
      .toEqual(chainPluginIds);

    const host = createBuiltinCordisHost(new InMemoryCordisStateStore());
    await host.initialize();

    for (const [index, pluginId] of chainPluginIds.entries()) {
      expect(host.listPlugins(catalogAccess)).toContainEqual(expect.objectContaining({
        pluginId,
        status: index === 0 ? "isolated" : "disabled",
      }));
      expect(host.readSettingsSchema(pluginId, schemaAccess)).toMatchObject({
        fields: expect.arrayContaining([
          expect.objectContaining({ id: "enabled", type: "boolean", default: index === 0 }),
          expect.objectContaining({ id: "endpoint", type: "string", format: "rpc-endpoint" }),
          expect.objectContaining({ id: "networkId", type: "string" }),
          expect.objectContaining({ id: "addressValidation", type: "string", default: "strict", choices: ["strict"] }),
        ]),
      });
      await expect(host.readHealth(pluginId, healthAccess)).resolves.toMatchObject({
        status: index === 0 ? "isolated" : "disabled",
      });
    }
  });

  it("ships the seven chain adapters as fixed signed plugins with separate RPC and address capabilities", async () => {
    const expectedChainPlugins = [
      "@catomicals/plugin-chain-bitcoin",
      "@catomicals/plugin-chain-bitcoin-cash",
      "@catomicals/plugin-chain-bsv",
      "@catomicals/plugin-chain-fractal-bitcoin",
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
    const chains = host.listPlugins(catalogAccess).filter(({ pluginId }) => pluginId.startsWith("@catomicals/plugin-chain-"));
    expect(chains).toHaveLength(7);
    expect(chains.find(({ pluginId }) => pluginId === "@catomicals/plugin-chain-bitcoin"))
      .toMatchObject({ enabled: true, capabilities: ["chain.rpc", "chain.address"] });
    expect(chains.filter(({ pluginId }) => pluginId !== "@catomicals/plugin-chain-bitcoin"))
      .toEqual(expect.arrayContaining(expectedChainPlugins.slice(1).map((pluginId) => expect.objectContaining({
        pluginId,
        enabled: false,
        status: "disabled",
      }))));
  });

  it("uses a common non-secret chain configuration and reports plugin restart impact", () => {
    for (const { registration } of builtinPackages().filter(({ registration }) =>
      registration.id.includes("plugin-chain-"))) {
      expect(registration.settingsSchema.fields.map(({ id }) => id)).toEqual([
        "enabled", "networkId", "nodeSource", "transport", "endpoint", "networkAccess", "credentialRef", "access", "addressValidation",
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
      expect(registration.settingsSchema.fields.find(({ id }) => id === "addressValidation"))
        .toMatchObject({ default: "strict", choices: ["strict"], restart: "none" });
    }
  });

  it("provides separate built-in mainnet and testnet choices without requiring an endpoint", () => {
    const schemas = new Map(builtinPackages()
      .filter(({ registration }) => registration.id.startsWith("@catomicals/plugin-chain-"))
      .map(({ registration }) => [registration.id, registration.settingsSchema]));

    expect(schemas.get("@catomicals/plugin-chain-bitcoin")?.fields.find(({ id }) => id === "networkId"))
      .toMatchObject({ default: "bitcoin-inquisition", choices: expect.arrayContaining(["bitcoin-mainnet", "bitcoin-testnet4", "bitcoin-signet"]) });
    expect(schemas.get("@catomicals/plugin-chain-bitcoin-cash")?.fields.find(({ id }) => id === "networkId"))
      .toMatchObject({ choices: [
        "bitcoin-cash-mainnet",
        "bitcoin-cash-testnet3",
        "bitcoin-cash-testnet4",
        "bitcoin-cash-chipnet",
        "bitcoin-cash-scalenet",
        "bitcoin-cash-regtest",
      ] });
    expect(schemas.get("@catomicals/plugin-chain-bsv")?.fields.find(({ id }) => id === "networkId"))
      .toMatchObject({ choices: ["bsv-mainnet", "bsv-testnet", "bsv-stn", "bsv-regtest"] });
    expect(schemas.get("@catomicals/plugin-chain-kaspa")?.fields.find(({ id }) => id === "networkId"))
      .toMatchObject({ choices: [
        "kaspa-mainnet",
        "kaspa-testnet-10",
        "kaspa-testnet-11",
        "kaspa-simnet",
        "kaspa-devnet",
      ] });
    for (const schema of schemas.values()) {
      expect(schema.fields.find(({ id }) => id === "nodeSource"))
        .toMatchObject({ label: "节点来源", default: "preset", choices: ["preset", "custom"] });
      expect(schema.fields.find(({ id }) => id === "networkId")).toMatchObject({ label: "网络" });
      expect(schema.fields.find(({ id }) => id === "endpoint"))
        .toMatchObject({ required: false });
      expect(schema.fields.find(({ id }) => id === "endpoint")).not.toHaveProperty("default");
    }
  });

  it("uses only transports implemented by each chain adapter", () => {
    const byId = new Map(builtinPackages().map(({ registration }) => [registration.id, registration.settingsSchema]));
    const transport = (pluginId: string) => byId.get(pluginId)?.fields.find(({ id }) => id === "transport");

    expect(transport("@catomicals/plugin-chain-bitcoin"))
      .toMatchObject({ default: "json-rpc", choices: ["json-rpc"] });
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

  it("stores wallet-owned signer settings with a fixed protocol, fixed round count, and editable timeouts", () => {
    const walletSchema = builtinPackages()
      .find(({ registration }) => registration.id === "@catomicals/plugin-walletd")
      ?.registration.settingsSchema;

    expect(walletSchema?.fields.map(({ id }) => id)).toEqual([
      "endpoint",
      "processMode",
      "signerProtocol",
      "signingRounds",
      "roundTimeoutMs",
      "sessionTimeoutMs",
    ]);
    expect(walletSchema?.fields.find(({ id }) => id === "signerProtocol"))
      .toMatchObject({ type: "string", default: "frost-secp256k1-tr-v1", choices: ["frost-secp256k1-tr-v1"], restart: "plugin" });
    expect(walletSchema?.fields.find(({ id }) => id === "signingRounds"))
      .toMatchObject({ type: "integer", default: 2, minimum: 2, maximum: 2, restart: "plugin" });
    expect(walletSchema?.fields.find(({ id }) => id === "roundTimeoutMs"))
      .toMatchObject({ type: "integer", default: 30_000, minimum: 1_000, maximum: 120_000, restart: "plugin" });
    expect(walletSchema?.fields.find(({ id }) => id === "sessionTimeoutMs"))
      .toMatchObject({ type: "integer", default: 120_000, minimum: 1_000, maximum: 900_000, restart: "plugin" });
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
      pluginVersion: "1.2.0",
      settingsSchemaVersion: 3,
      enabled: false,
      settings: {
        enabled: false,
        networkId: "kaspa-mainnet",
        nodeSource: "preset",
        transport: "https-api",
        networkAccess: "public",
        access: "read",
      },
    });
  });

  it("maps legacy unqualified mainnet settings to each plugin's explicit RPC preset", () => {
    const cases = [
      ["@catomicals/plugin-chain-bitcoin-cash", "bitcoin-cash-mainnet"],
      ["@catomicals/plugin-chain-bsv", "bsv-mainnet"],
      ["@catomicals/plugin-chain-fractal-bitcoin", "fractal-bitcoin-mainnet"],
      ["@catomicals/plugin-chain-kaspa", "kaspa-mainnet"],
      ["@catomicals/plugin-chain-chia", "chia-mainnet"],
      ["@catomicals/plugin-chain-ergo", "ergo-mainnet"],
    ] as const;

    for (const [pluginId, rpcPresetId] of cases) {
      const migration = builtinPackages()
        .find(({ registration }) => registration.id === pluginId)
        ?.registration.migrations?.find(({ from }) => from === 0);
      expect(migration?.migrate({ enabled: false, networkId: "mainnet" }))
        .toMatchObject({ networkId: rpcPresetId });
    }

    const kaspaMigration = builtinPackages()
      .find(({ registration }) => registration.id === "@catomicals/plugin-chain-kaspa")
      ?.registration.migrations?.find(({ from }) => from === 0);
    expect(() => kaspaMigration?.migrate({ enabled: false, networkId: "bitcoin-mainnet" }))
      .toThrow("unsupported legacy kaspa RPC preset: bitcoin-mainnet");
  });

  it("migrates older wallet settings to include signer defaults", async () => {
    const store = new InMemoryCordisStateStore();
    const pluginId = "@catomicals/plugin-walletd";
    const oldSettings = { endpoint: "http://127.0.0.1:18787", processMode: "managed" };
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
      { name: "walletd.health", health: async () => ({ status: "healthy" }) },
    ]);
    await host.initialize();

    await expect(host.readPluginSettings(pluginId, cordisAccess("plugin.settings.read"))).resolves.toMatchObject({
      settingsSchemaVersion: 2,
      settings: {
        endpoint: "http://127.0.0.1:18787",
        processMode: "managed",
        signerProtocol: "frost-secp256k1-tr-v1",
        signingRounds: 2,
        roundTimeoutMs: 30_000,
        sessionTimeoutMs: 120_000,
      },
    });
  });

  it("isolates core plugins until their required services are registered", async () => {
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore());

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toEqual(FIXED_PLUGIN_IDS.map((pluginId, index) => {
      const chainPlugin = pluginId.startsWith("@catomicals/plugin-chain-");
      const enabledChainPlugin = pluginId === "@catomicals/plugin-chain-bitcoin";
      return expect.objectContaining({
        pluginId,
        status: index < 4 || enabledChainPlugin ? "isolated" : chainPlugin ? "disabled" : "ready",
        ...(index < 4 || enabledChainPlugin ? { errorCode: "missing_service" } : {}),
      });
    }));
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
      status: pluginId.startsWith("@catomicals/plugin-chain-") && pluginId !== "@catomicals/plugin-chain-bitcoin"
        ? "disabled"
        : "ready",
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
