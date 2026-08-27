import { describe, expect, it } from "vitest";
import { CordisHost } from "./host.js";
import { digestJson } from "./manifest.js";
import { cordisAccess } from "./permissions.js";
import { InMemoryCordisStateStore } from "./store.js";
import { createSignedFixture } from "./test-fixtures.js";

describe("Cordis fixed plugin host", () => {
  const catalogAccess = cordisAccess("plugin.catalog.read");
  const manifestAccess = cordisAccess("plugin.manifest.read");
  const schemaAccess = cordisAccess("plugin.settings_schema.read");
  const healthAccess = cordisAccess("plugin.health.read");
  const validateAccess = cordisAccess("plugin.settings.validate");
  const intentAccess = cordisAccess("plugin.settings_intent.create");

  it("isolates a bad package without blocking a valid plugin", async () => {
    const good = createSignedFixture({ id: "@catomicals/plugin-walletd" });
    const bad = createSignedFixture({ id: "@catomicals/plugin-browser" });
    const host = new CordisHost({
      registrations: [good.registration, { ...bad.registration, descriptor: "tampered" }],
      trust: [good.trust, bad.trust],
      stateStore: new InMemoryCordisStateStore(),
    });

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toEqual(expect.arrayContaining([
      expect.objectContaining({ pluginId: good.registration.id, status: "ready" }),
      expect.objectContaining({ pluginId: bad.registration.id, status: "isolated", errorCode: "package_invalid" }),
    ]));
  });

  it("isolates a plugin with a missing required service", async () => {
    const fixture = createSignedFixture({ requiredServices: ["walletd.health"] });
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
    });

    await host.initialize();

    expect(await host.readHealth(fixture.registration.id, healthAccess)).toMatchObject({
      status: "isolated",
      code: "missing_service",
    });
    expect(host.readManifest(fixture.registration.id, manifestAccess).plugin_id).toBe(fixture.registration.id);
    expect(host.readSettingsSchema(fixture.registration.id, schemaAccess).version).toBe(1);
    expect(host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess)).toMatchObject({ valid: true });
    const recovery = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);
    await expect(host.promoteSettingsIntent(recovery.intentId)).rejects.toThrow("plugin isolated");
  });

  it("validates patches and creates an intent without mutating last-good settings", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    const before = host.readPlugin(fixture.registration.id);

    const validation = host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess);
    const invalid = host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "plaintext" }],
    }, validateAccess);
    const intent = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);

    expect(validation.valid).toBe(true);
    expect(invalid).toMatchObject({ valid: false, error: "invalid secret reference" });
    expect(intent).toMatchObject({ pluginId: fixture.registration.id, restartImpact: "none" });
    expect(host.listPlugins(catalogAccess)).toContainEqual(expect.objectContaining({ pluginId: fixture.registration.id, status: "ready" }));
    expect(host.readPlugin(fixture.registration.id).settings).toEqual(before.settings);
    expect((await store.load(fixture.registration.id))?.lastGood.settings).toEqual(before.settings);
  });

  it("keeps the last-good tree when migration fails", async () => {
    const fixture = createSignedFixture({ migrationCurrent: 1 });
    fixture.registration.migrations = [{
      from: 0,
      to: 1,
      migrate: () => { throw new Error("broken migration"); },
    }];
    const store = new InMemoryCordisStateStore();
    await store.save(fixture.registration.id, {
      storageVersion: 1,
      pluginId: fixture.registration.id,
      lastGood: {
        pluginVersion: "0.9.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings: { endpoint: "http://127.0.0.1:19999", enabled: true },
        settingsDigest: digestJson({ endpoint: "http://127.0.0.1:19999", enabled: true }),
      },
    });
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });

    await host.initialize();

    expect(await host.readHealth(fixture.registration.id, healthAccess)).toMatchObject({ status: "isolated", code: "migration_failed" });
    expect(host.readManifest(fixture.registration.id, manifestAccess).plugin_id).toBe(fixture.registration.id);
    expect(host.readSettingsSchema(fixture.registration.id, schemaAccess).version).toBe(1);
    expect(host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess)).toMatchObject({ valid: true });
    expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).toMatchObject({ pluginId: fixture.registration.id });
    expect((await store.load(fixture.registration.id))?.lastGood.settings.endpoint).toBe("http://127.0.0.1:19999");
  });

  it("does not promote an unhealthy candidate", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async ({ settings }) => settings.enabled === false
      ? { status: "unhealthy", message: "disabled" }
      : { status: "healthy" };
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    const intent = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);

    await expect(host.promoteSettingsIntent(intent.intentId)).rejects.toThrow("health check");

    expect(host.readPlugin(fixture.registration.id).settings.enabled).toBe(true);
    expect((await store.load(fixture.registration.id))?.lastGood.settings.enabled).toBe(true);
  });

  it("promotes a fully revalidated recovery intent after old settings caused health isolation", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async ({ settings }) => settings.enabled
      ? { status: "healthy" }
      : { status: "unhealthy", message: "disabled" };
    const store = new InMemoryCordisStateStore();
    const oldSettings = { endpoint: "http://127.0.0.1:18787", enabled: false };
    await store.save(fixture.registration.id, {
      storageVersion: 1,
      pluginId: fixture.registration.id,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings: oldSettings,
        settingsDigest: digestJson(oldSettings),
      },
    });
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    expect(await host.readHealth(fixture.registration.id, healthAccess)).toMatchObject({ status: "isolated" });

    const recovery = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: true }],
    }, intentAccess);
    await expect(host.promoteSettingsIntent(recovery.intentId)).resolves.toMatchObject({ status: "ready" });
    expect((await store.load(fixture.registration.id))?.lastGood.settings.enabled).toBe(true);
  });

  it("serializes competing promotions and rejects the stale intent", async () => {
    const fixture = createSignedFixture();
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
    });
    await host.initialize();
    const first = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18881" }],
    }, intentAccess);
    const second = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18882" }],
    }, intentAccess);

    const results = await Promise.allSettled([
      host.promoteSettingsIntent(first.intentId),
      host.promoteSettingsIntent(second.intentId),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(results.find((result) => result.status === "rejected")).toMatchObject({
      reason: expect.objectContaining({ message: "stale settings intent" }),
    });
  });

  it("enforces the permission scope at each host operation", async () => {
    const fixture = createSignedFixture();
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
    });
    await host.initialize();

    expect(() => host.listPlugins(healthAccess)).toThrow("permission denied");
    await expect(host.readHealth(fixture.registration.id, catalogAccess)).rejects.toThrow("permission denied");
    expect(() => host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).toThrow("permission denied");
    expect(() => host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess)).toThrow("permission denied");
  });

  it("re-reads state and opaque secret references during promotion", async () => {
    const fixture = createSignedFixture();
    const available = new Set(["secret-ref:abcdefghijklmnop"]);
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: store,
      secretReferences: { exists: async (reference) => available.has(reference) },
    });
    await host.initialize();
    const intent = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:abcdefghijklmnop" }],
    }, intentAccess);
    available.clear();

    await expect(host.promoteSettingsIntent(intent.intentId)).rejects.toThrow("secret reference unavailable");

    const stale = host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18888" }],
    }, intentAccess);
    const externalSettings = { endpoint: "http://127.0.0.1:19999", enabled: true };
    await store.save(fixture.registration.id, {
      storageVersion: 1,
      pluginId: fixture.registration.id,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings: externalSettings,
        settingsDigest: digestJson(externalSettings),
      },
    });
    await expect(host.promoteSettingsIntent(stale.intentId)).rejects.toThrow("stale settings intent");
  });
});
