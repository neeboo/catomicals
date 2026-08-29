import { describe, expect, it } from "vitest";
import { CordisHost } from "./host.js";
import { digestJson } from "./manifest.js";
import { cordisAccess, cordisDesktopAccess } from "./permissions.js";
import { InMemoryCordisStateStore } from "./store.js";
import { createSignedFixture } from "./test-fixtures.js";

describe("Cordis fixed plugin host", () => {
  const catalogAccess = cordisAccess("plugin.catalog.read");
  const manifestAccess = cordisAccess("plugin.manifest.read");
  const schemaAccess = cordisAccess("plugin.settings_schema.read");
  const healthAccess = cordisAccess("plugin.health.read");
  const settingsReadAccess = cordisAccess("plugin.settings.read");
  const validateAccess = cordisAccess("plugin.settings.validate");
  const intentAccess = cordisAccess("plugin.settings_intent.create");

  it("initializes independent plugin health checks concurrently", async () => {
    let release!: () => void;
    let markBothStarted!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const bothStarted = new Promise<void>((resolve) => { markBothStarted = resolve; });
    const started: string[] = [];
    const first = createSignedFixture({ id: "@catomicals/plugin-walletd" });
    const second = createSignedFixture({ id: "@catomicals/plugin-browser" });
    first.registration.healthCheck = async () => {
      started.push("walletd");
      if (started.length === 2) markBothStarted();
      await gate;
      return { status: "healthy" };
    };
    second.registration.healthCheck = async () => {
      started.push("browser");
      if (started.length === 2) markBothStarted();
      await gate;
      return { status: "healthy" };
    };
    const host = new CordisHost({
      registrations: [first.registration, second.registration],
      trust: [first.trust, second.trust],
      stateStore: new InMemoryCordisStateStore(),
    });

    const initializing = host.initialize();
    await bothStarted;

    expect(started).toEqual(["walletd", "browser"]);
    release();
    await initializing;
  });

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
    await expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).rejects.toThrow("plugin settings unavailable");
  });

  it("keeps disabled plugins ready without resolving services or running health checks", async () => {
    const fixture = createSignedFixture({
      requiredServices: ["chain.kaspa.health"],
      settingsSchema: {
        version: 1,
        fields: [{ id: "enabled", label: "Enabled", type: "boolean", required: true, default: false, restart: "plugin" }],
      },
      catalog: { category: "chain", capabilities: ["chain.rpc", "chain.address"] },
    });
    let serviceChecks = 0;
    let packageChecks = 0;
    fixture.registration.healthCheck = async () => {
      packageChecks += 1;
      return { status: "healthy" };
    };
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
      services: [{
        name: "chain.kaspa.health",
        health: async () => {
          serviceChecks += 1;
          return { status: "healthy" };
        },
      }],
    });

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toEqual([expect.objectContaining({
      enabled: false,
      category: "chain",
      capabilities: ["chain.rpc", "chain.address"],
      status: "ready",
    })]);
    await expect(host.readHealth(fixture.registration.id, healthAccess)).resolves.toMatchObject({
      status: "disabled",
      code: "disabled",
    });
    expect(serviceChecks).toBe(0);
    expect(packageChecks).toBe(0);

    const review = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: true }],
    }, intentAccess);
    expect(review.restartImpact).toBe("plugin");
    await host.confirmSettingsIntent(review.reviewId, cordisDesktopAccess);
    expect(serviceChecks).toBe(1);
    expect(packageChecks).toBe(1);
  });

  it("persists validated defaults before isolating a first-run health failure", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async () => ({ status: "unhealthy", message: "wallet offline" });
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toContainEqual(expect.objectContaining({
      pluginId: fixture.registration.id,
      status: "isolated",
      errorCode: "health_failed",
    }));
    await expect(host.readPluginSettings(fixture.registration.id, settingsReadAccess)).resolves.toMatchObject({
      status: "isolated",
      errorCode: "health_failed",
      settings: { endpoint: "http://127.0.0.1:18787", enabled: true },
    });
    expect((await store.load(fixture.registration.id))?.lastGood.settings).toEqual({
      endpoint: "http://127.0.0.1:18787",
      enabled: true,
    });
  });

  it("recovers a first-run health failure through a healthy settings intent", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async ({ settings }) => settings.endpoint === "http://127.0.0.1:28888"
      ? { status: "healthy" }
      : { status: "unhealthy", message: "wallet offline" };
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();

    const intent = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:28888" }],
    }, intentAccess);
    const promoted = await host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess);

    expect(promoted).toMatchObject({
      status: "ready",
      settings: { endpoint: "http://127.0.0.1:28888", enabled: true },
    });
    expect(host.listPlugins(catalogAccess)).toContainEqual(expect.objectContaining({
      pluginId: fixture.registration.id,
      status: "ready",
    }));
  });

  it("validates patches and creates an intent without mutating last-good settings", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    const before = await host.readPluginSettings(fixture.registration.id, settingsReadAccess);

    const validation = host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess);
    const invalid = host.validateSettingsPatch(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "plaintext" }],
    }, validateAccess);
    const intent = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);

    expect(validation.valid).toBe(true);
    expect(invalid).toMatchObject({ valid: false, error: "invalid secret reference" });
    expect(intent).toMatchObject({ pluginId: fixture.registration.id, restartImpact: "none" });
    expect(host.listPlugins(catalogAccess)).toContainEqual(expect.objectContaining({ pluginId: fixture.registration.id, status: "ready" }));
    expect((await host.readPluginSettings(fixture.registration.id, settingsReadAccess)).settings).toEqual(before.settings);
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
    await expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).rejects.toThrow("broken migration");
    expect((await store.load(fixture.registration.id))?.lastGood.settings.endpoint).toBe("http://127.0.0.1:19999");
  });

  it("does not promote an unhealthy candidate", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async ({ settings }) => settings.endpoint === "http://127.0.0.1:19999"
      ? { status: "unhealthy", message: "endpoint unavailable" }
      : { status: "healthy" };
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    const intent = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:19999" }],
    }, intentAccess);

    await expect(host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess)).rejects.toThrow("health check");

    expect((await host.readPluginSettings(fixture.registration.id, settingsReadAccess)).settings.endpoint).toBe("http://127.0.0.1:18787");
    expect((await store.load(fixture.registration.id))?.lastGood.settings.endpoint).toBe("http://127.0.0.1:18787");
  });

  it("promotes a fully revalidated recovery intent after old settings caused health isolation", async () => {
    const fixture = createSignedFixture();
    fixture.registration.healthCheck = async ({ settings }) => settings.endpoint === "http://127.0.0.1:18787"
      ? { status: "healthy" }
      : { status: "unhealthy", message: "endpoint unavailable" };
    const store = new InMemoryCordisStateStore();
    const oldSettings = { endpoint: "http://127.0.0.1:19999", enabled: true };
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

    const recovery = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18787" }],
    }, intentAccess);
    await expect(host.confirmSettingsIntent(recovery.reviewId, cordisDesktopAccess)).resolves.toMatchObject({ status: "ready" });
    expect((await store.load(fixture.registration.id))?.lastGood.settings.endpoint).toBe("http://127.0.0.1:18787");
  });

  it("serializes competing promotions and rejects the stale intent", async () => {
    const fixture = createSignedFixture();
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
    });
    await host.initialize();
    const first = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18881" }],
    }, intentAccess);
    const second = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18882" }],
    }, intentAccess);

    const results = await Promise.allSettled([
      host.confirmSettingsIntent(first.reviewId, cordisDesktopAccess),
      host.confirmSettingsIntent(second.reviewId, cordisDesktopAccess),
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
    await expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, validateAccess)).rejects.toThrow("permission denied");
    const review = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);
    await expect(host.confirmSettingsIntent(review.reviewId, settingsReadAccess as never))
      .rejects.toThrow("desktop permission denied");
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
    const intent = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:abcdefghijklmnop" }],
    }, intentAccess);
    available.clear();

    await expect(host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess)).rejects.toThrow("secret reference unavailable");

    const stale = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18888" }],
    }, intentAccess);
    const externalSettings = { endpoint: "http://127.0.0.1:19999", enabled: true };
    const loaded = await store.load(fixture.registration.id);
    await store.save(fixture.registration.id, {
      ...loaded!,
      lastGood: {
        ...loaded!.lastGood,
        settings: externalSettings,
        settingsDigest: digestJson(externalSettings),
      },
    });
    await expect(host.confirmSettingsIntent(stale.reviewId, cordisDesktopAccess)).rejects.toThrow("stale settings intent");
  });

  it("reads authoritative last-good settings without exposing secret references", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const settings = {
      endpoint: "http://127.0.0.1:18787",
      enabled: true,
      credential: "secret-ref:abcdefghijklmnop",
    };
    await store.save(fixture.registration.id, {
      storageVersion: 1,
      pluginId: fixture.registration.id,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings,
        settingsDigest: digestJson(settings),
      },
    });
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();

    const view = await host.readPluginSettings(fixture.registration.id, settingsReadAccess);

    expect(view).toMatchObject({
      pluginId: fixture.registration.id,
      pluginVersion: "1.0.0",
      settingsSchemaVersion: 1,
      settingsDigest: digestJson(settings),
      settings: { endpoint: "http://127.0.0.1:18787", enabled: true },
      secretStates: { credential: "set" },
      schema: { version: 1 },
    });
    expect(JSON.stringify(view)).not.toContain("secret-ref:abcdefghijklmnop");
    await expect(host.readPluginSettings(fixture.registration.id, healthAccess)).rejects.toThrow("permission denied");
  });

  it("creates a host-authored field review with redacted secret changes and a computed permission delta", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const ids = [
      "60675e8d-b7a2-4602-b744-4c85d6dc0206",
      "30a2ea93-8ea0-43be-ab7e-77bfa64730a4",
    ];
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: store,
      createId: () => ids.shift()!,
      now: () => new Date("2026-08-27T12:00:00.000Z"),
    });
    await host.initialize();

    const review = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [
        { id: "endpoint", value: "http://127.0.0.1:18888" },
        { id: "credential", value: "secret-ref:abcdefghijklmnop" },
      ],
    }, intentAccess);

    expect(review).toMatchObject({
      intentId: "60675e8d-b7a2-4602-b744-4c85d6dc0206",
      reviewId: "30a2ea93-8ea0-43be-ab7e-77bfa64730a4",
      pluginId: fixture.registration.id,
      pluginVersion: "1.0.0",
      state: "current",
      restartImpact: "plugin",
      permissionDelta: { added: [], removed: [] },
      changes: [
        expect.objectContaining({ id: "endpoint", before: "http://127.0.0.1:18787", after: "http://127.0.0.1:18888" }),
        expect.objectContaining({ id: "credential", secretState: "set" }),
      ],
    });
    expect(review.baseSettingsDigest).toMatch(/^sha256:/);
    expect(review.candidateSettingsDigest).toMatch(/^sha256:/);
    const stored = (await store.load(fixture.registration.id))?.pendingSettingsReviews?.[0];
    expect(review.review_digest).toBe(stored?.payloadDigest);
    expect(review.review_digest).not.toBe(digestJson(review));
    expect(review.expiresAt).toBe("2026-08-27T12:30:00.000Z");
    expect(JSON.stringify(review)).not.toContain("secret-ref:abcdefghijklmnop");
    expect((await store.load(fixture.registration.id))?.pendingSettingsReviews).toHaveLength(1);
  });

  it("describes secret replacement and removal without returning either opaque reference", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const settings = {
      endpoint: "http://127.0.0.1:18787",
      enabled: true,
      credential: "secret-ref:abcdefghijklmnop",
    };
    await store.save(fixture.registration.id, {
      storageVersion: 1,
      pluginId: fixture.registration.id,
      lastGood: {
        pluginVersion: "1.0.0",
        settingsSchemaVersion: 1,
        migrationVersion: 0,
        settings,
        settingsDigest: digestJson(settings),
      },
    });
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();

    const changed = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:qrstuvwxyzabcdef" }],
    }, intentAccess);
    const unset = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: null }],
    }, intentAccess);

    expect(changed.changes).toEqual([expect.objectContaining({ id: "credential", secretState: "changed" })]);
    expect(unset.changes).toEqual([expect.objectContaining({ id: "credential", secretState: "unset" })]);
    expect(JSON.stringify([changed, unset])).not.toMatch(/secret-ref:/);
  });

  it("reloads persisted reviews and marks them stale against the current last-good digest", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const first = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await first.initialize();
    const created = await first.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:18888" }],
    }, intentAccess);

    const restarted = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await restarted.initialize();
    await expect(restarted.readSettingsReview(created.reviewId, settingsReadAccess))
      .resolves.toMatchObject({
        reviewId: created.reviewId,
        review_digest: created.review_digest,
        state: "current",
      });

    const loaded = await store.load(fixture.registration.id);
    const externalSettings = { endpoint: "http://127.0.0.1:19999", enabled: true };
    await store.save(fixture.registration.id, {
      ...loaded!,
      lastGood: { ...loaded!.lastGood, settings: externalSettings, settingsDigest: digestJson(externalSettings) },
    });

    await expect(restarted.readSettingsReview(created.reviewId, settingsReadAccess))
      .resolves.toMatchObject({
        reviewId: created.reviewId,
        review_digest: created.review_digest,
        state: "stale",
      });
  });

  it("rejects a persisted review whose authoritative payload digest no longer matches", async () => {
    const fixture = createSignedFixture();
    const backing = new InMemoryCordisStateStore();
    const first = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: backing });
    await first.initialize();
    const created = await first.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);
    let state = (await backing.load(fixture.registration.id))!;
    state = {
      ...state,
      pendingSettingsReviews: state.pendingSettingsReviews!.map((review) => ({
        ...review,
        payloadDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      })),
    };
    const tamperedStore = {
      load: async () => structuredClone(state),
      save: async (_pluginId: string, next: typeof state) => { state = structuredClone(next); },
    };
    const restarted = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: tamperedStore,
    });
    await restarted.initialize();

    await expect(restarted.readSettingsReview(created.reviewId, settingsReadAccess))
      .rejects.toThrow("invalid pending settings review");
  });

  it("finds a persisted review even when an earlier fixed plugin has no last-good state", async () => {
    const unavailable = createSignedFixture({
      id: "@catomicals/plugin-walletd",
      requiredServices: ["walletd.health"],
    });
    const available = createSignedFixture({ id: "@catomicals/plugin-browser" });
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({
      registrations: [unavailable.registration, available.registration],
      trust: [unavailable.trust, available.trust],
      stateStore: store,
    });
    await host.initialize();
    const review = await host.createSettingsIntent(available.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);

    await expect(host.readSettingsReview(review.reviewId, settingsReadAccess))
      .resolves.toMatchObject({ pluginId: available.registration.id, state: "current" });
  });

  it("bounds persisted reviews per plugin", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    const host = new CordisHost({ registrations: [fixture.registration], trust: [fixture.trust], stateStore: store });
    await host.initialize();
    for (let index = 0; index < 32; index += 1) {
      await host.createSettingsIntent(fixture.registration.id, {
        schemaVersion: 1,
        changes: [{ id: "endpoint", value: `http://127.0.0.1:${20_000 + index}` }],
      }, intentAccess);
    }

    await expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).rejects.toThrow("too many pending settings reviews");
    expect((await store.load(fixture.registration.id))?.pendingSettingsReviews).toHaveLength(32);
  });

  it("serializes review identifier allocation across plugins", async () => {
    const first = createSignedFixture({ id: "@catomicals/plugin-walletd" });
    const second = createSignedFixture({ id: "@catomicals/plugin-browser" });
    const backing = new InMemoryCordisStateStore();
    let barrierEnabled = false;
    let arrivals = 0;
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const store = {
      load: async (pluginId: string) => {
        const state = await backing.load(pluginId);
        if (barrierEnabled) {
          arrivals += 1;
          if (arrivals === 2) release();
          else await gate;
        }
        return state;
      },
      save: (pluginId: string, state: Parameters<InMemoryCordisStateStore["save"]>[1]) => backing.save(pluginId, state),
    };
    let idCall = 0;
    const host = new CordisHost({
      registrations: [first.registration, second.registration],
      trust: [first.trust, second.trust],
      stateStore: store,
      createId: () => idCall++ % 2 === 0
        ? "60675e8d-b7a2-4602-b744-4c85d6dc0206"
        : "30a2ea93-8ea0-43be-ab7e-77bfa64730a4",
    });
    await host.initialize();
    barrierEnabled = true;

    const results = await Promise.allSettled([
      host.createSettingsIntent(first.registration.id, {
        schemaVersion: 1,
        changes: [{ id: "enabled", value: false }],
      }, intentAccess),
      host.createSettingsIntent(second.registration.id, {
        schemaVersion: 1,
        changes: [{ id: "enabled", value: false }],
      }, intentAccess),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(results.find((result) => result.status === "rejected")).toMatchObject({
      reason: expect.objectContaining({ message: "duplicate settings review identifier" }),
    });
  });

  it("rejects a host identifier generator that does not return a UUID", async () => {
    const fixture = createSignedFixture();
    const host = new CordisHost({
      registrations: [fixture.registration],
      trust: [fixture.trust],
      stateStore: new InMemoryCordisStateStore(),
      createId: () => "review-1",
    });
    await host.initialize();

    await expect(host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess)).rejects.toThrow("invalid settings review");
  });

  it("expires reviews and never promotes them after their bounded lifetime", async () => {
    const fixture = createSignedFixture();
    const store = new InMemoryCordisStateStore();
    let now = new Date("2026-08-27T12:00:00.000Z");
    const host = new CordisHost({
      registrations: [fixture.registration], trust: [fixture.trust], stateStore: store, now: () => now,
    });
    await host.initialize();
    const review = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "enabled", value: false }],
    }, intentAccess);
    now = new Date("2026-08-27T12:31:00.000Z");

    await expect(host.readSettingsReview(review.reviewId, settingsReadAccess)).rejects.toThrow("not found");
    await expect(host.confirmSettingsIntent(review.reviewId, cordisDesktopAccess)).rejects.toThrow("not found");
    expect((await store.load(fixture.registration.id))?.pendingSettingsReviews).toEqual([]);
  });

  it("confirms only a current review after re-reading secrets and candidate health", async () => {
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
    const review = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:abcdefghijklmnop" }],
    }, intentAccess);

    await expect(host.confirmSettingsIntent(review.reviewId, cordisDesktopAccess)).resolves.toMatchObject({
      pluginId: fixture.registration.id,
      secretStates: { credential: "set" },
    });
    expect((await store.load(fixture.registration.id))?.pendingSettingsReviews).toEqual([]);

    const unavailable = await host.createSettingsIntent(fixture.registration.id, {
      schemaVersion: 1,
      changes: [{ id: "credential", value: "secret-ref:qrstuvwxyzabcdef" }],
    }, intentAccess);
    await expect(host.confirmSettingsIntent(unavailable.reviewId, cordisDesktopAccess)).rejects.toThrow("secret reference unavailable");
  });
});
