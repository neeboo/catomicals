import { readFileSync } from "node:fs";
import { chmod, mkdtemp, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CordisRuntimeConfig } from "./cordis/runtime-config.js";
import { digestJson } from "./cordis/manifest.js";
import { FileCordisStateStore, InMemoryCordisStateStore, type StoredPluginState } from "./cordis/store.js";
import {
  LegacyRuntimeMigrationCoordinator,
  type LegacyRuntimeMigrationCheckpoint,
} from "./runtime-migration.js";
import { SettingsStore, type LegacyDesktopRuntimeSettings } from "./settings-store.js";

const pluginIds = [
  "@catomicals/plugin-executor-codex",
  "@catomicals/plugin-executor-deepseek",
  "@catomicals/plugin-executor-claude-code",
  "@catomicals/plugin-browser",
  "@catomicals/plugin-walletd",
  "@catomicals/plugin-mcp",
] as const;

const initialSettings: Record<(typeof pluginIds)[number], Record<string, string | boolean>> = {
  "@catomicals/plugin-executor-codex": { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  "@catomicals/plugin-executor-deepseek": { command: "dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  "@catomicals/plugin-executor-claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  "@catomicals/plugin-browser": { home: "https://mempool.space/signet" },
  "@catomicals/plugin-walletd": { endpoint: "http://127.0.0.1:18787", processMode: "managed" },
  "@catomicals/plugin-mcp": { enabled: true, transport: "stdio" },
};

const legacy: LegacyDesktopRuntimeSettings = {
  version: 1,
  defaultHarness: "claude-code",
  adapters: {
    codex: { command: "codex-next", defaultModel: "gpt-next", reasoningEffort: "xhigh", workingDirectory: "/work/codex" },
    deepseek: { command: "dsh-next", defaultModel: "", reasoningEffort: "high", workingDirectory: "/work/deepseek" },
    "claude-code": { command: "claude-next", defaultModel: "sonnet", reasoningEffort: "high", workingDirectory: "/work/claude" },
  },
  mcpEnabled: false,
  walletNodeUrl: "http://127.0.0.1:18888",
  browserHome: "https://example.com",
};

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

function state(pluginId: string, settings: Record<string, string | boolean>): StoredPluginState {
  return {
    storageVersion: 1,
    pluginId,
    lastGood: {
      pluginVersion: "1.0.0",
      settingsSchemaVersion: 1,
      migrationVersion: 0,
      settings,
      settingsDigest: digestJson(settings),
    },
    pendingSettingsReviews: [],
  };
}

async function fixture(options: {
  failConfirmationAt?: number;
  failInitialize?: boolean;
  interruptAt?: LegacyRuntimeMigrationCheckpoint;
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "catomicals-runtime-migration-"));
  directories.push(directory);
  const settingsStore = new SettingsStore(directory);
  await settingsStore.restoreLegacyRuntimeSettings(legacy);
  const stateStore = new FileCordisStateStore(directory);
  for (const pluginId of pluginIds) await stateStore.save(pluginId, state(pluginId, initialSettings[pluginId]));
  const reviews = new Map<string, { pluginId: string; changes: Array<{ id: string; value: string | boolean }> }>();
  let confirmations = 0;
  const host = {
    initialize: vi.fn(async () => {
      if (options.failInitialize) throw new Error("host initialize failed");
    }),
    readPluginSettings: vi.fn(async (pluginId: string) => {
      const stored = (await stateStore.load(pluginId))!;
      return {
        pluginId,
        pluginVersion: stored.lastGood.pluginVersion,
        settingsSchemaVersion: stored.lastGood.settingsSchemaVersion,
        settings: stored.lastGood.settings,
        settingsDigest: stored.lastGood.settingsDigest,
      };
    }),
    createSettingsIntent: vi.fn(async (pluginId: string, patch: { changes: Array<{ id: string; value: string | boolean }> }) => {
      const reviewId = `review-${reviews.size + 1}`;
      reviews.set(reviewId, { pluginId, changes: patch.changes });
      return { reviewId };
    }),
    confirmSettingsIntent: vi.fn(async (reviewId: string) => {
      confirmations += 1;
      if (confirmations === options.failConfirmationAt) throw new Error("confirmation failed");
      const review = reviews.get(reviewId)!;
      const stored = (await stateStore.load(review.pluginId))!;
      const settings = { ...stored.lastGood.settings };
      for (const change of review.changes) settings[change.id] = change.value;
      await stateStore.save(review.pluginId, {
        ...stored,
        lastGood: { ...stored.lastGood, settings, settingsDigest: digestJson(settings) },
      });
      return {};
    }),
  };
  const coordinator = new LegacyRuntimeMigrationCoordinator({
    userDataPath: directory,
    settingsStore,
    stateStore,
    ...(options.interruptAt ? {
      checkpoint: (checkpoint) => checkpoint === options.interruptAt ? "interrupt" : "continue",
    } : {}),
  });
  await coordinator.recoverBeforeRuntime();
  return { directory, settingsStore, stateStore, host, coordinator };
}

async function settingsByPlugin(store: FileCordisStateStore): Promise<Record<string, unknown>> {
  return Object.fromEntries(await Promise.all(pluginIds.map(async (pluginId) => [
    pluginId,
    (await store.load(pluginId))!.lastGood.settings,
  ])));
}

describe("legacy runtime migration transaction", () => {
  it("makes the first-run journal directory entry durable before writing the journal", () => {
    const source = readFileSync(new URL("./runtime-migration.ts", import.meta.url), "utf8");
    const classStart = source.indexOf("class FileMigrationJournalStore");
    const ensureStart = source.indexOf("async ensureDirectoryReady()", classStart);
    const mkdir = source.indexOf("mkdir(this.directory", ensureStart);
    const parentSync = source.indexOf("syncDirectory(this.userDataPath)", ensureStart);
    const saveStart = source.indexOf("async save(payload: MigrationJournalPayload)", classStart);
    const waitForBarrier = source.indexOf("this.ensureDirectoryReady()", saveStart);

    expect(ensureStart).toBeGreaterThan(classStart);
    expect(mkdir).toBeGreaterThan(ensureStart);
    expect(parentSync).toBeGreaterThan(mkdir);
    expect(waitForBarrier).toBeGreaterThan(saveStart);
  });

  it("does not start migration when the first-run journal parent sync fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-runtime-journal-sync-"));
    directories.push(directory);
    const settingsStore = new SettingsStore(directory);
    await settingsStore.restoreLegacyRuntimeSettings(legacy);
    const stateStore = new InMemoryCordisStateStore();
    for (const pluginId of pluginIds) await stateStore.save(pluginId, state(pluginId, initialSettings[pluginId]));
    const host = {
      initialize: vi.fn(async () => undefined),
      readPluginSettings: vi.fn(async (pluginId: string) => {
        const stored = (await stateStore.load(pluginId))!;
        return {
          pluginId,
          pluginVersion: stored.lastGood.pluginVersion,
          settingsSchemaVersion: stored.lastGood.settingsSchemaVersion,
          settings: stored.lastGood.settings,
          settingsDigest: stored.lastGood.settingsDigest,
        };
      }),
      createSettingsIntent: vi.fn(async () => ({ reviewId: "unused" })),
      confirmSettingsIntent: vi.fn(async () => ({})),
    };
    const coordinator = new LegacyRuntimeMigrationCoordinator({ userDataPath: directory, settingsStore, stateStore });
    await coordinator.recoverBeforeRuntime();

    const probe = await open(directory, "r");
    const fileHandlePrototype = Object.getPrototypeOf(probe) as { sync: typeof probe.sync };
    const originalSync = fileHandlePrototype.sync;
    await probe.close();
    const sync = vi.spyOn(fileHandlePrototype, "sync").mockImplementation(async function () {
      const handle = this as typeof probe;
      if ((await handle.stat()).isDirectory()) throw new Error("journal parent sync failed");
      await originalSync.call(handle);
    });
    try {
      await expect(coordinator.migrate(host, legacy)).rejects.toThrow("journal parent sync failed");
      expect(host.createSettingsIntent).not.toHaveBeenCalled();
      await expect(settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
      await expect(stat(coordinator.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
      expect(coordinator.isRuntimeReady()).toBe(true);
    } finally {
      sync.mockRestore();
    }
  });

  it.each([2, 3])("rolls every plugin back when confirmation %i fails", async (failureAt) => {
    const context = await fixture({ failConfirmationAt: failureAt });

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("confirmation failed");

    expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
    expect(context.host.initialize).toHaveBeenCalledOnce();
    expect(context.coordinator.isRuntimeReady()).toBe(true);
  });

  it("rolls plugins back when the SettingsStore v2 commit fails", async () => {
    const context = await fixture();
    vi.spyOn(context.settingsStore, "completeLegacyRuntimeMigration").mockRejectedValueOnce(new Error("settings commit failed"));

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("settings commit failed");

    expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
    expect(context.coordinator.isRuntimeReady()).toBe(true);
  });

  it("rolls plugins back when the SettingsStore reports success without committing v2", async () => {
    const context = await fixture();
    vi.spyOn(context.settingsStore, "completeLegacyRuntimeMigration").mockResolvedValueOnce(undefined);

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("commit verification failed");

    expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
    expect(context.coordinator.isRuntimeReady()).toBe(true);
  });

  it("keeps the journal until a failed plugin durability barrier has been rolled back", async () => {
    const context = await fixture();
    const durableSave = context.stateStore.save.bind(context.stateStore);
    let saves = 0;
    vi.spyOn(context.stateStore, "save").mockImplementation(async (pluginId, nextState) => {
      await durableSave(pluginId, nextState);
      saves += 1;
      if (saves === 1) throw new Error("plugin durability barrier failed");
    });

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("plugin durability barrier failed");

    expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
    await expect(stat(context.coordinator.journalPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(context.coordinator.isRuntimeReady()).toBe(true);
  });

  it("keeps runtime blocked when host reinitialization after rollback fails", async () => {
    const context = await fixture({ failConfirmationAt: 2, failInitialize: true });

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("host initialize failed");

    expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    expect(context.coordinator.isRuntimeReady()).toBe(false);
  });

  it("rejects a source whose live plugin version differs from the snapshotted state", async () => {
    const context = await fixture();
    context.host.readPluginSettings.mockImplementationOnce(async (pluginId: string) => {
      const stored = (await context.stateStore.load(pluginId))!;
      return {
        pluginId,
        pluginVersion: "2.0.0",
        settingsSchemaVersion: stored.lastGood.settingsSchemaVersion,
        settings: stored.lastGood.settings,
        settingsDigest: stored.lastGood.settingsDigest,
      };
    });

    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("source changed");

    expect(context.host.createSettingsIntent).not.toHaveBeenCalled();
    expect(context.coordinator.isRuntimeReady()).toBe(true);
  });

  it.each<LegacyRuntimeMigrationCheckpoint>([
    "journal-prepared",
    ...pluginIds.map((pluginId) => `plugin-confirmed:${pluginId}` as const),
    "settings-committed",
  ])("recovers deterministically after an abrupt stop at %s", async (checkpoint) => {
    const context = await fixture({ interruptAt: checkpoint });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    expect(context.coordinator.isRuntimeReady()).toBe(false);

    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });
    await restarted.recoverBeforeRuntime();

    if (checkpoint === "settings-committed") {
      await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toBeUndefined();
      expect((await context.stateStore.load("@catomicals/plugin-browser"))!.lastGood.settings.home).toBe("https://example.com");
    } else {
      await expect(context.settingsStore.readLegacyRuntimeSettings()).resolves.toEqual(legacy);
      expect(await settingsByPlugin(context.stateStore)).toEqual(initialSettings);
    }
    expect(restarted.isRuntimeReady()).toBe(true);
  });

  it("keeps the private journal durable and makes retry idempotent", async () => {
    const context = await fixture({ interruptAt: "plugin-confirmed:@catomicals/plugin-executor-claude-code" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    expect((await stat(context.coordinator.journalPath)).mode & 0o777).toBe(0o600);

    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });
    await restarted.recoverBeforeRuntime();
    await restarted.migrate(context.host, legacy);
    const confirmedAfterRetry = context.host.confirmSettingsIntent.mock.calls.length;
    await restarted.migrate(context.host, legacy);

    expect(context.host.confirmSettingsIntent.mock.calls.length).toBe(confirmedAfterRetry);
    expect(JSON.parse(await readFile(context.settingsStore.path, "utf8"))).toEqual({ version: 2, defaultHarness: "claude-code" });
  });

  it("blocks every runtime read until an unfinished journal is recovered", async () => {
    const context = await fixture({ interruptAt: "journal-prepared" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    const reader = { readPluginSettings: vi.fn(async () => ({ settings: { home: "https://example.com" } })) };
    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });
    const runtime = new CordisRuntimeConfig(reader, restarted);

    await expect(runtime.browserHome()).rejects.toThrow("migration recovery required");
    expect(reader.readPluginSettings).not.toHaveBeenCalled();
    await restarted.recoverBeforeRuntime();
    await expect(runtime.browserHome()).resolves.toBe("https://example.com");
  });

  it("fails closed when a journal snapshot is tampered", async () => {
    const context = await fixture({ interruptAt: "journal-prepared" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    const journal = JSON.parse(await readFile(context.coordinator.journalPath, "utf8")) as Record<string, unknown>;
    const payload = journal.payload as Record<string, unknown>;
    (payload.plugins as Array<Record<string, unknown>>)[0]!.pluginId = "@catomicals/plugin-attacker";
    journal.payloadDigest = digestJson(payload);
    await writeFile(context.coordinator.journalPath, JSON.stringify(journal), { mode: 0o600 });
    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });

    await expect(restarted.recoverBeforeRuntime()).rejects.toThrow("invalid migration journal");
    expect(restarted.isRuntimeReady()).toBe(false);
  });

  it("rejects a journal that changes the snapshotted plugin version", async () => {
    const context = await fixture({ interruptAt: "journal-prepared" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    const journal = JSON.parse(await readFile(context.coordinator.journalPath, "utf8")) as Record<string, unknown>;
    const payload = journal.payload as Record<string, unknown>;
    const plugin = (payload.plugins as Array<Record<string, unknown>>)[0]!;
    const before = plugin.before as Record<string, unknown>;
    const lastGood = before.lastGood as Record<string, unknown>;
    lastGood.pluginVersion = "2.0.0";
    journal.payloadDigest = digestJson(payload);
    await writeFile(context.coordinator.journalPath, JSON.stringify(journal), { mode: 0o600 });
    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });

    await expect(restarted.recoverBeforeRuntime()).rejects.toThrow("invalid migration journal");
    expect(restarted.isRuntimeReady()).toBe(false);
  });

  it("rejects an oversized journal before parsing it", async () => {
    const context = await fixture({ interruptAt: "journal-prepared" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    await writeFile(context.coordinator.journalPath, "x".repeat(1024 * 1024 + 1), { mode: 0o600 });
    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });

    await expect(restarted.recoverBeforeRuntime()).rejects.toThrow("migration journal too large");
    expect(restarted.isRuntimeReady()).toBe(false);
  });

  it("rejects a journal with group or world permissions", async () => {
    const context = await fixture({ interruptAt: "journal-prepared" });
    await expect(context.coordinator.migrate(context.host, legacy)).rejects.toThrow("migration interrupted");
    await chmod(context.coordinator.journalPath, 0o644);
    const restarted = new LegacyRuntimeMigrationCoordinator({
      userDataPath: context.directory,
      settingsStore: context.settingsStore,
      stateStore: context.stateStore,
    });

    await expect(restarted.recoverBeforeRuntime()).rejects.toThrow("migration journal permissions");
    expect(restarted.isRuntimeReady()).toBe(false);
  });
});
