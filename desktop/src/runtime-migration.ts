import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { DesktopSettings } from "./contracts.js";
import { digestJson } from "./cordis/manifest.js";
import { cordisAccess, cordisDesktopAccess, type CordisAccessContext, type CordisDesktopAccessContext } from "./cordis/permissions.js";
import {
  parseStoredPluginState,
  type CordisStateStore,
  type StoredPluginState,
} from "./cordis/store.js";
import { legacyRuntimeCandidates } from "./runtime-coordinator.js";
import {
  parseLegacyRuntimeSettings,
  type LegacyDesktopRuntimeSettings,
  type SettingsStore,
} from "./settings-store.js";

const migrationPluginIds = [
  "@catomicals/plugin-executor-codex",
  "@catomicals/plugin-executor-deepseek",
  "@catomicals/plugin-executor-claude-code",
  "@catomicals/plugin-browser",
  "@catomicals/plugin-walletd",
  "@catomicals/plugin-mcp",
] as const;

const migrationAccess = cordisAccess("plugin.settings.read", "plugin.settings_intent.create");
const MAX_MIGRATION_JOURNAL_BYTES = 1024 * 1024;

interface MigrationHost {
  initialize(): Promise<void>;
  readPluginSettings(pluginId: unknown, access: CordisAccessContext): Promise<{
    pluginId: string;
    pluginVersion: string;
    settingsSchemaVersion: number;
    settings: Readonly<Record<string, string | boolean | number | null>>;
    settingsDigest: string;
  }>;
  createSettingsIntent(
    pluginId: unknown,
    patch: unknown,
    access: CordisAccessContext,
  ): Promise<{ reviewId: string }>;
  confirmSettingsIntent(reviewId: unknown, access: CordisDesktopAccessContext): Promise<unknown>;
}

interface MigrationSettingsStore {
  readonly path: string;
  readPersistedMigrationSettings(): Promise<DesktopSettings | LegacyDesktopRuntimeSettings | undefined>;
  completeLegacyRuntimeMigration(value: unknown): Promise<void>;
  restoreLegacyRuntimeSettings(value: unknown): Promise<void>;
}

interface JournalPlugin {
  readonly pluginId: string;
  readonly before: StoredPluginState;
  readonly target: StoredPluginState;
}

interface MigrationJournalPayload {
  readonly migrationId: string;
  readonly legacy: LegacyDesktopRuntimeSettings;
  readonly targetDesktopSettings: DesktopSettings;
  readonly plugins: readonly JournalPlugin[];
}

interface MigrationJournal {
  readonly journalVersion: 1;
  readonly payload: MigrationJournalPayload;
  readonly payloadDigest: string;
}

export type LegacyRuntimeMigrationCheckpoint =
  | "journal-prepared"
  | `plugin-confirmed:${(typeof migrationPluginIds)[number]}`
  | "settings-committed";

type MigrationCheckpointResult = "continue" | "interrupt";

interface LegacyRuntimeMigrationCoordinatorOptions {
  readonly userDataPath: string;
  readonly settingsStore: SettingsStore | MigrationSettingsStore;
  readonly stateStore: CordisStateStore;
  readonly checkpoint?: (checkpoint: LegacyRuntimeMigrationCheckpoint) => MigrationCheckpointResult;
}

class MigrationInterruptedError extends Error {
  constructor() {
    super("legacy runtime migration interrupted");
    this.name = "MigrationInterruptedError";
  }
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}

function parseJournalPlugin(value: unknown): JournalPlugin {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid migration journal");
  const input = value as Record<string, unknown>;
  if (!exactKeys(input, ["before", "pluginId", "target"])
    || typeof input.pluginId !== "string"
    || !migrationPluginIds.includes(input.pluginId as (typeof migrationPluginIds)[number])) {
    throw new Error("invalid migration journal");
  }
  const before = parseStoredPluginState(input.before, input.pluginId);
  const target = parseStoredPluginState(input.target, input.pluginId);
  if (before.lastGood.settingsDigest !== digestJson(before.lastGood.settings)
    || target.lastGood.settingsDigest !== digestJson(target.lastGood.settings)
    || before.lastGood.pluginVersion !== target.lastGood.pluginVersion
    || before.lastGood.settingsSchemaVersion !== target.lastGood.settingsSchemaVersion
    || before.lastGood.migrationVersion !== target.lastGood.migrationVersion) {
    throw new Error("invalid migration journal");
  }
  return { pluginId: input.pluginId, before, target };
}

function parseMigrationJournal(value: unknown): MigrationJournal {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid migration journal");
  const input = value as Record<string, unknown>;
  if (!exactKeys(input, ["journalVersion", "payload", "payloadDigest"])
    || input.journalVersion !== 1
    || typeof input.payloadDigest !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(input.payloadDigest)
    || !input.payload || typeof input.payload !== "object" || Array.isArray(input.payload)
    || digestJson(input.payload) !== input.payloadDigest) {
    throw new Error("invalid migration journal");
  }
  const payload = input.payload as Record<string, unknown>;
  if (!exactKeys(payload, ["legacy", "migrationId", "plugins", "targetDesktopSettings"])
    || typeof payload.migrationId !== "string"
    || !/^[0-9a-f-]{36}$/.test(payload.migrationId)
    || !Array.isArray(payload.plugins)
    || payload.plugins.length !== migrationPluginIds.length) {
    throw new Error("invalid migration journal");
  }
  const legacy = parseLegacyRuntimeSettings(payload.legacy);
  const target = payload.targetDesktopSettings as Record<string, unknown> | undefined;
  if (!legacy || !target || !exactKeys(target, ["defaultHarness", "version"])
    || target.version !== 2 || target.defaultHarness !== legacy.defaultHarness) {
    throw new Error("invalid migration journal");
  }
  const plugins = payload.plugins.map(parseJournalPlugin);
  if (plugins.some((plugin, index) => plugin.pluginId !== migrationPluginIds[index])) {
    throw new Error("invalid migration journal");
  }
  return {
    journalVersion: 1,
    payload: {
      migrationId: payload.migrationId,
      legacy,
      targetDesktopSettings: { version: 2, defaultHarness: legacy.defaultHarness },
      plugins,
    },
    payloadDigest: input.payloadDigest,
  };
}

async function syncDirectory(path: string): Promise<void> {
  const directory = await open(path, "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

class FileMigrationJournalStore {
  readonly path: string;

  constructor(userDataPath: string) {
    this.path = join(userDataPath, "cordis", "legacy-runtime-migration.json");
  }

  async load(): Promise<MigrationJournal | undefined> {
    try {
      const file = await open(this.path, "r");
      try {
        const metadata = await file.stat();
        if ((metadata.mode & 0o077) !== 0) throw new Error("migration journal permissions are not private");
        if (metadata.size > MAX_MIGRATION_JOURNAL_BYTES) throw new Error("migration journal too large");
        return parseMigrationJournal(JSON.parse(await file.readFile("utf8")) as unknown);
      } finally {
        await file.close();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      if (error instanceof Error && [
        "invalid migration journal",
        "migration journal permissions are not private",
        "migration journal too large",
      ].includes(error.message)) throw error;
      throw new Error("invalid migration journal", { cause: error });
    }
  }

  async save(payload: MigrationJournalPayload): Promise<void> {
    const journal = parseMigrationJournal({
      journalVersion: 1,
      payload,
      payloadDigest: digestJson(payload),
    });
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(`${JSON.stringify(journal, null, 2)}\n`, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, this.path);
    await syncDirectory(directory);
  }

  async remove(): Promise<void> {
    try {
      await unlink(this.path);
      await syncDirectory(dirname(this.path));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

function statesEqual(left: StoredPluginState, right: StoredPluginState): boolean {
  return digestJson(left) === digestJson(right);
}

export class LegacyRuntimeMigrationCoordinator {
  private readonly journalStore: FileMigrationJournalStore;
  private runtimeReady = false;

  constructor(private readonly options: LegacyRuntimeMigrationCoordinatorOptions) {
    this.journalStore = new FileMigrationJournalStore(options.userDataPath);
  }

  get journalPath(): string {
    return this.journalStore.path;
  }

  isRuntimeReady(): boolean {
    return this.runtimeReady;
  }

  assertRuntimeReady(): void {
    if (!this.runtimeReady) throw new Error("legacy runtime migration recovery required");
  }

  async recoverBeforeRuntime(): Promise<"none" | "rolled-back" | "committed"> {
    this.runtimeReady = false;
    const journal = await this.journalStore.load();
    if (!journal) {
      this.runtimeReady = true;
      return "none";
    }
    const persisted = await this.options.settingsStore.readPersistedMigrationSettings();
    const targetCommitted = persisted?.version === 2
      && digestJson(persisted) === digestJson(journal.payload.targetDesktopSettings)
      && await this.targetsMatch(journal);
    if (targetCommitted) {
      await this.journalStore.remove();
      this.runtimeReady = true;
      return "committed";
    }
    for (const plugin of journal.payload.plugins) {
      await this.options.stateStore.save(plugin.pluginId, plugin.before);
    }
    await this.options.settingsStore.restoreLegacyRuntimeSettings(journal.payload.legacy);
    if (!await this.beforeStatesMatch(journal)
      || digestJson(await this.options.settingsStore.readPersistedMigrationSettings()) !== digestJson(journal.payload.legacy)) {
      throw new Error("legacy runtime migration rollback verification failed");
    }
    await this.journalStore.remove();
    this.runtimeReady = true;
    return "rolled-back";
  }

  async migrate(host: MigrationHost, legacy: LegacyDesktopRuntimeSettings): Promise<void> {
    this.assertRuntimeReady();
    this.runtimeReady = false;
    try {
      const payload = await this.prepare(host, legacy);
      await this.journalStore.save(payload);
      this.checkpoint("journal-prepared");
      for (const plugin of payload.plugins) {
        if (statesEqual(plugin.before, plugin.target)) continue;
        const changes = Object.entries(plugin.target.lastGood.settings).flatMap(([id, value]) =>
          Object.is(plugin.before.lastGood.settings[id], value) ? [] : [{ id, value }]);
        const intent = await host.createSettingsIntent(plugin.pluginId, { schemaVersion: 1, changes }, migrationAccess);
        await host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess);
        const actual = await this.options.stateStore.load(plugin.pluginId);
        if (!actual || !statesEqual(actual, plugin.target)) throw new Error("legacy runtime migration target mismatch");
        this.checkpoint(`plugin-confirmed:${plugin.pluginId}` as LegacyRuntimeMigrationCheckpoint);
      }
      await this.options.settingsStore.completeLegacyRuntimeMigration(payload.targetDesktopSettings);
      this.checkpoint("settings-committed");
      const persisted = await this.options.settingsStore.readPersistedMigrationSettings();
      if (!persisted || digestJson(persisted) !== digestJson(payload.targetDesktopSettings)
        || !await this.targetsMatch({ journalVersion: 1, payload, payloadDigest: digestJson(payload) })) {
        throw new Error("legacy runtime migration commit verification failed");
      }
      await this.journalStore.remove();
      this.runtimeReady = true;
    } catch (error) {
      if (error instanceof MigrationInterruptedError) throw error;
      const recovery = await this.recoverBeforeRuntime();
      try {
        await host.initialize();
      } catch (initializeError) {
        this.runtimeReady = false;
        throw initializeError;
      }
      if (recovery === "committed") return;
      throw error;
    }
  }

  private async prepare(host: MigrationHost, legacyValue: LegacyDesktopRuntimeSettings): Promise<MigrationJournalPayload> {
    const legacy = parseLegacyRuntimeSettings(legacyValue);
    if (!legacy) throw new Error("invalid legacy runtime settings");
    const candidates = new Map(legacyRuntimeCandidates(legacy));
    const plugins: JournalPlugin[] = [];
    for (const pluginId of migrationPluginIds) {
      const before = await this.options.stateStore.load(pluginId);
      if (!before || before.pluginId !== pluginId || before.lastGood.settingsDigest !== digestJson(before.lastGood.settings)) {
        throw new Error("legacy runtime migration source unavailable");
      }
      const current = await host.readPluginSettings(pluginId, migrationAccess);
      if (current.pluginId !== pluginId
        || current.pluginVersion !== before.lastGood.pluginVersion
        || current.settingsSchemaVersion !== before.lastGood.settingsSchemaVersion
        || current.settingsDigest !== before.lastGood.settingsDigest) {
        throw new Error("legacy runtime migration source changed");
      }
      const settings = { ...before.lastGood.settings, ...candidates.get(pluginId)! };
      const target: StoredPluginState = parseStoredPluginState({
        ...before,
        lastGood: { ...before.lastGood, settings, settingsDigest: digestJson(settings) },
      }, pluginId);
      plugins.push({ pluginId, before, target });
    }
    return {
      migrationId: randomUUID(),
      legacy,
      targetDesktopSettings: { version: 2, defaultHarness: legacy.defaultHarness },
      plugins,
    };
  }

  private checkpoint(checkpoint: LegacyRuntimeMigrationCheckpoint): void {
    if (this.options.checkpoint?.(checkpoint) === "interrupt") throw new MigrationInterruptedError();
  }

  private async targetsMatch(journal: MigrationJournal): Promise<boolean> {
    for (const plugin of journal.payload.plugins) {
      const actual = await this.options.stateStore.load(plugin.pluginId);
      if (!actual || !statesEqual(actual, plugin.target)) return false;
    }
    return true;
  }

  private async beforeStatesMatch(journal: MigrationJournal): Promise<boolean> {
    for (const plugin of journal.payload.plugins) {
      const actual = await this.options.stateStore.load(plugin.pluginId);
      if (!actual || !statesEqual(actual, plugin.before)) return false;
    }
    return true;
  }
}
