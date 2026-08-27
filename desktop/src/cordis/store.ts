import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CordisSettings } from "./settings.js";

export interface PluginTree {
  readonly pluginVersion: string;
  readonly settingsSchemaVersion: number;
  readonly migrationVersion: number;
  readonly settings: CordisSettings;
  readonly settingsDigest: string;
}

export interface StoredPluginState {
  readonly storageVersion: 1;
  readonly pluginId: string;
  readonly lastGood: PluginTree;
}

export interface CordisStateStore {
  load(pluginId: string): Promise<StoredPluginState | undefined>;
  save(pluginId: string, state: StoredPluginState): Promise<void>;
}

export class InMemoryCordisStateStore implements CordisStateStore {
  private readonly values = new Map<string, StoredPluginState>();

  async load(pluginId: string): Promise<StoredPluginState | undefined> {
    const value = this.values.get(pluginId);
    return value ? structuredClone(value) : undefined;
  }

  async save(pluginId: string, state: StoredPluginState): Promise<void> {
    if (state.pluginId !== pluginId) throw new Error("plugin state namespace mismatch");
    this.values.set(pluginId, structuredClone(state));
  }
}

function namespaceFilename(pluginId: string): string {
  return `${createHash("sha256").update(pluginId).digest("hex")}.json`;
}

function parseStoredState(value: unknown, pluginId: string): StoredPluginState {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid plugin state");
  const state = value as Record<string, unknown>;
  if (Object.keys(state).sort().join(",") !== "lastGood,pluginId,storageVersion" || state.storageVersion !== 1 || state.pluginId !== pluginId) {
    throw new Error("invalid plugin state");
  }
  if (!state.lastGood || typeof state.lastGood !== "object" || Array.isArray(state.lastGood)) throw new Error("invalid last-good tree");
  const tree = state.lastGood as Record<string, unknown>;
  if (Object.keys(tree).sort().join(",") !== "migrationVersion,pluginVersion,settings,settingsDigest,settingsSchemaVersion"
    || typeof tree.pluginVersion !== "string"
    || !Number.isSafeInteger(tree.settingsSchemaVersion) || (tree.settingsSchemaVersion as number) < 1
    || !Number.isSafeInteger(tree.migrationVersion) || (tree.migrationVersion as number) < 0
    || typeof tree.settingsDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(tree.settingsDigest)
    || !tree.settings || typeof tree.settings !== "object" || Array.isArray(tree.settings)) {
    throw new Error("invalid last-good tree");
  }
  const settings: Record<string, string | boolean | number | null> = {};
  for (const [key, item] of Object.entries(tree.settings as Record<string, unknown>)) {
    if (item !== null && typeof item !== "string" && typeof item !== "boolean"
      && !(typeof item === "number" && Number.isSafeInteger(item))) throw new Error("invalid stored setting");
    settings[key] = item as string | boolean | number | null;
  }
  return {
    storageVersion: 1,
    pluginId,
    lastGood: {
      pluginVersion: tree.pluginVersion,
      settingsSchemaVersion: tree.settingsSchemaVersion as number,
      migrationVersion: tree.migrationVersion as number,
      settings,
      settingsDigest: tree.settingsDigest,
    },
  };
}

export class FileCordisStateStore implements CordisStateStore {
  private readonly directory: string;

  constructor(userDataPath: string) {
    this.directory = join(userDataPath, "cordis", "plugins");
  }

  async load(pluginId: string): Promise<StoredPluginState | undefined> {
    try {
      return parseStoredState(JSON.parse(await readFile(join(this.directory, namespaceFilename(pluginId)), "utf8")) as unknown, pluginId);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  async save(pluginId: string, state: StoredPluginState): Promise<void> {
    if (state.pluginId !== pluginId) throw new Error("plugin state namespace mismatch");
    await mkdir(this.directory, { recursive: true });
    const path = join(this.directory, namespaceFilename(pluginId));
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, path);
  }
}
