import { randomUUID } from "node:crypto";
import { open, readFile, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { mkdir } from "node:fs/promises";
import { HARNESS_IDS, type DesktopSettings, type HarnessId, type HarnessSettings } from "./contracts.js";
import { parseBrowserUrl } from "./browser-security.js";
import { parseExecutorRuntimeProfile, parseLoopbackWalletEndpoint } from "./cordis/runtime-config.js";
import { parseDesktopSettingsUpdate } from "./settings-validation.js";

const defaults: DesktopSettings = {
  version: 2,
  defaultHarness: "codex",
};

export interface LegacyDesktopRuntimeSettings {
  version: 1;
  defaultHarness: HarnessId;
  adapters: Record<HarnessId, HarnessSettings>;
  mcpEnabled: boolean;
  walletNodeUrl: string;
  browserHome: string;
}

export function parseLegacyRuntimeSettings(value: unknown): LegacyDesktopRuntimeSettings | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const input = value as Record<string, unknown>;
  if (input.version !== 1 || typeof input.defaultHarness !== "string"
    || !HARNESS_IDS.includes(input.defaultHarness as HarnessId)
    || typeof input.mcpEnabled !== "boolean") return undefined;
  const expected = ["adapters", "browserHome", "defaultHarness", "mcpEnabled", "version", "walletNodeUrl"];
  if (Object.keys(input).sort().join(",") !== expected.sort().join(",")) return undefined;
  if (!input.adapters || typeof input.adapters !== "object" || Array.isArray(input.adapters)) return undefined;
  const adapters = input.adapters as Record<string, unknown>;
  if (Object.keys(adapters).sort().join(",") !== [...HARNESS_IDS].sort().join(",")) return undefined;
  try {
    return {
      version: 1,
      defaultHarness: input.defaultHarness as HarnessId,
      adapters: Object.fromEntries(HARNESS_IDS.map((id) => [
        id,
        parseExecutorRuntimeProfile(adapters[id] as Readonly<Record<string, unknown>>),
      ])) as Record<HarnessId, HarnessSettings>,
      mcpEnabled: input.mcpEnabled,
      walletNodeUrl: parseLoopbackWalletEndpoint(input.walletNodeUrl),
      browserHome: parseBrowserUrl(input.browserHome),
    };
  } catch {
    return undefined;
  }
}

export function parsePersistedSettings(value: unknown): DesktopSettings {
  try {
    return parseDesktopSettingsUpdate(value);
  } catch {
    const legacy = parseLegacyRuntimeSettings(value);
    return legacy ? { version: 2, defaultHarness: legacy.defaultHarness } : structuredClone(defaults);
  }
}

export class SettingsStore {
  readonly path: string;

  constructor(userDataPath: string) {
    this.path = join(userDataPath, "settings.json");
  }

  async read(): Promise<DesktopSettings> {
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as unknown;
      return parsePersistedSettings(parsed);
    } catch {
      return structuredClone(defaults);
    }
  }

  async write(value: unknown): Promise<DesktopSettings> {
    const settings = parseDesktopSettingsUpdate(value);
    await this.persist(settings);
    return settings;
  }

  async readLegacyRuntimeSettings(): Promise<LegacyDesktopRuntimeSettings | undefined> {
    try {
      return parseLegacyRuntimeSettings(JSON.parse(await readFile(this.path, "utf8")) as unknown);
    } catch {
      return undefined;
    }
  }

  async readPersistedMigrationSettings(): Promise<DesktopSettings | LegacyDesktopRuntimeSettings | undefined> {
    try {
      const value = JSON.parse(await readFile(this.path, "utf8")) as unknown;
      const legacy = parseLegacyRuntimeSettings(value);
      if (legacy) return legacy;
      return parseDesktopSettingsUpdate(value);
    } catch {
      return undefined;
    }
  }

  async completeLegacyRuntimeMigration(value: unknown): Promise<void> {
    await this.persist(parseDesktopSettingsUpdate(value));
  }

  async restoreLegacyRuntimeSettings(value: unknown): Promise<void> {
    const settings = parseLegacyRuntimeSettings(value);
    if (!settings) throw new Error("invalid legacy runtime settings");
    await this.persist(settings);
  }

  private async persist(settings: DesktopSettings | LegacyDesktopRuntimeSettings): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const file = await open(temporaryPath, "wx", 0o600);
    try {
      await file.writeFile(`${JSON.stringify(settings, null, 2)}\n`, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporaryPath, this.path);
    const directory = await open(dirname(this.path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
}
