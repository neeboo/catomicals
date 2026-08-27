import { readFile, rename, writeFile } from "node:fs/promises";
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

function legacySettings(value: unknown): LegacyDesktopRuntimeSettings | undefined {
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
    const legacy = legacySettings(value);
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
      return legacySettings(JSON.parse(await readFile(this.path, "utf8")) as unknown);
    } catch {
      return undefined;
    }
  }

  async completeLegacyRuntimeMigration(value: unknown): Promise<void> {
    await this.persist(parseDesktopSettingsUpdate(value));
  }

  private async persist(settings: DesktopSettings): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporaryPath = `${this.path}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.path);
  }
}
