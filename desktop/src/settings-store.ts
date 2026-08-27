import { readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { mkdir } from "node:fs/promises";
import type { DesktopSettings } from "./contracts.js";
import { DESKTOP_ENDPOINTS } from "./runtime-security.js";
import { parseDesktopSettingsUpdate } from "./settings-validation.js";

const defaults: DesktopSettings = {
  version: 1,
  defaultHarness: "codex",
  adapters: {
    codex: { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
    deepseek: { command: "deepseek-harness", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
    "claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  },
  mcpEnabled: true,
  walletNodeUrl: DESKTOP_ENDPOINTS.walletNodeUrl,
  browserHome: "https://mempool.space/signet",
};

export function parsePersistedSettings(value: unknown): DesktopSettings {
  try {
    return parseDesktopSettingsUpdate(value);
  } catch {
    return structuredClone(defaults);
  }
}

export class SettingsStore {
  readonly path: string;

  constructor(userDataPath: string) {
    this.path = join(userDataPath, "settings.json");
  }

  async read(): Promise<DesktopSettings> {
    try {
      return parsePersistedSettings(JSON.parse(await readFile(this.path, "utf8")) as unknown);
    } catch {
      return structuredClone(defaults);
    }
  }

  async write(value: unknown): Promise<DesktopSettings> {
    const settings = parseDesktopSettingsUpdate(value);
    await mkdir(dirname(this.path), { recursive: true });
    const temporaryPath = `${this.path}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.path);
    return settings;
  }
}
