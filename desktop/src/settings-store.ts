import { readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { mkdir } from "node:fs/promises";
import {
  HARNESS_IDS,
  REASONING_EFFORTS,
  type DesktopSettings,
  type HarnessId,
  type HarnessSettings,
  type ReasoningEffort,
} from "./contracts.js";

const defaults: DesktopSettings = {
  version: 1,
  defaultHarness: "codex",
  adapters: {
    codex: { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
    deepseek: { command: "deepseek-harness", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
    "claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
  },
  mcpEnabled: true,
  walletNodeUrl: "http://127.0.0.1:18787",
  browserHome: "https://mempool.space/signet",
};

function text(value: unknown, fallback: string, maxLength = 1024): string {
  return typeof value === "string" && value.length <= maxLength ? value : fallback;
}

function parseAdapter(value: unknown, fallback: HarnessSettings): HarnessSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  const record = value as Record<string, unknown>;
  const reasoningEffort = typeof record.reasoningEffort === "string"
    && REASONING_EFFORTS.includes(record.reasoningEffort as ReasoningEffort)
      ? record.reasoningEffort as ReasoningEffort
      : fallback.reasoningEffort;
  return {
    command: text(record.command, fallback.command, 256),
    defaultModel: text(record.defaultModel, fallback.defaultModel, 256),
    reasoningEffort,
    workingDirectory: text(record.workingDirectory, fallback.workingDirectory),
  };
}

export function parsePersistedSettings(value: unknown): DesktopSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return structuredClone(defaults);
  const record = value as Record<string, unknown>;
  const adapters = record.adapters && typeof record.adapters === "object" && !Array.isArray(record.adapters)
    ? record.adapters as Record<string, unknown>
    : {};
  const defaultHarness = typeof record.defaultHarness === "string" && HARNESS_IDS.includes(record.defaultHarness as HarnessId)
    ? record.defaultHarness as HarnessId
    : "codex";
  return {
    version: 1,
    defaultHarness,
    adapters: Object.fromEntries(HARNESS_IDS.map((id) => [id, parseAdapter(adapters[id], defaults.adapters[id])])) as Record<HarnessId, HarnessSettings>,
    mcpEnabled: typeof record.mcpEnabled === "boolean" ? record.mcpEnabled : true,
    walletNodeUrl: text(record.walletNodeUrl, defaults.walletNodeUrl, 512),
    browserHome: text(record.browserHome, defaults.browserHome, 512),
  };
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
    const settings = parsePersistedSettings(value);
    await mkdir(dirname(this.path), { recursive: true });
    const temporaryPath = `${this.path}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.path);
    return settings;
  }
}
