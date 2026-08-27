import {
  HARNESS_IDS,
  REASONING_EFFORTS,
  type DesktopSettings,
  type HarnessId,
  type HarnessSettings,
} from "./contracts.js";
import { parseBrowserUrl } from "./browser-security.js";
import { DESKTOP_ENDPOINTS } from "./runtime-security.js";

function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Record<string, unknown>;
}

function exactFields(record: Record<string, unknown>, fields: readonly string[]): void {
  const keys = Object.keys(record).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("unexpected fields");
  }
}

function boundedText(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length > maximum) throw new Error(`invalid ${field}`);
  return value;
}

function processText(value: unknown, field: string, maximum: number): string {
  const parsed = boundedText(value, field, maximum);
  if (/[\0\r\n]/.test(parsed)) throw new Error(`invalid ${field}`);
  return parsed;
}

function parseHarnessSettings(value: unknown): HarnessSettings {
  const record = plainRecord(value);
  exactFields(record, ["command", "defaultModel", "reasoningEffort", "workingDirectory"]);
  const reasoningEffort = record.reasoningEffort;
  if (typeof reasoningEffort !== "string" || !REASONING_EFFORTS.includes(reasoningEffort as HarnessSettings["reasoningEffort"])) {
    throw new Error("invalid reasoning effort");
  }
  return {
    command: processText(record.command, "harness command", 256),
    defaultModel: processText(record.defaultModel, "default model", 256),
    reasoningEffort: reasoningEffort as HarnessSettings["reasoningEffort"],
    workingDirectory: processText(record.workingDirectory, "working directory", 1024),
  };
}

function parseWalletNodeUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 512) throw new Error("invalid wallet node URL");
  const url = new URL(value);
  if (!DESKTOP_ENDPOINTS.walletNodeOrigins.includes(url.origin as typeof DESKTOP_ENDPOINTS.walletNodeOrigins[number])
    || url.username || url.password
    || (url.pathname !== "/" && url.pathname !== "")
    || url.search || url.hash) {
    throw new Error("invalid wallet node URL");
  }
  return value;
}

export function parseDesktopSettingsUpdate(value: unknown): DesktopSettings {
  const record = plainRecord(value);
  exactFields(record, ["version", "defaultHarness", "adapters", "mcpEnabled", "walletNodeUrl", "browserHome"]);
  if (record.version !== 1) throw new Error("invalid settings version");
  if (typeof record.defaultHarness !== "string" || !HARNESS_IDS.includes(record.defaultHarness as HarnessId)) {
    throw new Error("invalid default harness");
  }
  if (typeof record.mcpEnabled !== "boolean") throw new Error("invalid MCP setting");
  const adapters = plainRecord(record.adapters);
  exactFields(adapters, HARNESS_IDS);
  const parsedAdapters = Object.fromEntries(
    HARNESS_IDS.map((id) => [id, parseHarnessSettings(adapters[id])]),
  ) as Record<HarnessId, HarnessSettings>;
  return {
    version: 1,
    defaultHarness: record.defaultHarness as HarnessId,
    adapters: parsedAdapters,
    mcpEnabled: record.mcpEnabled,
    walletNodeUrl: parseWalletNodeUrl(record.walletNodeUrl),
    browserHome: parseBrowserUrl(record.browserHome),
  };
}
