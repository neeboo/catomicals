import {
  HARNESS_IDS,
  TOOL_TAB_IDS,
  type HarnessId,
  type HarnessRequest,
  type PaneBounds,
  type ToolTabId,
} from "./contracts.js";

export {
  isPrivateBrowserHost,
  parseBrowserUrl,
  shouldBlockBrowserRequest,
} from "./browser-security.js";
export { parseDesktopSettingsUpdate } from "./settings-validation.js";

export const IPC_CHANNELS = Object.freeze({
  getState: "catomicals:state:get",
  selectTab: "catomicals:tab:select",
  closeTools: "catomicals:tools:close",
  setPaneBounds: "catomicals:pane:set-bounds",
  browserNavigate: "catomicals:browser:navigate",
  browserBack: "catomicals:browser:back",
  browserForward: "catomicals:browser:forward",
  browserReload: "catomicals:browser:reload",
  settingsGet: "catomicals:settings:get",
  settingsUpdate: "catomicals:settings:update",
  harnessInvoke: "catomicals:harness:invoke",
} as const);

export const ALLOWED_INVOKE_CHANNELS = Object.freeze(Object.values(IPC_CHANNELS));

export function parseIpcArguments(values: readonly unknown[], expectedCount: number): readonly unknown[] {
  if (values.length !== expectedCount) throw new Error("invalid IPC argument count");
  return values;
}

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

export function parseToolTab(value: unknown): ToolTabId {
  if (typeof value !== "string" || !TOOL_TAB_IDS.includes(value as ToolTabId)) {
    throw new Error("invalid tool tab");
  }
  return value as ToolTabId;
}

export function parsePaneBounds(value: unknown): PaneBounds {
  const record = plainRecord(value);
  exactFields(record, ["x", "y", "width", "height"]);
  const result = Object.fromEntries(["x", "y", "width", "height"].map((key) => {
    const item = record[key];
    if (typeof item !== "number" || !Number.isFinite(item)) throw new Error("invalid pane bounds");
    return [key, Math.max(0, Math.round(item))];
  })) as unknown as PaneBounds;
  if (result.width > 1200 || result.height > 4000) throw new Error("pane bounds too large");
  return result;
}

export function parseHarnessRequest(value: unknown): HarnessRequest {
  const record = plainRecord(value);
  exactFields(record, ["harnessId", "sessionId", "prompt"]);
  if (typeof record.harnessId !== "string" || !HARNESS_IDS.includes(record.harnessId as HarnessId)) throw new Error("invalid harness");
  if (typeof record.sessionId !== "string" || !/^[a-zA-Z0-9_-]{1,80}$/.test(record.sessionId)) throw new Error("invalid session");
  if (typeof record.prompt !== "string" || record.prompt.trim().length === 0 || record.prompt.length > 20_000) throw new Error("invalid prompt");
  return { harnessId: record.harnessId as HarnessId, sessionId: record.sessionId, prompt: record.prompt };
}
