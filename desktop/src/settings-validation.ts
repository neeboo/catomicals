import { HARNESS_IDS, type DesktopSettings, type HarnessId } from "./contracts.js";

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

export function parseDesktopSettingsUpdate(value: unknown): DesktopSettings {
  const record = plainRecord(value);
  exactFields(record, ["version", "defaultHarness"]);
  if (record.version !== 2) throw new Error("invalid settings version");
  if (typeof record.defaultHarness !== "string" || !HARNESS_IDS.includes(record.defaultHarness as HarnessId)) {
    throw new Error("invalid default harness");
  }
  return {
    version: 2,
    defaultHarness: record.defaultHarness as HarnessId,
  };
}
