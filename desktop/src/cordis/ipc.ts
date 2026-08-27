import { parsePluginId } from "./manifest.js";
import { parseSettingsPatch, type CordisSettingsPatch } from "./settings.js";

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error("unexpected fields");
  }
}

export function parsePluginIdRequest(value: unknown): { pluginId: string } {
  const input = record(value);
  exactFields(input, ["pluginId"]);
  return { pluginId: parsePluginId(input.pluginId) };
}

export function parsePluginSettingsPatchRequest(value: unknown): { pluginId: string; patch: CordisSettingsPatch } {
  const input = record(value);
  exactFields(input, ["pluginId", "patch"]);
  return { pluginId: parsePluginId(input.pluginId), patch: parseSettingsPatch(input.patch) };
}
