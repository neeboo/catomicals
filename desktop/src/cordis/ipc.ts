import { parseSettingsReviewId } from "./identifiers.js";
import { parsePluginId } from "./manifest.js";
import { parseSettingsPatch, type CordisSettingsPatch } from "./settings.js";

const MAX_IPC_REQUEST_BYTES = 64 * 1024;
const MAX_IPC_NODES = 512;

function assertClosedRequest(value: unknown): void {
  const budget = { bytes: 0, nodes: 0 };
  const visit = (item: unknown, depth: number): void => {
    budget.nodes += 1;
    if (budget.nodes > MAX_IPC_NODES || depth > 8) throw new Error("IPC request too large");
    if (typeof item === "string") budget.bytes += Buffer.byteLength(item, "utf8");
    else if (item === null || typeof item === "boolean" || typeof item === "number") budget.bytes += 8;
    else if (Array.isArray(item)) {
      if (item.length > 256) throw new Error("IPC request too large");
      for (const child of item) visit(child, depth + 1);
    } else if (typeof item === "object" && item) {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new Error("expected plain object");
      if (Reflect.ownKeys(item).some((key) => typeof key !== "string")) throw new Error("expected plain object");
      for (const [key, child] of Object.entries(item)) {
        if (key === "__proto__" || key === "prototype" || key === "constructor") throw new Error("unsafe object field");
        budget.bytes += Buffer.byteLength(key, "utf8");
        visit(child, depth + 1);
      }
    } else {
      throw new Error("invalid IPC value");
    }
    if (budget.bytes > MAX_IPC_REQUEST_BYTES) throw new Error("IPC request too large");
  };
  visit(value, 0);
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("expected plain object");
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
  assertClosedRequest(value);
  const input = record(value);
  exactFields(input, ["pluginId"]);
  return { pluginId: parsePluginId(input.pluginId) };
}

export function parsePluginSettingsPatchRequest(value: unknown): { pluginId: string; patch: CordisSettingsPatch } {
  assertClosedRequest(value);
  const input = record(value);
  exactFields(input, ["pluginId", "patch"]);
  return { pluginId: parsePluginId(input.pluginId), patch: parseSettingsPatch(input.patch) };
}

export function parsePluginSettingsReviewRequest(value: unknown): { reviewId: string } {
  assertClosedRequest(value);
  const input = record(value);
  exactFields(input, ["reviewId"]);
  return { reviewId: parseSettingsReviewId(input.reviewId) };
}
