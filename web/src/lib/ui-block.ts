import type { DesktopBridge } from "./desktop";

export type UiBlockReference =
  | { kind: "plugin_settings_diff"; reviewId: string }
  | { kind: "health_status"; pluginId: string }
  | { kind: "review_card"; reviewId: string };

type UiBlockReader = Pick<DesktopBridge, "readPluginHealth" | "readPluginSettingsReview">;

function plainRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid UI block");
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((field, index) => field !== wanted[index])) {
    throw new Error("unexpected UI block fields");
  }
}

function referenceId(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^[0-9A-Za-z@._:/-]{1,160}$/.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

export function parseUiBlockReference(value: unknown): UiBlockReference {
  const input = plainRecord(value);
  if (input.kind === "plugin_settings_diff" || input.kind === "review_card") {
    exactFields(input, ["kind", "reviewId"]);
    return { kind: input.kind, reviewId: referenceId(input.reviewId, "review reference") };
  }
  if (input.kind === "health_status") {
    exactFields(input, ["kind", "pluginId"]);
    return { kind: "health_status", pluginId: referenceId(input.pluginId, "plugin reference") };
  }
  throw new Error("unsupported UI block");
}

export async function loadControlledUiBlock(reference: UiBlockReference, bridge: UiBlockReader) {
  if (reference.kind === "health_status") {
    return { kind: reference.kind, health: await bridge.readPluginHealth(reference.pluginId) } as const;
  }
  return { kind: reference.kind, review: await bridge.readPluginSettingsReview(reference.reviewId) } as const;
}
