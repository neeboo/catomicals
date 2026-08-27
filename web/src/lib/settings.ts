import {
  DEFAULT_HARNESS_ID,
  isHarnessId,
  type HarnessId,
} from "./harness";

export interface DesktopSettings {
  version: 2;
  defaultHarness: HarnessId;
}

export const DEFAULT_DESKTOP_SETTINGS: DesktopSettings = {
  version: 2,
  defaultHarness: DEFAULT_HARNESS_ID,
};

export function parseDesktopSettings(value: unknown): DesktopSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return DEFAULT_DESKTOP_SETTINGS;
  const record = value as Record<string, unknown>;
  if (record.version !== 2 || !isHarnessId(record.defaultHarness)) return DEFAULT_DESKTOP_SETTINGS;
  return {
    version: 2,
    defaultHarness: record.defaultHarness,
  };
}

export function serializeDesktopSettings(settings: DesktopSettings): string {
  return JSON.stringify(parseDesktopSettings(settings), null, 2);
}
