import { describe, expect, it } from "vitest";
import {
  DEFAULT_DESKTOP_SETTINGS,
  parseDesktopSettings,
  serializeDesktopSettings,
} from "./settings";

describe("desktop settings schema", () => {
  it("accepts only typed non-secret configuration", () => {
    const parsed = parseDesktopSettings({
      ...DEFAULT_DESKTOP_SETTINGS,
      defaultHarness: "deepseek",
      adapters: {
        ...DEFAULT_DESKTOP_SETTINGS.adapters,
        deepseek: {
          ...DEFAULT_DESKTOP_SETTINGS.adapters.deepseek,
          command: "deepseek-harness",
        },
      },
      token: "must-not-survive",
    });

    expect(parsed.defaultHarness).toBe("deepseek");
    expect(parsed.adapters.deepseek.command).toBe("deepseek-harness");
    expect(serializeDesktopSettings(parsed)).not.toContain("must-not-survive");
  });

  it("falls back safely when persisted data is malformed", () => {
    expect(parseDesktopSettings({ adapters: null })).toEqual(DEFAULT_DESKTOP_SETTINGS);
  });
});
