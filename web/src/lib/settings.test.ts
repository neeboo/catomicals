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
      token: "must-not-survive",
    });

    expect(parsed.defaultHarness).toBe("deepseek");
    expect(parsed).toEqual({ version: 2, defaultHarness: "deepseek" });
    expect(serializeDesktopSettings(parsed)).not.toContain("must-not-survive");
  });

  it("falls back safely when persisted data is malformed", () => {
    expect(parseDesktopSettings({ version: 2, defaultHarness: "unknown" })).toEqual(DEFAULT_DESKTOP_SETTINGS);
  });
});
