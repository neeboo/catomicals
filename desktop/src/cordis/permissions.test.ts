import { describe, expect, it } from "vitest";
import { calculatePermissionDelta } from "./permissions.js";

describe("Cordis permission review", () => {
  it("computes additions and removals from host-validated permission sets", () => {
    expect(calculatePermissionDelta(
      ["plugin.health.read", "plugin.settings.validate"],
      ["plugin.settings.validate", "plugin.settings_intent.create"],
    )).toEqual({
      added: ["plugin.settings_intent.create"],
      removed: ["plugin.health.read"],
    });
  });
});
