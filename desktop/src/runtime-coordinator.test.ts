import { describe, expect, it, vi } from "vitest";
import { applyRuntimeSettingsImpact } from "./runtime-coordinator.js";

describe("runtime settings coordination", () => {
  it("marks only matching executor sessions when confirmation requires a plugin restart", () => {
    const registry = { noteConfigurationChange: vi.fn() };

    applyRuntimeSettingsImpact(registry, {
      pluginId: "@catomicals/plugin-executor-deepseek",
      restartImpact: "plugin",
    });

    expect(registry.noteConfigurationChange).toHaveBeenCalledWith("deepseek", "plugin");
  });

  it("does not mutate executor sessions for browser or wallet confirmations", () => {
    const registry = { noteConfigurationChange: vi.fn() };
    applyRuntimeSettingsImpact(registry, { pluginId: "@catomicals/plugin-browser", restartImpact: "none" });
    applyRuntimeSettingsImpact(registry, { pluginId: "@catomicals/plugin-walletd", restartImpact: "plugin" });
    expect(registry.noteConfigurationChange).not.toHaveBeenCalled();
  });

});
