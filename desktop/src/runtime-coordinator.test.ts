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

  it("reconfigures only the personal signer when signer timeout fields change", () => {
    const registry = { noteConfigurationChange: vi.fn() };
    const signer = { noteConfigurationChange: vi.fn() };

    applyRuntimeSettingsImpact(registry, {
      pluginId: "@catomicals/plugin-walletd",
      restartImpact: "plugin",
      changes: [{ id: "roundTimeoutMs" }],
    }, signer);

    expect(signer.noteConfigurationChange).toHaveBeenCalledOnce();
    expect(registry.noteConfigurationChange).not.toHaveBeenCalled();
  });

  it("does not restart the signer for wallet endpoint changes", () => {
    const signer = { noteConfigurationChange: vi.fn() };
    applyRuntimeSettingsImpact({ noteConfigurationChange: vi.fn() }, {
      pluginId: "@catomicals/plugin-walletd",
      restartImpact: "plugin",
      changes: [{ id: "endpoint" }],
    }, signer);
    expect(signer.noteConfigurationChange).not.toHaveBeenCalled();
  });

});
