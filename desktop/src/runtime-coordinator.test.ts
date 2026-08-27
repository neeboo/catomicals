import { describe, expect, it, vi } from "vitest";
import { applyRuntimeSettingsImpact, migrateLegacyRuntimeSettings } from "./runtime-coordinator.js";

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

  it("migrates each changed legacy runtime value through Cordis settings intents", async () => {
    const current = new Map<string, Record<string, string | boolean>>([
      ["@catomicals/plugin-executor-codex", { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" }],
      ["@catomicals/plugin-executor-deepseek", { command: "dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "" }],
      ["@catomicals/plugin-executor-claude-code", { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" }],
      ["@catomicals/plugin-browser", { home: "https://mempool.space/signet" }],
      ["@catomicals/plugin-walletd", { endpoint: "http://127.0.0.1:18787", processMode: "managed" }],
      ["@catomicals/plugin-mcp", { enabled: true, transport: "stdio" }],
    ]);
    let next = 0;
    const host = {
      readPluginSettings: vi.fn(async (pluginId: string) => ({ settings: current.get(pluginId)! })),
      createSettingsIntent: vi.fn(async (pluginId: string, patch: { changes: Array<{ id: string; value: string | boolean }> }) => {
        for (const change of patch.changes) current.get(pluginId)![change.id] = change.value;
        return { reviewId: `review-${++next}` };
      }),
      confirmSettingsIntent: vi.fn(async () => ({})),
    };

    await migrateLegacyRuntimeSettings(host, {
      version: 1,
      defaultHarness: "codex",
      adapters: {
        codex: { command: "codex-next", defaultModel: "gpt-next", reasoningEffort: "xhigh", workingDirectory: "/work" },
        deepseek: { command: "dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
        "claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
      },
      mcpEnabled: false,
      walletNodeUrl: "http://127.0.0.1:18787",
      browserHome: "https://example.com",
    });

    expect(host.createSettingsIntent).toHaveBeenCalledTimes(3);
    expect(current.get("@catomicals/plugin-executor-codex")).toMatchObject({ command: "codex-next", defaultModel: "gpt-next" });
    expect(current.get("@catomicals/plugin-browser")?.home).toBe("https://example.com");
    expect(current.get("@catomicals/plugin-mcp")?.enabled).toBe(false);
    expect(host.confirmSettingsIntent).toHaveBeenCalledTimes(3);
  });
});
