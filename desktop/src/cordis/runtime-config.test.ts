import { describe, expect, it, vi } from "vitest";
import type { PluginSettingsView } from "../contracts.js";
import { CordisRuntimeConfig } from "./runtime-config.js";

function settingsView(pluginId: string, settings: Record<string, string | boolean | number | null>): PluginSettingsView {
  return {
    pluginId,
    pluginVersion: "1.0.0",
    status: "ready",
    settingsSchemaVersion: 1,
    settingsDigest: `sha256:${"1".repeat(64)}`,
    settings,
    secretStates: {},
    schema: { version: 1, fields: [] },
  };
}

describe("Cordis runtime configuration", () => {
  it("reads executor profiles only from the matching plugin last-good settings", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      command: "codex-next",
      defaultModel: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      workingDirectory: "/workspace",
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.executor("codex")).resolves.toEqual({
      command: "codex-next",
      defaultModel: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      workingDirectory: "/workspace",
    });
    expect(readPluginSettings).toHaveBeenCalledWith("@catomicals/plugin-executor-codex", expect.any(Object));
  });

  it("rejects non-loopback wallet endpoints before exposing them to the renderer", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      endpoint: "https://wallet.example",
      processMode: "external",
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.walletEndpoint()).rejects.toThrow("loopback");
  });

  it("reads browser, wallet, and MCP values from their individual plugins", async () => {
    const values: Record<string, Record<string, string | boolean>> = {
      "@catomicals/plugin-browser": { home: "https://example.com/explorer" },
      "@catomicals/plugin-walletd": { endpoint: "http://[::1]:28787", processMode: "external" },
      "@catomicals/plugin-mcp": { enabled: false, transport: "stdio" },
    };
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, values[pluginId]!));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.browserHome()).resolves.toBe("https://example.com/explorer");
    await expect(runtime.renderer()).resolves.toEqual({
      walletEndpoint: "http://[::1]:28787",
      mcpEnabled: false,
    });
  });
});
