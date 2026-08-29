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
      "@catomicals/plugin-walletd": {
        endpoint: "http://[::1]:28787",
        processMode: "external",
        signerProtocol: "frost-secp256k1-tr-v1",
        signingRounds: 2,
        roundTimeoutMs: 30_000,
        sessionTimeoutMs: 120_000,
      },
      "@catomicals/plugin-mcp": { enabled: false, transport: "stdio" },
    };
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, values[pluginId]!));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.browserHome()).resolves.toBe("https://example.com/explorer");
    await expect(runtime.walletEndpoint()).resolves.toBe("http://[::1]:28787");
    await expect(runtime.walletRuntime()).resolves.toEqual({
      endpoint: "http://[::1]:28787",
      processMode: "external",
    });
    await expect(runtime.mcpEnabled()).resolves.toBe(false);
  });

  it("reads signer runtime from wallet settings and enforces the fixed protocol contract", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      signerProtocol: "frost-secp256k1-tr-v1",
      signingRounds: 2,
      roundTimeoutMs: 45_000,
      sessionTimeoutMs: 180_000,
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.signerRuntime()).resolves.toEqual({
      protocol: "frost-secp256k1-tr-v1",
      signingRounds: 2,
      roundTimeoutMs: 45_000,
      sessionTimeoutMs: 180_000,
    });
  });

  it("rejects signer settings drift from the wallet-owned contract", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      signerProtocol: "frost-secp256k1-tr-v2",
      signingRounds: 3,
      roundTimeoutMs: 45_000,
      sessionTimeoutMs: 180_000,
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.signerRuntime()).rejects.toThrow("signer");
  });

  it("rejects a signer session budget shorter than both fixed FROST rounds", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      signerProtocol: "frost-secp256k1-tr-v1",
      signingRounds: 2,
      roundTimeoutMs: 30_000,
      sessionTimeoutMs: 59_999,
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.signerRuntime()).rejects.toThrow("session timeout");
  });

  it("reads the shared generative UI policy from its Cordis plugin", async () => {
    const readPluginSettings = vi.fn(async (pluginId: string) => settingsView(pluginId, {
      enabled: true,
      preference: "prefer",
      maxBlocks: 2,
      referenceRepository: "/workspace/deepseek-harness",
      customInstructions: "Keep status cards concise.",
    }));
    const runtime = new CordisRuntimeConfig({ readPluginSettings });

    await expect(runtime.generativeUi()).resolves.toEqual({
      enabled: true,
      preference: "prefer",
      maxBlocks: 2,
      referenceRepository: "/workspace/deepseek-harness",
      customInstructions: "Keep status cards concise.",
    });
    expect(readPluginSettings).toHaveBeenCalledWith("@catomicals/plugin-generative-ui", expect.any(Object));
  });
});
