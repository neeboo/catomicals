import { describe, expect, it } from "vitest";
import {
  buildSettingsPatch,
  executorPluginId,
  executorPresentation,
  pluginDisplayName,
  settingsDraft,
  type PluginSettingsView,
} from "./cordis";

function executorSettings(overrides: Partial<PluginSettingsView> = {}): PluginSettingsView {
  return {
    pluginId: "@catomicals/plugin-executor-codex",
    pluginVersion: "1.0.0",
    status: "ready",
    settingsSchemaVersion: 1,
    settingsDigest: `sha256:${"a".repeat(64)}`,
    settings: {
      command: "codex",
      defaultModel: "gpt-5.6",
      reasoningEffort: "high",
      workingDirectory: "/workspace",
    },
    secretStates: {},
    schema: {
      version: 1,
      fields: [
        { id: "command", label: "Command", type: "string", required: true, restart: "plugin" },
        { id: "defaultModel", label: "Default model", type: "string", required: true, restart: "none" },
        { id: "reasoningEffort", label: "Reasoning effort", type: "string", required: true, restart: "none" },
        { id: "workingDirectory", label: "Working directory", type: "string", required: true, restart: "none" },
      ],
    },
    ...overrides,
  };
}

describe("Cordis renderer model", () => {
  it("builds a minimal typed patch without rewriting unchanged or hidden secret values", () => {
    const view: PluginSettingsView = {
      ...executorSettings(),
      settingsSchemaVersion: 4,
      settings: { command: "codex", enabled: true },
      secretStates: { credential: "set" },
      schema: {
        version: 4,
        fields: [
          { id: "command", label: "Command", type: "string", required: true, restart: "plugin" },
          { id: "enabled", label: "Enabled", type: "boolean", required: true, restart: "plugin" },
          { id: "credential", label: "Credential", type: "string", required: false, restart: "plugin", secretReference: true },
        ],
      },
    };

    expect(buildSettingsPatch(view, { command: "codex-next", enabled: true, credential: "" })).toEqual({
      schemaVersion: 4,
      changes: [{ id: "command", value: "codex-next" }],
    });
    expect(buildSettingsPatch(view, {
      command: "codex",
      enabled: true,
      credential: "secret-ref:abcdefghijklmnop",
    }).changes).toContainEqual({ id: "credential", value: "secret-ref:abcdefghijklmnop" });
    expect(settingsDraft(view)).toEqual({ command: "codex", enabled: true, credential: "" });
  });

  it("maps executors and fixed plugins to stable user-facing names", () => {
    expect(executorPluginId("claude-code")).toBe("@catomicals/plugin-executor-claude-code");
    expect(pluginDisplayName("@catomicals/plugin-walletd")).toBe("钱包节点");
  });

  it("shows host-probed availability and only capabilities the provider really supports", () => {
    const codex = executorPresentation(
      "codex",
      { provider: "codex", availability: "available", version: "codex-cli 1.2", capabilities: {
        create: true, send: true, interrupt: true, status: true, dispose: true, resume: true,
        modelSelection: true, reasoningEffort: true, mcp: false, walletApproval: false, signing: false, broadcast: false,
      } },
      executorSettings(),
    );
    expect(codex).toMatchObject({ availabilityLabel: "可用", model: "gpt-5.6", reasoningEffort: "high" });

    const deepseek = executorPresentation(
      "deepseek",
      { provider: "deepseek", availability: "unavailable", reason: "not-found", capabilities: {
        create: true, send: true, interrupt: true, status: true, dispose: true, resume: false,
        modelSelection: false, reasoningEffort: false, mcp: false, walletApproval: false, signing: false, broadcast: false,
      } },
      executorSettings({ pluginId: "@catomicals/plugin-executor-deepseek" }),
    );
    expect(deepseek).toMatchObject({ availabilityLabel: "未找到命令" });
    expect(deepseek.model).toBeUndefined();
    expect(deepseek.reasoningEffort).toBeUndefined();
  });
});
