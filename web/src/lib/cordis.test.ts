import { describe, expect, it } from "vitest";
import {
  buildSettingsPatch,
  executorPluginId,
  executorPresentation,
  pluginCapabilitySummary,
  pluginCategories,
  pluginCategory,
  pluginSurfaces,
  pluginDisplayName,
  productPlugins,
  settingChoiceLabel,
  settingsDraft,
  supportedChains,
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
    expect(pluginDisplayName("@catomicals/plugin-generative-ui")).toBe("生成式界面");
  });

  it("publishes the seven CovHub chains in a stable display order", () => {
    expect(supportedChains.map(({ id, label, pluginId }) => [id, label, pluginId])).toEqual([
      ["bitcoin", "Bitcoin", "@catomicals/plugin-chain-bitcoin"],
      ["bitcoin-cash", "Bitcoin Cash", "@catomicals/plugin-chain-bitcoin-cash"],
      ["bsv", "BSV", "@catomicals/plugin-chain-bsv"],
      ["fractal-bitcoin", "Fractal Bitcoin", "@catomicals/plugin-chain-fractal-bitcoin"],
      ["kaspa", "Kaspa", "@catomicals/plugin-chain-kaspa"],
      ["chia", "Chia", "@catomicals/plugin-chain-chia"],
      ["ergo", "Ergo", "@catomicals/plugin-chain-ergo"],
    ]);
  });

  it("exposes only product chain plugins in a dedicated secondary category", () => {
    expect(pluginCategories.map((category) => category.label)).toEqual(["链插件"]);
    expect(productPlugins([
      { pluginId: "@catomicals/plugin-walletd", status: "ready" },
      { pluginId: "@catomicals/plugin-bitcoin-node", status: "ready" },
      { pluginId: "@catomicals/plugin-indexer", status: "ready" },
      { pluginId: "@catomicals/plugin-mcp", status: "ready" },
      { pluginId: "@catomicals/plugin-browser", status: "ready" },
      { pluginId: "@catomicals/plugin-chain-bitcoin", status: "ready" },
      { pluginId: "@catomicals/plugin-chain-ergo", status: "disabled" },
    ])).toEqual([
      expect.objectContaining({ pluginId: "@catomicals/plugin-chain-bitcoin" }),
      expect.objectContaining({ pluginId: "@catomicals/plugin-chain-ergo", status: "disabled" }),
    ]);
  });

  it("maps every fixed plugin to its secondary category with a safe fallback", () => {
    for (const chain of supportedChains) expect(pluginCategory(chain.pluginId)).toBe("chain-plugins");
    expect(pluginCategory("@catomicals/plugin-unknown")).toBe("chain-plugins");
  });

  it("derives chain settings surfaces from signed manifest capabilities", () => {
    const chainPlugin = {
      pluginId: "@catomicals/plugin-chain-kaspa",
      status: "ready",
      category: "chain",
      capabilities: ["chain.rpc", "chain.address"],
    } as const;
    expect(pluginSurfaces(chainPlugin)).toEqual(["chain-plugins"]);
    expect(pluginSurfaces({ ...chainPlugin, capabilities: ["chain.address"] })).toEqual(["chain-plugins"]);
    expect(pluginSurfaces("@catomicals/plugin-chain-bitcoin")).toEqual(["chain-plugins"]);
  });

  it("combines host capabilities with non-secret plugin settings", () => {
    const plugin = {
      pluginId: "@catomicals/plugin-chain-kaspa",
      pluginVersion: "1.0.0",
      status: "ready",
      enabled: true,
      category: "chain",
      capabilities: ["chain.rpc", "chain.address"],
    } as const;
    expect(pluginCapabilitySummary(plugin, {
      settings: {
        networkId: "testnet-10",
        access: "read",
        networkAccess: "private-network",
        endpoint: "https://node.example.internal/rpc?token=secret",
      },
    })).toEqual({
      chainId: "kaspa",
      chainLabel: "Kaspa",
      network: "testnet-10",
      capabilityLabel: "地址 · RPC",
      permissionLabel: "只读",
      networkAccessLabel: "私有网络",
      endpoint: "https://node.example.internal",
      verificationLabel: "RPC 验证",
    });

    expect(pluginCapabilitySummary({
      pluginId: "@catomicals/plugin-chain-ergo",
      status: "ready",
    })).toMatchObject({ chainId: "ergo", chainLabel: "Ergo", permissionLabel: "只读" });
  });

  it("localizes chain access settings", () => {
    expect(settingChoiceLabel("preset")).toBe("默认节点");
    expect(settingChoiceLabel("custom")).toBe("自建节点");
    expect(settingChoiceLabel("bitcoin-mainnet")).toBe("Bitcoin 主网");
    expect(settingChoiceLabel("bitcoin-testnet4")).toBe("Bitcoin Testnet4");
    expect(settingChoiceLabel("bitcoin-cash-chipnet")).toBe("Bitcoin Cash Chipnet");
    expect(settingChoiceLabel("bsv-testnet")).toBe("BSV 测试网");
    expect(settingChoiceLabel("fractal-bitcoin-testnet4")).toBe("Fractal Bitcoin Testnet4");
    expect(settingChoiceLabel("chia-testnet11")).toBe("Chia Testnet11");
    expect(settingChoiceLabel("ergo-testnet")).toBe("Ergo 测试网");
    expect(settingChoiceLabel("local")).toBe("仅本机");
    expect(settingChoiceLabel("private-network")).toBe("私有网络");
    expect(settingChoiceLabel("public")).toBe("公网");
    expect(settingChoiceLabel("read")).toBe("只读");
    expect(settingChoiceLabel("broadcast")).toBe("可广播");
  });

  it("localizes generative-ui choice values and passes unknown choices through", () => {
    expect(settingChoiceLabel("prefer")).toBe("优先生成组件");
    expect(settingChoiceLabel("automatic")).toBe("自动判断");
    expect(settingChoiceLabel("off")).toBe("仅使用 Markdown");
    expect(settingChoiceLabel("custom-value")).toBe("custom-value");
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
