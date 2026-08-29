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
    expect(supportedChains.map(({ id, label }) => [id, label])).toEqual([
      ["bitcoin", "Bitcoin"],
      ["kaspa", "Kaspa"],
      ["bitcoin-cash", "Bitcoin Cash"],
      ["bsv", "BSV"],
      ["fractal-bitcoin", "Fractal Bitcoin"],
      ["chia", "Chia"],
      ["ergo", "Ergo"],
    ]);
  });

  it("orders the settings rail by plugin responsibility", () => {
    expect(pluginCategories.map((category) => category.label)).toEqual([
      "钱包与安全",
      "链与地址",
      "节点与 RPC",
      "数据与索引",
      "代理",
      "界面与工具",
    ]);
  });

  it("maps every fixed plugin to its secondary category with a safe fallback", () => {
    expect(pluginCategory("@catomicals/plugin-walletd")).toBe("wallet-security");
    expect(pluginCategory("@catomicals/plugin-backup")).toBe("wallet-security");
    expect(pluginCategory("@catomicals/plugin-bitcoin-node")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-kaspa")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-bitcoin-cash")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-bsv")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-fractal-bitcoin")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-chia")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-chain-ergo")).toBe("chains-addresses");
    expect(pluginCategory("@catomicals/plugin-indexer")).toBe("data-indexing");
    expect(pluginCategory("@catomicals/plugin-mcp")).toBe("agents");
    expect(pluginCategory("@catomicals/plugin-executor-codex")).toBe("agents");
    expect(pluginCategory("@catomicals/plugin-executor-deepseek")).toBe("agents");
    expect(pluginCategory("@catomicals/plugin-executor-claude-code")).toBe("agents");
    expect(pluginCategory("@catomicals/plugin-generative-ui")).toBe("interface-tools");
    expect(pluginCategory("@catomicals/plugin-browser")).toBe("interface-tools");
    expect(pluginCategory("@catomicals/plugin-unknown")).toBe("interface-tools");
    expect(pluginCategory({
      pluginId: "@catomicals/plugin-external-index",
      category: "data",
    })).toBe("data-indexing");
  });

  it("derives chain settings surfaces from signed manifest capabilities", () => {
    const chainPlugin = {
      pluginId: "@catomicals/plugin-chain-kaspa",
      status: "ready",
      category: "chain",
      capabilities: ["chain.rpc", "chain.address"],
    } as const;
    expect(pluginSurfaces(chainPlugin)).toEqual(["chains-addresses", "node-rpc"]);
    expect(pluginSurfaces({ ...chainPlugin, capabilities: ["chain.address"] })).toEqual(["chains-addresses"]);
    expect(pluginSurfaces("@catomicals/plugin-bitcoin-node")).toEqual(["chains-addresses", "node-rpc"]);
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
