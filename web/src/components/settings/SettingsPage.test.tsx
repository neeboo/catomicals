// @vitest-environment jsdom

import type { ReactNode } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PluginListEntry, PluginSettingsView } from "@/lib/cordis";
import { SettingsPage } from "./SettingsPage";

const testState = vi.hoisted(() => ({
  desktopBridge: null as Record<string, unknown> | null,
}));

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="#settings">{children}</a>,
}));

vi.mock("@/lib/desktop", () => ({
  optionalDesktopBridge: () => testState.desktopBridge,
  requireDesktopBridge: () => {
    if (!testState.desktopBridge) throw new Error("desktop unavailable");
    return testState.desktopBridge;
  },
}));

// Wallet/node status for the compact menu-entry indicators (网络与数据,
// 钱包与安全). Healthy defaults; individual tests can override via
// testState.statusOverrides.
const testStatus = vi.hoisted(() => ({
  node: { data: { network: "signet" } as { network: string } | undefined, isSuccess: true },
  wallet: {
    data: { node: { op_cat_active: true }, threshold: { max_signers: 3 } },
    isSuccess: true,
  },
  signer: { data: { configured: true, min_signers: 2 } },
  credentials: { data: [{ credential_id: "cred-1", label: "MacBook" }] },
}));

vi.mock("@/lib/hooks", () => ({
  useNodeStatusQuery: () => testStatus.node,
  useWalletStatusQuery: () => testStatus.wallet,
  useSignerStatusQuery: () => testStatus.signer,
  useCredentialsQuery: () => testStatus.credentials,
}));

const FIXED_PLUGINS: PluginListEntry[] = [
  { pluginId: "@catomicals/plugin-walletd", pluginVersion: "1.0.0", status: "ready", enabled: true, category: "wallet", capabilities: ["wallet"] },
  {
    pluginId: "@catomicals/plugin-bitcoin-node",
    pluginVersion: "1.0.0",
    status: "ready",
    enabled: true,
    category: "system",
    capabilities: [],
  },
  {
    pluginId: "@catomicals/plugin-chain-bitcoin",
    pluginVersion: "1.0.0",
    status: "ready",
    enabled: true,
    category: "chain",
    capabilities: ["chain.rpc", "chain.address"],
  },
  {
    pluginId: "@catomicals/plugin-chain-kaspa",
    pluginVersion: "1.0.0",
    status: "ready",
    enabled: true,
    category: "chain",
    capabilities: ["chain.rpc", "chain.address"],
  },
  { pluginId: "@catomicals/plugin-chain-bitcoin-cash", pluginVersion: "1.0.0", status: "ready", enabled: true, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
  { pluginId: "@catomicals/plugin-chain-bsv", pluginVersion: "1.0.0", status: "disabled", enabled: false, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
  { pluginId: "@catomicals/plugin-chain-fractal-bitcoin", pluginVersion: "1.0.0", status: "ready", enabled: true, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
  { pluginId: "@catomicals/plugin-chain-chia", pluginVersion: "1.0.0", status: "ready", enabled: true, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
  { pluginId: "@catomicals/plugin-chain-ergo", pluginVersion: "1.0.0", status: "ready", enabled: true, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
  { pluginId: "@catomicals/plugin-indexer", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-mcp", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-executor-codex", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-executor-deepseek", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-executor-claude-code", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-generative-ui", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-backup", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-browser", pluginVersion: "1.0.0", status: "ready" },
];

function minimalView(pluginId: string): PluginSettingsView {
  const chainSettings: Partial<Record<string, PluginSettingsView["settings"]>> = {
    "@catomicals/plugin-chain-bitcoin": {
      enabled: true,
      networkId: "inquisition-signet",
      access: "broadcast",
      networkAccess: "local",
      endpoint: "http://127.0.0.1:38332",
      addressValidation: "strict",
    },
    "@catomicals/plugin-chain-kaspa": {
      enabled: true,
      networkId: "kaspa-testnet-10",
      nodeSource: "preset",
      access: "read",
      transport: "https-api",
      networkAccess: "public",
      addressValidation: "strict",
    },
  };
  return {
    pluginId,
    pluginVersion: "1.0.0",
    status: "ready",
    settingsSchemaVersion: 1,
    settingsDigest: `sha256:${"a".repeat(64)}`,
    settings: chainSettings[pluginId] ?? { enabled: true },
    secretStates: {},
    schema: {
      version: 1,
      fields: pluginId.startsWith("@catomicals/plugin-chain-") ? [
        { id: "enabled", label: "启用", type: "boolean", required: true, restart: "plugin" },
        { id: "networkId", label: "网络", type: "string", required: true, restart: "plugin", choices: ["kaspa-mainnet", "kaspa-testnet-10", "kaspa-testnet-11"] },
        { id: "nodeSource", label: "节点来源", type: "string", required: true, restart: "plugin", choices: ["preset", "custom"] },
        { id: "transport", label: "传输协议", type: "string", required: true, restart: "plugin", choices: ["https-api"] },
        { id: "endpoint", label: "RPC endpoint", type: "string", required: false, restart: "plugin", format: "rpc-endpoint" },
        { id: "networkAccess", label: "网络访问", type: "string", required: true, restart: "plugin", choices: ["local", "private-network", "public"] },
        { id: "credentialRef", label: "RPC 凭证", type: "string", required: false, restart: "plugin", secretReference: true },
        { id: "addressValidation", label: "地址校验", type: "string", required: true, restart: "none", choices: ["strict"] },
      ] : [{ id: "enabled", label: "启用", type: "boolean", required: true, restart: "none" }],
    },
  };
}

function installBridge() {
  const bridge = {
    listPlugins: vi.fn().mockResolvedValue(FIXED_PLUGINS),
    readPluginSettings: vi.fn(async (pluginId: string) => minimalView(pluginId)),
    readPluginHealth: vi.fn().mockResolvedValue({ status: "healthy", checkedAt: "2026-08-29T05:00:00.000Z" }),
    validatePluginSettings: vi.fn().mockResolvedValue({ valid: true }),
    createPluginSettingsIntent: vi.fn().mockResolvedValue({ reviewId: "11111111-1111-4111-8111-111111111111" }),
    readPluginSettingsReview: vi.fn(),
    confirmPluginSettingsIntent: vi.fn(),
  };
  testState.desktopBridge = bridge;
  return bridge;
}

beforeEach(() => {
  testState.desktopBridge = null;
  testStatus.node = { data: { network: "signet" }, isSuccess: true };
  testStatus.wallet = {
    data: { node: { op_cat_active: true }, threshold: { max_signers: 3 } },
    isSuccess: true,
  };
  testStatus.signer = { data: { configured: true, min_signers: 2 } };
  testStatus.credentials = { data: [{ credential_id: "cred-1", label: "MacBook" }] };
});

afterEach(() => {
  cleanup();
});

describe("settings plugin catalog", () => {
  it("shows only the product chain plugin category and hides internal Cordis modules", async () => {
    const bridge = installBridge();
    render(<SettingsPage />);

    expect(await screen.findByRole("heading", { name: "插件", level: 1 })).toBeTruthy();
    for (const label of ["全部插件", "链插件"]) {
      expect(screen.getByRole("button", { name: new RegExp(label) })).toBeTruthy();
    }
    expect(screen.getByRole("button", { name: /全部插件\s*7/ })).toBeTruthy();
    for (const pluginId of [
      "@catomicals/plugin-walletd",
      "@catomicals/plugin-bitcoin-node",
      "@catomicals/plugin-indexer",
      "@catomicals/plugin-mcp",
      "@catomicals/plugin-browser",
    ]) {
      expect(screen.queryByTestId(`plugin-row-${pluginId}`)).toBeNull();
      expect(bridge.readPluginSettings).not.toHaveBeenCalledWith(pluginId);
    }
  });

  it("shows the seven supported chains without renaming them", async () => {
    installBridge();
    render(<SettingsPage />);

    const overview = await screen.findByLabelText("支持的链");
    for (const chain of ["Bitcoin", "Kaspa", "Bitcoin Cash", "BSV", "Fractal Bitcoin", "Chia", "Ergo"]) {
      expect(within(overview).getByText(chain)).toBeTruthy();
    }
  });

  it("presents all seven chain adapters once in the dedicated chain category", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    const chainFilter = await screen.findByRole("button", { name: /链插件\s*7/ });
    expect(chainFilter).toBeTruthy();
    expect(screen.getAllByTestId("plugin-row-@catomicals/plugin-chain-kaspa")).toHaveLength(1);

    await user.click(chainFilter);
    for (const plugin of FIXED_PLUGINS.filter((entry) => entry.pluginId.startsWith("@catomicals/plugin-chain-"))) {
      expect(screen.getByTestId(`plugin-row-${plugin.pluginId}`)).toBeTruthy();
    }
    expect(screen.queryByTestId("plugin-row-@catomicals/plugin-walletd")).toBeNull();
    expect(screen.getByRole("heading", { name: "链插件", level: 2 })).toBeTruthy();
  });

  it("shows chain, network, permission, endpoint, health, check time and verification on a plugin row", async () => {
    installBridge();
    render(<SettingsPage />);

    const kaspa = await screen.findByTestId("plugin-row-@catomicals/plugin-chain-kaspa");
    expect(within(kaspa).getAllByText("Kaspa").length).toBeGreaterThan(0);
    expect(within(kaspa).getByText(/kaspa-testnet-10/)).toBeTruthy();
    for (const text of ["地址 · RPC", "只读 · 公网", "默认节点", "运行正常", "RPC 验证"]) {
      expect(within(kaspa).getByText(text)).toBeTruthy();
    }
    expect(within(kaspa).getByText(/最后检查/)).toBeTruthy();
  });

  it("uses the settings view for the current broadcast access instead of the catalog default", async () => {
    installBridge();
    render(<SettingsPage />);

    const bitcoin = await screen.findByTestId("plugin-row-@catomicals/plugin-chain-bitcoin");
    expect(within(bitcoin).getByText("可广播 · 仅本机")).toBeTruthy();
  });

  it("treats a disabled plugin as disabled rather than unhealthy", async () => {
    installBridge();
    render(<SettingsPage />);

    const bsv = await screen.findByTestId("plugin-row-@catomicals/plugin-chain-bsv");
    expect(within(bsv).getByText("已停用").getAttribute("data-health")).toBe("disabled");
    expect(within(bsv).queryByText("隔离")).toBeNull();
  });

  it("stages an enable toggle through settings review without changing the switch immediately", async () => {
    const bridge = installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    const kaspa = await screen.findByTestId("plugin-row-@catomicals/plugin-chain-kaspa");
    const toggle = within(kaspa).getByRole("switch", { name: "停用 Kaspa" });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    await user.click(toggle);

    expect(bridge.createPluginSettingsIntent).toHaveBeenCalledWith(
      "@catomicals/plugin-chain-kaspa",
      { schemaVersion: 1, changes: [{ id: "enabled", value: false }] },
    );
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    expect(await screen.findByText(/确认后生效/)).toBeTruthy();
  });
});

describe("settings labels", () => {
  it("shows the localized plugin name and id in the expanded configuration", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: "配置 Kaspa" }));

    expect(await screen.findByRole("heading", { name: "Kaspa", level: 2 })).toBeTruthy();
    expect(screen.getAllByText("@catomicals/plugin-chain-kaspa").length).toBeGreaterThan(0);
  });

  it("shows only network choice for a preset and reveals manual RPC fields for a custom node", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: "配置 Kaspa" }));

    const validation = (await screen.findByLabelText(/地址校验/)) as HTMLSelectElement;
    expect(within(validation).getByRole("option").textContent).toBe("严格校验");
    expect(validation.value).toBe("strict");
    expect(screen.queryByLabelText(/RPC endpoint/)).toBeNull();
    expect(screen.queryByLabelText(/传输协议/)).toBeNull();
    expect(screen.queryByLabelText(/网络访问/)).toBeNull();

    const source = (await screen.findByLabelText(/节点来源/)) as HTMLSelectElement;
    await user.selectOptions(source, "custom");
    const endpoint = (await screen.findByLabelText(/RPC endpoint/)) as HTMLInputElement;
    expect(await screen.findByLabelText(/传输协议/)).toBeTruthy();
    expect(await screen.findByLabelText(/网络访问/)).toBeTruthy();
    expect(await screen.findByLabelText(/RPC 凭证/)).toBeTruthy();
    const reviewButton = screen.getByRole("button", { name: "创建审查" });
    expect(reviewButton.hasAttribute("disabled")).toBe(false);

    await user.clear(endpoint);
    await user.type(endpoint, "https://kaspa.example/v2");
    expect(endpoint.value).toBe("https://kaspa.example/v2");
    expect(reviewButton.hasAttribute("disabled")).toBe(false);
  });
});
