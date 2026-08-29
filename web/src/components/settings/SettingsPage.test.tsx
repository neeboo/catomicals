// @vitest-environment jsdom

import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
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
  { pluginId: "@catomicals/plugin-chain-bsv", pluginVersion: "1.0.0", status: "ready", enabled: false, category: "chain", capabilities: ["chain.rpc", "chain.address"] },
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

const GENERATIVE_UI_VIEW: PluginSettingsView = {
  pluginId: "@catomicals/plugin-generative-ui",
  pluginVersion: "1.0.0",
  status: "ready",
  settingsSchemaVersion: 1,
  settingsDigest: `sha256:${"c".repeat(64)}`,
  settings: {
    enabled: true,
    preference: "prefer",
    maxBlocks: 2,
    referenceRepository: "/Users/ghostcorn/dev/deepseek-harness",
    customInstructions: "默认规范",
  },
  secretStates: {},
  schema: {
    version: 1,
    fields: [
      { id: "enabled", label: "启用生成式界面", type: "boolean", required: true, restart: "none" },
      { id: "preference", label: "组件输出偏好", type: "string", required: true, restart: "none", choices: ["prefer", "automatic", "off"] },
      { id: "maxBlocks", label: "每条回复最多组件数", type: "integer", required: true, restart: "none" },
      { id: "referenceRepository", label: "界面参考仓库", type: "string", required: true, restart: "none", maxLength: 1024 },
      { id: "customInstructions", label: "追加生成规范", type: "string", required: true, restart: "none", maxLength: 4096, control: "textarea" },
    ],
  },
};

function minimalView(pluginId: string): PluginSettingsView {
  const chainSettings: Partial<Record<string, PluginSettingsView["settings"]>> = {
    "@catomicals/plugin-bitcoin-node": {
      enabled: true,
      networkId: "inquisition-signet",
      access: "broadcast",
      networkAccess: "local",
      endpoint: "http://127.0.0.1:38332",
    },
    "@catomicals/plugin-chain-kaspa": {
      enabled: true,
      networkId: "testnet-10",
      access: "read",
      networkAccess: "private-network",
      endpoint: "https://kaspa.example/rpc",
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
      fields: [{ id: "enabled", label: "启用", type: "boolean", required: true, restart: "none" }],
    },
  };
}

/** Install a desktop bridge whose generative-ui plugin exposes the full field set. */
function installBridge() {
  const bridge = {
    listPlugins: vi.fn().mockResolvedValue(FIXED_PLUGINS),
    readPluginSettings: vi.fn(async (pluginId: string) =>
      pluginId === "@catomicals/plugin-generative-ui" ? GENERATIVE_UI_VIEW : minimalView(pluginId)),
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
  it("shows the plugin responsibilities as compact secondary navigation", async () => {
    installBridge();
    render(<SettingsPage />);

    expect(await screen.findByRole("heading", { name: "插件", level: 1 })).toBeTruthy();
    for (const label of ["全部插件", "钱包与安全", "链与地址", "节点与 RPC", "数据与索引", "代理", "界面与工具"]) {
      expect(screen.getByRole("button", { name: new RegExp(label) })).toBeTruthy();
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

  it("presents all seven chain adapters on both address and RPC surfaces without duplicating the all view", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    const addressFilter = await screen.findByRole("button", { name: /链与地址\s*7/ });
    const rpcFilter = screen.getByRole("button", { name: /节点与 RPC\s*7/ });
    expect(addressFilter).toBeTruthy();
    expect(screen.getAllByTestId("plugin-row-@catomicals/plugin-chain-kaspa")).toHaveLength(1);

    await user.click(rpcFilter);
    for (const plugin of FIXED_PLUGINS.filter((entry) => entry.category === "chain")) {
      expect(screen.getByTestId(`plugin-row-${plugin.pluginId}`)).toBeTruthy();
    }
    expect(screen.queryByTestId("plugin-row-@catomicals/plugin-walletd")).toBeNull();
    expect(screen.getByRole("heading", { name: "节点与 RPC", level: 2 })).toBeTruthy();
  });

  it("shows chain, network, permission, endpoint, health, check time and verification on a plugin row", async () => {
    installBridge();
    render(<SettingsPage />);

    const kaspa = await screen.findByTestId("plugin-row-@catomicals/plugin-chain-kaspa");
    expect(within(kaspa).getAllByText("Kaspa").length).toBeGreaterThan(0);
    expect(within(kaspa).getByText(/testnet-10/)).toBeTruthy();
    for (const text of ["地址 · RPC", "只读 · 私有网络", "https://kaspa.example", "运行正常", "RPC 验证"]) {
      expect(within(kaspa).getByText(text)).toBeTruthy();
    }
    expect(within(kaspa).getByText(/最后检查/)).toBeTruthy();
  });

  it("uses the settings view for the current broadcast access instead of the catalog default", async () => {
    installBridge();
    render(<SettingsPage />);

    const bitcoin = await screen.findByTestId("plugin-row-@catomicals/plugin-bitcoin-node");
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

    await user.click(await screen.findByRole("button", { name: "配置 生成式界面" }));

    expect(await screen.findByRole("heading", { name: "生成式界面", level: 2 })).toBeTruthy();
    expect(screen.getAllByText("@catomicals/plugin-generative-ui").length).toBeGreaterThan(0);
  });

  it("localizes schema-declared choice values in the select", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: "配置 生成式界面" }));

    const preference = (await screen.findByLabelText(/组件输出偏好/)) as HTMLSelectElement;
    expect(within(preference).getAllByRole("option").map((option) => option.textContent))
      .toEqual(["优先生成组件", "自动判断", "仅使用 Markdown"]);
    expect(preference.value).toBe("prefer");
  });
});

describe("settings multiline field", () => {
  it("renders a schema-declared textarea with its stored value and max length", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: "配置 生成式界面" }));

    const textarea = (await screen.findByLabelText(/追加生成规范/)) as HTMLTextAreaElement;
    expect(textarea.tagName).toBe("TEXTAREA");
    expect(textarea.getAttribute("maxlength")).toBe("4096");
    expect(textarea.value).toBe("默认规范");
  });

  it("stages edits into the draft and arms the review button", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: "配置 生成式界面" }));

    const textarea = (await screen.findByLabelText(/追加生成规范/)) as HTMLTextAreaElement;
    const reviewButton = screen.getByRole("button", { name: "创建审查" });
    expect(reviewButton.hasAttribute("disabled")).toBe(true);

    await user.clear(textarea);
    await user.type(textarea, "界面优先使用受控组件");

    expect(textarea.value).toBe("界面优先使用受控组件");
    expect(reviewButton.hasAttribute("disabled")).toBe(false);

    // A later change to the same field keeps the staged edit the patch would write.
    fireEvent.change(textarea, { target: { value: "重写规范" } });
    expect(textarea.value).toBe("重写规范");
    expect(reviewButton.hasAttribute("disabled")).toBe(false);
  });
});
