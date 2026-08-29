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
  { pluginId: "@catomicals/plugin-walletd", pluginVersion: "1.0.0", status: "ready" },
  { pluginId: "@catomicals/plugin-bitcoin-node", pluginVersion: "1.0.0", status: "ready" },
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
  return {
    pluginId,
    pluginVersion: "1.0.0",
    status: "ready",
    settingsSchemaVersion: 1,
    settingsDigest: `sha256:${"a".repeat(64)}`,
    settings: { enabled: true },
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
    readPluginHealth: vi.fn().mockResolvedValue({ status: "healthy" }),
    validatePluginSettings: vi.fn().mockResolvedValue({ valid: true }),
    createPluginSettingsIntent: vi.fn().mockResolvedValue({ reviewId: "review-1" }),
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
  it("groups the settings rail into the four secondary categories", async () => {
    installBridge();
    render(<SettingsPage />);

    // Headings carry the compact category status in their accessible name, so
    // match by prefix.
    const heading = (name: RegExp) => screen.getByRole("heading", { name });
    await screen.findByRole("heading", { name: /^钱包与安全/ });
    expect(heading(/^网络与数据/)).toBeTruthy();
    expect(heading(/^代理/)).toBeTruthy();
    expect(heading(/^界面与工具/)).toBeTruthy();

    const sectionOf = (headingName: RegExp) => heading(headingName).closest("section") as HTMLElement;
    expect(within(sectionOf(/^钱包与安全/)).getByRole("button", { name: /钱包节点/ })).toBeTruthy();
    expect(within(sectionOf(/^钱包与安全/)).getByRole("button", { name: /备份/ })).toBeTruthy();
    expect(within(sectionOf(/^网络与数据/)).getByRole("button", { name: /比特币节点/ })).toBeTruthy();
    expect(within(sectionOf(/^网络与数据/)).getByRole("button", { name: /索引器/ })).toBeTruthy();
    expect(within(sectionOf(/^代理/)).getByRole("button", { name: /MCP/ })).toBeTruthy();
    expect(within(sectionOf(/^代理/)).getByRole("button", { name: /Codex/ })).toBeTruthy();
    expect(within(sectionOf(/^代理/)).getByRole("button", { name: /DeepSeek Harness/ })).toBeTruthy();
    expect(within(sectionOf(/^代理/)).getByRole("button", { name: /Claude Code/ })).toBeTruthy();
    expect(within(sectionOf(/^界面与工具/)).getByRole("button", { name: /生成式界面/ })).toBeTruthy();
    expect(within(sectionOf(/^界面与工具/)).getByRole("button", { name: /浏览器/ })).toBeTruthy();
  });

  it("renders a status tag on each plugin button", async () => {
    installBridge();
    render(<SettingsPage />);

    const generativeUi = await screen.findByRole("button", { name: /生成式界面/ });
    expect(generativeUi.querySelector("small")?.getAttribute("data-status")).toBe("ready");
    expect(generativeUi.textContent).toContain("就绪");
  });

  it("shows compact node+CAT and FROST+Passkey status on the relevant menu entries", async () => {
    installBridge();
    render(<SettingsPage />);

    await screen.findByRole("heading", { name: /^网络与数据/ });
    const sectionOf = (name: RegExp) =>
      screen.getByRole("heading", { name }).closest("section") as HTMLElement;

    const networkStatus = within(sectionOf(/^网络与数据/)).getByText("signet · CAT");
    expect(networkStatus.className).toContain("settings-category-status");
    expect(networkStatus.getAttribute("data-health")).toBe("ok");

    const walletStatus = within(sectionOf(/^钱包与安全/)).getByText("2/3 · 1");
    expect(walletStatus.className).toContain("settings-category-status");
    expect(walletStatus.getAttribute("data-health")).toBe("ok");
  });

  it("warns on the menu entry when the node is offline", async () => {
    installBridge();
    testStatus.node = { data: undefined, isSuccess: false };
    render(<SettingsPage />);

    await screen.findByRole("heading", { name: /^网络与数据/ });
    const status = screen.getByText("节点离线");
    expect(status.className).toContain("settings-category-status");
    expect(status.getAttribute("data-health")).toBe("warn");
  });
});

describe("settings labels", () => {
  it("shows the localized plugin name and id in the panel header", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: /生成式界面/ }));

    expect(await screen.findByRole("heading", { name: "生成式界面", level: 1 })).toBeTruthy();
    expect(screen.getByText("@catomicals/plugin-generative-ui")).toBeTruthy();
  });

  it("localizes schema-declared choice values in the select", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: /生成式界面/ }));

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

    await user.click(await screen.findByRole("button", { name: /生成式界面/ }));

    const textarea = (await screen.findByLabelText(/追加生成规范/)) as HTMLTextAreaElement;
    expect(textarea.tagName).toBe("TEXTAREA");
    expect(textarea.getAttribute("maxlength")).toBe("4096");
    expect(textarea.value).toBe("默认规范");
  });

  it("stages edits into the draft and arms the review button", async () => {
    installBridge();
    const user = userEvent.setup();
    render(<SettingsPage />);

    await user.click(await screen.findByRole("button", { name: /生成式界面/ }));

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
