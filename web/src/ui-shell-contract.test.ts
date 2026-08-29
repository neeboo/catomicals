import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const workbench = readFileSync(new URL("./components/workbench/WalletWorkbench.tsx", import.meta.url), "utf8");
const workbenchModel = readFileSync(new URL("./lib/workbench.ts", import.meta.url), "utf8");
const routes = readFileSync(new URL("./routeTree.ts", import.meta.url), "utf8");
const settings = readFileSync(new URL("./components/settings/SettingsPage.tsx", import.meta.url), "utf8");
const css = readFileSync(new URL("./index.css", import.meta.url), "utf8");

describe("Codex-style shell contract", () => {
  it("keeps tools out of the conversation header and enters settings from the left rail footer", () => {
    expect(workbench).not.toContain("function PluginToolbar");
    expect(workbench).toContain('to="/settings"');
    expect(workbench).toContain("ToolAreaState");
    expect(workbench).toContain('<aside className="tool-discovery-rail"');
    expect(workbench).toContain("<ToolAreaPanel");
  });

  it("keeps the center pane chat-first with a lightweight empty-session guide", () => {
    // The old wallet-chat offline card and dashboard-like starter cards stay gone.
    expect(workbench).not.toContain('className="conversation-status-card"');
    expect(workbench).not.toContain("CONVERSATION_STARTERS");
    expect(workbench).not.toContain('className="chat-empty"');
    expect(workbench).not.toContain("chat-starter-actions");
    expect(workbench).toContain('className="conversation-empty"');
    expect(workbench).toContain("从一项钱包任务开始");
    expect(workbench).toContain("直接描述目标，或从一个常用任务开始。");
    expect(workbench).toContain("检查一笔交易");
    expect(workbench).toContain("查看钱包状态");
    expect(workbench).toContain("设计一个 covenant 发行方案");
    // Transcript and composer remain the primary interaction surface.
    expect(workbench).toContain('className="conversation-scroll"');
    expect(workbench).toContain("buildSessionTranscript");
    expect(workbench).toContain("turn/start");
    expect(workbench).toContain("turn/end");
    expect(workbench).not.toContain('className="conversation-error"');
  });

  it("mounts the settings route and preserves review-before-confirm", () => {
    expect(routes).toContain('path: "/settings"');
    expect(settings).toContain("createPluginSettingsIntent");
    expect(settings).toContain("confirmPluginSettingsIntent");
    expect(settings).not.toContain("updatePluginSettings");
  });

  it("uses the real Electron browser surface and keeps bounds synchronized", () => {
    expect(workbenchModel).toContain("mountBrowserPane");
    expect(workbench).toContain("queue.selectTab(next)");
    expect(workbenchModel).toContain("createToolAreaBridgeQueue");
    expect(workbenchModel).toContain("ResizeObserver");
    expect(workbenchModel).toContain("setPaneBounds");
    expect(workbench).toContain("closeTools");
  });

  it("renders protocol message parts through the fixed controlled UI path", () => {
    expect(workbench).toContain("message.parts");
    expect(workbench).toContain('part.type === "text"');
    expect(workbench).toContain('part.type === "ui_block"');
    expect(workbench).toContain("<ControlledUiBlock block={part.block}");
    expect(workbench).toContain('part.type === "review_reference"');
    expect(workbench).toContain("parseReviewReference(part.reference)");
  });

  it("loads persisted executor settings before probing and surfaces desktop bridge errors", () => {
    expect(workbench).toContain("settingsLoaded");
    expect(workbench).toContain("resolveExecutorProbeProvider(settingsLoaded, provider)");
    expect(workbench).toContain("desktopError");
    expect(workbench).toContain('role="alert"');
  });

  it("keeps settings, controlled cards, executor state, and browser tools in the existing monochrome system", () => {
    expect(css).toContain(".settings-shell");
    expect(css).toContain(".controlled-card");
    expect(css).toContain(".executor-selector");
    expect(css).toContain(".browser-surface");
    expect(css).toContain("--left-rail: 312px");
    expect(css).toContain("--right-rail: 384px");
    expect(css).toContain("--tool-discovery-rail: 48px");
    expect(css).toContain("grid-template-columns: 40px 40px 40px minmax(0, 1fr)");
    expect(css).toMatch(/\.primary-action\s*\{[^}]*height: 44px/s);
    expect(css).not.toContain(".plugin-toolbar");
  });

  it("removes the app-wide title bar, the literal headless label, and all workbench status prose", () => {
    // No TitleBar component anywhere in the renderer shell.
    expect(workbench).not.toContain("TitleBar");
    expect(settings).not.toContain("TitleBar");
    // The literal "headless" runtime label is gone from the UI shell.
    expect(workbench).not.toContain("headless");
    expect(settings).not.toContain("headless");
    expect(css).not.toContain("headless");
    // No titlebar row selector survives in the stylesheet.
    expect(css).not.toContain(".window-titlebar");
    expect(css).not.toMatch(/\.titlebar/);

    // Removed workbench prose.
    expect(workbench).not.toContain("对话只能生成提案");
    expect(workbench).not.toContain("Passkey 和 FROST 策略控制");
    expect(workbench).not.toContain("Passkey 授权 · FROST 签名");
    expect(workbench).not.toContain("钱包节点已连接");
    expect(workbench).not.toContain("节点在线 · CAT");
    expect(workbench).not.toContain("compact-wallet-status");
    expect(css).not.toContain(".compact-wallet-status");
    expect(css).not.toContain(".header-security");
    expect(css).not.toContain(".composer-boundary");
  });

  it("keeps the conversation header to the current session title and essential actions only", () => {
    expect(workbench).toContain('className="conversation-title"');
    expect(workbench).toContain('data-testid="conversation-title"');
    // The static "钱包工作台" placeholder is gone: the title is the session.
    expect(workbench).not.toContain("<strong>钱包工作台</strong>");
    expect(workbench).not.toContain("header-security");
    expect(workbench).not.toContain("composer-boundary");
    expect(workbench).not.toContain("钱包节点已连接");
    expect(css).not.toContain(".conversation-subtitle");
  });

  it("keeps the left rail identity to one quiet product label and one login action", () => {
    expect(workbench).toContain("<strong>Catomicals</strong>");
    expect(workbench).toContain('aria-label={identitySession?.displayName ?? "登录"}');
    expect(workbench).not.toContain("wallet-avatar");
    expect(workbench).not.toContain("本地工作区");
    expect(workbench).not.toContain("本机用户");
    expect(workbench).not.toContain("身份服务待接入");
  });

  it("reveals session row actions only on hover or keyboard focus", () => {
    expect(css).toMatch(/\.session-row:hover \.session-row-actions/);
    expect(css).toMatch(/\.session-row:focus-within \.session-row-actions/);
    expect(css).not.toMatch(/\.session-row\[data-active="true"\] \.session-row-actions/);
  });

  it("keeps invisible drag regions without any layout-height titlebar row", () => {
    // The only drag regions are absolutely positioned overlays on the two
    // sidebars (zero layout height) and the conversation-header context row
    // itself — never a separate 38px titlebar strip.
    expect(css).toMatch(/\.workbench-left::before\s*\{[^}]*position:\s*absolute[^}]*\}/);
    expect(css).toMatch(/\.settings-sidebar::before\s*\{[^}]*position:\s*absolute[^}]*\}/);
    expect(css).toMatch(/\.conversation-header\s*\{[^}]*app-region:\s*drag[^}]*\}/);
    expect(css).toMatch(
      /\.conversation-header\s*:\s*where\(button,\s*a,\s*select,\s*input,\s*textarea,\s*label\)\s*\{[^}]*app-region:\s*no-drag[^}]*\}/,
    );
    // No drag rule may carry a layout height: absolute overlays are the only
    // drag surface besides the (non-layout) header row.
    expect(css).not.toMatch(/app-region:\s*drag[^}]*height:/s);
  });

  it("shows plugin state on plugin rows and treats disabled plugins separately from failures", () => {
    expect(settings).toContain('className="settings-plugin-health"');
    expect(settings).toContain('if (!pluginEnabled(plugin)) return { label: "已停用", state: "disabled" }');
    expect(settings).toContain('role="switch"');
    expect(settings).toContain('确认后生效');
    expect(css).toContain(".settings-plugin-health");
    expect(css).toContain('.settings-plugin-health[data-health="disabled"]');
  });
});

describe("chat message layout contract", () => {
  it("right-aligns user turns into a restrained dark bubble and keeps agent turns plain", () => {
    expect(workbench).not.toContain("data-wallet");
    expect(workbench).toContain('data-role={message.role}');
    expect(workbench).toContain('className="user-bubble"');
    expect(css).toMatch(/\.chat-message\[data-role="user"\]\s*\{[^}]*align-items:\s*flex-end[^}]*\}/);
    expect(css).toMatch(/\.user-bubble\s*\{[^}]*background:[^}]*\}/);
    expect(css).toMatch(/\.user-bubble\s*\{[^}]*border-radius:[^}]*\}/);
    expect(css).toMatch(/\.user-bubble\s*\{[^}]*max-width:[^}]*\}/);
  });

  it("drops the card border from chat turns", () => {
    expect(css).not.toContain('.chat-message[data-wallet="true"]');
    expect(css).not.toMatch(/\.chat-message\s*\{[^}]*border-bottom:[^}]*\}/);
  });

  it("renders a live processing status and a persistent failure row", () => {
    expect(workbench).toContain('className="processing-row"');
    expect(workbench).toContain('className="processing-elapsed"');
    expect(workbench).toContain('className="turn-failure"');
    expect(workbench).toContain("正在处理");
    expect(css).toMatch(/\.processing-row\s*\{/);
    expect(css).toMatch(/\.turn-failure\s*\{/);
  });

  it("reports the real round duration on completed turns", () => {
    expect(workbench).toContain("durationMs");
    expect(workbench).toContain("formatDuration(message.durationMs)");
    expect(workbench).toContain("formatDuration(elapsedMs)");
    expect(css).toMatch(/\.turn-duration\s*\{/);
  });

  it("shows only real executor state: no invented tool steps or streamed tokens", () => {
    expect(workbench).not.toContain("tool_steps");
    expect(workbench).not.toContain("正在调用工具");
    expect(workbench).not.toContain("streaming");
    expect(workbench).toContain('result.state !== "completed"');
  });
});
