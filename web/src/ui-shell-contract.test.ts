import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const workbench = readFileSync(new URL("./components/workbench/WalletWorkbench.tsx", import.meta.url), "utf8");
const routes = readFileSync(new URL("./routeTree.ts", import.meta.url), "utf8");
const settings = readFileSync(new URL("./components/settings/SettingsPage.tsx", import.meta.url), "utf8");
const css = readFileSync(new URL("./index.css", import.meta.url), "utf8");

describe("Codex-style shell contract", () => {
  it("keeps tools out of the conversation header and enters settings from the left rail footer", () => {
    expect(workbench).not.toContain("function PluginToolbar");
    expect(workbench).toContain('to="/settings"');
    expect(workbench).toContain("ToolAreaState");
  });

  it("mounts the settings route and preserves review-before-confirm", () => {
    expect(routes).toContain('path: "/settings"');
    expect(settings).toContain("createPluginSettingsIntent");
    expect(settings).toContain("confirmPluginSettingsIntent");
    expect(settings).not.toContain("updatePluginSettings");
  });

  it("uses the real Electron browser surface and keeps bounds synchronized", () => {
    expect(workbench).toContain('selectTab("browser")');
    expect(workbench).toContain("ResizeObserver");
    expect(workbench).toContain("setPaneBounds");
    expect(workbench).toContain("closeTools");
  });

  it("keeps settings, controlled cards, executor state, and browser tools in the existing monochrome system", () => {
    expect(css).toContain(".settings-shell");
    expect(css).toContain(".controlled-card");
    expect(css).toContain(".executor-selector");
    expect(css).toContain(".browser-surface");
    expect(css).not.toContain(".plugin-toolbar");
  });
});
