import { contextBridge, ipcRenderer } from "electron";

type ToolTabId = "browser" | "transaction" | "intents" | "security" | "issuance";
type HarnessId = "codex" | "deepseek" | "claude-code";
type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

interface PaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface HarnessSettings {
  command: string;
  defaultModel: string;
  reasoningEffort: ReasoningEffort;
  workingDirectory: string;
}

interface DesktopSettings {
  version: 1;
  defaultHarness: HarnessId;
  adapters: Record<HarnessId, HarnessSettings>;
  mcpEnabled: boolean;
  walletNodeUrl: string;
  browserHome: string;
}

interface DesktopState {
  desktop: true;
  toolsOpen: boolean;
  activeTab: ToolTabId | null;
  safeStorageAvailable: boolean;
}

interface HarnessRequest {
  harnessId: HarnessId;
  sessionId: string;
  prompt: string;
}

interface HarnessResult {
  ok: false;
  status: "not-connected";
  message: string;
}

const api = Object.freeze({
  getState: (): Promise<DesktopState> => ipcRenderer.invoke("catomicals:state:get"),
  selectTab: (tab: ToolTabId): Promise<DesktopState> => ipcRenderer.invoke("catomicals:tab:select", tab),
  closeTools: (): Promise<DesktopState> => ipcRenderer.invoke("catomicals:tools:close"),
  setPaneBounds: (bounds: PaneBounds): Promise<void> => ipcRenderer.invoke("catomicals:pane:set-bounds", bounds),
  navigateBrowser: (url: string): Promise<string> => ipcRenderer.invoke("catomicals:browser:navigate", url),
  browserBack: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:back"),
  browserForward: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:forward"),
  browserReload: (): Promise<void> => ipcRenderer.invoke("catomicals:browser:reload"),
  getSettings: (): Promise<DesktopSettings> => ipcRenderer.invoke("catomicals:settings:get"),
  updateSettings: (settings: DesktopSettings): Promise<DesktopSettings> => ipcRenderer.invoke("catomicals:settings:update", settings),
  invokeHarness: (request: HarnessRequest): Promise<HarnessResult> => ipcRenderer.invoke("catomicals:harness:invoke", request),
});

contextBridge.exposeInMainWorld("catomicalsDesktop", api);
