import { contextBridge, ipcRenderer } from "electron";
import { IPC_CHANNELS } from "./ipc.js";
import type {
  DesktopSettings,
  DesktopState,
  HarnessRequest,
  HarnessResult,
  PaneBounds,
  ToolTabId,
} from "./contracts.js";

const api = Object.freeze({
  getState: (): Promise<DesktopState> => ipcRenderer.invoke(IPC_CHANNELS.getState),
  selectTab: (tab: ToolTabId): Promise<DesktopState> => ipcRenderer.invoke(IPC_CHANNELS.selectTab, tab),
  closeTools: (): Promise<DesktopState> => ipcRenderer.invoke(IPC_CHANNELS.closeTools),
  setPaneBounds: (bounds: PaneBounds): Promise<void> => ipcRenderer.invoke(IPC_CHANNELS.setPaneBounds, bounds),
  navigateBrowser: (url: string): Promise<string> => ipcRenderer.invoke(IPC_CHANNELS.browserNavigate, url),
  browserBack: (): Promise<void> => ipcRenderer.invoke(IPC_CHANNELS.browserBack),
  browserForward: (): Promise<void> => ipcRenderer.invoke(IPC_CHANNELS.browserForward),
  browserReload: (): Promise<void> => ipcRenderer.invoke(IPC_CHANNELS.browserReload),
  getSettings: (): Promise<DesktopSettings> => ipcRenderer.invoke(IPC_CHANNELS.settingsGet),
  updateSettings: (settings: DesktopSettings): Promise<DesktopSettings> => ipcRenderer.invoke(IPC_CHANNELS.settingsUpdate, settings),
  invokeHarness: (request: HarnessRequest): Promise<HarnessResult> => ipcRenderer.invoke(IPC_CHANNELS.harnessInvoke, request),
});

contextBridge.exposeInMainWorld("catomicalsDesktop", api);
