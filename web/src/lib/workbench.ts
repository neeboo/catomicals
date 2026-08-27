import type { HarnessId } from "./harness";

export const INSPECTOR_MODES = [
  "transaction",
  "intents",
  "security",
  "issuance",
] as const;

export type InspectorMode = (typeof INSPECTOR_MODES)[number];
export const TOOL_TABS = ["browser", ...INSPECTOR_MODES] as const;
export type ToolTab = (typeof TOOL_TABS)[number];
export type PluginPanelState = InspectorMode | null;
export type PluginPanelEvent =
  | { type: "select"; mode: InspectorMode }
  | { type: "close" };

export const DEFAULT_PLUGIN_PANEL: PluginPanelState = null;

export function transitionPluginPanel(
  _current: PluginPanelState,
  event: PluginPanelEvent,
): PluginPanelState {
  return event.type === "select" ? event.mode : null;
}

export interface ToolAreaState {
  open: boolean;
  activeTab: ToolTab | null;
}

export interface BrowserPaneBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface BrowserPaneBridge {
  selectTab(tab: ToolTab): Promise<unknown>;
  setPaneBounds(bounds: BrowserPaneBounds): Promise<unknown>;
}

export interface BrowserPaneSurface {
  getBoundingClientRect(): BrowserPaneBounds;
}

export interface BrowserPaneObserver {
  observe(surface: Element): void;
  disconnect(): void;
}

interface BrowserPaneOptions {
  createObserver?: (callback: () => void) => BrowserPaneObserver;
  scheduleFrame?: (callback: () => void) => number;
  cancelFrame?: (frameId: number) => void;
  onError?: (cause: unknown) => void;
}

export function mountBrowserPane(
  bridge: BrowserPaneBridge,
  surface: BrowserPaneSurface,
  options: BrowserPaneOptions = {},
): () => void {
  const createObserver = options.createObserver ?? ((callback) => new ResizeObserver(callback));
  const scheduleFrame = options.scheduleFrame ?? requestAnimationFrame;
  const cancelFrame = options.cancelFrame ?? cancelAnimationFrame;
  let active = true;
  let frameId: number | null = null;

  function report(cause: unknown) {
    if (active) options.onError?.(cause);
  }

  function scheduleBounds() {
    if (frameId !== null) return;
    frameId = scheduleFrame(() => {
      frameId = null;
      if (!active) return;
      const { x, y, width, height } = surface.getBoundingClientRect();
      void bridge.setPaneBounds({ x, y, width, height }).catch(report);
    });
  }

  const observer = createObserver(scheduleBounds);
  observer.observe(surface as Element);
  scheduleBounds();
  void bridge.selectTab("browser").catch(report);

  return () => {
    active = false;
    observer.disconnect();
    if (frameId !== null) cancelFrame(frameId);
  };
}

export type ToolAreaEvent =
  | { type: "expand" }
  | { type: "select"; tab: ToolTab }
  | { type: "back" }
  | { type: "close" };

export const DEFAULT_TOOL_AREA: ToolAreaState = {
  open: false,
  activeTab: null,
};

export function resolveExecutorProbeProvider(
  settingsLoaded: boolean,
  provider: HarnessId,
): HarnessId | null {
  return settingsLoaded ? provider : null;
}

export function transitionToolArea(
  current: ToolAreaState,
  event: ToolAreaEvent,
): ToolAreaState {
  if (event.type === "close") return DEFAULT_TOOL_AREA;
  if (event.type === "back") return { open: true, activeTab: null };
  if (event.type === "select") return { open: true, activeTab: event.tab };
  return { ...current, open: true };
}

export type ActiveDrawer = "left" | "right" | null;
export type DrawerEvent = "open-left" | "open-right" | "select-tool" | "close";

export function transitionDrawer(
  _current: ActiveDrawer,
  event: DrawerEvent,
): ActiveDrawer {
  if (event === "open-left") return "left";
  if (event === "open-right" || event === "select-tool") return "right";
  return null;
}

export interface StarterAction {
  mode: InspectorMode;
  title: string;
  description: string;
  available: boolean;
}

export const starterActions: readonly StarterAction[] = [
  {
    mode: "transaction",
    title: "检查一笔交易",
    description: "解析原始交易、输入来源、费用与签名摘要。",
    available: true,
  },
  {
    mode: "intents",
    title: "处理待批准意图",
    description: "查看由钱包节点保存的签名意图与授权状态。",
    available: true,
  },
  {
    mode: "security",
    title: "检查钱包安全",
    description: "核对节点、OP_CAT、FROST 与 Passkey 的实时状态。",
    available: true,
  },
  {
    mode: "issuance",
    title: "设计资产发行",
    description: "链上发行协议尚未实现；这里仅记录需求与约束。",
    available: false,
  },
] as const;
