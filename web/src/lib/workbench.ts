export const INSPECTOR_MODES = [
  "transaction",
  "intents",
  "security",
  "issuance",
] as const;

export type InspectorMode = (typeof INSPECTOR_MODES)[number];
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
