import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type RefObject,
} from "react";
import { Link } from "@tanstack/react-router";
import {
  IconAlertTriangle,
  IconArrowLeft,
  IconArrowRight,
  IconArrowUp,
  IconBrowser,
  IconChevronRight,
  IconCoin,
  IconFileSearch,
  IconFingerprint,
  IconGitBranch,
  IconLock,
  IconMenu2,
  IconPlus,
  IconRefresh,
  IconSettings,
  IconShieldCheck,
  IconTools,
  IconX,
} from "@tabler/icons-react";
import { ApiError } from "@/lib/api";
import { ControlledUiBlock } from "@/components/controlled-ui/ControlledUiBlock";
import { errorMessage } from "@/lib/errors";
import { formatRelative, formatUnix, shortHex } from "@/lib/format";
import { executorPluginId, executorPresentation, type ExecutorPresentation } from "@/lib/cordis";
import { optionalDesktopBridge, requireDesktopBridge, type DesktopBridge } from "@/lib/desktop";
import { DEFAULT_HARNESS_ID, HARNESS_ADAPTERS, type HarnessId } from "@/lib/harness";
import { parseReviewReference } from "@/lib/ui-block";
import {
  useChatStateQuery,
  useCreateChatMessageMutation,
  useCredentialsQuery,
  useIntentsQuery,
  useNodeStatusQuery,
  useSignerStatusQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import type { ChatIntentBinding, ChatMessage, ChatMessagePart, SigningIntent } from "@/lib/types";
import {
  DEFAULT_TOOL_AREA,
  createToolAreaBridgeQueue,
  mountBrowserPane,
  resolveExecutorProbeProvider,
  starterActions,
  transitionDrawer,
  transitionToolArea,
  type ActiveDrawer,
  type InspectorMode,
  type ToolAreaState,
  type ToolAreaBridgeQueue,
  type ToolTab,
} from "@/lib/workbench";
import { TransactionInspector } from "./TransactionInspector";

const pluginMeta: Record<InspectorMode, { label: string; icon: typeof IconFileSearch }> = {
  transaction: { label: "交易检查", icon: IconFileSearch },
  intents: { label: "签名意图", icon: IconGitBranch },
  security: { label: "安全状态", icon: IconShieldCheck },
  issuance: { label: "资产发行", icon: IconCoin },
};

const toolMeta: Record<ToolTab, { label: string; icon: typeof IconFileSearch }> = {
  browser: { label: "浏览器", icon: IconBrowser },
  ...pluginMeta,
};

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    function onChange(event: MediaQueryListEvent) {
      setMatches(event.matches);
    }
    setMatches(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

function LeftRail({
  onClose,
  active,
  backgroundInert,
  railRef,
  closeButtonRef,
}: {
  onClose: () => void;
  active: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const wallet = useWalletStatusQuery();
  const signer = useSignerStatusQuery();
  const credentials = useCredentialsQuery();
  const opCat = wallet.data?.node?.op_cat_active;
  const threshold = signer.data?.configured
    ? `${signer.data.min_signers}/${wallet.data?.threshold.max_signers ?? "?"}`
    : "未配置";

  return (
    <aside
      className="workbench-left"
      aria-label="钱包与会话"
      aria-hidden={backgroundInert || undefined}
      aria-modal={active || undefined}
      inert={backgroundInert || undefined}
      ref={railRef}
      role={active ? "dialog" : undefined}
    >
      <div className="brand-row">
        <div><strong>Catomicals</strong><span>Covenant wallet</span></div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭会话栏" ref={closeButtonRef}><IconX size={17} /></button>
      </div>

      <div className="rail-section session-section">
        <button className="new-session" type="button" disabled title="钱包节点当前只提供单一内存会话">
          <IconPlus size={14} />新会话
        </button>
        <label className="session-search"><span>搜索会话</span><input type="search" placeholder="搜索当前会话" disabled /></label>
        <div className="rail-section-title"><span>会话</span></div>
        <button className="session-row active" type="button">
          <span><strong>钱包工作台</strong><small>当前节点会话</small></span>
        </button>
      </div>

      <div className="rail-spacer" />
      <div className="rail-footer-actions">
        <button type="button" disabled><span className="account-mark">C</span><span><strong>本机用户</strong><small>身份服务待接入</small></span></button>
        <Link to="/settings"><IconSettings size={15} /><span>设置</span></Link>
      </div>
      <div className="compact-wallet-status" title="钱包节点、OP_CAT、FROST 和 Passkey 实时状态">
        <span>{wallet.isSuccess ? "节点在线" : "节点离线"}</span>
        <span>CAT {opCat === true ? "active" : opCat === false ? "inactive" : "unknown"}</span>
        <span>FROST {threshold}</span>
        <span>Passkey {credentials.data?.length ?? 0}</span>
      </div>
    </aside>
  );
}

function WalletAction({ action }: { action: ChatIntentBinding }) {
  return (
    <div className="message-action">
      <div><IconLock size={14} /><strong>待授权签名意图</strong><span>{action.authorization.replaceAll("_", " ")}</span></div>
      <code>{shortHex(action.intent_digest_hex, 12, 10)}</code>
      <Link to="/intents/$intentId" params={{ intentId: action.intent_id }}>
        检查并批准 <IconChevronRight size={14} />
      </Link>
    </div>
  );
}

function messagePartKey(part: ChatMessagePart, index: number): string {
  if (part.type === "ui_block") return part.block.block_id;
  if (part.type === "review_reference") return part.reference.review_id;
  if (part.type === "tool_call") return part.tool_call_id;
  if (part.type === "tool_result") return `${part.tool_call_id}-result`;
  if (part.type === "error") return `${part.code}-${index}`;
  return `text-${index}`;
}

export function MessagePart({ part }: { part: ChatMessagePart }) {
  if (part.type === "text") return <p>{part.text}</p>;
  if (part.type === "ui_block") return <ControlledUiBlock block={part.block} />;
  if (part.type === "review_reference") {
    try {
      const reference = parseReviewReference(part.reference);
      return <div className="message-review-reference"><span>审查引用</span><code>{reference.review_id}</code></div>;
    } catch (cause) {
      return <div className="controlled-card-error"><IconAlertTriangle size={14} />{cause instanceof Error ? cause.message : "审查引用无效"}</div>;
    }
  }
  if (part.type === "tool_call") return <div className="message-protocol-event"><span>调用工具</span><code>{part.tool_name}</code></div>;
  if (part.type === "tool_result") return <div className="message-protocol-event"><span>工具结果</span><code>{part.outcome}</code></div>;
  return <div className="controlled-card-error"><IconAlertTriangle size={14} />{part.message}</div>;
}

function Message({ message }: { message: ChatMessage }) {
  const wallet = message.role === "wallet";
  return (
    <article className="chat-message" data-wallet={wallet}>
      <div className="message-meta"><strong>{wallet ? "钱包节点" : "你"}</strong><time>{formatUnix(message.created_at)}</time></div>
      {message.parts?.length
        ? message.parts.map((part, index) => <MessagePart key={messagePartKey(part, index)} part={part} />)
        : <p>{message.content}</p>}
      {message.wallet_action ? <WalletAction action={message.wallet_action} /> : null}
    </article>
  );
}

function ExecutorSelector() {
  const [provider, setProvider] = useState<HarnessId>(DEFAULT_HARNESS_ID);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [details, setDetails] = useState<ExecutorPresentation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const bridge = optionalDesktopBridge();
    if (!bridge) {
      setError("仅桌面端可检查执行器");
      return () => { active = false; };
    }
    void bridge.getSettings().then(
      (value) => {
        if (!active) return;
        setProvider(value.defaultHarness);
        setSettingsLoaded(true);
      },
      (cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : "无法读取执行器设置"); },
    );
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const bridge = optionalDesktopBridge();
    const probeProvider = resolveExecutorProbeProvider(settingsLoaded, provider);
    if (!bridge || !probeProvider) return () => { active = false; };
    setDetails(null);
    setError(null);
    void Promise.all([
      bridge.probeExecutor(probeProvider),
      bridge.readPluginSettings(executorPluginId(probeProvider)),
    ]).then(
      ([probe, settings]) => { if (active) setDetails(executorPresentation(probeProvider, probe, settings)); },
      (cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : "执行器检查失败"); },
    );
    return () => { active = false; };
  }, [provider, settingsLoaded]);

  async function selectProvider(next: HarnessId) {
    const bridge = optionalDesktopBridge();
    if (!bridge) {
      setProvider(next);
      return;
    }
    setError(null);
    try {
      await bridge.updateSettings({ version: 2, defaultHarness: next });
      setProvider(next);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法切换执行器");
    }
  }

  return (
    <div className="executor-selector">
      <label>
        <span className="sr-only">执行器</span>
        <select value={provider} onChange={(event) => void selectProvider(event.target.value as HarnessId)}>
          {HARNESS_ADAPTERS.map((adapter) => <option key={adapter.id} value={adapter.id}>{adapter.label}</option>)}
        </select>
      </label>
      <span className="executor-status" data-available={details?.availabilityLabel === "可用"}>
        {error ?? details?.availabilityLabel ?? "检查中"}
        {details?.model ? ` · ${details.model}` : ""}
        {details?.reasoningEffort ? ` · ${details.reasoningEffort}` : ""}
      </span>
    </div>
  );
}

function Conversation({
  onOpenLeft,
  onOpenTools,
  backgroundInert,
}: {
  onOpenLeft: () => void;
  onOpenTools: () => void;
  backgroundInert: boolean;
}) {
  const chat = useChatStateQuery();
  const send = useCreateChatMessageMutation();
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const transcriptRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const shouldFollowRef = useRef(true);

  useEffect(() => {
    const transcript = transcriptRef.current;
    if (!transcript || !shouldFollowRef.current) return;
    transcript.scrollTo({ top: transcript.scrollHeight });
  }, [chat.data?.messages.length]);

  function onTranscriptScroll() {
    const transcript = transcriptRef.current;
    if (!transcript) return;
    shouldFollowRef.current =
      transcript.scrollHeight - transcript.scrollTop - transcript.clientHeight < 96;
  }

  function scrollAfterSend() {
    shouldFollowRef.current = true;
    requestAnimationFrame(() => {
      const transcript = transcriptRef.current;
      transcript?.scrollTo({ top: transcript.scrollHeight, behavior: "smooth" });
    });
  }

  function submit(event?: FormEvent) {
    event?.preventDefault();
    const clean = content.trim();
    if (!clean || send.isPending) return;
    setError(null);
    send.mutate({ content: clean }, {
      onSuccess: () => {
        setContent("");
        inputRef.current?.focus();
        scrollAfterSend();
      },
      onError: (cause) => setError(cause instanceof ApiError ? cause.message : errorMessage(cause)),
    });
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  }

  const messages = chat.data?.messages ?? [];
  return (
    <main className="conversation-pane" aria-hidden={backgroundInert || undefined} inert={backgroundInert || undefined}>
      <header className="conversation-header">
        <button className="mobile-rail-button left-toggle" type="button" onClick={onOpenLeft} aria-label="打开会话栏"><IconMenu2 size={18} /></button>
        <div><strong>钱包工作台</strong><span>{chat.isSuccess ? "钱包节点已连接" : "等待钱包节点"}</span></div>
        <div className="header-security">Passkey 授权 · FROST 签名</div>
        <button className="tool-area-toggle" type="button" onClick={onOpenTools} aria-label="打开工具区"><IconTools size={17} /></button>
      </header>

      <div className="conversation-scroll" onScroll={onTranscriptScroll} ref={transcriptRef}>
        <div className="conversation-width">
          {chat.isPending ? <div className="conversation-loading"><IconRefresh className="spin" size={16} />正在读取钱包会话</div> : null}
          {chat.isError ? (
            <div className="conversation-error"><IconAlertTriangle size={17} /><div><strong>钱包节点不可用</strong><span>{chat.error.message}</span></div></div>
          ) : null}
          {!chat.isPending && !chat.isError && messages.length === 0 ? (
            <section className="chat-empty">
              <h1>开始一段钱包对话</h1>
              <p>描述你想完成的操作。交易检查、授权和节点状态可从右侧工具区打开。</p>
            </section>
          ) : null}
          {messages.map((message) => <Message key={message.id} message={message} />)}
        </div>
      </div>

      <div className="composer-zone">
        <form className="composer" onSubmit={submit}>
          <textarea
            ref={inputRef}
            rows={2}
            maxLength={2_000}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder="描述你要检查、创建或批准的交易……"
          />
          <div className="composer-footer">
            <ExecutorSelector />
            <button className="send-button" type="submit" disabled={!content.trim() || send.isPending} aria-label="发送消息">
              {send.isPending ? <IconRefresh className="spin" size={17} /> : <IconArrowUp size={17} />}
            </button>
          </div>
        </form>
        {error ? <p className="composer-error">{error}</p> : null}
        <p className="composer-boundary">对话只能生成提案；批准与签名仍由本机 Passkey 和 FROST 策略控制。</p>
      </div>
    </main>
  );
}

function IntentRow({ intent }: { intent: SigningIntent }) {
  const now = Date.now() / 1000;
  const expired = intent.status === "pending" && intent.expiry <= now;
  const status = expired ? "已过期" : intent.status;
  return (
    <Link className="intent-row" to="/intents/$intentId" params={{ intentId: intent.id }}>
      <div><strong>{intent.action.replaceAll("_", " ")}</strong><small>{status}</small></div>
      <code>{shortHex(intent.tx_digest, 9, 7)}</code>
      <span>签名者 #{intent.signer_id} · {expired ? "已过期" : formatRelative(intent.expiry, now)}</span>
      <IconChevronRight size={15} />
    </Link>
  );
}

function IntentsInspector() {
  const intents = useIntentsQuery();
  const list = intents.data ?? [];
  return (
    <div className="inspector-scroll">
      <div className="inspector-summary-line"><span>{list.filter((item) => item.status === "pending").length} 个待处理</span><button type="button" onClick={() => void intents.refetch()} aria-label="刷新签名意图"><IconRefresh className={intents.isFetching ? "spin" : ""} size={14} />刷新</button></div>
      {intents.isError ? <p className="form-error"><IconAlertTriangle size={14} />{intents.error.message}</p> : null}
      {intents.isPending ? <div className="panel-loading"><IconRefresh className="spin" size={16} />读取签名意图</div> : null}
      {!intents.isPending && list.length === 0 ? <div className="panel-empty"><strong>暂无签名意图</strong><span>检查交易并创建意图后，它会出现在这里。</span></div> : null}
      <div className="intent-list">{list.map((intent) => <IntentRow key={intent.id} intent={intent} />)}</div>
    </div>
  );
}

function SecurityInspector() {
  const node = useNodeStatusQuery();
  const wallet = useWalletStatusQuery();
  const signer = useSignerStatusQuery();
  const credentials = useCredentialsQuery();
  const nodeSnapshot = wallet.data?.node;
  const rows = [
    { label: "钱包节点", value: node.isSuccess ? `${node.data.network} · 在线` : "离线" },
    { label: "OP_CAT / BIP 347", value: nodeSnapshot?.op_cat_active ? "当前链已激活" : "未激活或节点不可达" },
    { label: "FROST 门限", value: signer.data?.configured ? `${signer.data.min_signers}-of-${wallet.data?.threshold.max_signers ?? "?"}` : "未配置" },
    { label: "Passkey", value: `${credentials.data?.length ?? 0} 个凭证` },
    { label: "密钥存储", value: node.data?.secret_storage ?? "不可用" },
  ];
  return (
    <div className="inspector-scroll">
      <p className="plugin-description">Passkey 证明用户同意，FROST 节点生成门限签名。两者保持独立。</p>
      <dl className="security-list">
        {rows.map((row) => <div key={row.label}><dt>{row.label}</dt><dd>{row.value}</dd></div>)}
      </dl>
      <div className="boundary-note"><IconAlertTriangle size={15} /><p><strong>当前为 Signet 研发设施</strong>进程内密钥和内存持久化不适合真实资产。部署前需要外部密钥存储、备份和恢复规范。</p></div>
      <Link className="secondary-link" to="/passkeys"><IconFingerprint size={15} />管理 Passkey<IconChevronRight size={14} /></Link>
    </div>
  );
}

function IssuanceInspector() {
  return (
    <div className="inspector-scroll issuance-panel">
      <span className="research-label">研究中的协议边界</span>
      <h3>资产发行仍在定义</h3>
      <p>当前钱包尚未实现 covenant 资产协议、Mint 状态机或链上索引规则，所以这里不会生成虚构资产或交易。</p>
      <div className="research-checks">
        <div><strong>待定义</strong><span>发行上限、铸造资格和状态递归规则</span></div>
        <div><strong>待验证</strong><span>无需索引器参与结算的 UTXO 约束</span></div>
        <div><strong>待实现</strong><span>防替换订单与创作者分账范例</span></div>
      </div>
      <div className="boundary-note"><IconAlertTriangle size={15} /><p><strong>无链上操作</strong>此入口目前只陈述研发状态，不会广播交易或创建资产。</p></div>
    </div>
  );
}

function BrowserToolPane() {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const [address, setAddress] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const surface = surfaceRef.current;
    if (!surface) return;
    let bridge;
    try {
      bridge = requireDesktopBridge();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "桌面宿主不可用");
      return () => { active = false; };
    }
    const cleanup = mountBrowserPane(bridge, surface, {
      onError: (cause) => {
        if (active) setError(cause instanceof Error ? cause.message : "浏览器区域无法同步");
      },
    });
    return () => {
      active = false;
      cleanup();
    };
  }, []);

  async function navigate(event: FormEvent) {
    event.preventDefault();
    const next = address.trim();
    if (!next) return;
    setError(null);
    try {
      setAddress(await requireDesktopBridge().navigateBrowser(next));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "网址无法打开");
    }
  }

  async function runBrowserAction(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "浏览器操作失败");
    }
  }

  return (
    <div className="browser-tool">
      <form className="browser-controls" onSubmit={(event) => void navigate(event)}>
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserBack())} aria-label="后退"><IconArrowLeft size={14} /></button>
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserForward())} aria-label="前进"><IconArrowRight size={14} /></button>
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserReload())} aria-label="刷新"><IconRefresh size={14} /></button>
        <input value={address} onChange={(event) => setAddress(event.target.value)} placeholder="输入公开网址" aria-label="浏览器网址" />
      </form>
      {error ? <p className="browser-error">{error}</p> : null}
      <div className="browser-surface" ref={surfaceRef}><span>桌面浏览器视图</span></div>
    </div>
  );
}

function ToolChooser({ onSelect }: { onSelect: (tab: ToolTab) => void }) {
  return (
    <nav className="tool-chooser" aria-label="工具">
      <button type="button" onClick={() => onSelect("browser")}><span><strong>浏览器</strong><small>在隔离页签查看公开网页</small></span><IconChevronRight size={15} /></button>
      {starterActions.map((tool) => (
        <button key={tool.mode} type="button" onClick={() => onSelect(tool.mode)}>
          <span><strong>{pluginMeta[tool.mode].label}</strong><small>{tool.description}</small></span>
          <IconChevronRight size={15} />
        </button>
      ))}
    </nav>
  );
}

function ToolAreaPanel({
  state,
  onClose,
  onBack,
  onSelect,
  activeDrawer,
  backgroundInert,
  railRef,
  closeButtonRef,
}: {
  state: ToolAreaState;
  onClose: () => void;
  onBack: () => void;
  onSelect: (tab: ToolTab) => void;
  activeDrawer: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const activeTab = state.activeTab;
  const meta = activeTab ? toolMeta[activeTab] : { label: "工具", icon: IconTools };
  const plugin = activeTab && activeTab !== "browser" ? starterActions.find((item) => item.mode === activeTab) : undefined;
  return (
    <aside
      className="workbench-right"
      aria-label={`${meta.label}工具区`}
      aria-hidden={backgroundInert || undefined}
      aria-modal={activeDrawer || undefined}
      inert={backgroundInert || undefined}
      ref={railRef}
      role={activeDrawer ? "dialog" : "complementary"}
    >
      <header className="inspector-header">
        <div>{activeTab ? <button className="tool-back" type="button" onClick={onBack} aria-label="返回工具列表"><IconArrowLeft size={15} /></button> : null}<strong>{meta.label}</strong>{plugin?.available === false ? <span className="inspector-mode-state">规划中</span> : null}</div>
        <button className="plugin-close" type="button" onClick={onClose} aria-label="关闭工具区" ref={closeButtonRef}><IconX size={17} /></button>
      </header>
      {activeTab === null ? <ToolChooser onSelect={onSelect} /> : null}
      {activeTab === "browser" ? <BrowserToolPane /> : null}
      {activeTab === "transaction" ? <TransactionInspector /> : null}
      {activeTab === "intents" ? <IntentsInspector /> : null}
      {activeTab === "security" ? <SecurityInspector /> : null}
      {activeTab === "issuance" ? <IssuanceInspector /> : null}
    </aside>
  );
}

export function WalletWorkbench() {
  const [toolArea, setToolArea] = useState<ToolAreaState>(DEFAULT_TOOL_AREA);
  const [activeDrawer, setActiveDrawer] = useState<ActiveDrawer>(null);
  const [desktopError, setDesktopError] = useState<string | null>(null);
  const leftIsOverlay = useMediaQuery("(max-width: 760px)");
  const rightIsOverlay = useMediaQuery("(max-width: 1180px)");
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const toolTriggerRef = useRef<HTMLElement | null>(null);
  const leftRailRef = useRef<HTMLElement>(null);
  const rightRailRef = useRef<HTMLElement>(null);
  const leftCloseRef = useRef<HTMLButtonElement>(null);
  const rightCloseRef = useRef<HTMLButtonElement>(null);
  const toolBridgeQueueRef = useRef<{ bridge: DesktopBridge; queue: ToolAreaBridgeQueue } | null>(null);

  const openDrawer = useCallback((drawer: Exclude<ActiveDrawer, null>) => {
    setActiveDrawer((current) => {
      if (current === null && document.activeElement instanceof HTMLElement) {
        previousFocusRef.current = document.activeElement;
      }
      return transitionDrawer(current, drawer === "left" ? "open-left" : "open-right");
    });
  }, []);

  const closeDrawer = useCallback(() => {
    setActiveDrawer((current) => transitionDrawer(current, "close"));
    requestAnimationFrame(() => previousFocusRef.current?.focus());
  }, []);

  const reportDesktopBridgeError = useCallback((cause: unknown) => {
    setDesktopError(cause instanceof Error ? cause.message : "桌面操作失败");
  }, []);

  const syncToolAreaFromDesktop = useCallback(async (bridge: DesktopBridge) => {
    try {
      const desktopState = await bridge.getState();
      setToolArea(desktopState.toolsOpen
        ? { open: true, activeTab: desktopState.activeTab }
        : DEFAULT_TOOL_AREA);
    } catch (cause) {
      reportDesktopBridgeError(cause);
    }
  }, [reportDesktopBridgeError]);

  const runToolBridgeAction = useCallback((action: (queue: ToolAreaBridgeQueue) => Promise<void>) => {
    const bridge = optionalDesktopBridge();
    if (!bridge) {
      setDesktopError("桌面宿主不可用");
      return;
    }
    if (toolBridgeQueueRef.current?.bridge !== bridge) {
      toolBridgeQueueRef.current = {
        bridge,
        queue: createToolAreaBridgeQueue(bridge, async (cause) => {
          reportDesktopBridgeError(cause);
          await syncToolAreaFromDesktop(bridge);
        }),
      };
    }
    setDesktopError(null);
    void action(toolBridgeQueueRef.current.queue);
  }, [reportDesktopBridgeError, syncToolAreaFromDesktop]);

  const closeToolArea = useCallback(() => {
    setToolArea((current) => transitionToolArea(current, { type: "close" }));
    runToolBridgeAction((queue) => queue.closeTools());
    if (activeDrawer === "right") closeDrawer();
    else requestAnimationFrame(() => toolTriggerRef.current?.focus());
  }, [activeDrawer, closeDrawer, runToolBridgeAction]);

  useEffect(() => {
    if (!activeDrawer) return;
    const container = activeDrawer === "left" ? leftRailRef.current : rightRailRef.current;
    const closeButton = activeDrawer === "left" ? leftCloseRef.current : rightCloseRef.current;
    const focusFrame = requestAnimationFrame(() => closeButton?.focus());

    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (activeDrawer === "right") closeToolArea();
        else closeDrawer();
        return;
      }
      if (event.key !== "Tab" || !container) return;
      const focusable = Array.from(container.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )).filter((element) => !element.hasAttribute("hidden"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [activeDrawer, closeDrawer, closeToolArea]);

  useEffect(() => {
    if (!activeDrawer) return;
    const media = window.matchMedia(activeDrawer === "left" ? "(max-width: 760px)" : "(max-width: 1180px)");
    function onBreakpointChange(event: MediaQueryListEvent) {
      if (!event.matches) closeDrawer();
    }
    media.addEventListener("change", onBreakpointChange);
    return () => media.removeEventListener("change", onBreakpointChange);
  }, [activeDrawer, closeDrawer]);

  useEffect(() => {
    if (rightIsOverlay && toolArea.open && activeDrawer === null) {
      openDrawer("right");
    }
  }, [activeDrawer, openDrawer, rightIsOverlay, toolArea.open]);

  useEffect(() => {
    let active = true;
    const bridge = optionalDesktopBridge();
    if (!bridge) return () => { active = false; };
    void bridge.getState().then(
      (desktopState) => {
        if (!active || !desktopState.toolsOpen) return;
        setToolArea({ open: true, activeTab: desktopState.activeTab });
      },
      (cause: unknown) => { if (active) reportDesktopBridgeError(cause); },
    );
    return () => { active = false; };
  }, [reportDesktopBridgeError]);

  function openTools() {
    if (!toolArea.open && document.activeElement instanceof HTMLElement) {
      toolTriggerRef.current = document.activeElement;
    }
    setToolArea((current) => transitionToolArea(current, { type: "expand" }));
    if (rightIsOverlay) openDrawer("right");
  }

  function selectTool(next: ToolTab) {
    setToolArea((current) => transitionToolArea(current, { type: "select", tab: next }));
    runToolBridgeAction((queue) => queue.selectTab(next));
  }

  function backToTools() {
    setToolArea((current) => transitionToolArea(current, { type: "back" }));
    runToolBridgeAction((queue) => queue.closeTools());
  }

  function dismissOverlay() {
    if (activeDrawer === "right") closeToolArea();
    else closeDrawer();
  }

  return (
    <div
      className="workbench-shell"
      data-left-open={activeDrawer === "left"}
      data-right-open={activeDrawer === "right"}
      data-tools-open={toolArea.open}
    >
      <div className="drawer-backdrop" onClick={dismissOverlay} aria-hidden="true" />
      {desktopError ? <div className="desktop-error" role="alert"><IconAlertTriangle size={14} /><span>{desktopError}</span><button type="button" onClick={() => setDesktopError(null)} aria-label="关闭错误"><IconX size={13} /></button></div> : null}
      <LeftRail
        onClose={closeDrawer}
        active={activeDrawer === "left"}
        backgroundInert={(leftIsOverlay && activeDrawer !== "left") || activeDrawer === "right"}
        railRef={leftRailRef}
        closeButtonRef={leftCloseRef}
      />
      <Conversation
        onOpenLeft={() => openDrawer("left")}
        onOpenTools={openTools}
        backgroundInert={activeDrawer !== null}
      />
      {toolArea.open ? (
        <ToolAreaPanel
          state={toolArea}
          onClose={closeToolArea}
          onBack={backToTools}
          onSelect={selectTool}
          activeDrawer={activeDrawer === "right"}
          backgroundInert={(rightIsOverlay && activeDrawer !== "right") || activeDrawer === "left"}
          railRef={rightRailRef}
          closeButtonRef={rightCloseRef}
        />
      ) : null}
    </div>
  );
}
