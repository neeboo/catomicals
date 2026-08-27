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
  IconArrowUp,
  IconChevronRight,
  IconCoin,
  IconFileSearch,
  IconFingerprint,
  IconGitBranch,
  IconLock,
  IconMenu2,
  IconPlus,
  IconRefresh,
  IconShieldCheck,
  IconX,
} from "@tabler/icons-react";
import { ApiError } from "@/lib/api";
import { errorMessage } from "@/lib/errors";
import { formatRelative, formatUnix, shortHex } from "@/lib/format";
import {
  useChatStateQuery,
  useCreateChatMessageMutation,
  useCredentialsQuery,
  useIntentsQuery,
  useNodeStatusQuery,
  useSignerStatusQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import type { ChatIntentBinding, ChatMessage, SigningIntent } from "@/lib/types";
import {
  DEFAULT_PLUGIN_PANEL,
  starterActions,
  transitionDrawer,
  transitionPluginPanel,
  type ActiveDrawer,
  type InspectorMode,
  type PluginPanelState,
} from "@/lib/workbench";
import { TransactionInspector } from "./TransactionInspector";

const pluginMeta: Record<InspectorMode, { label: string; icon: typeof IconFileSearch }> = {
  transaction: { label: "交易检查", icon: IconFileSearch },
  intents: { label: "签名意图", icon: IconGitBranch },
  security: { label: "安全状态", icon: IconShieldCheck },
  issuance: { label: "资产发行", icon: IconCoin },
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
        <div className="rail-section-title"><span>会话</span></div>
        <button className="session-row active" type="button">
          <span><strong>钱包工作台</strong><small>当前节点会话</small></span>
        </button>
      </div>

      <div className="rail-spacer" />
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

function Message({ message }: { message: ChatMessage }) {
  const wallet = message.role === "wallet";
  return (
    <article className="chat-message" data-wallet={wallet}>
      <div className="message-meta"><strong>{wallet ? "钱包节点" : "你"}</strong><time>{formatUnix(message.created_at)}</time></div>
      <p>{message.content}</p>
      {message.wallet_action ? <WalletAction action={message.wallet_action} /> : null}
    </article>
  );
}

function PluginToolbar({
  activePlugin,
  onSelectPlugin,
}: {
  activePlugin: PluginPanelState;
  onSelectPlugin: (mode: InspectorMode) => void;
}) {
  return (
    <nav className="plugin-toolbar" aria-label="钱包插件">
      {starterActions.map((plugin) => {
        const Icon = pluginMeta[plugin.mode].icon;
        return (
          <button
            key={plugin.mode}
            type="button"
            data-active={activePlugin === plugin.mode}
            aria-pressed={activePlugin === plugin.mode}
            aria-label={`${pluginMeta[plugin.mode].label}${plugin.available ? "" : "，规划中且不可执行，打开说明"}`}
            onClick={() => onSelectPlugin(plugin.mode)}
          >
            <Icon size={14} />
            <span>{pluginMeta[plugin.mode].label}</span>
            {plugin.available ? null : <small>规划中</small>}
          </button>
        );
      })}
    </nav>
  );
}

function Conversation({
  activePlugin,
  onSelectPlugin,
  onOpenLeft,
  backgroundInert,
}: {
  activePlugin: PluginPanelState;
  onSelectPlugin: (mode: InspectorMode) => void;
  onOpenLeft: () => void;
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
      </header>
      <PluginToolbar activePlugin={activePlugin} onSelectPlugin={onSelectPlugin} />

      <div className="conversation-scroll" onScroll={onTranscriptScroll} ref={transcriptRef}>
        <div className="conversation-width">
          {chat.isPending ? <div className="conversation-loading"><IconRefresh className="spin" size={16} />正在读取钱包会话</div> : null}
          {chat.isError ? (
            <div className="conversation-error"><IconAlertTriangle size={17} /><div><strong>钱包节点不可用</strong><span>{chat.error.message}</span></div></div>
          ) : null}
          {!chat.isPending && !chat.isError && messages.length === 0 ? (
            <section className="chat-empty">
              <h1>开始一段钱包对话</h1>
              <p>描述你想完成的操作。需要检查交易、授权或节点状态时，从上方打开相应插件。</p>
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
            <span>Enter 发送 · Shift + Enter 换行</span>
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

function PluginPanel({
  mode,
  onClose,
  activeDrawer,
  backgroundInert,
  railRef,
  closeButtonRef,
}: {
  mode: InspectorMode;
  onClose: () => void;
  activeDrawer: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const meta = pluginMeta[mode];
  const plugin = starterActions.find((item) => item.mode === mode);
  const Icon = meta.icon;
  return (
    <aside
      className="workbench-right"
      aria-label={`${meta.label}插件`}
      aria-hidden={backgroundInert || undefined}
      aria-modal={activeDrawer || undefined}
      inert={backgroundInert || undefined}
      ref={railRef}
      role={activeDrawer ? "dialog" : "complementary"}
    >
      <header className="inspector-header">
        <div><Icon size={15} /><strong>{meta.label}</strong>{plugin?.available === false ? <span className="inspector-mode-state">规划中</span> : null}</div>
        <button className="plugin-close" type="button" onClick={onClose} aria-label={`关闭${meta.label}插件`} ref={closeButtonRef}><IconX size={17} /></button>
      </header>
      {mode === "transaction" ? <TransactionInspector /> : null}
      {mode === "intents" ? <IntentsInspector /> : null}
      {mode === "security" ? <SecurityInspector /> : null}
      {mode === "issuance" ? <IssuanceInspector /> : null}
    </aside>
  );
}

export function WalletWorkbench() {
  const [activePlugin, setActivePlugin] = useState<PluginPanelState>(DEFAULT_PLUGIN_PANEL);
  const [activeDrawer, setActiveDrawer] = useState<ActiveDrawer>(null);
  const leftIsOverlay = useMediaQuery("(max-width: 760px)");
  const rightIsOverlay = useMediaQuery("(max-width: 1180px)");
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const pluginTriggerRef = useRef<HTMLElement | null>(null);
  const leftRailRef = useRef<HTMLElement>(null);
  const rightRailRef = useRef<HTMLElement>(null);
  const leftCloseRef = useRef<HTMLButtonElement>(null);
  const rightCloseRef = useRef<HTMLButtonElement>(null);

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

  const closePlugin = useCallback(() => {
    setActivePlugin((current) => transitionPluginPanel(current, { type: "close" }));
    if (activeDrawer === "right") closeDrawer();
    else requestAnimationFrame(() => pluginTriggerRef.current?.focus());
  }, [activeDrawer, closeDrawer]);

  useEffect(() => {
    if (!activeDrawer) return;
    const container = activeDrawer === "left" ? leftRailRef.current : rightRailRef.current;
    const closeButton = activeDrawer === "left" ? leftCloseRef.current : rightCloseRef.current;
    const focusFrame = requestAnimationFrame(() => closeButton?.focus());

    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (activeDrawer === "right") closePlugin();
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
  }, [activeDrawer, closeDrawer, closePlugin]);

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
    if (rightIsOverlay && activePlugin !== null && activeDrawer === null) {
      openDrawer("right");
    }
  }, [activeDrawer, activePlugin, openDrawer, rightIsOverlay]);

  function selectPlugin(next: InspectorMode) {
    if (activePlugin === null && document.activeElement instanceof HTMLElement) {
      pluginTriggerRef.current = document.activeElement;
    }
    setActivePlugin((current) => transitionPluginPanel(current, { type: "select", mode: next }));
    if (rightIsOverlay) openDrawer("right");
  }

  function dismissOverlay() {
    if (activeDrawer === "right") closePlugin();
    else closeDrawer();
  }

  return (
    <div
      className="workbench-shell"
      data-left-open={activeDrawer === "left"}
      data-right-open={activeDrawer === "right"}
      data-plugin-open={activePlugin !== null}
    >
      <div className="drawer-backdrop" onClick={dismissOverlay} aria-hidden="true" />
      <LeftRail
        onClose={closeDrawer}
        active={activeDrawer === "left"}
        backgroundInert={(leftIsOverlay && activeDrawer !== "left") || activeDrawer === "right"}
        railRef={leftRailRef}
        closeButtonRef={leftCloseRef}
      />
      <Conversation
        activePlugin={activePlugin}
        onSelectPlugin={selectPlugin}
        onOpenLeft={() => openDrawer("left")}
        backgroundInert={activeDrawer !== null}
      />
      {activePlugin ? (
        <PluginPanel
          mode={activePlugin}
          onClose={closePlugin}
          activeDrawer={activeDrawer === "right"}
          backgroundInert={(rightIsOverlay && activeDrawer !== "right") || activeDrawer === "left"}
          railRef={rightRailRef}
          closeButtonRef={rightCloseRef}
        />
      ) : null}
    </div>
  );
}
