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
  IconAdjustmentsHorizontal,
  IconAlertTriangle,
  IconArrowUp,
  IconAtom,
  IconBolt,
  IconCheck,
  IconChevronRight,
  IconCoin,
  IconFileSearch,
  IconFingerprint,
  IconGitBranch,
  IconLock,
  IconMenu2,
  IconMessage,
  IconPlus,
  IconRefresh,
  IconServer,
  IconShieldCheck,
  IconSparkles,
  IconUser,
  IconX,
} from "@tabler/icons-react";
import { ApiError, apiBase } from "@/lib/api";
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
  starterActions,
  transitionDrawer,
  type ActiveDrawer,
  type InspectorMode,
} from "@/lib/workbench";
import { TransactionInspector } from "./TransactionInspector";

const modeMeta: Record<InspectorMode, { label: string; icon: typeof IconFileSearch }> = {
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

function StatusPip({ active, warn = false }: { active: boolean; warn?: boolean }) {
  return <span className="status-pip" data-active={active} data-warn={warn} aria-hidden="true" />;
}

function LeftRail({
  mode,
  onModeChange,
  onClose,
  active,
  backgroundInert,
  railRef,
  closeButtonRef,
}: {
  mode: InspectorMode;
  onModeChange: (mode: InspectorMode) => void;
  onClose: () => void;
  active: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const wallet = useWalletStatusQuery();
  const node = useNodeStatusQuery();
  const signer = useSignerStatusQuery();
  const credentials = useCredentialsQuery();
  const opCatActive = wallet.data?.node?.op_cat_active ?? false;

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
        <div className="brand-mark"><IconAtom size={18} /></div>
        <div><strong>Catomicals</strong><span>Covenant wallet</span></div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭左栏" ref={closeButtonRef}><IconX size={17} /></button>
      </div>

      <div className="rail-section session-section">
        <div className="rail-section-title"><span>会话</span><button type="button" disabled title="钱包节点当前只提供单一内存会话"><IconPlus size={15} /></button></div>
        <button className="session-row active" type="button">
          <IconMessage size={16} />
          <span><strong>钱包工作台</strong><small>当前节点会话</small></span>
          <StatusPip active={wallet.isSuccess} />
        </button>
      </div>

      <div className="rail-section tools-section">
        <div className="rail-section-title"><span>工具</span></div>
        {starterActions.map((action) => {
          const Icon = modeMeta[action.mode].icon;
          return (
            <button
              className="tool-row"
              data-active={mode === action.mode}
              key={action.mode}
              type="button"
              onClick={() => onModeChange(action.mode)}
              aria-label={`${modeMeta[action.mode].label}${action.available ? "" : "，规划中且不可执行，打开说明"}`}
            >
              <Icon size={16} />
              <span>{modeMeta[action.mode].label}{action.available ? null : <small>规划中</small>}</span>
              <IconChevronRight size={14} />
            </button>
          );
        })}
      </div>

      <div className="rail-spacer" />
      <div className="rail-section live-stack">
        <div className="rail-section-title"><span>本机状态</span><IconRefresh className={wallet.isFetching ? "spin" : ""} size={13} /></div>
        <div className="live-row"><StatusPip active={node.isSuccess} /><span>钱包节点</span><small>{node.isSuccess ? "在线" : "离线"}</small></div>
        <div className="live-row"><StatusPip active={opCatActive} warn={wallet.isSuccess && !opCatActive} /><span>OP_CAT</span><small>{opCatActive ? "已激活" : wallet.data?.node ? "未激活" : "未知"}</small></div>
        <div className="live-row"><StatusPip active={signer.data?.configured ?? false} /><span>FROST</span><small>{signer.data?.configured ? `${signer.data.min_signers}-of-${wallet.data?.threshold.max_signers ?? "?"}` : "未配置"}</small></div>
        <div className="live-row"><StatusPip active={(credentials.data?.length ?? 0) > 0} /><span>Passkey</span><small>{credentials.data?.length ?? 0} 个</small></div>
      </div>
      <div className="rail-footer"><IconServer size={14} /><span title={apiBase()}>{apiBase()}</span></div>
    </aside>
  );
}

function WalletAction({ action }: { action: ChatIntentBinding }) {
  return (
    <div className="message-action">
      <div><IconLock size={15} /><strong>待授权签名意图</strong><span>{action.authorization.replaceAll("_", " ")}</span></div>
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
      <div className="message-avatar">{wallet ? <IconSparkles size={16} /> : <IconUser size={16} />}</div>
      <div className="message-content">
        <div className="message-meta"><strong>{wallet ? "钱包节点" : "你"}</strong><time>{formatUnix(message.created_at)}</time></div>
        <p>{message.content}</p>
        {message.wallet_action ? <WalletAction action={message.wallet_action} /> : null}
      </div>
    </article>
  );
}

function Conversation({
  onChooseMode,
  onOpenLeft,
  onOpenRight,
  backgroundInert,
}: {
  onChooseMode: (mode: InspectorMode) => void;
  onOpenLeft: () => void;
  onOpenRight: () => void;
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
    <main
      className="conversation-pane"
      aria-hidden={backgroundInert || undefined}
      inert={backgroundInert || undefined}
    >
      <header className="conversation-header">
        <button className="mobile-rail-button left-toggle" type="button" onClick={onOpenLeft} aria-label="打开左栏"><IconMenu2 size={18} /></button>
        <div><strong>钱包工作台</strong><span><StatusPip active={chat.isSuccess} /> {chat.isSuccess ? "钱包节点已连接" : "等待钱包节点"}</span></div>
        <div className="header-security"><IconLock size={14} /> Passkey 授权 · FROST 签名</div>
        <button className="mobile-rail-button right-toggle" type="button" onClick={onOpenRight} aria-label="打开详情"><IconAdjustmentsHorizontal size={18} /></button>
      </header>

      <div className="conversation-scroll" onScroll={onTranscriptScroll} ref={transcriptRef}>
        <div className="conversation-width">
          {chat.isPending ? <div className="conversation-loading"><IconRefresh className="spin" size={18} />正在读取钱包会话</div> : null}
          {chat.isError ? (
            <div className="conversation-error"><IconAlertTriangle size={18} /><div><strong>钱包节点不可用</strong><span>{chat.error.message}</span></div></div>
          ) : null}
          {!chat.isPending && !chat.isError && messages.length === 0 ? (
            <section className="chat-empty">
              <div className="empty-symbol"><IconBolt size={22} /></div>
              <h1>告诉钱包你想完成什么</h1>
              <p>对话负责理解目标；交易字节、授权边界和签名状态始终可以独立检查。</p>
              <div className="starter-grid">
                {starterActions.map((action) => {
                  const Icon = modeMeta[action.mode].icon;
                  return (
                    <button
                      key={action.mode}
                      type="button"
                      onClick={() => onChooseMode(action.mode)}
                      aria-label={`${action.title}${action.available ? "" : "，规划中且不可执行，打开说明"}`}
                    >
                      <Icon size={17} />
                      <span>
                        <strong>{action.title}</strong>
                        <small>{action.description}</small>
                        {action.available ? null : <em>规划中 · 仅查看边界</em>}
                      </span>
                      <IconChevronRight size={15} />
                    </button>
                  );
                })}
              </div>
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
            <div className="composer-tools">
              <button type="button" onClick={() => onChooseMode("transaction")} aria-label="打开交易检查"><IconFileSearch size={17} /></button>
              <button type="button" onClick={() => onChooseMode("security")} aria-label="打开安全状态"><IconShieldCheck size={17} /></button>
              <span>Enter 发送 · Shift + Enter 换行</span>
            </div>
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
  return (
    <Link className="intent-row" to="/intents/$intentId" params={{ intentId: intent.id }}>
      <div><StatusPip active={intent.status === "approved" || intent.status === "signed"} warn={expired} /><strong>{intent.action.replaceAll("_", " ")}</strong></div>
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
      <div className="inspector-summary-line"><span>{list.filter((item) => item.status === "pending").length} 个待处理</span><button type="button" onClick={() => void intents.refetch()}><IconRefresh className={intents.isFetching ? "spin" : ""} size={14} />刷新</button></div>
      {intents.isError ? <p className="form-error"><IconAlertTriangle size={14} />{intents.error.message}</p> : null}
      {intents.isPending ? <div className="panel-loading"><IconRefresh className="spin" size={17} />读取签名意图</div> : null}
      {!intents.isPending && list.length === 0 ? <div className="panel-empty"><IconGitBranch size={22} /><strong>暂无签名意图</strong><span>检查交易并创建意图后，它会出现在这里。</span></div> : null}
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
    { icon: IconServer, label: "钱包节点", value: node.isSuccess ? `${node.data.network} · 在线` : "离线", active: node.isSuccess },
    { icon: IconBolt, label: "OP_CAT / BIP 347", value: nodeSnapshot?.op_cat_active ? "当前链已激活" : "未激活或节点不可达", active: nodeSnapshot?.op_cat_active ?? false },
    { icon: IconGitBranch, label: "FROST 门限", value: signer.data?.configured ? `${signer.data.min_signers}-of-${wallet.data?.threshold.max_signers ?? "?"}` : "未配置", active: signer.data?.configured ?? false },
    { icon: IconFingerprint, label: "Passkey", value: `${credentials.data?.length ?? 0} 个凭证`, active: (credentials.data?.length ?? 0) > 0 },
    { icon: IconLock, label: "密钥存储", value: node.data?.secret_storage ?? "不可用", active: node.isSuccess },
  ];
  return (
    <div className="inspector-scroll">
      <div className="security-banner"><IconShieldCheck size={18} /><div><strong>授权与签名分离</strong><span>Passkey 证明用户同意；FROST 节点生成门限签名。</span></div></div>
      <div className="security-list">
        {rows.map((row) => {
          const Icon = row.icon;
          return <div key={row.label}><div className="security-icon"><Icon size={16} /></div><span><strong>{row.label}</strong><small>{row.value}</small></span><StatusPip active={row.active} warn={!row.active} /></div>;
        })}
      </div>
      <div className="boundary-note"><IconAlertTriangle size={16} /><p><strong>当前为 Signet 研发设施</strong>进程内密钥和内存持久化不适合真实资产。部署前需要外部密钥存储、备份和恢复规范。</p></div>
      <Link className="secondary-link" to="/passkeys"><IconFingerprint size={15} />管理 Passkey<IconChevronRight size={14} /></Link>
    </div>
  );
}

function IssuanceInspector() {
  return (
    <div className="inspector-scroll issuance-panel">
      <div className="issuance-mark"><IconCoin size={23} /></div>
      <span className="research-label">研究中的协议边界</span>
      <h3>资产发行仍在定义</h3>
      <p>当前钱包尚未实现 covenant 资产协议、Mint 状态机或链上索引规则，所以这里不会生成虚构资产或交易。</p>
      <div className="research-checks">
        <div><IconCheck size={15} /><span><strong>待定义</strong>发行上限、铸造资格和状态递归规则</span></div>
        <div><IconCheck size={15} /><span><strong>待验证</strong>无需索引器参与结算的 UTXO 约束</span></div>
        <div><IconCheck size={15} /><span><strong>待实现</strong>防替换订单与创作者分账范例</span></div>
      </div>
      <div className="boundary-note"><IconAlertTriangle size={16} /><p><strong>无链上操作</strong>此入口目前只陈述研发状态，不会广播交易或创建资产。</p></div>
    </div>
  );
}

function ContextInspector({
  mode,
  onModeChange,
  onClose,
  active,
  backgroundInert,
  railRef,
  closeButtonRef,
}: {
  mode: InspectorMode;
  onModeChange: (mode: InspectorMode) => void;
  onClose: () => void;
  active: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const meta = modeMeta[mode];
  const action = starterActions.find((item) => item.mode === mode);
  const Icon = meta.icon;
  return (
    <aside
      className="workbench-right"
      aria-label="上下文详情"
      aria-hidden={backgroundInert || undefined}
      aria-modal={active || undefined}
      inert={backgroundInert || undefined}
      ref={railRef}
      role={active ? "dialog" : undefined}
    >
      <header className="inspector-header">
        <div><Icon size={17} /><strong>{meta.label}</strong>{action?.available === false ? <span className="inspector-mode-state">规划中</span> : null}</div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭详情" ref={closeButtonRef}><IconX size={17} /></button>
      </header>
      <nav className="inspector-tabs" aria-label="详情模式" role="tablist">
        {(Object.keys(modeMeta) as InspectorMode[]).map((item) => {
          const ItemIcon = modeMeta[item].icon;
          const available = starterActions.find((actionItem) => actionItem.mode === item)?.available ?? true;
          return <button key={item} type="button" data-active={mode === item} onClick={() => onModeChange(item)} aria-label={`${modeMeta[item].label}${available ? "" : "，规划中且不可执行"}`} aria-selected={mode === item} role="tab"><ItemIcon size={16} /></button>;
        })}
      </nav>
      {mode === "transaction" ? <TransactionInspector /> : null}
      {mode === "intents" ? <IntentsInspector /> : null}
      {mode === "security" ? <SecurityInspector /> : null}
      {mode === "issuance" ? <IssuanceInspector /> : null}
    </aside>
  );
}

export function WalletWorkbench() {
  const [mode, setMode] = useState<InspectorMode>("transaction");
  const [activeDrawer, setActiveDrawer] = useState<ActiveDrawer>(null);
  const leftIsOverlay = useMediaQuery("(max-width: 760px)");
  const rightIsOverlay = useMediaQuery("(max-width: 1180px)");
  const previousFocusRef = useRef<HTMLElement | null>(null);
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

  useEffect(() => {
    if (!activeDrawer) return;
    const container = activeDrawer === "left" ? leftRailRef.current : rightRailRef.current;
    const closeButton = activeDrawer === "left" ? leftCloseRef.current : rightCloseRef.current;
    const focusFrame = requestAnimationFrame(() => closeButton?.focus());

    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        closeDrawer();
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
  }, [activeDrawer, closeDrawer]);

  useEffect(() => {
    if (!activeDrawer) return;
    const media = window.matchMedia(
      activeDrawer === "left" ? "(max-width: 760px)" : "(max-width: 1180px)",
    );
    function onBreakpointChange(event: MediaQueryListEvent) {
      if (!event.matches) closeDrawer();
    }
    media.addEventListener("change", onBreakpointChange);
    return () => media.removeEventListener("change", onBreakpointChange);
  }, [activeDrawer, closeDrawer]);

  function chooseMode(next: InspectorMode) {
    setMode(next);
    if (rightIsOverlay) {
      setActiveDrawer((current) => {
        if (current === null && document.activeElement instanceof HTMLElement) {
          previousFocusRef.current = document.activeElement;
        }
        return transitionDrawer(current, "select-tool");
      });
    } else {
      setActiveDrawer(null);
    }
  }

  return (
    <div className="workbench-shell" data-left-open={activeDrawer === "left"} data-right-open={activeDrawer === "right"}>
      <div className="drawer-backdrop" onClick={closeDrawer} aria-hidden="true" />
      <LeftRail
        mode={mode}
        onModeChange={chooseMode}
        onClose={closeDrawer}
        active={activeDrawer === "left"}
        backgroundInert={(leftIsOverlay && activeDrawer !== "left") || activeDrawer === "right"}
        railRef={leftRailRef}
        closeButtonRef={leftCloseRef}
      />
      <Conversation
        onChooseMode={chooseMode}
        onOpenLeft={() => openDrawer("left")}
        onOpenRight={() => openDrawer("right")}
        backgroundInert={activeDrawer !== null}
      />
      <ContextInspector
        mode={mode}
        onModeChange={setMode}
        onClose={closeDrawer}
        active={activeDrawer === "right"}
        backgroundInert={(rightIsOverlay && activeDrawer !== "right") || activeDrawer === "left"}
        railRef={rightRailRef}
        closeButtonRef={rightCloseRef}
      />
    </div>
  );
}
