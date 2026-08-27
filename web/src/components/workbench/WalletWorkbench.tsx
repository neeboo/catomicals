import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
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
import { starterActions, type InspectorMode } from "@/lib/workbench";
import { TransactionInspector } from "./TransactionInspector";

const modeMeta: Record<InspectorMode, { label: string; icon: typeof IconFileSearch }> = {
  transaction: { label: "交易检查", icon: IconFileSearch },
  intents: { label: "签名意图", icon: IconGitBranch },
  security: { label: "安全状态", icon: IconShieldCheck },
  issuance: { label: "资产发行", icon: IconCoin },
};

function StatusPip({ active, warn = false }: { active: boolean; warn?: boolean }) {
  return <span className="status-pip" data-active={active} data-warn={warn} aria-hidden="true" />;
}

function LeftRail({
  mode,
  onModeChange,
  onClose,
}: {
  mode: InspectorMode;
  onModeChange: (mode: InspectorMode) => void;
  onClose: () => void;
}) {
  const wallet = useWalletStatusQuery();
  const node = useNodeStatusQuery();
  const signer = useSignerStatusQuery();
  const credentials = useCredentialsQuery();
  const opCatActive = wallet.data?.node?.op_cat_active ?? false;

  return (
    <aside className="workbench-left" aria-label="钱包与会话">
      <div className="brand-row">
        <div className="brand-mark"><IconAtom size={18} /></div>
        <div><strong>Catomicals</strong><span>Covenant wallet</span></div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭左栏"><IconX size={17} /></button>
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
            >
              <Icon size={16} />
              <span>{modeMeta[action.mode].label}</span>
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
}: {
  onChooseMode: (mode: InspectorMode) => void;
  onOpenLeft: () => void;
  onOpenRight: () => void;
}) {
  const chat = useChatStateQuery();
  const send = useCreateChatMessageMutation();
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const transcriptRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight, behavior: "smooth" });
  }, [chat.data?.messages.length]);

  function submit(event?: FormEvent) {
    event?.preventDefault();
    const clean = content.trim();
    if (!clean || send.isPending) return;
    setError(null);
    send.mutate({ content: clean }, {
      onSuccess: () => setContent(""),
      onError: (cause) => setError(cause instanceof ApiError ? cause.message : (cause as Error).message),
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
    <main className="conversation-pane">
      <header className="conversation-header">
        <button className="mobile-rail-button left-toggle" type="button" onClick={onOpenLeft} aria-label="打开左栏"><IconMenu2 size={18} /></button>
        <div><strong>钱包工作台</strong><span><StatusPip active={chat.isSuccess} /> {chat.isSuccess ? "钱包节点已连接" : "等待钱包节点"}</span></div>
        <div className="header-security"><IconLock size={14} /> Passkey 授权 · FROST 签名</div>
        <button className="mobile-rail-button right-toggle" type="button" onClick={onOpenRight} aria-label="打开详情"><IconAdjustmentsHorizontal size={18} /></button>
      </header>

      <div className="conversation-scroll" ref={transcriptRef}>
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
                    <button key={action.mode} type="button" onClick={() => onChooseMode(action.mode)}>
                      <Icon size={17} />
                      <span><strong>{action.title}</strong><small>{action.description}</small></span>
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
              <button type="button" onClick={() => onChooseMode("transaction")} title="打开交易检查"><IconFileSearch size={17} /></button>
              <button type="button" onClick={() => onChooseMode("security")} title="打开安全状态"><IconShieldCheck size={17} /></button>
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

function ContextInspector({ mode, onModeChange, onClose }: { mode: InspectorMode; onModeChange: (mode: InspectorMode) => void; onClose: () => void }) {
  const meta = modeMeta[mode];
  const Icon = meta.icon;
  return (
    <aside className="workbench-right" aria-label="上下文详情">
      <header className="inspector-header">
        <div><Icon size={17} /><strong>{meta.label}</strong></div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭详情"><IconX size={17} /></button>
      </header>
      <nav className="inspector-tabs" aria-label="详情模式">
        {(Object.keys(modeMeta) as InspectorMode[]).map((item) => {
          const ItemIcon = modeMeta[item].icon;
          return <button key={item} type="button" data-active={mode === item} onClick={() => onModeChange(item)} title={modeMeta[item].label}><ItemIcon size={16} /></button>;
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
  const [leftOpen, setLeftOpen] = useState(false);
  const [rightOpen, setRightOpen] = useState(false);

  function chooseMode(next: InspectorMode) {
    setMode(next);
    setRightOpen(true);
  }

  return (
    <div className="workbench-shell" data-left-open={leftOpen} data-right-open={rightOpen}>
      <div className="drawer-backdrop" onClick={() => { setLeftOpen(false); setRightOpen(false); }} aria-hidden="true" />
      <LeftRail mode={mode} onModeChange={chooseMode} onClose={() => setLeftOpen(false)} />
      <Conversation
        onChooseMode={chooseMode}
        onOpenLeft={() => setLeftOpen(true)}
        onOpenRight={() => setRightOpen(true)}
      />
      <ContextInspector mode={mode} onModeChange={setMode} onClose={() => setRightOpen(false)} />
    </div>
  );
}
