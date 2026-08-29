import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
} from "react";
import { Link } from "@tanstack/react-router";
import {
  IconAgentPresetOutline16,
  IconBranchOutline16,
  IconChevronLeftOutline14,
  IconChevronRightOutline14,
  IconCloseOutline16,
  IconDataOutline16,
  IconEnhanceOutline16,
  IconGlobeOutline14,
  IconPanelLeftOutline16,
  IconProjectAddOutline16,
  IconRefreshOutline16,
  IconSendOutline16,
  IconSettingsOutline16,
  IconUserOutline16,
  IconWarningOutline16,
} from "@/components/icons";
import { ControlledUiBlock } from "@/components/controlled-ui/LazyControlledUiBlock";
import { MarkdownContent } from "@/components/chat/MarkdownContent";
import { AccountDialog } from "@/components/account/AccountDialog";
import { SessionList } from "@/components/sessions/SessionList";
import { errorMessage } from "@/lib/errors";
import { formatDuration, formatRelative, formatUnix, shortHex } from "@/lib/format";
import { executorPluginId, executorPresentation, type ExecutorPresentation } from "@/lib/cordis";
import { optionalDesktopBridge, requireDesktopBridge, type AppendableSessionEvent, type DesktopBridge, type IdentitySession, type SessionEvent, type SessionHeader } from "@/lib/desktop";
import { createIdentityClient } from "@/lib/account";
import { DEFAULT_HARNESS_ID, HARNESS_ADAPTERS, type HarnessId } from "@/lib/harness";
import { executorAssistantResponse } from "@/lib/executor-chat";
import { buildSessionTranscript, lastNativeSessionId, type SessionTranscriptItem, type SessionTranscriptMessage } from "@/lib/session-transcript";
import { parseReviewReference } from "@/lib/ui-block";
import { useSessionStore } from "@/lib/session";
import {
  buildSessionTitlePrompt,
  fallbackSessionTitle,
  normalizeGeneratedSessionTitle,
} from "@/lib/session-title";
import {
  useCredentialsQuery,
  useIntentsQuery,
  useNodeStatusQuery,
  useSignerStatusQuery,
  useWalletStatusQuery,
} from "@/lib/hooks";
import type { ChatMessagePart, SigningIntent } from "@/lib/types";
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

const LEFT_RAIL_WIDTH_KEY = "catomicals:workbench:leftWidth";
const RIGHT_RAIL_WIDTH_KEY = "catomicals:workbench:rightWidth";
const LEFT_RAIL_MIN = 240;
const LEFT_RAIL_MAX = 480;
const LEFT_RAIL_DEFAULT = 312;
const RIGHT_RAIL_MIN = 320;
const RIGHT_RAIL_MAX = 720;
const RIGHT_RAIL_DEFAULT = 384;
const RAIL_KEYBOARD_STEP = 16;

function clampRailWidth(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(value)));
}

function readRailWidth(key: string, fallback: number, min: number, max: number): number {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return fallback;
    const value = Number(raw);
    if (!Number.isFinite(value) || value < min || value > max) return fallback;
    return clampRailWidth(value, min, max);
  } catch {
    return fallback;
  }
}

function writeRailWidth(key: string, value: number): void {
  try {
    window.localStorage.setItem(key, String(value));
  } catch {
    // Persistence is best-effort; the live layout still applies.
  }
}

const pluginMeta: Record<InspectorMode, { label: string; icon: typeof IconDataOutline16 }> = {
  transaction: { label: "交易检查", icon: IconDataOutline16 },
  intents: { label: "签名意图", icon: IconBranchOutline16 },
  security: { label: "安全状态", icon: IconAgentPresetOutline16 },
  issuance: { label: "资产发行", icon: IconProjectAddOutline16 },
};

const toolMeta: Record<ToolTab, { label: string; icon: typeof IconDataOutline16 }> = {
  browser: { label: "浏览器", icon: IconGlobeOutline14 },
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
  provider,
  onDesktopError,
}: {
  onClose: () => void;
  active: boolean;
  backgroundInert: boolean;
  railRef: RefObject<HTMLElement | null>;
  closeButtonRef: RefObject<HTMLButtonElement | null>;
  provider: HarnessId;
  onDesktopError: (cause: unknown) => void;
}) {
  const store = useSessionStore();
  const [accountOpen, setAccountOpen] = useState(false);
  const [identitySession, setIdentitySession] = useState<IdentitySession | null>(null);
  const identityClient = useMemo(() => createIdentityClient(optionalDesktopBridge()), []);
  const closeAccount = useCallback(() => setAccountOpen(false), []);

  useEffect(() => {
    let active = true;
    void identityClient.state().then((state) => {
      if (active) setIdentitySession(state.session);
    }, () => undefined);
    return () => { active = false; };
  }, [identityClient]);

  async function selectSession(id: string) {
    try {
      await store.navigate({ kind: "session-open", sessionId: id });
    } catch (cause) {
      onDesktopError(cause);
    }
  }

  async function createSession() {
    try {
      const summary = await store.create({ title: "新会话", provider, executor: provider });
      await store.navigate({ kind: "session-open", sessionId: summary.id });
    } catch (cause) {
      onDesktopError(cause);
    }
  }

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
        <div className="brand-title"><strong>Catomicals</strong></div>
        <button className="rail-close" type="button" onClick={onClose} aria-label="关闭会话栏" ref={closeButtonRef}><IconCloseOutline16 size={16} /></button>
      </div>

      <div className="rail-section session-section">
        <SessionList onSelectSession={(id) => void selectSession(id)} onCreateSession={() => void createSession()} />
      </div>

      <div className="rail-footer-actions">
        <button type="button" aria-label={identitySession?.displayName ?? "登录"} onClick={() => setAccountOpen(true)}><IconUserOutline16 size={15} /><span>{identitySession?.displayName ?? "登录"}</span></button>
        <Link to="/settings"><IconSettingsOutline16 size={15} /><span>设置</span></Link>
      </div>
      {accountOpen ? <AccountDialog client={identityClient} onSessionChange={setIdentitySession} onClose={closeAccount} /> : null}
    </aside>
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
  if (part.type === "text") return <MarkdownContent content={part.text} />;
  if (part.type === "ui_block") return <ControlledUiBlock block={part.block} />;
  if (part.type === "review_reference") {
    try {
      const reference = parseReviewReference(part.reference);
      return <div className="message-review-reference"><span>审查引用</span><code>{reference.review_id}</code></div>;
    } catch (cause) {
      return <div className="controlled-card-error"><IconWarningOutline16 size={14} />{cause instanceof Error ? cause.message : "审查引用无效"}</div>;
    }
  }
  if (part.type === "tool_call") return <div className="message-protocol-event"><span>调用工具</span><code>{part.tool_name}</code></div>;
  if (part.type === "tool_result") return <div className="message-protocol-event"><span>工具结果</span><code>{part.outcome}</code></div>;
  return <div className="controlled-card-error"><IconWarningOutline16 size={14} />{part.message}</div>;
}

/** A transcript message with its rendered label resolved. */
interface TranscriptMessageView extends SessionTranscriptMessage {
  label: string;
}

function AgentMessage({ message }: { message: TranscriptMessageView }) {
  return (
    <article className="chat-message" data-role={message.role}>
      <div className="message-meta">
        <strong>{message.label}</strong>
        {message.durationMs !== undefined ? <span className="turn-duration">{formatDuration(message.durationMs)}</span> : null}
        <time>{formatUnix(message.createdAt / 1000)}</time>
      </div>
      {message.failed ? (
        <div className="turn-failure" role="alert">
          <IconWarningOutline16 size={14} />
          <div>
            <strong>处理失败</strong>
            <span>{message.error}</span>
            {message.durationMs !== undefined ? <time>{formatDuration(message.durationMs)}</time> : null}
          </div>
        </div>
      ) : message.role === "user" ? (
        <div className="user-bubble"><p>{message.content}</p></div>
      ) : (
        <Fragment>
          {message.content ? <MarkdownContent content={message.content} /> : null}
          {message.parts?.map((part, index) => <MessagePart key={messagePartKey(part, index)} part={part} />)}
          {message.uiBlocks?.map((block) => <ControlledUiBlock key={block.block_id} block={block} />)}
        </Fragment>
      )}
    </article>
  );
}

/** Compact protocol row for a standalone tool/call or tool/result event. */
function ProtocolEventRow({ item }: { item: Extract<SessionTranscriptItem, { kind: "tool-call" | "tool-result" }> }) {
  const label = item.kind === "tool-call" ? "调用工具" : "工具结果";
  return (
    <div className="message-protocol-event" data-kind={item.kind}>
      <span>{label}</span>
      <code>{item.label}</code>
      {item.detail ? <small>{item.detail}</small> : null}
    </div>
  );
}

function ProcessingRow({ elapsedMs }: { elapsedMs: number }) {
  return (
    <div className="processing-row" role="status">
      <IconRefreshOutline16 className="spin" size={14} />
      <span>正在处理…</span>
      <time className="processing-elapsed">{formatDuration(elapsedMs)}</time>
    </div>
  );
}

function providerLabel(provider: HarnessId): string {
  return HARNESS_ADAPTERS.find((adapter) => adapter.id === provider)?.label ?? provider;
}

function ExecutorSelector({
  provider,
  onProviderChange,
  disabled,
}: {
  provider: HarnessId;
  onProviderChange: (provider: HarnessId) => void;
  disabled: boolean;
}) {
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
        onProviderChange(value.defaultHarness);
        setSettingsLoaded(true);
      },
      (cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : "无法读取执行器设置"); },
    );
    return () => { active = false; };
  }, [onProviderChange]);

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
      onProviderChange(next);
      return;
    }
    setError(null);
    try {
      await bridge.updateSettings({ version: 2, defaultHarness: next });
      onProviderChange(next);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法切换执行器");
    }
  }

  return (
    <div className="executor-selector">
      <label>
        <span className="sr-only">执行器</span>
        <select value={provider} disabled={disabled} onChange={(event) => void selectProvider(event.target.value as HarnessId)}>
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
  provider,
  changeProvider,
  onDesktopError,
}: {
  onOpenLeft: () => void;
  onOpenTools: () => void;
  backgroundInert: boolean;
  provider: HarnessId;
  changeProvider: (provider: HarnessId) => void;
  onDesktopError: (cause: unknown) => void;
}) {
  const store = useSessionStore();
  const currentSessionId = store.currentSessionId;
  const [events, setEvents] = useState<SessionEvent[]>([]);
  const [header, setHeader] = useState<SessionHeader | null>(null);
  const [loadingTranscript, setLoadingTranscript] = useState(false);
  const [transcriptError, setTranscriptError] = useState<string | null>(null);
  const [content, setContent] = useState("");
  const [sending, setSending] = useState(false);
  const [pending, setPending] = useState<{ startedAt: number } | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const transcriptRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const shouldFollowRef = useRef(true);
  const readySessionsRef = useRef(new Set<string>());
  const activeSessionIdRef = useRef(currentSessionId);
  const requestSequenceRef = useRef(0);
  const activeRequestRef = useRef<{ token: number; sessionId: string | null } | null>(null);
  activeSessionIdRef.current = currentSessionId;

  const starterPrompts = [
    "检查一笔交易",
    "查看钱包状态",
    "设计一个 covenant 发行方案",
  ] as const;

  const transcript = useMemo(() => buildSessionTranscript(events), [events]);
  const currentSummary = store.sessions?.find((summary) => summary.id === currentSessionId);
  const displayTitle = currentSessionId
    ? (currentSummary?.title ?? `会话 ${currentSessionId.slice(0, 8)}`)
    : "新会话";

  useEffect(() => {
    const request = activeRequestRef.current;
    if (!request || request.sessionId === currentSessionId) return;
    activeRequestRef.current = null;
    setSending(false);
    setPending(null);
    setElapsedMs(0);
  }, [currentSessionId]);

  useEffect(() => {
    if (!pending) return;
    const startedAt = pending.startedAt;
    const tick = () => setElapsedMs(Math.max(0, Date.now() - startedAt));
    tick();
    const timer = window.setInterval(tick, 1_000);
    return () => window.clearInterval(timer);
  }, [pending]);

  // Load the full persisted history whenever the selected session changes.
  useEffect(() => {
    if (!currentSessionId) {
      setEvents([]);
      setHeader(null);
      setTranscriptError(null);
      return;
    }
    let active = true;
    setLoadingTranscript(true);
    setTranscriptError(null);
    let bridge: DesktopBridge;
    try {
      bridge = requireDesktopBridge();
    } catch (cause) {
      setTranscriptError(cause instanceof Error ? cause.message : "桌面运行时不可用");
      setLoadingTranscript(false);
      return () => { active = false; };
    }
    void bridge.sessions.read(currentSessionId).then(
      (inspection) => {
        if (!active) return;
        setEvents([...inspection.events]);
        setHeader(inspection.meta);
      },
      (cause: unknown) => {
        if (!active) return;
        setEvents([]);
        setHeader(null);
        setTranscriptError(cause instanceof Error ? cause.message : String(cause));
      },
    ).finally(() => { if (active) setLoadingTranscript(false); });
    return () => { active = false; };
  }, [currentSessionId]);

  useEffect(() => {
    const transcript = transcriptRef.current;
    if (!transcript || !shouldFollowRef.current) return;
    transcript.scrollTo({ top: transcript.scrollHeight });
  }, [transcript.items.length, loadingTranscript]);

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

  /** Bind the persistent session to its native executor session (create or resume). */
  async function ensureExecutorSession(bridge: DesktopBridge, selectedProvider: HarnessId, sessionId: string): Promise<string> {
    if (!sessionId) throw new Error("没有打开的会话");
    const bindingKey = `${selectedProvider}:${sessionId}`;
    if (readySessionsRef.current.has(bindingKey)) return sessionId;
    const nativeSessionId = lastNativeSessionId(events);
    try {
      if (nativeSessionId) {
        const resumed = await bridge.resumeExecutorSession(selectedProvider, sessionId, nativeSessionId).catch(() => undefined);
        if (resumed) {
          readySessionsRef.current.add(bindingKey);
          return sessionId;
        }
      }
      const existing = await bridge.getExecutorStatus(sessionId);
      if (existing.provider !== selectedProvider) throw new Error("executor provider changed");
    } catch {
      await bridge.createExecutorSession(selectedProvider, sessionId);
    }
    readySessionsRef.current.add(bindingKey);
    return sessionId;
  }

  async function generateInitialTitle(
    bridge: DesktopBridge,
    sessionId: string,
    turn: number,
    startedAt: number,
  ): Promise<void> {
    const sessionsApi = bridge.sessions;
    let firstUserMessage: string;
    try {
      const before = (await sessionsApi.list()).find((summary) => summary.id === sessionId);
      if (before?.title !== "新会话") return;
      const inspection = await sessionsApi.read(sessionId);
      const firstUserEvent = inspection.events.find((event) => event.type === "user/message");
      const content = firstUserEvent?.data.content;
      if (typeof content !== "string" || !content.trim()) return;
      firstUserMessage = content;
    } catch {
      return;
    }

    const auxiliarySessionId = `${sessionId}-title-${turn}-${startedAt}`;
    let auxiliaryCreated = false;
    let title = fallbackSessionTitle(firstUserMessage);
    try {
      await bridge.createExecutorSession(provider, auxiliarySessionId);
      auxiliaryCreated = true;
      const result = await bridge.sendExecutorMessage(
        auxiliarySessionId,
        buildSessionTitlePrompt(firstUserMessage),
      );
      if (result.state === "completed") {
        const generated = normalizeGeneratedSessionTitle(
          executorAssistantResponse(provider, result.output).text,
        );
        if (generated) title = generated;
      }
    } catch {
      // Title generation is best-effort. The deterministic first-message title
      // below keeps the primary conversation independent from this auxiliary run.
    } finally {
      if (auxiliaryCreated) {
        await bridge.disposeExecutorSession(auxiliarySessionId).catch(() => undefined);
      }
    }

    try {
      const latest = (await sessionsApi.list()).find((summary) => summary.id === sessionId);
      if (latest?.title !== "新会话") return;
      await sessionsApi.rename(sessionId, title);
      await store.refresh();
    } catch {
      // A title failure must never surface as a failed chat turn.
    }
  }

  async function submit(event?: FormEvent) {
    event?.preventDefault();
    const clean = content.trim();
    if (!clean || sending) return;
    const bridge = requireDesktopBridge();
    const sessionsApi = bridge.sessions;
    let sessionId = currentSessionId;
    const requestToken = requestSequenceRef.current + 1;
    requestSequenceRef.current = requestToken;
    activeRequestRef.current = { token: requestToken, sessionId };
    const requestIsCurrent = () => activeRequestRef.current?.token === requestToken;
    const requestOwnsView = () => requestIsCurrent()
      && activeSessionIdRef.current === sessionId;
    setSending(true);
    setContent("");
    const startedAt = Date.now();

    // Auto-create a session when none is open (blank composer stays ready).
    let turn = transcript.lastTurn + 1;
    if (!sessionId) {
      try {
        const summary = await sessionsApi.create({ title: "新会话", provider, executor: provider });
        sessionId = summary.id;
        if (!requestIsCurrent()) return;
        activeRequestRef.current = { token: requestToken, sessionId };
        await store.navigate({ kind: "session-open", sessionId });
        if (!requestIsCurrent()) return;
        activeSessionIdRef.current = sessionId;
        const inspection = await sessionsApi.read(sessionId);
        if (requestOwnsView()) {
          setEvents([...inspection.events]);
          setHeader(inspection.meta);
        }
        turn = 1;
      } catch (cause) {
        if (requestIsCurrent()) {
          onDesktopError(cause);
          setSending(false);
          setContent(clean);
          activeRequestRef.current = null;
        }
        return;
      }
    }

    const initialHeader: Record<string, string> = { provider, executor: provider };
    if (header?.model) initialHeader.model = header.model;
    const userEvents: AppendableSessionEvent[] = [
      { type: "turn/start", time: startedAt, data: { turn } },
      { type: "user/message", time: startedAt, data: { content: clean } },
      {
        type: "request/header",
        time: startedAt,
        data: { header: initialHeader, reason: "initial" },
      },
    ];
    let assignedUser: SessionEvent[];
    try {
      assignedUser = await sessionsApi.append(sessionId, userEvents);
    } catch (cause) {
      if (requestOwnsView()) {
        onDesktopError(cause);
        setSending(false);
        setContent(clean);
        activeRequestRef.current = null;
      }
      return;
    }
    if (requestOwnsView()) {
      setEvents((current) => [...current, ...assignedUser]);
      setPending({ startedAt });
      scrollAfterSend();
    }

    const appendTurnEnd = async (eventsToAppend: AppendableSessionEvent[]): Promise<boolean> => {
      try {
        const assigned = await sessionsApi.append(sessionId, eventsToAppend);
        if (requestOwnsView()) setEvents((current) => [...current, ...assigned]);
        return true;
      } catch (cause) {
        if (requestOwnsView()) onDesktopError(cause);
        return false;
      }
    };

    try {
      const executorSessionId = await ensureExecutorSession(bridge, provider, sessionId);
      const result = await bridge.sendExecutorMessage(executorSessionId, clean);
      const durationMs = Date.now() - startedAt;
      if (result.state !== "completed") throw new Error(result.lastError ?? `执行器状态：${result.state}`);
      const response = executorAssistantResponse(provider, result.output);
      const uiBlockParts = response.uiBlocks.map((block) => ({ type: "ui_block", block: block as unknown as Record<string, unknown> }));
      const endEvents: AppendableSessionEvent[] = [
        ...(result.nativeSessionId
          ? [{
            type: "request/header",
            time: Date.now(),
            data: {
              header: {
                provider,
                ...(result.model ? { model: result.model } : {}),
                executor: provider,
                nativeSessionId: result.nativeSessionId,
              },
              reason: "resume",
            },
          } as AppendableSessionEvent]
          : []),
        {
          type: "assistant/message",
          time: Date.now(),
          data: {
            content: response.text,
            ...(uiBlockParts.length > 0 ? { parts: uiBlockParts } : {}),
            durationMs,
          },
        },
        { type: "turn/end", time: Date.now(), data: { turn, reason: { kind: "completed" }, durationMs } },
      ];
      const persisted = await appendTurnEnd(endEvents);
      if (persisted) {
        void generateInitialTitle(bridge, sessionId, turn, startedAt);
      }
    } catch (cause) {
      const durationMs = Date.now() - startedAt;
      const message = errorMessage(cause);
      await appendTurnEnd([
        {
          type: "assistant/message",
          time: Date.now(),
          data: {
            content: "",
            parts: [{ type: "error", code: "EXECUTOR_FAILED", message, retriable: true }],
            durationMs,
          },
        },
        {
          type: "turn/end",
          time: Date.now(),
          data: { turn, reason: { kind: "error", error: { message, code: "EXECUTOR_FAILED" } }, durationMs },
        },
      ]);
    } finally {
      if (requestOwnsView()) {
        setSending(false);
        setPending(null);
        setElapsedMs(0);
        activeRequestRef.current = null;
        inputRef.current?.focus();
        scrollAfterSend();
      }
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void submit();
    }
  }

  function useStarterPrompt(prompt: string) {
    setContent(prompt);
    inputRef.current?.focus();
  }

  const items = transcript.items;
  return (
    <main className="conversation-pane" aria-hidden={backgroundInert || undefined} inert={backgroundInert || undefined}>
      <header className="conversation-header">
        <button className="mobile-rail-button left-toggle" type="button" onClick={onOpenLeft} aria-label="打开会话栏"><IconPanelLeftOutline16 size={18} /></button>
        <div className="conversation-title">
          <strong data-testid="conversation-title">{displayTitle}</strong>
        </div>
        <button className="tool-area-toggle" type="button" onClick={onOpenTools} aria-label="打开工具区"><IconEnhanceOutline16 size={17} /></button>
      </header>

      <div className="conversation-scroll" onScroll={onTranscriptScroll} ref={transcriptRef} data-testid="conversation-scroll">
        <div className="conversation-width">
          {loadingTranscript ? <div className="conversation-loading"><IconRefreshOutline16 className="spin" size={16} />正在读取会话</div> : null}
          {transcriptError ? (
            <div className="conversation-error-card" role="alert">
              <IconWarningOutline16 size={17} />
              <div><strong>无法打开会话</strong><span>{transcriptError}</span></div>
            </div>
          ) : null}
          {!loadingTranscript && !transcriptError && items.length === 0 && !pending ? (
            <section className="conversation-empty" aria-label="常用任务">
              <h1>从一项钱包任务开始</h1>
              <p>直接描述目标，或从一个常用任务开始。</p>
              <div className="conversation-starters">
                {starterPrompts.map((prompt) => (
                  <button key={prompt} type="button" onClick={() => useStarterPrompt(prompt)}>
                    {prompt}
                  </button>
                ))}
              </div>
            </section>
          ) : null}
          {items.map((item: SessionTranscriptItem) => {
            if ("kind" in item) {
              return <ProtocolEventRow key={item.id} item={item} />;
            }
            const label = item.role === "user" ? "你" : providerLabel((item.provider ?? provider) as HarnessId);
            return <AgentMessage key={item.id} message={{ ...item, label }} />;
          })}
          {pending ? <ProcessingRow elapsedMs={elapsedMs} /> : null}
        </div>
      </div>

      <div className="composer-zone">
        <form className="composer" onSubmit={(event) => void submit(event)}>
          <textarea
            ref={inputRef}
            rows={2}
            maxLength={2_000}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder="向所选代理描述你要完成的任务……"
          />
          <div className="composer-footer">
            <ExecutorSelector provider={provider} onProviderChange={changeProvider} disabled={sending} />
            <button className="send-button" type="submit" disabled={!content.trim() || sending} aria-label="发送消息">
              {sending ? <IconRefreshOutline16 className="spin" size={17} /> : <IconSendOutline16 size={17} />}
            </button>
          </div>
        </form>
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
      <IconChevronRightOutline14 size={15} />
    </Link>
  );
}

function IntentsInspector() {
  const intents = useIntentsQuery();
  const list = intents.data ?? [];
  return (
    <div className="inspector-scroll">
      <div className="inspector-summary-line"><span>{list.filter((item) => item.status === "pending").length} 个待处理</span><button type="button" onClick={() => void intents.refetch()} aria-label="刷新签名意图"><IconRefreshOutline16 className={intents.isFetching ? "spin" : ""} size={14} />刷新</button></div>
      {intents.isError ? <p className="form-error"><IconWarningOutline16 size={14} />{intents.error.message}</p> : null}
      {intents.isPending ? <div className="panel-loading"><IconRefreshOutline16 className="spin" size={16} />读取签名意图</div> : null}
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
      <div className="boundary-note"><IconWarningOutline16 size={15} /><p><strong>当前为 Signet 研发设施</strong>进程内密钥和内存持久化不适合真实资产。部署前需要外部密钥存储、备份和恢复规范。</p></div>
      <Link className="secondary-link" to="/passkeys"><IconUserOutline16 size={15} />管理 Passkey<IconChevronRightOutline14 size={14} /></Link>
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
      <div className="boundary-note"><IconWarningOutline16 size={15} /><p><strong>无链上操作</strong>此入口目前只陈述研发状态，不会广播交易或创建资产。</p></div>
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
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserBack())} aria-label="后退"><IconChevronLeftOutline14 size={14} /></button>
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserForward())} aria-label="前进"><IconChevronRightOutline14 size={14} /></button>
        <button type="button" onClick={() => void runBrowserAction(() => requireDesktopBridge().browserReload())} aria-label="刷新"><IconRefreshOutline16 size={14} /></button>
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
      <button type="button" onClick={() => onSelect("browser")}><span><strong>浏览器</strong><small>在隔离页签查看公开网页</small></span><IconChevronRightOutline14 size={15} /></button>
      {starterActions.map((tool) => (
        <button key={tool.mode} type="button" onClick={() => onSelect(tool.mode)}>
          <span><strong>{pluginMeta[tool.mode].label}</strong><small>{tool.description}</small></span>
          <IconChevronRightOutline14 size={15} />
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
  const meta = activeTab ? toolMeta[activeTab] : { label: "工具", icon: IconEnhanceOutline16 };
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
        <div>{activeTab ? <button className="tool-back" type="button" onClick={onBack} aria-label="返回工具列表"><IconChevronLeftOutline14 size={15} /></button> : null}<strong>{meta.label}</strong>{plugin?.available === false ? <span className="inspector-mode-state">规划中</span> : null}</div>
        <button className="plugin-close" type="button" onClick={onClose} aria-label="关闭工具区" ref={closeButtonRef}><IconCloseOutline16 size={17} /></button>
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

function ToolDiscoveryRail({
  onOpen,
  triggerRef,
}: {
  onOpen: () => void;
  triggerRef: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <aside className="tool-discovery-rail" aria-label="工具区">
      <button ref={triggerRef} type="button" onClick={onOpen} aria-label="打开工具区" title="打开工具区">
        <IconEnhanceOutline16 size={18} />
      </button>
    </aside>
  );
}

function WorkbenchResizer({
  side,
  label,
  value,
  min,
  max,
  inert,
  onChange,
}: {
  side: "left" | "right";
  label: string;
  value: number;
  min: number;
  max: number;
  inert: boolean;
  onChange: (next: number) => void;
}) {
  const dragRef = useRef<{ startX: number; startValue: number } | null>(null);
  // The right pane is dragged from its left boundary, so pointer and arrow
  // motion mirror the left rail.
  const direction = side === "left" ? 1 : -1;

  function commit(next: number) {
    onChange(clampRailWidth(next, min, max));
  }

  function onPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
    dragRef.current = { startX: event.clientX, startValue: value };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  }

  function onPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const drag = dragRef.current;
    if (!drag) return;
    commit(drag.startValue + direction * (event.clientX - drag.startX));
  }

  function onPointerUp(event: ReactPointerEvent<HTMLDivElement>) {
    if (!dragRef.current) return;
    dragRef.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    let next: number | null = null;
    if (event.key === "ArrowLeft") next = value - direction * RAIL_KEYBOARD_STEP;
    else if (event.key === "ArrowRight") next = value + direction * RAIL_KEYBOARD_STEP;
    else if (event.key === "Home") next = min;
    else if (event.key === "End") next = max;
    if (next === null) return;
    event.preventDefault();
    commit(next);
  }

  return (
    <div
      className="workbench-resizer"
      data-side={side}
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      inert={inert || undefined}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onKeyDown={onKeyDown}
    />
  );
}

export function WalletWorkbench() {
  const [toolArea, setToolArea] = useState<ToolAreaState>(DEFAULT_TOOL_AREA);
  const [activeDrawer, setActiveDrawer] = useState<ActiveDrawer>(null);
  const [desktopError, setDesktopError] = useState<string | null>(null);
  const [provider, setProvider] = useState<HarnessId>(DEFAULT_HARNESS_ID);
  const [leftWidth, setLeftWidth] = useState<number>(() =>
    readRailWidth(LEFT_RAIL_WIDTH_KEY, LEFT_RAIL_DEFAULT, LEFT_RAIL_MIN, LEFT_RAIL_MAX));
  const [rightWidth, setRightWidth] = useState<number>(() =>
    readRailWidth(RIGHT_RAIL_WIDTH_KEY, RIGHT_RAIL_DEFAULT, RIGHT_RAIL_MIN, RIGHT_RAIL_MAX));
  const leftIsOverlay = useMediaQuery("(max-width: 760px)");
  const rightIsOverlay = useMediaQuery("(max-width: 1180px)");
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const toolDiscoveryRef = useRef<HTMLButtonElement | null>(null);
  const toolReturnFocusRef = useRef<HTMLButtonElement | null>(null);
  const leftRailRef = useRef<HTMLElement>(null);
  const rightRailRef = useRef<HTMLElement>(null);
  const leftCloseRef = useRef<HTMLButtonElement>(null);
  const rightCloseRef = useRef<HTMLButtonElement>(null);
  const toolBridgeQueueRef = useRef<{ bridge: DesktopBridge; queue: ToolAreaBridgeQueue } | null>(null);

  // The executor provider is shell-wide state: bound into every new session's
  // header and used by the composer's ExecutorSelector. Persisted via settings.
  const changeProvider = useCallback((next: HarnessId) => setProvider(next), []);
  useEffect(() => {
    let active = true;
    const bridge = optionalDesktopBridge();
    if (!bridge) return () => { active = false; };
    void bridge.getSettings().then(
      (settings) => { if (active) setProvider(settings.defaultHarness); },
      () => undefined,
    );
    return () => { active = false; };
  }, []);

  useEffect(() => { writeRailWidth(LEFT_RAIL_WIDTH_KEY, leftWidth); }, [leftWidth]);
  useEffect(() => { writeRailWidth(RIGHT_RAIL_WIDTH_KEY, rightWidth); }, [rightWidth]);

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

  const restoreToolFocus = useCallback(() => {
    requestAnimationFrame(() => {
      const returnTarget = toolReturnFocusRef.current?.isConnected
        ? toolReturnFocusRef.current
        : toolDiscoveryRef.current;
      returnTarget?.focus();
    });
  }, []);

  const closeToolArea = useCallback(() => {
    setToolArea((current) => transitionToolArea(current, { type: "close" }));
    runToolBridgeAction((queue) => queue.closeTools());
    if (activeDrawer === "right") {
      setActiveDrawer((current) => transitionDrawer(current, "close"));
    }
    restoreToolFocus();
  }, [activeDrawer, restoreToolFocus, runToolBridgeAction]);

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
    if (!toolArea.open && document.activeElement instanceof HTMLButtonElement) {
      toolReturnFocusRef.current = document.activeElement;
    }
    setToolArea((current) => transitionToolArea(current, { type: "expand" }));
    if (rightIsOverlay) openDrawer("right");
  }

  function selectTool(next: ToolTab) {
    if (!toolArea.open && document.activeElement instanceof HTMLButtonElement) {
      toolReturnFocusRef.current = document.activeElement;
    }
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
    <div className="app-frame">
      <div
        className="workbench-shell"
        data-left-open={activeDrawer === "left"}
        data-right-open={activeDrawer === "right"}
        data-tools-open={toolArea.open}
        style={{ "--left-rail": `${leftWidth}px`, "--right-rail": `${rightWidth}px` } as CSSProperties}
      >
        <div className="drawer-backdrop" onClick={dismissOverlay} aria-hidden="true" />
        {desktopError ? <div className="desktop-error" role="alert"><IconWarningOutline16 size={14} /><span>{desktopError}</span><button type="button" onClick={() => setDesktopError(null)} aria-label="关闭错误"><IconCloseOutline16 size={13} /></button></div> : null}
        <LeftRail
          onClose={closeDrawer}
          active={activeDrawer === "left"}
          backgroundInert={(leftIsOverlay && activeDrawer !== "left") || activeDrawer === "right"}
          railRef={leftRailRef}
          closeButtonRef={leftCloseRef}
          provider={provider}
          onDesktopError={reportDesktopBridgeError}
        />
        {!leftIsOverlay ? (
          <WorkbenchResizer
            side="left"
            label="调整左侧栏宽度"
            value={leftWidth}
            min={LEFT_RAIL_MIN}
            max={LEFT_RAIL_MAX}
            inert={activeDrawer !== null}
            onChange={setLeftWidth}
          />
        ) : null}
        <Conversation
          onOpenLeft={() => openDrawer("left")}
          onOpenTools={openTools}
          backgroundInert={activeDrawer !== null}
          provider={provider}
          changeProvider={changeProvider}
          onDesktopError={reportDesktopBridgeError}
        />
        {toolArea.open ? (
          <Fragment>
            {!rightIsOverlay ? (
              <WorkbenchResizer
                side="right"
                label="调整工具区宽度"
                value={rightWidth}
                min={RIGHT_RAIL_MIN}
                max={RIGHT_RAIL_MAX}
                inert={activeDrawer !== null}
                onChange={setRightWidth}
              />
            ) : null}
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
          </Fragment>
        ) : <ToolDiscoveryRail onOpen={openTools} triggerRef={toolDiscoveryRef} />}
      </div>
    </div>
  );
}
