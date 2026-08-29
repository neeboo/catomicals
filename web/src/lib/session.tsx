/**
 * Web session store: typed client over the desktop session bridge plus a React
 * store that mirrors DSH's renderer session binding (session-provider.tsx):
 * current-session identity, the session list, search, and deeplink-driven
 * navigation events. All persistence lives in the desktop main process under
 * append-only JSONL; this module holds no component-only memory.
 *
 * @module catomicals-wallet-web/session
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  optionalDesktopBridge,
  requireDesktopBridge,
  type CatomicalsNavigationEvent,
  type CreateSessionInput,
  type DesktopBridge,
  type SessionBridgeApi,
  type SessionEventSearchHit,
  type SessionEventSearchRequest,
  type SessionHeader,
  type SessionInspection,
  type SessionSearchHit,
  type SessionSearchPage,
  type SessionSearchRequest,
  type SessionSummary,
  type TrashEntry,
} from "./desktop";

export type {
  AppendableSessionEvent,
  CatomicalsNavigationEvent,
  CreateSessionInput,
  SessionBridgeApi,
  SessionEvent,
  SessionEventSearchHit,
  SessionEventSearchRequest,
  SessionHeader,
  SessionInspection,
  SessionSearchHit,
  SessionSearchPage,
  SessionSearchRequest,
  SessionSummary,
  TrashEntry,
} from "./desktop";

/** Resolve the session bridge from the trusted preload surface (fails closed). */
export function sessionBridge(bridge?: SessionBridgeApi): SessionBridgeApi {
  const candidate = bridge ?? optionalDesktopBridge()?.sessions;
  if (!candidate) throw new Error("session store unavailable: desktop runtime not connected");
  return candidate;
}

/** A short human title for a session summary. */
export function sessionDisplayTitle(summary: Pick<SessionSummary, "id" | "title">): string {
  return summary.title?.trim() || `会话 ${summary.id.slice(0, 8)}`;
}

/** Format a session timestamp as a compact relative label. */
export function formatSessionTime(updatedAt: number, now: number = Date.now()): string {
  const delta = Math.max(0, now - updatedAt);
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} 天前`;
  return new Date(updatedAt).toLocaleDateString();
}

/** Navigation target accepted by the store. */
export type SessionNavigationTarget =
  | { kind: "session-open"; sessionId: string }
  | { kind: "session-list" };

/** What the store exposes to consumers. */
export interface SessionStoreValue {
  /** Latest session list, or undefined while loading. */
  sessions: SessionSummary[] | undefined;
  /** Currently open session id (from app selection or deeplink navigation). */
  currentSessionId: string | null;
  /** The most recent navigation event (deeplink or app), if any. */
  lastNavigation: CatomicalsNavigationEvent | null;
  /** Loading/error state for the last list operation. */
  loading: boolean;
  error: string | null;
  refresh(): Promise<void>;
  create(input?: CreateSessionInput): Promise<SessionSummary>;
  openSession(id: string): Promise<void>;
  closeSession(id: string): Promise<void>;
  /** Read a session's full history from the desktop SessionManager. */
  readSession(id: string): Promise<SessionInspection>;
  rename(id: string, title: string): Promise<SessionSummary>;
  setArchived(id: string, archived: boolean): Promise<SessionSummary>;
  remove(id: string): Promise<TrashEntry>;
  restore(id: string, deletedAt: number): Promise<SessionSummary>;
  purge(id: string, deletedAt: number): Promise<void>;
  listTrash(): Promise<TrashEntry[]>;
  search(request: SessionSearchRequest): Promise<SessionSearchPage<SessionSearchHit>>;
  searchEvents(request: SessionEventSearchRequest): Promise<SessionSearchPage<SessionEventSearchHit> & { session: SessionHeader }>;
  navigate(target: SessionNavigationTarget): Promise<void>;
}

const SessionStoreContext = createContext<SessionStoreValue | null>(null);

/**
 * Root provider: owns the session list, the current session id, and the
 * deeplink navigation subscription. Navigation events from the desktop
 * (`catomicals://session/<id>` open-url / second-instance) update
 * `currentSessionId` and `lastNavigation`.
 */
export function SessionStoreProvider({
  bridge,
  children,
}: {
  bridge?: DesktopBridge;
  children: ReactNode;
}) {
  const desktop = useMemo(() => bridge ?? optionalDesktopBridge(), [bridge]);
  // The store is desktop-backed; in a browser-only context the bridge is
  // absent and every session operation fails closed with a clear error.
  const api = useMemo(() => desktop?.sessions, [desktop]);
  const [sessions, setSessions] = useState<SessionSummary[] | undefined>(undefined);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [lastNavigation, setLastNavigation] = useState<CatomicalsNavigationEvent | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!api) {
      setError("会话存储不可用：未连接桌面运行时");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setSessions(await api.list());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Subscribe to desktop-driven navigation (deeplinks) once. The subscription
  // lives on the top-level bridge, not the sessions namespace.
  useEffect(() => {
    const subscribe = desktop?.onSessionNavigation;
    if (!subscribe) return;
    let active = true;
    const unsubscribe = subscribe((event) => {
      if (!active) return;
      setLastNavigation(event);
      if (event.kind === "session-open" && event.sessionId) setCurrentSessionId(event.sessionId);
      if (event.kind === "session-list") setCurrentSessionId(null);
    });
    return () => {
      active = false;
      unsubscribe?.();
    };
  }, [desktop]);

  const requireApi = useCallback((): SessionBridgeApi => {
    if (!api) throw new Error("会话存储不可用：未连接桌面运行时");
    return api;
  }, [api]);

  const value = useMemo<SessionStoreValue>(() => ({
    sessions,
    currentSessionId,
    lastNavigation,
    loading,
    error,
    refresh,
    create: async (input = {}) => {
      const summary = await requireApi().create(input);
      await refresh();
      return summary;
    },
    openSession: async (id) => {
      await requireApi().read(id);
      setCurrentSessionId(id);
    },
    readSession: (id) => requireApi().read(id),
    closeSession: async (id) => {
      setCurrentSessionId(previous => previous === id ? null : previous);
      await refresh();
    },
    rename: async (id, title) => {
      const summary = await requireApi().rename(id, title);
      await refresh();
      return summary;
    },
    setArchived: async (id, archived) => {
      const summary = await requireApi().setArchived(id, archived);
      await refresh();
      return summary;
    },
    remove: async (id) => {
      const entry = await requireApi().remove(id);
      setCurrentSessionId(previous => previous === id ? null : previous);
      await refresh();
      return entry;
    },
    restore: async (id, deletedAt) => {
      const summary = await requireApi().restore(id, deletedAt);
      await refresh();
      return summary;
    },
    purge: async (id, deletedAt) => {
      await requireApi().purge(id, deletedAt);
      await refresh();
    },
    listTrash: () => requireApi().listTrash(),
    search: (request) => requireApi().search(request),
    searchEvents: (request) => requireApi().searchEvents(request),
    navigate: async (target) => {
      await requireApi().navigate(target);
      if (target.kind === "session-open") setCurrentSessionId(target.sessionId);
      else setCurrentSessionId(null);
    },
  }), [sessions, currentSessionId, lastNavigation, loading, error, refresh, requireApi]);

  return <SessionStoreContext.Provider value={value}>{children}</SessionStoreContext.Provider>;
}

/** Read the session store; throws outside a provider. */
export function useSessionStore(): SessionStoreValue {
  const value = useContext(SessionStoreContext);
  if (value === null) throw new Error("useSessionStore must be used inside SessionStoreProvider");
  return value;
}

/** The current session list (undefined while loading). */
export function useSessionList(): SessionSummary[] | undefined {
  return useSessionStore().sessions;
}

/** The currently open session id (from selection or deeplink). */
export function useCurrentSessionId(): string | null {
  return useSessionStore().currentSessionId;
}

/** The most recent navigation event (deeplink or app), if any. */
export function useSessionNavigation(): CatomicalsNavigationEvent | null {
  return useSessionStore().lastNavigation;
}

/** Parse a `catomicals://session/<id>` URL string in the renderer (mirror of desktop deeplink.ts). */
export function parseSessionDeeplink(raw: string): { kind: "session-open"; sessionId: string } | { kind: "session-list" } | undefined {
  const url = raw.trim();
  const withoutScheme = url.replace(/^catomicals:\/\//i, "").replace(/^\/+/, "").replace(/\/+$/, "");
  if (withoutScheme === "sessions") return { kind: "session-list" };
  if (withoutScheme.startsWith("session/")) {
    const sessionId = withoutScheme.slice("session/".length).split("?")[0];
    if (/^[a-zA-Z0-9_-]{1,80}$/.test(sessionId)) return { kind: "session-open", sessionId };
  }
  return undefined;
}

/** Require the desktop bridge for direct (non-provider) callers. */
export function requireSessionBridge(): SessionBridgeApi {
  return requireDesktopBridge().sessions;
}
