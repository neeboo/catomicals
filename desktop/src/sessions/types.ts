/**
 * Catomicals session domain types.
 *
 * The model deliberately reuses the DeepSeek Harness session architecture
 * (see the final summary for exact DSH sources): an append-only JSONL event
 * log per session whose first line is an immutable header, mutable metadata
 * (title, archive state) folded from log events, and a derived SQLite FTS5
 * search index. Provider/model/executor identity lives in session metadata.
 * Wallet state is NEVER stored here — wallet actions stay MCP/executor tools.
 *
 * @module catomicals-desktop/sessions/types
 */

/** Identifies one session in the store and its persistence artifacts. */
export type SessionId = string & { readonly __catomicalsSessionId: unique symbol };

/** Brand a string as a {@link SessionId} (compile-time cast, no runtime cost). */
export function SessionId(value: string): SessionId {
  return value as SessionId;
}

/** Accepted session id shape used at every IPC boundary (uuid or slug). */
export const SESSION_ID_PATTERN = /^[a-zA-Z0-9_-]{1,80}$/;

/** The on-disk session format version, stamped into every written header. */
export const SESSION_FORMAT_VERSION = 1;

/** Known executor providers (mirrors desktop/src/contracts.ts HarnessId). */
export const EXECUTOR_IDS = ["codex", "deepseek", "claude-code"] as const;
export type ExecutorId = (typeof EXECUTOR_IDS)[number];

/**
 * Immutable validated storage metadata, kept in the JSONL header line and
 * never rewritten. Mutable presentation metadata (title, archive state) is
 * folded from log events so the canonical log stays append-only.
 */
export interface SessionHeader {
  /** On-disk format version; a backend rejects any other version on load. */
  readonly version: number;
  /** The session's id (mirrors the store's id). */
  readonly id: SessionId;
  /** Non-negative safe-integer Unix epoch milliseconds at creation. */
  readonly createdAt: number;
  /** Absolute working directory the session was created in, if any. */
  readonly cwd?: string;
  /** The session this one was forked from (seed lineage), if any. */
  readonly parentSession?: SessionId;
  /** How many leading events were inherited through a seed. */
  readonly seedLength?: number;
  /** Executor provider identity that owns this session. */
  readonly provider?: string;
  /** Provider-owned model id used by this session. */
  readonly model?: string;
  /** Executor adapter identity (e.g. the HarnessId) when distinct from provider. */
  readonly executor?: string;
  /** Coarse product classification for a session created as a subagent child. */
  readonly origin?: "subagent";
  /** Delegation depth: absent (zero) for top-level sessions. */
  readonly delegationDepth?: number;
  /** Id of the agent preset this session's agent was composed from. */
  readonly agentPreset?: string;
}

/** Mutable metadata folded from the latest `session/title` event. */
export interface SessionTitleState {
  readonly title?: string;
}

/** Mutable metadata folded from the latest `session/archive` event. */
export interface SessionArchiveState {
  readonly archived: boolean;
}

/** One entry in an agent's todo list (whole-list snapshot semantics). */
export interface TodoItem {
  readonly content: string;
  readonly status: "pending" | "in_progress" | "completed";
}

/** Why a turn ended. */
export type TurnEndReason =
  | { kind: "completed" }
  | { kind: "aborted"; reason?: { kind: "user" | "parent" | "hook" | "disposed" | "legacy"; hookReason?: string } }
  | { kind: "error"; error: { message: string; code: string } }
  | { kind: "max-tokens" }
  | { kind: "interrupted" };

/** Token usage reported by an executor adapter, when any. */
export interface TokenUsage {
  readonly input?: number;
  readonly output?: number;
  readonly total?: number;
  readonly cacheRead?: number;
  readonly cacheWrite?: number;
}

/** Request-level route snapshot for a `request/header` event. */
export interface RequestHeaderSnapshot {
  readonly provider: string;
  readonly model: string;
  readonly executor?: string;
  /** Native executor session id (e.g. a Codex thread id) for resume. */
  readonly nativeSessionId?: string;
  readonly config?: {
    readonly reasoningEffort?: string;
    readonly temperature?: number;
    readonly maxTokens?: number;
  };
}

/** Why a `request/header` event was appended. */
export type RequestHeaderReason = "initial" | "resume" | "change";

/** Tool outcome for a `tool/result` event. */
export type ToolOutcome = "succeeded" | "failed" | "cancelled";

/** Structured tool failure attached to a `tool/result`. */
export interface ToolError {
  readonly name?: string;
  readonly code: string;
  readonly message?: string;
}

/** JSON-safe opaque payload (mirrors the DSH lossless-JSON gate). */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

// --- Message parts (mirror web/src/lib/types.ts ChatMessagePart over IPC) ---

/** Controlled UI reference stored with a message (schema 1, web-canonical). */
export interface SessionUiBlockReference {
  readonly schema_version: 1;
  readonly block_id: string;
  readonly component: string;
  readonly data_bindings: ReadonlyArray<{
    readonly slot: string;
    readonly source: string;
    readonly reference_kind: string;
    readonly reference_id: string;
  }>;
  readonly action_bindings: readonly unknown[];
}

/** Review reference stored with a message (schema 1, web-canonical). */
export interface SessionReviewReference {
  readonly schema_version: 1;
  readonly review_id: string;
  readonly kind: string;
  readonly source: string;
  readonly review_digest: string;
  readonly created_at: string;
  readonly state: string;
  readonly valid_until?: string;
  readonly intent_id?: string;
  readonly policy_hash?: string;
  readonly node_snapshot_id?: string;
  readonly plugin_id?: string;
  readonly plugin_version?: string;
}

export type SessionMessagePart =
  | { type: "text"; text: string }
  | {
    type: "tool_call";
    tool_call_id: string;
    tool_name: string;
    request_digest: string;
    permission_scope: string;
    intent_id?: string;
    review_id?: string;
  }
  | {
    type: "tool_result";
    tool_call_id: string;
    outcome: ToolOutcome;
    result_digest?: string;
    intent_id?: string;
    review_id?: string;
  }
  | { type: "ui_block"; block: SessionUiBlockReference }
  | { type: "review_reference"; reference: SessionReviewReference }
  | { type: "error"; code: string; message: string; retriable: boolean };

// --- Events ---

/** The appendable event-type keys, merge-extensible. */
export interface SessionEventMap {
  "turn/start": { turn: number };
  "turn/end": { turn: number; reason: TurnEndReason; durationMs?: number };
  "user/message": { content: string; parts?: SessionMessagePart[] };
  "assistant/message": {
    content: string;
    parts?: SessionMessagePart[];
    interrupted?: true;
    usage?: TokenUsage;
    durationMs?: number;
  };
  "assistant/chunk": { delta: string };
  "tool/call": { callId: string; name: string; arguments: string; permissionScope?: string };
  "tool/result": {
    callId: string;
    outcome: ToolOutcome;
    error?: ToolError;
    resultDigest?: string;
    meta?: JsonValue;
  };
  "request/header": { header: RequestHeaderSnapshot; reason: RequestHeaderReason };
  /** Mutable rename metadata; the latest event wins on read. */
  "session/title": { title: string };
  /** Mutable archive state; the latest event wins on read. */
  "session/archive": { archived: boolean };
  "todo/write": { todos: TodoItem[] };
  /** Marks the end of a constructor seed (resume/fork). */
  "session/end-seed": Record<string, never>;
}

/** The appendable event-type keys of {@link SessionEventMap}. */
export type SessionEventType = keyof SessionEventMap;

/** Event types that produce model-visible messages on the ordered surface. */
export type SurfaceEventType = "user/message" | "assistant/message" | "tool/result";

/** How a surface event entered the ordered surface. */
export type SurfaceOp = "append" | { op: "replace"; start: number; end: number };

/**
 * One immutable entry in the session log — the DSH envelope (type/seq/time/data
 * plus conditional surface metadata) applied to the Catomicals event map.
 */
export type SessionEvent<T extends SessionEventType = SessionEventType> = {
  [K in SessionEventType]: {
    type: K;
    /** Monotonic sequence number within the session (contiguous from 0). */
    seq: number;
    /** Unix epoch milliseconds. */
    time: number;
    data: SessionEventMap[K];
    /** Purely informational record a reader may skip when `type` is unknown. */
    ignorable?: true;
  } & (K extends SurfaceEventType ? {
    sourceEventSeqs?: number[];
    surfaceOp?: SurfaceOp;
  } : object);
}[T];

/** A validated detached observation of a session's complete raw log. */
export interface SessionInspection {
  /** Cloned session header from the same observation as `events`. */
  readonly meta: SessionHeader;
  /** Cloned contiguous raw events after repair and validation. */
  readonly events: readonly SessionEvent[];
}

/** One stored session's metadata plus stat-derived revision. */
export interface SessionPersistenceSnapshot {
  readonly header: SessionHeader;
  /** Source-qualified revision identifying the exact stored prefix. */
  readonly revision: string;
}

/** Lightweight summary returned by `list()` — folded from header + log tail. */
export interface SessionSummary {
  readonly id: SessionId;
  readonly title?: string;
  readonly archived: boolean;
  readonly provider?: string;
  readonly model?: string;
  readonly executor?: string;
  readonly createdAt: number;
  /** Time of the last event, or createdAt for an empty log. */
  readonly updatedAt: number;
  /** Event count (last seq + 1), or 0 for an empty log. */
  readonly eventCount: number;
  /** Latest turn error, when the most recent turn failed. */
  readonly lastError?: { message: string; code: string };
}

/** A trash entry produced by recoverable delete. */
export interface TrashEntry {
  readonly id: SessionId;
  readonly deletedAt: number;
  readonly originalCwd?: string;
  readonly title?: string;
}

/** Event-metadata filter kinds shared by cross-session and within-session search. */
export type SessionEventMetadataFilter =
  | ({ kind: "seq" } & SessionResultRange)
  | ({ kind: "time" } & SessionResultRange)
  | { kind: "type"; values: readonly SessionEventType[] }
  | { kind: "surface"; values: readonly SessionEventSurface[] };

/** Event placement in the folded session surface. */
export type SessionEventSurface = "current" | "shadowed" | "log-only";

/** Inclusive numeric interval used by time and sequence filters. */
export interface SessionResultRange {
  readonly from?: number;
  readonly to?: number;
}

/** Source availability predicates understood by logical-session filters. */
export type SessionAvailability = "live" | "persisted";

/** One logical-session predicate; a filter array is ANDed, `values` ORed. */
export type SessionResultFilter =
  | { kind: "id"; values: readonly SessionId[] }
  | { kind: "cwd"; values: readonly (string | null)[] }
  | ({ kind: "created-at" } & SessionResultRange)
  | { kind: "parent"; values: readonly (SessionId | null)[] }
  | { kind: "availability"; values: readonly SessionAvailability[] }
  | { kind: "provider"; values: readonly string[] }
  | { kind: "model"; values: readonly string[] }
  | { kind: "executor"; values: readonly string[] }
  | { kind: "archived"; values: readonly boolean[] };

/** Opaque continuation cursor returned by search pages. */
export type SessionSearchCursor = string & { readonly __catomicalsSearchCursor: unique symbol };

/** One cursor-paginated result page. */
export interface SessionSearchPage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: SessionSearchCursor;
}

/** One event full-text search hit with a bounded plain-text excerpt. */
export interface SessionEventSearchHit {
  readonly sessionId: SessionId;
  readonly seq: number;
  readonly type: SessionEventType;
  readonly time: number;
  readonly surface: SessionEventSurface;
  readonly snippet: string;
}

/** One grouped cross-session hit, ranked by its strongest matching event. */
export interface SessionSearchHit {
  readonly header: SessionHeader;
  readonly live: boolean;
  readonly persisted: boolean;
  readonly bestMatch: SessionEventSearchHit;
}

/** Event-search results bound to the indexed target-session observation. */
export interface SessionEventSearchPage extends SessionSearchPage<SessionEventSearchHit> {
  readonly session: SessionHeader;
}

/** Cross-session full-text search request. */
export interface SessionSearchRequest {
  /** Full-text query interpreted as data, never executable FTS syntax. */
  readonly query: string;
  readonly sessionFilters?: readonly SessionResultFilter[];
  readonly eventFilters?: readonly SessionEventMetadataFilter[];
  readonly limit?: number;
  readonly cursor?: SessionSearchCursor;
}

/** Within-session full-text search request. */
export interface SessionEventSearchRequest {
  readonly sessionId: SessionId;
  readonly query: string;
  readonly filters?: readonly SessionEventMetadataFilter[];
  readonly limit?: number;
  readonly cursor?: SessionSearchCursor;
}

/** Searchable semantic document derived from one session event. */
export interface SessionEventSearchDocument {
  readonly sessionId: SessionId;
  readonly seq: number;
  readonly type: SessionEventType;
  readonly time: number;
  readonly surface: SessionEventSurface;
  readonly text: string;
}

/** Navigation event pushed to the renderer and emitted by the manager. */
export interface CatomicalsNavigationEvent {
  readonly kind: "session-open" | "session-list";
  readonly sessionId?: SessionId;
  readonly source: "deeplink" | "app";
  readonly at: number;
}
