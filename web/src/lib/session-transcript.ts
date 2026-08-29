/**
 * Session transcript model: folds the append-only JSONL event log of one
 * persistent session into the ordered conversation surface the chat shell
 * renders. This is the renderer-side reconstruction used on reload/reopen —
 * the canonical history always comes from the desktop SessionManager, never
 * from React-only state.
 *
 * @module catomicals-wallet-web/session-transcript
 */

import type {
  SessionEvent,
  SessionHeader,
  SessionMessagePart,
} from "./desktop";
import type { AgentUiBlockReference, ChatReviewReference } from "./ui-block";
import type { ChatMessagePart } from "./types";

/** A closed or still-open turn, folded from turn/start + turn/end events. */
export interface SessionTranscriptTurn {
  readonly turn: number;
  readonly startedAt: number;
  readonly endedAt?: number;
  readonly durationMs?: number;
  readonly status: "open" | "completed" | "error" | "aborted" | "max-tokens" | "interrupted";
  readonly error?: { message: string; code: string };
}

/** One rendered conversation message (user right / agent left). */
export interface SessionTranscriptMessage {
  readonly id: string;
  readonly role: "user" | "agent";
  readonly content: string;
  readonly parts?: ChatMessagePart[];
  readonly createdAt: number;
  readonly durationMs?: number;
  readonly failed?: boolean;
  readonly error?: string;
  readonly uiBlocks?: AgentUiBlockReference[];
  /** Provider/model from the most recent request/header event, when any. */
  readonly provider?: string;
  readonly model?: string;
  readonly turn?: number;
}

/** A compact protocol event row (tool call / tool result) between messages. */
export interface SessionTranscriptProtocolEvent {
  readonly id: string;
  readonly kind: "tool-call" | "tool-result";
  readonly label: string;
  readonly detail: string;
  readonly createdAt: number;
  readonly turn?: number;
}

export type SessionTranscriptItem = SessionTranscriptMessage | SessionTranscriptProtocolEvent;

/** The folded transcript of one session log. */
export interface SessionTranscript {
  readonly items: readonly SessionTranscriptItem[];
  readonly turns: readonly SessionTranscriptTurn[];
  /** Highest turn number seen (next turn starts at lastTurn + 1). */
  readonly lastTurn: number;
}

const MAX_PROTOCOL_DETAIL = 120;

/** Map a stored part to the renderer's message-part model (structural cast). */
export function sessionPartsToWeb(parts: readonly SessionMessagePart[] | undefined): ChatMessagePart[] | undefined {
  if (!parts || parts.length === 0) return undefined;
  return parts.map((part) => {
    switch (part.type) {
      case "text":
        return { type: "text", text: part.text };
      case "tool_call":
        return {
          type: "tool_call",
          tool_call_id: part.tool_call_id,
          tool_name: part.tool_name,
          request_digest: part.request_digest,
          permission_scope: part.permission_scope,
          ...(part.intent_id !== undefined ? { intent_id: part.intent_id } : {}),
          ...(part.review_id !== undefined ? { review_id: part.review_id } : {}),
        } as ChatMessagePart;
      case "tool_result":
        return {
          type: "tool_result",
          tool_call_id: part.tool_call_id,
          outcome: part.outcome,
          ...(part.result_digest !== undefined ? { result_digest: part.result_digest } : {}),
          ...(part.intent_id !== undefined ? { intent_id: part.intent_id } : {}),
          ...(part.review_id !== undefined ? { review_id: part.review_id } : {}),
        } as ChatMessagePart;
      case "ui_block":
        return { type: "ui_block", block: part.block as unknown as AgentUiBlockReference };
      case "review_reference":
        return { type: "review_reference", reference: part.reference as unknown as ChatReviewReference };
      case "error":
        return { type: "error", code: part.code, message: part.message, retriable: part.retriable };
      default:
        return { type: "error", code: "UNKNOWN_PART", message: "未知消息片段", retriable: false };
    }
  });
}

/** Extract UI-block references from an assistant message's stored parts. */
export function sessionUiBlocks(parts: readonly SessionMessagePart[] | undefined): AgentUiBlockReference[] | undefined {
  const blocks = parts
    ?.filter((part): part is Extract<SessionMessagePart, { type: "ui_block" }> => part.type === "ui_block")
    .map((part) => part.block as unknown as AgentUiBlockReference);
  return blocks && blocks.length > 0 ? blocks : undefined;
}

function truncate(value: string): string {
  return value.length > MAX_PROTOCOL_DETAIL ? `${value.slice(0, MAX_PROTOCOL_DETAIL)}…` : value;
}

/**
 * Fold a session's raw event log into the ordered transcript surface.
 * Events are expected to be seq-contiguous (the backend guarantees it); the
 * builder is defensive about ordering anyway.
 */
export function buildSessionTranscript(events: readonly SessionEvent[]): SessionTranscript {
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  const items: SessionTranscriptItem[] = [];
  const turns: SessionTranscriptTurn[] = [];
  const turnById = new Map<number, SessionTranscriptTurn>();
  const lastMessageByTurn = new Map<number, SessionTranscriptMessage>();
  let openTurn: SessionTranscriptTurn | null = null;
  let lastRequest: { provider?: string; model?: string; executor?: string } | null = null;
  let lastTurn = 0;

  for (const event of sorted) {
    switch (event.type) {
      case "turn/start": {
        const data = event.data as { turn: number };
        const turn: SessionTranscriptTurn = { turn: data.turn, startedAt: event.time, status: "open" };
        openTurn = turn;
        turns.push(turn);
        turnById.set(turn.turn, turn);
        lastTurn = Math.max(lastTurn, turn.turn);
        break;
      }
      case "turn/end": {
        const data = event.data as { turn: number; reason: { kind: string; error?: { message: string; code: string } }; durationMs?: number };
        const turn = turnById.get(data.turn) ?? openTurn;
        if (turn) {
          const status = data.reason.kind === "error"
            ? "error"
            : data.reason.kind === "completed"
              ? "completed"
              : data.reason.kind as SessionTranscriptTurn["status"];
          const durationMs = data.durationMs ?? (turn.endedAt !== undefined ? turn.endedAt - turn.startedAt : undefined);
          const error = data.reason.kind === "error" ? data.reason.error : undefined;
          Object.assign(turn, {
            endedAt: event.time,
            durationMs,
            status,
            ...(error ? { error } : {}),
          });
          const last = lastMessageByTurn.get(data.turn);
          if (last && !last.failed && status === "error") {
            Object.assign(last, {
              failed: true,
              error: error?.message ?? "执行器处理失败",
              durationMs: last.durationMs ?? durationMs,
            });
          } else if (last && last.durationMs === undefined && durationMs !== undefined) {
            Object.assign(last, { durationMs });
          }
          if (openTurn?.turn === data.turn) openTurn = null;
        }
        break;
      }
      case "user/message": {
        const data = event.data as { content: string; parts?: SessionMessagePart[] };
        const parts = sessionPartsToWeb(data.parts);
        items.push({
          id: `msg-${event.seq}`,
          role: "user",
          content: data.content,
          ...(parts ? { parts } : {}),
          createdAt: event.time,
          ...(openTurn ? { turn: openTurn.turn } : {}),
        });
        break;
      }
      case "assistant/message": {
        const data = event.data as {
          content: string;
          parts?: SessionMessagePart[];
          interrupted?: true;
          durationMs?: number;
        };
        const parts = sessionPartsToWeb(data.parts);
        const uiBlocks = sessionUiBlocks(data.parts);
        const failed = data.interrupted === true
          || parts?.some((part) => part.type === "error") === true;
        const errorPart = parts?.find((part): part is Extract<ChatMessagePart, { type: "error" }> => part.type === "error");
        const message: SessionTranscriptMessage = {
          id: `msg-${event.seq}`,
          role: "agent",
          content: data.content,
          ...(parts ? { parts } : {}),
          ...(uiBlocks ? { uiBlocks } : {}),
          ...(data.durationMs !== undefined ? { durationMs: data.durationMs } : {}),
          ...(failed ? { failed: true, ...(errorPart ? { error: errorPart.message } : { error: "处理中断" }) } : {}),
          ...(lastRequest?.provider ? { provider: lastRequest.provider } : {}),
          ...(lastRequest?.model ? { model: lastRequest.model } : {}),
          createdAt: event.time,
          ...(openTurn ? { turn: openTurn.turn } : {}),
        };
        items.push(message);
        if (openTurn) lastMessageByTurn.set(openTurn.turn, message);
        break;
      }
      case "request/header": {
        const data = event.data as { header: { provider?: string; model?: string; executor?: string } };
        lastRequest = data.header;
        break;
      }
      case "tool/call": {
        const data = event.data as { callId: string; name: string; arguments: string };
        items.push({
          id: `tool-${event.seq}`,
          kind: "tool-call",
          label: data.name,
          detail: truncate(data.arguments),
          createdAt: event.time,
          ...(openTurn ? { turn: openTurn.turn } : {}),
        });
        break;
      }
      case "tool/result": {
        const data = event.data as { callId: string; outcome: string; error?: { code?: string; message?: string }; resultDigest?: string };
        items.push({
          id: `tool-${event.seq}`,
          kind: "tool-result",
          label: data.outcome,
          detail: truncate(data.error?.code ?? data.error?.message ?? data.resultDigest ?? ""),
          createdAt: event.time,
          ...(openTurn ? { turn: openTurn.turn } : {}),
        });
        break;
      }
      default:
        // session/title, session/archive, assistant/chunk, todo/write,
        // session/end-seed: no direct transcript row.
        break;
    }
  }

  return { items, turns, lastTurn };
}

/** The persisted header id + the folded transcript (convenience bundle). */
export interface SessionTranscriptView {
  readonly header: SessionHeader;
  readonly transcript: SessionTranscript;
}

/**
 * The most recent native executor session id recorded in the log (from
 * `request/header` events with reason "resume"), used to resume the native
 * Codex/Claude session on reopen. Returns undefined when none was recorded.
 */
export function lastNativeSessionId(events: readonly SessionEvent[]): string | undefined {
  let found: string | undefined;
  for (const event of [...events].sort((a, b) => a.seq - b.seq)) {
    if (event.type !== "request/header") continue;
    const header = (event.data as { header?: { nativeSessionId?: unknown } }).header;
    if (typeof header?.nativeSessionId === "string" && header.nativeSessionId.length > 0) {
      found = header.nativeSessionId;
    }
  }
  return found;
}
