// @vitest-environment node

import { describe, expect, it } from "vitest";
import {
  buildSessionTranscript,
  lastNativeSessionId,
  sessionPartsToWeb,
  sessionUiBlocks,
} from "./session-transcript";
import type { SessionEvent } from "./desktop";

function event(partial: Partial<SessionEvent> & { type: string; data: Record<string, unknown> }, seq: number, time = 1000): SessionEvent {
  return { seq, time, ...partial } as SessionEvent;
}

describe("buildSessionTranscript", () => {
  it("folds a completed turn into a user message (left) and an agent message (right) with durations", () => {
    const events: SessionEvent[] = [
      event({ type: "turn/start", data: { turn: 1 } }, 0),
      event({ type: "user/message", data: { content: "你好" } }, 1),
      event({ type: "request/header", data: { header: { provider: "codex", model: "gpt-5.3-codex" } } }, 2),
      event({ type: "assistant/message", data: { content: "我在", durationMs: 400 } }, 3),
      event({ type: "turn/end", data: { turn: 1, reason: { kind: "completed" }, durationMs: 400 } }, 4),
    ];

    const { items, turns, lastTurn } = buildSessionTranscript(events);

    expect(lastTurn).toBe(1);
    expect(turns[0]).toMatchObject({ turn: 1, status: "completed", durationMs: 400 });
    expect(items.map((item) => ("role" in item ? item.role : "protocol"))).toEqual(["user", "agent"]);
    const [user, agent] = items.map((item) => item as { role: string; content: string; provider?: string; model?: string; durationMs?: number });
    expect(user).toMatchObject({ role: "user", content: "你好" });
    expect(agent).toMatchObject({
      role: "agent",
      content: "我在",
      durationMs: 400,
      provider: "codex",
      model: "gpt-5.3-codex",
    });
  });

  it("marks an interrupted tail turn and attaches the turn duration to the last agent message", () => {
    const events: SessionEvent[] = [
      event({ type: "turn/start", data: { turn: 1 } }, 0),
      event({ type: "user/message", data: { content: "继续" } }, 1),
      event({ type: "assistant/message", data: { content: "部分回答" } }, 2),
      event({ type: "turn/end", data: { turn: 1, reason: { kind: "interrupted" } } }, 3),
    ];
    const { items, turns } = buildSessionTranscript(events);
    expect(turns[0].status).toBe("interrupted");
    const agent = items[1] as { role: string; durationMs?: number; failed?: boolean };
    expect(agent.role).toBe("agent");
  });

  it("renders an error turn as a failed agent message and protocol rows for tool events", () => {
    const events: SessionEvent[] = [
      event({ type: "turn/start", data: { turn: 1 } }, 0),
      event({ type: "user/message", data: { content: "检查" } }, 1),
      event({ type: "tool/call", data: { callId: "c1", name: "read_plugin_health", arguments: "{}" } }, 2),
      event({ type: "tool/result", data: { callId: "c1", outcome: "failed", error: { code: "E1" } } }, 3),
      event({
        type: "assistant/message",
        data: { content: "", parts: [{ type: "error", code: "E1", message: "健康状态不可用", retriable: true }] },
      }, 4),
      event({ type: "turn/end", data: { turn: 1, reason: { kind: "error", error: { message: "健康状态不可用", code: "E1" } } } }, 5),
    ];

    const { items } = buildSessionTranscript(events);

    const protocol = items.filter((item) => "kind" in item);
    expect(protocol.map((item) => item.kind)).toEqual(["tool-call", "tool-result"]);
    const agent = items[items.length - 1] as { role: string; failed?: boolean; error?: string };
    expect(agent).toMatchObject({ role: "agent", failed: true, error: "健康状态不可用" });
  });

  it("extracts controlled UI blocks from stored assistant parts", () => {
    const block = {
      schema_version: 1 as const,
      block_id: "blk-1",
      component: "fee_chart",
      data_bindings: [],
      action_bindings: [],
    };
    const parts = [{ type: "ui_block" as const, block }];
    const uiBlocks = sessionUiBlocks(parts);
    expect(uiBlocks?.[0]?.block_id).toBe("blk-1");

    const events: SessionEvent[] = [
      event({ type: "turn/start", data: { turn: 1 } }, 0),
      event({ type: "user/message", data: { content: "给我图表" } }, 1),
      event({ type: "assistant/message", data: { content: "好的", parts } }, 2),
      event({ type: "turn/end", data: { turn: 1, reason: { kind: "completed" } } }, 3),
    ];
    const { items } = buildSessionTranscript(events);
    const agent = items[1] as { uiBlocks?: Array<{ block_id: string }> };
    expect(agent.uiBlocks?.[0]?.block_id).toBe("blk-1");
  });

  it("maps stored message parts to the renderer model", () => {
    const parts = sessionPartsToWeb([
      { type: "text", text: "hi" },
      { type: "tool_call", tool_call_id: "c1", tool_name: "read_plugin_health", request_digest: "d", permission_scope: "plugin.health.read" },
      { type: "tool_result", tool_call_id: "c1", outcome: "succeeded" },
      { type: "error", code: "E", message: "m", retriable: true },
    ]);
    expect(parts?.map((part) => part.type)).toEqual(["text", "tool_call", "tool_result", "error"]);
  });

  it("reports the last recorded native session id from resume request headers", () => {
    const events: SessionEvent[] = [
      event({ type: "request/header", data: { header: { provider: "codex" }, reason: "initial" } }, 0),
      event({ type: "request/header", data: { header: { provider: "codex", nativeSessionId: "native-1" }, reason: "resume" } }, 1),
      event({ type: "request/header", data: { header: { provider: "codex", nativeSessionId: "native-2" }, reason: "resume" } }, 2),
    ];
    expect(lastNativeSessionId(events)).toBe("native-2");
    expect(lastNativeSessionId([events[0]])).toBeUndefined();
  });

  it("is defensive about out-of-order event lists", () => {
    const events: SessionEvent[] = [
      event({ type: "user/message", data: { content: "B" } }, 1),
      event({ type: "user/message", data: { content: "A" } }, 0),
    ];
    const { items } = buildSessionTranscript(events);
    expect(items.map((item) => (item as { content: string }).content)).toEqual(["A", "B"]);
  });
});
