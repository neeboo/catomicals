import { describe, expect, it } from "vitest";
import { createExecutorFinalMessage, extractExecutorFinalText } from "./stream-events";

describe("executor final message extraction", () => {
  it("selects only the last completed Codex agent message", () => {
    const output = [
      '{"type":"thread.started","thread_id":"thread-1"}',
      '{"type":"item.completed","item":{"type":"agent_message","text":"draft"}}',
      '{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"secret log"}}',
      '{"type":"item.completed","item":{"type":"agent_message","text":"final answer"}}',
      '{"type":"turn.completed"}',
    ].join("\n");

    expect(extractExecutorFinalText("codex", output)).toBe("final answer");
  });

  it("does not reuse an earlier Codex draft when the final agent message is empty", () => {
    const output = [
      '{"type":"item.completed","item":{"type":"agent_message","text":"draft"}}',
      '{"type":"item.completed","item":{"type":"agent_message","text":"   "}}',
    ].join("\n");

    expect(extractExecutorFinalText("codex", output)).toBeUndefined();
  });

  it("joins text blocks from the last Claude assistant message", () => {
    const output = [
      '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"old"}]}}',
      '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"final "},{"type":"tool_use","id":"tool-1"},{"type":"text","text":"answer"}]}}',
    ].join("\n");

    expect(extractExecutorFinalText("claude-code", output)).toBe("final answer");
  });

  it("preserves genuine DeepSeek plain text", () => {
    expect(extractExecutorFinalText("deepseek", "plain\nanswer\n")).toBe("plain\nanswer\n");
  });

  it("refuses to construct a completed message without display text", () => {
    expect(() => createExecutorFinalMessage("7fbcabf0-4fe8-4ce7-91d0-8678d65f79f6", ""))
      .toThrow("missing final text");
  });
});
