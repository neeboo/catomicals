import { describe, expect, it } from "vitest";
import { executorAssistantText, executorConversationSessionId } from "./executor-chat";

describe("executor chat adapter", () => {
  it("extracts the assistant message from Codex JSON events without surfacing diagnostics", () => {
    const output = [
      JSON.stringify({ type: "thread.started", thread_id: "native-1" }),
      JSON.stringify({ type: "item.completed", item: { type: "error", message: "local warning" } }),
      JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "我在。" } }),
      JSON.stringify({ type: "turn.completed" }),
    ].join("\n");

    expect(executorAssistantText("codex", output)).toBe("我在。");
  });

  it("extracts text blocks from Claude stream-json output", () => {
    const output = [
      JSON.stringify({ type: "system", subtype: "init", session_id: "native-2" }),
      JSON.stringify({
        type: "assistant",
        message: { content: [{ type: "text", text: "可以继续。" }] },
      }),
    ].join("\n");

    expect(executorAssistantText("claude-code", output)).toBe("可以继续。");
  });

  it("keeps DeepSeek headless text output as the reply", () => {
    expect(executorAssistantText("deepseek", "  已完成检查。\n")).toBe("已完成检查。");
  });

  it("uses a stable provider-scoped desktop session id", () => {
    expect(executorConversationSessionId("wallet-main", "codex")).toBe("wallet-main-codex");
    expect(executorConversationSessionId("wallet-main", "claude-code"))
      .toBe("wallet-main-claude-code");
  });
});
