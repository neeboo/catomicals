import { describe, expect, it } from "vitest";
import { executorAssistantResponse, executorAssistantText, executorConversationSessionId } from "./executor-chat";

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

  it("extracts strict reference-only UI blocks while preserving Markdown", () => {
    const response = executorAssistantResponse("deepseek", [
      "## 钱包状态",
      "状态如下。",
      "<catomicals-ui>",
      JSON.stringify({
        schema_version: 1,
        block_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        component: "health_status",
        data_bindings: [{
          slot: "health",
          source: "desktop_host",
          reference_kind: "plugin_id",
          reference_id: "@catomicals/plugin-walletd",
        }],
        action_bindings: [],
      }),
      "</catomicals-ui>",
    ].join("\n"));

    expect(response.text).toBe("## 钱包状态\n状态如下。");
    expect(response.uiBlocks).toHaveLength(1);
    expect(response.uiBlocks[0]).toMatchObject({ component: "health_status" });
    expect(response.rejectedUiBlocks).toBe(0);
  });

  it("drops forged values and duplicate blocks with a visible protocol notice", () => {
    const block = {
      schema_version: 1,
      block_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      component: "health_status",
      data_bindings: [{
        slot: "health",
        source: "desktop_host",
        reference_kind: "plugin_id",
        reference_id: "@catomicals/plugin-walletd",
      }],
      action_bindings: [],
    };
    const response = executorAssistantResponse("deepseek", [
      "结果",
      `<catomicals-ui>${JSON.stringify({ ...block, balance: 21_000_000 })}</catomicals-ui>`,
      `<catomicals-ui>${JSON.stringify(block)}</catomicals-ui>`,
      `<catomicals-ui>${JSON.stringify(block)}</catomicals-ui>`,
    ].join("\n"));

    expect(response.uiBlocks).toHaveLength(1);
    expect(response.rejectedUiBlocks).toBe(2);
    expect(response.text).toContain("2 个界面组件未通过宿主校验");
    expect(response.text).not.toContain("balance");
  });
});
