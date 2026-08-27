import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MessagePart } from "./WalletWorkbench";

describe("wallet workbench protocol message rendering", () => {
  it("renders text, tool activity, and errors from typed parts", () => {
    expect(renderToStaticMarkup(<MessagePart part={{ type: "text", text: "检查完成" }} />))
      .toContain("检查完成");
    expect(renderToStaticMarkup(<MessagePart part={{
      type: "tool_call",
      tool_call_id: "call-1",
      tool_name: "read_plugin_health",
      request_digest: `sha256:${"1".repeat(64)}`,
      permission_scope: "plugin.health.read",
    }} />)).toContain("read_plugin_health");
    expect(renderToStaticMarkup(<MessagePart part={{
      type: "error",
      code: "health_unavailable",
      message: "健康状态不可用",
      retriable: true,
    }} />)).toContain("健康状态不可用");
  });

  it("rejects an invalid review reference at the render boundary", () => {
    const markup = renderToStaticMarkup(<MessagePart part={{
      type: "review_reference",
      reference: {
        schema_version: 1,
        review_id: "review-1",
        kind: "plugin_settings",
        source: "desktop_host",
        review_digest: `sha256:${"2".repeat(64)}`,
        intent_id: "60675e8d-b7a2-4602-b744-4c85d6dc0206",
        plugin_id: "@catomicals/plugin-walletd",
        plugin_version: "1.0.0",
        created_at: "2026-08-27T09:00:00Z",
        state: "current",
      },
    }} />);

    expect(markup).toContain("invalid review id");
    expect(markup).not.toContain("审查引用</span>");
  });
});
