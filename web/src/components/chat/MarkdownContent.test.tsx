// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MarkdownContent } from "./MarkdownContent";

afterEach(cleanup);

describe("MarkdownContent", () => {
  it("renders GFM headings, emphasis, tables, and fenced code", () => {
    const { container } = render(<MarkdownContent content={[
      "## 钱包状态",
      "",
      "**地址可用**",
      "",
      "| 项目 | 状态 |",
      "| --- | --- |",
      "| 节点 | 在线 |",
      "",
      "```text",
      "tb1qexample",
      "```",
    ].join("\n")} />);

    expect(screen.getByRole("heading", { name: "钱包状态" })).toBeTruthy();
    expect(screen.getByText("地址可用").tagName).toBe("STRONG");
    expect(screen.getByRole("table")).toBeTruthy();
    expect(container.querySelector("pre code")?.textContent).toContain("tb1qexample");
  });

  it("does not execute raw HTML or keep unsafe links", () => {
    const { container } = render(<MarkdownContent content={'<script>bad()</script> [危险](javascript:alert(1))'} />);

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  });
});
