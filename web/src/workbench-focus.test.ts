import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("./index.css", import.meta.url), "utf8");

describe("workbench keyboard focus", () => {
  it("defines a monochrome focus-visible treatment for every interactive control", () => {
    expect(css).toContain(".workbench-shell :where(button, a, input, textarea, summary):focus-visible");
    expect(css).toContain("outline: 1px solid #d7d8d8");
    expect(css).toContain("outline-offset: 2px");
  });
});
