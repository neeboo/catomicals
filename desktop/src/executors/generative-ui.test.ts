import { describe, expect, it } from "vitest";
import { buildGenerativeUiPrompt } from "./generative-ui";

const settings = {
  enabled: true,
  preference: "prefer" as const,
  maxBlocks: 2 as const,
  referenceRepository: "/workspace/deepseek-harness",
  customInstructions: "Use compact status cards.",
};

describe("generative UI executor prompt", () => {
  it("injects the reference-only component contract without changing the visible user request", () => {
    const prompt = buildGenerativeUiPrompt("deepseek", "检查钱包状态", settings);

    expect(prompt).toContain("<catomicals-interface-policy>");
    expect(prompt).toContain("<catomicals-ui>");
    expect(prompt).toContain("action_bindings\":[]");
    expect(prompt).toContain("Never invent a reference");
    expect(prompt).toContain("/workspace/deepseek-harness/apps/web");
    expect(prompt).toContain("<user-request>\n检查钱包状态\n</user-request>");
  });

  it("returns the original prompt when structured UI is disabled", () => {
    expect(buildGenerativeUiPrompt("codex", "hello", { ...settings, enabled: false })).toBe("hello");
    expect(buildGenerativeUiPrompt("codex", "hello", { ...settings, preference: "off" })).toBe("hello");
  });
});
