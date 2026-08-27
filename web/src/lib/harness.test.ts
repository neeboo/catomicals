import { describe, expect, it } from "vitest";
import {
  DEFAULT_HARNESS_ID,
  HARNESS_ADAPTERS,
  parseHarnessId,
  selectedHarnessStorageKey,
} from "./harness";

describe("harness adapter registry", () => {
  it("exposes Codex, DeepSeek Harness, and Claude Code through one typed registry", () => {
    expect(HARNESS_ADAPTERS.map((adapter) => adapter.id)).toEqual([
      "codex",
      "deepseek",
      "claude-code",
    ]);
    expect(HARNESS_ADAPTERS.map((adapter) => adapter.label)).toEqual([
      "Codex",
      "DeepSeek Harness",
      "Claude Code",
    ]);
    expect(HARNESS_ADAPTERS.every((adapter) => !("status" in adapter))).toBe(true);
  });

  it("normalizes invalid selections and scopes valid selections to the chat session", () => {
    expect(parseHarnessId("deepseek")).toBe("deepseek");
    expect(parseHarnessId("unknown")).toBe(DEFAULT_HARNESS_ID);
    expect(selectedHarnessStorageKey("wallet-main")).toBe("catomicals:harness:wallet-main");
  });
});
