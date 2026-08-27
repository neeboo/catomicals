import { describe, expect, it, vi } from "vitest";
import { loadControlledUiBlock, parseUiBlockReference } from "./ui-block";

describe("controlled UI blocks", () => {
  it("accepts only fixed block kinds with one opaque authoritative reference", () => {
    expect(parseUiBlockReference({ kind: "review_card", reviewId: "review-42" }))
      .toEqual({ kind: "review_card", reviewId: "review-42" });
    expect(() => parseUiBlockReference({
      kind: "review_card",
      reviewId: "review-42",
      amount: 21_000_000,
    })).toThrow("unexpected UI block fields");
    expect(() => parseUiBlockReference({ kind: "html", html: "<button>approve</button>" }))
      .toThrow("unsupported UI block");
  });

  it("re-reads every display value from the desktop host", async () => {
    const review = {
      intentId: "intent-42",
      reviewId: "review-42",
      pluginId: "@catomicals/plugin-walletd",
      pluginVersion: "1.0.0",
      baseSettingsDigest: `sha256:${"a".repeat(64)}`,
      candidateSettingsDigest: `sha256:${"b".repeat(64)}`,
      patchDigest: `sha256:${"c".repeat(64)}`,
      restartImpact: "plugin" as const,
      permissionDelta: { added: [], removed: [] },
      changes: [{ id: "command", label: "Command", type: "string" as const, restart: "plugin" as const, before: "old", after: "new" }],
      state: "current" as const,
      createdAt: "2026-08-28T00:00:00.000Z",
      expiresAt: "2026-08-28T00:30:00.000Z",
    };
    const bridge = {
      readPluginSettingsReview: vi.fn(async () => review),
      readPluginHealth: vi.fn(async () => ({ status: "healthy" as const })),
    };

    await expect(loadControlledUiBlock({ kind: "plugin_settings_diff", reviewId: "review-42" }, bridge))
      .resolves.toEqual({ kind: "plugin_settings_diff", review });
    expect(bridge.readPluginSettingsReview).toHaveBeenCalledWith("review-42");
  });
});
