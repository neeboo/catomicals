import { describe, expect, it, vi } from "vitest";
import {
  createReviewCardBlock,
  loadControlledUiBlock,
  parseControlledUiBlock,
  parseReviewReference,
} from "./ui-block";

const reviewId = "11111111-2222-3333-4444-555555555555";
const blockId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

describe("controlled UI blocks", () => {
  it("consumes the complete protocol block without agent-supplied display values", () => {
    const block = createReviewCardBlock(reviewId, blockId);
    expect(parseControlledUiBlock(block)).toEqual(block);
    expect(() => parseControlledUiBlock({ ...block, amount: 21_000_000 }))
      .toThrow("unexpected UI block fields");
    expect(() => parseControlledUiBlock({
      ...block,
      data_bindings: [{ ...block.data_bindings[0], reference_id: "review-42" }],
    })).toThrow("invalid review reference");
    expect(() => parseControlledUiBlock({
      ...block,
      action_bindings: [{ action_id: "approve", action: "confirm_review", target_binding: "review" }],
    })).toThrow("unsupported UI block action");
    expect(() => parseControlledUiBlock({ ...block, title: "Agent supplied title" }))
      .toThrow("unexpected UI block fields");
    expect(() => parseControlledUiBlock({ ...block, description: "Agent supplied description" }))
      .toThrow("unexpected UI block fields");
  });

  it("validates plugin ids independently from review UUIDs", () => {
    const healthBlock = {
      schema_version: 1,
      block_id: blockId,
      component: "health_status",
      data_bindings: [{
        slot: "health",
        source: "desktop_host",
        reference_kind: "plugin_id",
        reference_id: "@catomicals/plugin-walletd",
      }],
      action_bindings: [],
    };
    expect(parseControlledUiBlock(healthBlock)).toEqual(healthBlock);
    expect(() => parseControlledUiBlock({
      ...healthBlock,
      data_bindings: [{ ...healthBlock.data_bindings[0], reference_id: reviewId }],
    })).toThrow("invalid plugin reference");
  });

  it("accepts every reference-only component shape defined by the shared schema", () => {
    const transactionBlock = {
      schema_version: 1,
      block_id: blockId,
      component: "transaction_summary",
      data_bindings: [{
        slot: "intent",
        source: "walletd",
        reference_kind: "intent_id",
        reference_id: "60675e8d-b7a2-4602-b744-4c85d6dc0206",
      }],
      action_bindings: [],
    };

    expect(parseControlledUiBlock(transactionBlock)).toEqual(transactionBlock);
  });

  it("accepts only schema-aligned review references with UUID identities and digests", () => {
    const reference = {
      schema_version: 1,
      review_id: reviewId,
      kind: "plugin_settings",
      source: "desktop_host",
      review_digest: `sha256:${"1".repeat(64)}`,
      intent_id: "60675e8d-b7a2-4602-b744-4c85d6dc0206",
      plugin_id: "@catomicals/plugin-walletd",
      plugin_version: "1.0.0",
      created_at: "2026-08-27T09:00:00Z",
      state: "current",
    };

    expect(parseReviewReference(reference)).toEqual(reference);
    expect(() => parseReviewReference({ ...reference, review_id: "review-42" }))
      .toThrow("invalid review id");
    expect(() => parseReviewReference({ ...reference, review_digest: "sha256:short" }))
      .toThrow("invalid review digest");
    expect(() => parseReviewReference({ ...reference, display_amount: 21_000_000 }))
      .toThrow("unexpected review reference fields");
  });

  it("re-reads every display value from the desktop host", async () => {
    const review = {
      intentId: "intent-42",
      reviewId,
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

    await expect(loadControlledUiBlock(createReviewCardBlock(reviewId, blockId), bridge))
      .resolves.toMatchObject({ kind: "review_card", review });
    expect(bridge.readPluginSettingsReview).toHaveBeenCalledWith(reviewId);
  });
});
