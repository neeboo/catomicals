// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  ControlledSpecRenderer,
  buildHealthStatusSpec,
  buildReviewSpec,
} from "./ControlledJsonUi";

afterEach(cleanup);

describe("controlled json UI", () => {
  it("renders host-owned health data through json-render", () => {
    const spec = buildHealthStatusSpec("@catomicals/plugin-walletd", {
      status: "healthy",
      message: "钱包节点已连接",
      checkedAt: "2026-08-28T12:00:00.000Z",
    });
    const { container } = render(<ControlledSpecRenderer spec={spec} />);

    expect(container.querySelector('[data-renderer="json-render"]')).not.toBeNull();
    expect(screen.getByText("钱包节点")).toBeTruthy();
    expect(screen.getByText("钱包节点已连接")).toBeTruthy();
  });

  it("renders settings changes and the host confirmation control", () => {
    const spec = buildReviewSpec({
      intentId: "intent-1",
      reviewId: "review-1",
      pluginId: "@catomicals/plugin-indexer",
      pluginVersion: "1.0.0",
      baseSettingsDigest: "before",
      candidateSettingsDigest: "after",
      patchDigest: "patch",
      restartImpact: "plugin",
      permissionDelta: { added: [], removed: [] },
      changes: [{ id: "rpc", label: "RPC 地址", type: "string", restart: "plugin", before: "旧地址", after: "新地址" }],
      state: "current",
      createdAt: "2026-08-28T12:00:00.000Z",
      expiresAt: "2099-08-28T12:30:00.000Z",
    }, "review_card", false, false);
    render(<ControlledSpecRenderer spec={spec} onConfirmReview={() => undefined} />);

    expect(screen.getByText("RPC 地址")).toBeTruthy();
    expect(screen.getByText("旧地址").tagName).toBe("DEL");
    const confirm = screen.getByRole("button", { name: "确认更改" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(false);
  });
});
