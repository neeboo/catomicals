import { describe, expect, it } from "vitest";
import { requireDesktopBridge } from "./desktop";

describe("desktop bridge access", () => {
  it("returns only the trusted preload bridge and fails closed when it is absent", () => {
    const bridge = { getState: async () => ({ desktop: true as const, toolsOpen: false, activeTab: null, safeStorageAvailable: true }) };

    expect(requireDesktopBridge(bridge as never)).toBe(bridge);
    expect(() => requireDesktopBridge(undefined)).toThrow("desktop runtime unavailable");
  });
});
