import { describe, expect, it, vi } from "vitest";
import {
  assertPublicBrowserUrl,
  createBrowserPartitionName,
  releaseBrowserPartition,
} from "./browser-security";

describe("embedded browser security", () => {
  it("rejects a public-looking host that DNS resolves to loopback", async () => {
    const lookup = vi.fn().mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);

    await expect(assertPublicBrowserUrl("https://wallet.example", lookup))
      .rejects.toThrow("private network");
  });

  it("rejects a public-looking host when any DNS answer is private", async () => {
    const lookup = vi.fn().mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.9", family: 4 },
    ]);

    await expect(assertPublicBrowserUrl("https://mixed.example", lookup))
      .rejects.toThrow("private network");
  });

  it("allows a web URL only after all DNS answers are public", async () => {
    const lookup = vi.fn().mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ]);

    await expect(assertPublicBrowserUrl("https://example.com/path", lookup))
      .resolves.toBe("https://example.com/path");
  });

  it("uses a non-persistent partition unique to the browser session", () => {
    const first = createBrowserPartitionName("chat-main", "nonce-a");
    const second = createBrowserPartitionName("chat-main", "nonce-b");

    expect(first).not.toContain("persist:");
    expect(first).not.toBe(second);
    expect(first).toMatch(/^catomicals-browser:/);
  });

  it("closes and clears an ephemeral browser partition on release", async () => {
    const close = vi.fn();
    const clearStorageData = vi.fn().mockResolvedValue(undefined);
    const clearCache = vi.fn().mockResolvedValue(undefined);

    await releaseBrowserPartition({ close, clearStorageData, clearCache });

    expect(close).toHaveBeenCalledOnce();
    expect(clearStorageData).toHaveBeenCalledOnce();
    expect(clearCache).toHaveBeenCalledOnce();
  });
});
