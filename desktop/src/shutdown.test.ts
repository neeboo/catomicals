import { describe, expect, it, vi } from "vitest";
import { ShutdownCoordinator } from "./shutdown";

function resources() {
  return {
    closeAgentBridge: vi.fn().mockResolvedValue(undefined),
    cleanupExecutors: vi.fn().mockResolvedValue(undefined),
    cleanupWallet: vi.fn().mockResolvedValue(undefined),
    cleanupBrowser: vi.fn().mockResolvedValue(undefined),
    closeServer: vi.fn().mockResolvedValue(undefined),
    closeSessions: vi.fn().mockResolvedValue(undefined),
    quit: vi.fn(),
  };
}

describe("desktop shutdown coordination", () => {
  it("waits for browser, server, and session-store cleanup before requesting the final quit", async () => {
    const order: string[] = [];
    const coordinator = new ShutdownCoordinator({
      closeAgentBridge: async () => { order.push("agent-bridge"); },
      cleanupExecutors: async () => { order.push("executors"); },
      cleanupWallet: async () => { order.push("wallet"); },
      cleanupBrowser: async () => { order.push("browser"); },
      closeServer: async () => { order.push("server"); },
      closeSessions: async () => { order.push("sessions"); },
      quit: () => { order.push("quit"); },
    });
    const event = { preventDefault: vi.fn() };

    await coordinator.handleBeforeQuit(event);

    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(order).toEqual(["agent-bridge", "executors", "wallet", "browser", "server", "sessions", "quit"]);
  });

  it("allows the recursive quit event after cleanup without running it twice", async () => {
    const closeAgentBridge = vi.fn().mockResolvedValue(undefined);
    const cleanupExecutors = vi.fn().mockResolvedValue(undefined);
    const cleanupWallet = vi.fn().mockResolvedValue(undefined);
    const cleanupBrowser = vi.fn().mockResolvedValue(undefined);
    const closeServer = vi.fn().mockResolvedValue(undefined);
    const closeSessions = vi.fn().mockResolvedValue(undefined);
    const quit = vi.fn();
    const coordinator = new ShutdownCoordinator({ closeAgentBridge, cleanupExecutors, cleanupWallet, cleanupBrowser, closeServer, closeSessions, quit });
    const first = { preventDefault: vi.fn() };

    await coordinator.handleBeforeQuit(first);
    const recursive = { preventDefault: vi.fn() };
    await coordinator.handleBeforeQuit(recursive);

    expect(first.preventDefault).toHaveBeenCalledOnce();
    expect(recursive.preventDefault).not.toHaveBeenCalled();
    expect(closeAgentBridge).toHaveBeenCalledOnce();
    expect(cleanupExecutors).toHaveBeenCalledOnce();
    expect(cleanupWallet).toHaveBeenCalledOnce();
    expect(cleanupBrowser).toHaveBeenCalledOnce();
    expect(closeServer).toHaveBeenCalledOnce();
    expect(closeSessions).toHaveBeenCalledOnce();
    expect(quit).toHaveBeenCalledOnce();
  });

  it("still quits when the session-store flush fails, and reports the failure", async () => {
    const closeSessions = vi.fn().mockRejectedValue(new Error("flush failed"));
    const quit = vi.fn();
    const coordinator = new ShutdownCoordinator({ ...resources(), closeSessions, quit });
    const event = { preventDefault: vi.fn() };

    await expect(coordinator.handleBeforeQuit(event)).rejects.toMatchObject({
      message: "desktop shutdown cleanup failed",
      errors: [expect.objectContaining({ message: "flush failed" })],
    });
    expect(quit).toHaveBeenCalledOnce();
  });
});
