import { describe, expect, it, vi } from "vitest";
import { ShutdownCoordinator } from "./shutdown";

describe("desktop shutdown coordination", () => {
  it("waits for browser and server cleanup before requesting the final quit", async () => {
    const order: string[] = [];
    const coordinator = new ShutdownCoordinator({
      closeAgentBridge: async () => { order.push("agent-bridge"); },
      cleanupExecutors: async () => { order.push("executors"); },
      cleanupBrowser: async () => { order.push("browser"); },
      closeServer: async () => { order.push("server"); },
      quit: () => { order.push("quit"); },
    });
    const event = { preventDefault: vi.fn() };

    await coordinator.handleBeforeQuit(event);

    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(order).toEqual(["agent-bridge", "executors", "browser", "server", "quit"]);
  });

  it("allows the recursive quit event after cleanup without running it twice", async () => {
    const cleanupBrowser = vi.fn().mockResolvedValue(undefined);
    const cleanupExecutors = vi.fn().mockResolvedValue(undefined);
    const closeAgentBridge = vi.fn().mockResolvedValue(undefined);
    const closeServer = vi.fn().mockResolvedValue(undefined);
    const quit = vi.fn();
    const coordinator = new ShutdownCoordinator({ closeAgentBridge, cleanupExecutors, cleanupBrowser, closeServer, quit });
    const first = { preventDefault: vi.fn() };

    await coordinator.handleBeforeQuit(first);
    const recursive = { preventDefault: vi.fn() };
    await coordinator.handleBeforeQuit(recursive);

    expect(first.preventDefault).toHaveBeenCalledOnce();
    expect(recursive.preventDefault).not.toHaveBeenCalled();
    expect(closeAgentBridge).toHaveBeenCalledOnce();
    expect(cleanupExecutors).toHaveBeenCalledOnce();
    expect(cleanupBrowser).toHaveBeenCalledOnce();
    expect(closeServer).toHaveBeenCalledOnce();
    expect(quit).toHaveBeenCalledOnce();
  });
});
