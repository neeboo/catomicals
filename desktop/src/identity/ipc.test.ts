import { describe, expect, it, vi } from "vitest";
import { IPC_CHANNELS } from "../ipc";
import { registerIdentityIpc } from "./ipc";

describe("identity IPC wiring", () => {
  it("binds state, local login, and logout behind renderer validation", async () => {
    const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
    const removed: string[] = [];
    const ipc = {
      handle: (channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) => handlers.set(channel, handler),
      removeHandler: (channel: string) => removed.push(channel),
    };
    const state = vi.fn(async () => ({ available: true, session: null }));
    const login = vi.fn(async () => ({ provider: "local-device" }));
    const logout = vi.fn(async () => undefined);
    const recover = vi.fn(async () => undefined);
    const assertSender = vi.fn();
    const dispose = registerIdentityIpc({
      service: { state, login, logout, recover } as never,
      assertSender,
      ipc: ipc as never,
    });
    const event = { sender: "renderer" };

    await expect(handlers.get(IPC_CHANNELS.identityState)!(event)).resolves.toEqual({ available: true, session: null });
    await expect(handlers.get(IPC_CHANNELS.identityLogin)!(event, { provider: "local-device" }))
      .resolves.toEqual({ provider: "local-device" });
    await expect(handlers.get(IPC_CHANNELS.identityLogout)!(event)).resolves.toBeUndefined();
    const recoverChannel = (IPC_CHANNELS as Record<string, string>).identityRecover;
    expect(recoverChannel).toBe("catomicals:identity:recover");
    await expect(handlers.get(recoverChannel)!(event)).resolves.toBeUndefined();
    expect(assertSender).toHaveBeenCalledTimes(4);
    expect(login).toHaveBeenCalledWith({ provider: "local-device" });

    await expect(Promise.resolve().then(() => handlers.get(IPC_CHANNELS.identityLogout)!(event, "extra")))
      .rejects.toThrow("argument count");

    dispose();
    expect(removed).toEqual([
      IPC_CHANNELS.identityState,
      IPC_CHANNELS.identityLogin,
      IPC_CHANNELS.identityLogout,
      recoverChannel,
    ]);
  });

  it("keeps unexpected storage details behind a stable IPC error", async () => {
    const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
    registerIdentityIpc({
      service: {
        state: async () => { throw new Error("EACCES /Users/private/identity-session.json"); },
      } as never,
      assertSender: () => undefined,
      ipc: {
        handle: (channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) => handlers.set(channel, handler),
        removeHandler: () => undefined,
      } as never,
    });

    const result = Promise.resolve().then(() => handlers.get(IPC_CHANNELS.identityState)!({}));
    await expect(result).rejects.toThrow("identity operation failed");
    await expect(result).rejects.not.toThrow("/Users/private");
  });
});
