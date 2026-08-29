/**
 * Main-process session wiring contract: the exact composition desktop main.ts
 * uses (SessionManager + createRendererNavigationPusher +
 * createCatomicalsDeeplinkService) must deliver a `catomicals://session/<id>`
 * deep link as a renderer navigation push, and shutdown must close the store.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCatomicalsDeeplinkService, type CatomicalsDeeplinkServiceDeps } from "./deeplink";
import { SessionManager } from "./sessions/manager";
import { createRendererNavigationPusher } from "./sessions/ipc";
import { IPC_CHANNELS } from "./ipc";

describe("desktop main session wiring", () => {
  const roots: string[] = [];
  const unsubscribes: Array<() => void> = [];
  afterEach(() => {
    for (const unsubscribe of unsubscribes.splice(0)) unsubscribe();
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });

  it("routes a deeplink session-open through the manager to the renderer pusher", async () => {
    const root = mkdtempSync(join(tmpdir(), "catomicals-main-wiring-"));
    roots.push(root);
    const manager = new SessionManager({ root, searchOpenAt: "never" });
    const created = await manager.createSession({ title: "Deep-linked", provider: "codex" });

    const pushed: Array<{ kind: string; sessionId?: string; source: string }> = [];
    const fakeWindow = {
      webContents: {
        send: vi.fn((channel: string, event: unknown) => {
          expect(channel).toBe(IPC_CHANNELS.sessionNavigationPush);
          pushed.push(event as { kind: string; sessionId?: string; source: string });
        }),
      },
      isDestroyed: () => false,
    };
    const pusher = createRendererNavigationPusher(() => fakeWindow as never);
    unsubscribes.push(manager.onNavigate(pusher));

    const serviceDeps: CatomicalsDeeplinkServiceDeps = {
      registerProtocolClient: () => true,
      onOpenUrl: () => undefined,
      removeOpenUrlListener: () => undefined,
      onSecondInstance: () => undefined,
      removeSecondInstanceListener: () => undefined,
      currentArgv: [`catomicals://session/${created.id}`],
    };
    const service = createCatomicalsDeeplinkService(
      serviceDeps,
      (event) => manager.navigate(
        event.kind === "session-open" ? { kind: "session-open", sessionId: event.sessionId! } : { kind: "session-list" },
        "deeplink",
      ),
    );

    // The service honors the launch argv on the next microtask.
    await Promise.resolve();
    await Promise.resolve();

    expect(pushed).toHaveLength(1);
    expect(pushed[0]).toMatchObject({ kind: "session-open", sessionId: created.id, source: "deeplink" });

    service.dispose();
    await manager.close();
  });

  it("closes the manager idempotently on shutdown", async () => {
    const root = mkdtempSync(join(tmpdir(), "catomicals-main-wiring-"));
    roots.push(root);
    const manager = new SessionManager({ root, searchOpenAt: "never" });
    await manager.createSession({ title: "Flush me" });
    await expect(manager.close()).resolves.toBeUndefined();
    await expect(manager.close()).resolves.toBeUndefined();
    await expect(manager.listSessions()).rejects.toThrow("session manager is closed");
  });
});
