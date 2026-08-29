import { describe, expect, it, vi } from "vitest";
import type { RunningProcess } from "./executors/process-manager.js";
import { WalletNodeSupervisor } from "./wallet-supervisor.js";

function healthyWalletResponse(): Response {
  return new Response(JSON.stringify({
    network: "signet",
    rp_id: "localhost",
    rp_origin: "http://localhost:5173",
    production_ready: false,
    runtime_mode: "compatibility",
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

function deferredProcess(): { process: RunningProcess; finish: (exitCode?: number) => void } {
  let finish!: (value: { exitCode: number | null; signal: null; stdout: string; stderr: string }) => void;
  const completion = new Promise<{ exitCode: number | null; signal: null; stdout: string; stderr: string }>((resolve) => {
    finish = resolve;
  });
  return {
    process: { completion, interrupt: vi.fn(() => true) },
    finish: (exitCode = 1) => finish({ exitCode, signal: null, stdout: "", stderr: "stopped" }),
  };
}

describe("managed wallet node supervisor", () => {
  it("adopts an already healthy loopback wallet without spawning a second authority", async () => {
    const start = vi.fn();
    const fetcher = vi.fn(async () => healthyWalletResponse());
    const supervisor = new WalletNodeSupervisor({
      command: "/workspace/target/debug/catomicals",
      processHost: { start },
      fetcher,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
    })).resolves.toMatchObject({ state: "adopted", healthy: true });

    expect(start).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledWith(
      "http://127.0.0.1:18787/api/v1/node/status",
      expect.objectContaining({ method: "GET", credentials: "omit", redirect: "error" }),
    );
  });

  it("starts the exact wallet server command when managed mode is offline", async () => {
    const child = deferredProcess();
    const start = vi.fn(() => child.process);
    const fetcher = vi.fn()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(healthyWalletResponse());
    const supervisor = new WalletNodeSupervisor({
      command: "/workspace/target/debug/catomicals",
      processHost: { start },
      fetcher,
      wait: async () => undefined,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
      walletDataDirectory: "/safe/wallet",
      bitcoinDataDirectory: "/safe/inquisition",
    })).resolves.toMatchObject({ state: "managed", healthy: true });

    expect(start).toHaveBeenCalledWith({
      executable: "/workspace/target/debug/catomicals",
      args: [
        "wallet", "serve",
        "--addr", "127.0.0.1:18787",
        "--rp-id", "localhost",
        "--rp-origin", "http://localhost:5173",
        "--cors-origin", "http://localhost:5173",
        "--data-dir", "/safe/wallet",
        "--datadir", "/safe/inquisition",
      ],
      environmentKeys: [],
    });
    await supervisor.dispose();
    expect(child.process.interrupt).toHaveBeenCalledOnce();
  });

  it("leaves an unavailable external wallet untouched", async () => {
    const start = vi.fn();
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start },
      fetcher: async () => { throw new TypeError("offline"); },
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:28787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
    })).resolves.toMatchObject({ state: "external", healthy: false });
    expect(start).not.toHaveBeenCalled();
  });

  it("rejects non-loopback or credential-bearing endpoints before probing or spawning", async () => {
    const start = vi.fn();
    const fetcher = vi.fn();
    const supervisor = new WalletNodeSupervisor({ command: "catomicals", processHost: { start }, fetcher });

    await expect(supervisor.start({
      endpoint: "http://user:secret@127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
    })).rejects.toThrow("loopback");
    expect(start).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("restarts a managed child after an unexpected exit", async () => {
    const first = deferredProcess();
    const second = deferredProcess();
    const start = vi.fn()
      .mockReturnValueOnce(first.process)
      .mockReturnValueOnce(second.process);
    const fetcher = vi.fn()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockRejectedValueOnce(new TypeError("stopped"))
      .mockResolvedValue(healthyWalletResponse());
    const wait = vi.fn(async () => undefined);
    const supervisor = new WalletNodeSupervisor({ command: "catomicals", processHost: { start }, fetcher, wait });

    await supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
    });
    first.finish();
    await vi.waitFor(() => expect(start).toHaveBeenCalledTimes(2));

    await supervisor.dispose();
    expect(second.process.interrupt).toHaveBeenCalledOnce();
  });

  it("takes over when an adopted managed wallet later disappears", async () => {
    const child = deferredProcess();
    const start = vi.fn(() => child.process);
    const fetcher = vi.fn()
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockRejectedValueOnce(new TypeError("disappeared"))
      .mockResolvedValue(healthyWalletResponse());
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start },
      fetcher,
      wait: async () => undefined,
    });

    await supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
    });
    await vi.waitFor(() => expect(start).toHaveBeenCalledOnce());

    await supervisor.dispose();
  });

  it("does not adopt an unrelated HTTP service that only returns status 200", async () => {
    const child = deferredProcess();
    const start = vi.fn(() => child.process);
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))
      .mockResolvedValue(healthyWalletResponse());
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start },
      fetcher,
      wait: async () => undefined,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
      rpOrigin: "http://localhost:5173",
    })).resolves.toMatchObject({ state: "managed", healthy: true });
    expect(start).toHaveBeenCalledOnce();
    await supervisor.dispose();
  });
});
