import { describe, expect, it, vi } from "vitest";
import type { RunningProcess } from "./executors/process-manager.js";
import { WalletNodeSupervisor } from "./wallet-supervisor.js";

const bitcoinSignet = {
  schema_version: 1 as const,
  chain: "bitcoin" as const,
  network: "bitcoin.signet" as const,
};

const bitcoinSigningStatus = {
  chain_scope: bitcoinSignet,
  signing_suite_id: "btc.bip340.frost-secp256k1-tr.v1" as const,
  suite_availability: "executable" as const,
  signer_profile: null,
  backend: { id: "frost-secp256k1-tr", state: "ready" as const },
  ready_for_signing: false,
};

function chainStatusResponse(status = bitcoinSigningStatus): Response {
  return new Response(JSON.stringify({ schema_version: 1, chains: [status] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function healthyWalletResponse(overrides: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify({
    network: "signet",
    rp_id: "localhost",
    rp_origin: "http://localhost:5173",
    production_ready: false,
    runtime_mode: "compatibility",
    ...overrides,
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

function nonSignetStatus(
  chain: "bitcoin-cash" | "chia" | "ergo",
  network: string,
): typeof bitcoinSigningStatus {
  return {
    ...bitcoinSigningStatus,
    chain_scope: { schema_version: 1, chain, network },
    signing_suite_id: `${chain}.threshold-signing.v1`,
    suite_availability: "declaration-only",
    backend: { id: `${chain}-signer`, state: "unavailable" },
    ready_for_signing: false,
  } as unknown as typeof bitcoinSigningStatus;
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
  it.each([
    ["bitcoin-cash", "bitcoin-cash.chipnet"],
    ["chia", "chia.testnet11"],
    ["ergo", "ergo.testnet"],
  ] as const)("adopts wallet authority independently from the %s chain network", async (chain, network) => {
    const signingStatus = nonSignetStatus(chain, network);
    const fetcher = vi.fn()
      .mockResolvedValueOnce(healthyWalletResponse({ network: "legacy-value-must-be-ignored" }))
      .mockResolvedValueOnce(chainStatusResponse(signingStatus));
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start: vi.fn() },
      fetcher,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
    })).resolves.toMatchObject({
      state: "adopted",
      healthy: true,
      degradedReason: null,
      signing: { chain_scope: { chain, network } },
    });
  });

  it.each([
    { rp_id: "attacker.invalid" },
    { rp_origin: "http://localhost:9999" },
    { runtime_mode: "unknown" },
  ])("does not adopt a response with the wrong wallet authority: %o", async (override) => {
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start: vi.fn() },
      fetcher: async () => healthyWalletResponse(override),
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
    })).resolves.toEqual({
      state: "external",
      healthy: false,
      endpoint: "http://127.0.0.1:18787",
      signing: null,
      degradedReason: "wallet-authority-unavailable",
    });
  });

  it("reports chain status degradation without inventing a Bitcoin scope", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockResolvedValueOnce(new Response("unavailable", { status: 503 }));
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start: vi.fn() },
      fetcher,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
    })).resolves.toEqual({
      state: "adopted",
      healthy: true,
      endpoint: "http://127.0.0.1:18787",
      signing: null,
      degradedReason: "chain-status-unavailable",
    });
  });

  it("reads the default Bitcoin signing status from the wallet instead of claiming a static signer", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockResolvedValueOnce(chainStatusResponse({
        ...bitcoinSigningStatus,
        signer_profile: {
          profile_id: "10101010-1010-4010-8010-101010101010",
          signer_set_id: "11111111-1111-4111-8111-111111111111",
          epoch: 2,
          min_signers: 2,
          max_signers: 3,
        },
        ready_for_signing: true,
      }));
    const supervisor = new WalletNodeSupervisor({
      command: "catomicals",
      processHost: { start: vi.fn() },
      fetcher,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
    })).resolves.toMatchObject({
      signing: {
        signer_profile: { epoch: 2, min_signers: 2, max_signers: 3 },
        ready_for_signing: true,
      },
    });
    expect(fetcher).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1:18787/api/v1/chains/status",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("configures and reports an explicit chain scope, signing suite, profile, and backend", async () => {
    const start = vi.fn();
    const fetcher = vi.fn()
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockResolvedValueOnce(new Response(JSON.stringify({
        ...bitcoinSigningStatus,
        signer_profile: {
          profile_id: "10101010-1010-4010-8010-101010101010",
          signer_set_id: "11111111-1111-4111-8111-111111111111",
          epoch: 2,
          min_signers: 2,
          max_signers: 3,
        },
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const supervisor = new WalletNodeSupervisor({
      command: "/workspace/target/debug/catomicals",
      processHost: { start },
      fetcher,
    });

    await expect(supervisor.start({
      endpoint: "http://127.0.0.1:18787",
      processMode: "external",
      rpOrigin: "http://localhost:5173",
      signing: {
        chainScope: bitcoinSignet,
        signingSuiteId: "btc.bip340.frost-secp256k1-tr.v1",
      },
    })).resolves.toMatchObject({
      state: "adopted",
      healthy: true,
      signing: {
        chain_scope: bitcoinSignet,
        signing_suite_id: "btc.bip340.frost-secp256k1-tr.v1",
        backend: { state: "ready" },
      },
    });
    expect(fetcher).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1:18787/api/v1/chains/config",
      expect.objectContaining({ method: "POST", body: expect.any(String) }),
    );
    expect(start).not.toHaveBeenCalled();
  });
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
        "--allow-self-hosted-development-secrets",
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
      .mockResolvedValueOnce(chainStatusResponse())
      .mockRejectedValueOnce(new TypeError("stopped"))
      .mockResolvedValueOnce(healthyWalletResponse())
      .mockResolvedValue(chainStatusResponse());
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
