import { isAbsolute } from "node:path";
import type { ExecutorCommand } from "./executors/types.js";
import type { RunningProcess } from "./executors/process-manager.js";
import { parseLoopbackWalletEndpoint } from "./cordis/runtime-config.js";

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

export interface WalletRuntimeSettings {
  readonly endpoint: string;
  readonly processMode: "managed" | "external";
  readonly rpOrigin: string;
  readonly walletDataDirectory?: string;
  readonly bitcoinDataDirectory?: string;
}

export interface WalletSupervisorStatus {
  readonly state: "managed" | "adopted" | "external";
  readonly healthy: boolean;
  readonly endpoint: string;
}

interface WalletProcessHost {
  start(command: ExecutorCommand): RunningProcess;
}

interface WalletNodeSupervisorOptions {
  readonly command: string;
  readonly processHost: WalletProcessHost;
  readonly fetcher?: Fetcher;
  readonly wait?: (milliseconds: number) => Promise<void>;
}

const STARTUP_ATTEMPTS = 40;
const STARTUP_INTERVAL_MILLISECONDS = 100;
const RESTART_DELAY_MILLISECONDS = 250;
const ADOPTED_HEALTH_INTERVAL_MILLISECONDS = 5_000;
const MAXIMUM_HEALTH_RESPONSE_BYTES = 64 * 1024;

interface WalletHealthDocument {
  readonly network: "signet";
  readonly rp_id: string;
  readonly rp_origin: string;
  readonly production_ready: boolean;
  readonly runtime_mode: "compatibility" | "durable";
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  });
}

function parseLoopbackOrigin(value: string): URL {
  const origin = new URL(value);
  const hostname = origin.hostname.toLowerCase();
  if (origin.protocol !== "http:"
    || !["localhost", "127.0.0.1", "[::1]"].includes(hostname)
    || origin.username || origin.password
    || (origin.pathname !== "/" && origin.pathname !== "")
    || origin.search || origin.hash) {
    throw new Error("wallet RP origin must be an unauthenticated loopback HTTP origin");
  }
  return origin;
}

function validateDataDirectory(value: string | undefined, label = "data"): string | undefined {
  if (value === undefined) return undefined;
  if (!isAbsolute(value) || value.length > 4096 || /[\0\r\n]/.test(value)) {
    throw new Error(`invalid ${label} directory`);
  }
  return value;
}

export class WalletNodeSupervisor {
  private readonly fetcher: Fetcher;
  private readonly wait: (milliseconds: number) => Promise<void>;
  private child: RunningProcess | undefined;
  private settings: WalletRuntimeSettings | undefined;
  private disposed = false;
  private generation = 0;

  constructor(private readonly options: WalletNodeSupervisorOptions) {
    if (options.command.trim() === "" || options.command.length > 4096 || /[\0\r\n]/.test(options.command)) {
      throw new Error("invalid wallet command");
    }
    this.fetcher = options.fetcher ?? fetch;
    this.wait = options.wait ?? delay;
  }

  async start(input: WalletRuntimeSettings): Promise<WalletSupervisorStatus> {
    if (this.disposed) throw new Error("wallet supervisor disposed");
    const endpoint = parseLoopbackWalletEndpoint(input.endpoint);
    const rpOrigin = parseLoopbackOrigin(input.rpOrigin).origin;
    const walletDataDirectory = validateDataDirectory(input.walletDataDirectory, "wallet data");
    const bitcoinDataDirectory = validateDataDirectory(input.bitcoinDataDirectory, "Bitcoin data");
    if (input.processMode !== "managed" && input.processMode !== "external") {
      throw new Error("invalid wallet process mode");
    }
    this.settings = {
      endpoint,
      processMode: input.processMode,
      rpOrigin,
      ...(walletDataDirectory ? { walletDataDirectory } : {}),
      ...(bitcoinDataDirectory ? { bitcoinDataDirectory } : {}),
    };

    const healthy = await this.probe(endpoint, rpOrigin);
    if (healthy) {
      if (input.processMode === "managed") {
        const generation = ++this.generation;
        void this.monitorAdopted(this.settings, generation);
      }
      return { state: "adopted", healthy: true, endpoint };
    }
    if (input.processMode === "external") return { state: "external", healthy: false, endpoint };
    return this.launch(this.settings);
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    const child = this.child;
    this.child = undefined;
    child?.interrupt();
  }

  private command(settings: WalletRuntimeSettings): ExecutorCommand {
    const endpoint = new URL(settings.endpoint);
    const port = endpoint.port || "80";
    const address = `${endpoint.hostname}:${port}`;
    const rpOrigin = new URL(settings.rpOrigin);
    const args = [
      "wallet", "serve",
      "--addr", address,
      "--rp-id", rpOrigin.hostname,
      "--rp-origin", rpOrigin.origin,
      "--cors-origin", rpOrigin.origin,
    ];
    if (settings.walletDataDirectory) args.push("--data-dir", settings.walletDataDirectory);
    if (settings.bitcoinDataDirectory) args.push("--datadir", settings.bitcoinDataDirectory);
    return { executable: this.options.command, args, environmentKeys: [] };
  }

  private async probe(endpoint: string, expectedRpOrigin: string): Promise<boolean> {
    try {
      const response = await this.fetcher(`${endpoint}/api/v1/node/status`, {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        signal: AbortSignal.timeout(1_500),
      });
      if (!response.ok) return false;
      const contentLength = response.headers.get("content-length");
      if (contentLength !== null) {
        const declaredLength = Number(contentLength);
        if (!Number.isSafeInteger(declaredLength)
          || declaredLength < 0
          || declaredLength > MAXIMUM_HEALTH_RESPONSE_BYTES) return false;
      }
      const body = await response.text();
      if (new TextEncoder().encode(body).byteLength > MAXIMUM_HEALTH_RESPONSE_BYTES) return false;
      const document = JSON.parse(body) as Partial<WalletHealthDocument> | null;
      if (!document || typeof document !== "object" || Array.isArray(document)) return false;
      const expectedOrigin = parseLoopbackOrigin(expectedRpOrigin);
      return document.network === "signet"
        && document.rp_id === expectedOrigin.hostname
        && document.rp_origin === expectedOrigin.origin
        && typeof document.production_ready === "boolean"
        && (document.runtime_mode === "compatibility" || document.runtime_mode === "durable");
    } catch {
      return false;
    }
  }

  private async launch(settings: WalletRuntimeSettings): Promise<WalletSupervisorStatus> {
    if (this.disposed) throw new Error("wallet supervisor disposed");
    const generation = ++this.generation;
    const child = this.options.processHost.start(this.command(settings));
    this.child = child;
    void child.completion.then(() => this.childExited(child, generation));

    for (let attempt = 0; attempt < STARTUP_ATTEMPTS; attempt += 1) {
      if (this.disposed || this.child !== child) throw new Error("wallet startup interrupted");
      if (await this.probe(settings.endpoint, settings.rpOrigin)) {
        return { state: "managed", healthy: true, endpoint: settings.endpoint };
      }
      await this.wait(STARTUP_INTERVAL_MILLISECONDS);
    }
    child.interrupt();
    if (this.child === child) this.child = undefined;
    throw new Error("managed wallet node did not become healthy");
  }

  private async childExited(child: RunningProcess, generation: number): Promise<void> {
    if (this.disposed || this.child !== child || this.generation !== generation) return;
    this.child = undefined;
    const settings = this.settings;
    if (!settings || settings.processMode !== "managed") return;
    await this.wait(RESTART_DELAY_MILLISECONDS);
    if (this.disposed || this.generation !== generation) return;
    if (await this.probe(settings.endpoint, settings.rpOrigin)) {
      this.generation += 1;
      return;
    }
    await this.launch(settings).catch(() => undefined);
  }

  private async monitorAdopted(settings: WalletRuntimeSettings, generation: number): Promise<void> {
    await this.wait(ADOPTED_HEALTH_INTERVAL_MILLISECONDS);
    if (this.disposed || this.generation !== generation || this.child) return;
    if (await this.probe(settings.endpoint, settings.rpOrigin)) {
      void this.monitorAdopted(settings, generation);
      return;
    }
    await this.launch(settings).catch(() => undefined);
  }
}
