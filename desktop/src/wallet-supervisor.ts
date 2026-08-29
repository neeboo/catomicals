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
  readonly signing?: ChainSigningSelection;
}

export type ChainId = "bitcoin" | "bitcoin-cash" | "bsv" | "fractal-bitcoin" | "kaspa" | "chia" | "ergo";

export interface ChainScopeDocument {
  readonly schema_version: 1;
  readonly chain: ChainId;
  readonly network: string;
}

export interface SignerProfileDocument {
  readonly signer_set_id: string;
  readonly epoch: number;
  readonly min_signers: number;
  readonly max_signers: number;
}

export interface ChainSignerProfileDocument {
  readonly profile_id: string | null;
  readonly signer_set_id: string;
  readonly epoch: number;
  readonly min_signers: number;
  readonly max_signers: number;
}

export interface ChainSigningSelection {
  readonly chainScope: ChainScopeDocument;
  readonly signingSuiteId: string;
}

export interface ChainSigningRuntimeStatus {
  readonly chain_scope: ChainScopeDocument;
  readonly signing_suite_id: string;
  readonly suite_availability: "declaration-only" | "executable";
  readonly signer_profile: ChainSignerProfileDocument | null;
  readonly backend: {
    readonly id: string;
    readonly state: "ready" | "starting" | "unavailable" | "failed";
  };
  readonly ready_for_signing: boolean;
}

export interface WalletSupervisorStatus {
  readonly state: "managed" | "adopted" | "external";
  readonly healthy: boolean;
  readonly endpoint: string;
  readonly signing: ChainSigningRuntimeStatus | null;
  readonly degradedReason: "wallet-authority-unavailable" | "chain-status-unavailable" | null;
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
  readonly rp_id: string;
  readonly rp_origin: string;
  readonly production_ready: boolean;
  readonly runtime_mode: "compatibility" | "durable";
}

const CHAIN_IDS = new Set<ChainId>([
  "bitcoin", "bitcoin-cash", "bsv", "fractal-bitcoin", "kaspa", "chia", "ergo",
]);

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$/.test(value);
}

function parseChainScope(value: unknown): ChainScopeDocument {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid chain scope");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).sort().join(",") !== "chain,network,schema_version"
    || input.schema_version !== 1 || typeof input.chain !== "string"
    || !CHAIN_IDS.has(input.chain as ChainId) || typeof input.network !== "string"
    || !input.network.startsWith(`${input.chain}.`) || input.network.length > 128) {
    throw new Error("invalid chain scope");
  }
  return input as unknown as ChainScopeDocument;
}

function parseChainSignerProfile(value: unknown): ChainSignerProfileDocument | null {
  if (value === null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid signer profile");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).sort().join(",") !== "epoch,max_signers,min_signers,profile_id,signer_set_id"
    || (input.profile_id !== null && (typeof input.profile_id !== "string"
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.profile_id)))
    || !validIdentifier(input.signer_set_id)
    || !Number.isSafeInteger(input.epoch) || (input.epoch as number) < 1
    || !Number.isSafeInteger(input.min_signers) || (input.min_signers as number) < 1
    || !Number.isSafeInteger(input.max_signers) || (input.max_signers as number) < (input.min_signers as number)) {
    throw new Error("invalid signer profile");
  }
  return input as unknown as ChainSignerProfileDocument;
}

function validateSigningSelection(value: ChainSigningSelection | undefined): ChainSigningSelection | undefined {
  if (value === undefined) return undefined;
  const chainScope = parseChainScope(value.chainScope);
  if (!validIdentifier(value.signingSuiteId)) throw new Error("invalid signing suite id");
  return { chainScope, signingSuiteId: value.signingSuiteId };
}

function parseSigningStatus(value: unknown): ChainSigningRuntimeStatus {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid chain signing status");
  const input = value as Record<string, unknown>;
  const backend = input.backend;
  if (Object.keys(input).sort().join(",") !== "backend,chain_scope,ready_for_signing,signer_profile,signing_suite_id,suite_availability"
    || !validIdentifier(input.signing_suite_id)
    || (input.suite_availability !== "declaration-only" && input.suite_availability !== "executable")
    || typeof input.ready_for_signing !== "boolean"
    || !backend || typeof backend !== "object" || Array.isArray(backend)) {
    throw new Error("invalid chain signing status");
  }
  const backendInput = backend as Record<string, unknown>;
  if (Object.keys(backendInput).sort().join(",") !== "id,state" || !validIdentifier(backendInput.id)
    || !["ready", "starting", "unavailable", "failed"].includes(String(backendInput.state))) {
    throw new Error("invalid chain signing backend status");
  }
  parseChainScope(input.chain_scope);
  const signerProfile = parseChainSignerProfile(input.signer_profile);
  if (input.ready_for_signing && (!signerProfile?.profile_id || backendInput.state !== "ready")) {
    throw new Error("invalid ready chain signing status");
  }
  return input as unknown as ChainSigningRuntimeStatus;
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
    const signing = validateSigningSelection(input.signing);
    if (input.processMode !== "managed" && input.processMode !== "external") {
      throw new Error("invalid wallet process mode");
    }
    this.settings = {
      endpoint,
      processMode: input.processMode,
      rpOrigin,
      ...(walletDataDirectory ? { walletDataDirectory } : {}),
      ...(bitcoinDataDirectory ? { bitcoinDataDirectory } : {}),
      ...(signing ? { signing } : {}),
    };

    const healthy = await this.probe(endpoint, rpOrigin);
    if (healthy) {
      const signingStatus = signing
        ? await this.configureSigning(endpoint, signing)
        : await this.readChainSigningStatus(endpoint);
      if (input.processMode === "managed") {
        const generation = ++this.generation;
        void this.monitorAdopted(this.settings, generation);
      }
      return {
        state: "adopted",
        healthy: true,
        endpoint,
        signing: signingStatus,
        degradedReason: signingStatus ? null : "chain-status-unavailable",
      };
    }
    if (input.processMode === "external") {
      return {
        state: "external",
        healthy: false,
        endpoint,
        signing: null,
        degradedReason: "wallet-authority-unavailable",
      };
    }
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
    if (settings.walletDataDirectory) {
      args.push(
        "--data-dir", settings.walletDataDirectory,
        "--allow-self-hosted-development-secrets",
      );
    }
    if (settings.bitcoinDataDirectory) args.push("--datadir", settings.bitcoinDataDirectory);
    return { executable: this.options.command, args, environmentKeys: [] };
  }

  private async configureSigning(
    endpoint: string,
    signing: ChainSigningSelection,
  ): Promise<ChainSigningRuntimeStatus> {
    const response = await this.fetcher(`${endpoint}/api/v1/chains/config`, {
      method: "POST",
      credentials: "omit",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chain_scope: signing.chainScope,
        signing_suite_id: signing.signingSuiteId,
      }),
    });
    if (!response.ok) throw new Error("wallet chain configuration was rejected");
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > MAXIMUM_HEALTH_RESPONSE_BYTES) {
      throw new Error("wallet chain configuration response is too large");
    }
    return parseSigningStatus(JSON.parse(body));
  }

  private async readChainSigningStatus(endpoint: string): Promise<ChainSigningRuntimeStatus | null> {
    try {
      const response = await this.fetcher(`${endpoint}/api/v1/chains/status`, {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return null;
      const body = await response.text();
      if (new TextEncoder().encode(body).byteLength > MAXIMUM_HEALTH_RESPONSE_BYTES) {
        return null;
      }
      const document = JSON.parse(body) as Record<string, unknown>;
      if (!document || document.schema_version !== 1 || !Array.isArray(document.chains)) {
        return null;
      }
      const statuses = document.chains.map(parseSigningStatus);
      return statuses.find((status) => status.ready_for_signing) ?? statuses[0] ?? null;
    } catch {
      return null;
    }
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
      return document.rp_id === expectedOrigin.hostname
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
        const signing = settings.signing
          ? await this.configureSigning(settings.endpoint, settings.signing)
          : await this.readChainSigningStatus(settings.endpoint);
        return {
          state: "managed",
          healthy: true,
          endpoint: settings.endpoint,
          signing,
          degradedReason: signing ? null : "chain-status-unavailable",
        };
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
