import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { isAbsolute, join, parse, sep } from "node:path";
import type { Readable } from "node:stream";

const PROVISIONING_FORMAT_VERSION = 1;
const RUNTIME_FORMAT_VERSION = 2;
const MAX_PROVISIONING_BYTES = 64 * 1024;
const MAX_READY_BYTES = 4 * 1024;
const MAX_STDERR_BYTES = 4 * 1024;
const FIXED_MAX_FRAME_BYTES = 65_536;
const FIXED_MAX_CONNECTIONS = 1;

export interface PersonalSignerRuntimeSettings {
  readonly protocol: "frost-secp256k1-tr-v1";
  readonly signingRounds: 2;
  readonly roundTimeoutMs: number;
  readonly sessionTimeoutMs: number;
}

export type PersonalSignerErrorCode =
  | "provisioning-permissions"
  | "provisioning-invalid"
  | "config-write-failed"
  | "spawn-failed"
  | "ready-invalid"
  | "ready-timeout"
  | "profile-unavailable"
  | "onepassword-unavailable"
  | "secure-enclave-unavailable"
  | "certificate-unavailable"
  | "listener-unavailable"
  | "transport-stopped"
  | "process-failed";

export type PersonalSignerStatus =
  | { readonly state: "unconfigured" }
  | { readonly state: "starting"; readonly generation: number }
  | { readonly state: "ready"; readonly generation: number }
  | { readonly state: "failed"; readonly errorCode: PersonalSignerErrorCode; readonly generation: number }
  | { readonly state: "stopped"; readonly generation: number };

export interface PersonalSignerChild {
  readonly stdout: Readable;
  readonly stderr: Readable;
  kill(signal?: NodeJS.Signals): boolean;
  on(event: "error", listener: (error: Error) => void): this;
  on(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  once(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  removeListener(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
}

export interface PersonalSignerSpawnOptions {
  readonly shell: false;
  readonly windowsHide: true;
  readonly stdio: ["ignore", "pipe", "pipe"];
  readonly env: Readonly<Record<string, never>>;
}

export type SpawnPersonalSigner = (
  command: string,
  args: readonly string[],
  options: PersonalSignerSpawnOptions,
) => PersonalSignerChild;

/** @internal Deterministic race seams used only by supervisor security tests. */
export interface PersonalSignerSupervisorHooks {
  readonly afterInitialDirectorySnapshot?: () => void | Promise<void>;
  readonly afterProvisioningOpen?: () => void | Promise<void>;
  readonly afterRuntimeConfigTemporaryFileCreated?: () => void | Promise<void>;
  readonly beforeRuntimeConfigRename?: () => void | Promise<void>;
  readonly afterRuntimeConfigRename?: () => void | Promise<void>;
}

interface PersonalSignerSupervisorOptions {
  readonly userDataPath: string;
  readonly command: string;
  readonly spawn?: SpawnPersonalSigner;
  readonly readyTimeoutMs?: number;
  readonly stopTimeoutMs?: number;
  readonly hooks?: PersonalSignerSupervisorHooks;
}

interface DirectoryIdentity {
  readonly dev: number;
  readonly ino: number;
}

interface ProvisionedSigner {
  readonly provisioning: PersonalSignerProvisioning;
  readonly directoryIdentity: DirectoryIdentity;
}

interface PersonalSignerProvisioning {
  readonly format_version: 1;
  readonly listen_addr: string;
  readonly profile_path: string;
  readonly onepassword_executable: string;
  readonly wrapped_package_reference: string;
  readonly device_key_id: string;
  readonly server_cert_path: string;
  readonly server_key_path: string;
  readonly client_ca_cert_path: string;
  readonly coordinator_spki_sha256_hex: string;
  readonly device_id: string;
  readonly device_generation: number;
}

interface ReadyDocument {
  readonly event: "personal_signer_status";
  readonly state: "ready";
  readonly signer_id: 2;
  readonly signer_set_id: string;
  readonly epoch: number;
  readonly device_generation: number;
  readonly online: true;
  readonly protocol_profile: "frost-secp256k1-tr-v1";
  readonly signing_rounds: 2;
}

function defaultSpawn(command: string, args: readonly string[], options: PersonalSignerSpawnOptions): PersonalSignerChild {
  return spawn(command, [...args], options) as unknown as PersonalSignerChild;
}

function privateMode(mode: number): boolean {
  return (mode & 0o777) === 0o600;
}

function sameDirectory(left: DirectoryIdentity, right: DirectoryIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function safeAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4096
    && isAbsolute(value) && !/[\0\r\n]/.test(value);
}

function parseProvisioning(value: unknown): PersonalSignerProvisioning {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
  const input = value as Record<string, unknown>;
  const expected = [
    "client_ca_cert_path", "coordinator_spki_sha256_hex", "device_generation", "device_id",
    "device_key_id", "format_version", "listen_addr", "onepassword_executable", "profile_path",
    "server_cert_path", "server_key_path", "wrapped_package_reference",
  ];
  if (Object.keys(input).sort().join(",") !== expected.sort().join(",")
    || input.format_version !== PROVISIONING_FORMAT_VERSION
    || typeof input.listen_addr !== "string"
    || !/^(?:127\.0\.0\.1|\[::1\]):(?:[1-9][0-9]{0,4})$/.test(input.listen_addr)
    || !safeAbsolutePath(input.profile_path)
    || !safeAbsolutePath(input.onepassword_executable)
    || !safeAbsolutePath(input.server_cert_path)
    || !safeAbsolutePath(input.server_key_path)
    || !safeAbsolutePath(input.client_ca_cert_path)
    || typeof input.wrapped_package_reference !== "string"
    || !/^op:\/\/[^\s\0\r\n]{1,2043}$/.test(input.wrapped_package_reference)
    || typeof input.device_key_id !== "string" || input.device_key_id.length < 1 || input.device_key_id.length > 256
    || /[\0\r\n]/.test(input.device_key_id)
    || typeof input.coordinator_spki_sha256_hex !== "string"
    || !/^[0-9a-fA-F]{64}$/.test(input.coordinator_spki_sha256_hex)
    || typeof input.device_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.device_id)
    || !Number.isSafeInteger(input.device_generation) || (input.device_generation as number) < 1) {
    throw new Error("invalid");
  }
  const port = Number(input.listen_addr.slice(input.listen_addr.lastIndexOf(":") + 1));
  if (port > 65_535) throw new Error("invalid");
  return input as unknown as PersonalSignerProvisioning;
}

function validateRuntime(input: PersonalSignerRuntimeSettings): void {
  if (input.protocol !== "frost-secp256k1-tr-v1" || input.signingRounds !== 2
    || !Number.isSafeInteger(input.roundTimeoutMs) || input.roundTimeoutMs < 1_000 || input.roundTimeoutMs > 120_000
    || !Number.isSafeInteger(input.sessionTimeoutMs) || input.sessionTimeoutMs < input.roundTimeoutMs * 2
    || input.sessionTimeoutMs > 900_000) {
    throw new Error("invalid personal signer runtime settings");
  }
}

function parseReady(value: unknown): ReadyDocument {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
  const input = value as Record<string, unknown>;
  const expected = [
    "device_generation", "epoch", "event", "online", "protocol_profile", "signer_id",
    "signer_set_id", "signing_rounds", "state",
  ];
  if (Object.keys(input).sort().join(",") !== expected.sort().join(",")
    || input.event !== "personal_signer_status" || input.state !== "ready" || input.signer_id !== 2
    || typeof input.signer_set_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.signer_set_id)
    || !Number.isSafeInteger(input.epoch) || (input.epoch as number) < 1
    || !Number.isSafeInteger(input.device_generation) || (input.device_generation as number) < 1
    || input.online !== true || input.protocol_profile !== "frost-secp256k1-tr-v1" || input.signing_rounds !== 2) {
    throw new Error("invalid");
  }
  return input as unknown as ReadyDocument;
}

function mappedStderr(value: string): PersonalSignerErrorCode {
  if (value.includes("1Password signer package")) return "onepassword-unavailable";
  if (value.includes("Secure Enclave") || value.includes("device signer package could not be opened")) {
    return "secure-enclave-unavailable";
  }
  if (value.includes("personal signer profile")) return "profile-unavailable";
  if (value.includes("signer certificate") || value.includes("signer transport configuration")) {
    return "certificate-unavailable";
  }
  if (value.includes("signer listener could not start")) return "listener-unavailable";
  if (value.includes("signer transport stopped")) return "transport-stopped";
  return "process-failed";
}

function timerPromise(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  });
}

export class PersonalSignerSupervisor {
  private readonly directory: string;
  private readonly provisioningPath: string;
  private readonly configPath: string;
  private readonly spawn: SpawnPersonalSigner;
  private readonly readyTimeoutMs: number;
  private readonly stopTimeoutMs: number;
  private child: PersonalSignerChild | undefined;
  private statusValue: PersonalSignerStatus = { state: "unconfigured" };
  private activeKey: string | undefined;
  private pendingKey: string | undefined;
  private pending: Promise<PersonalSignerStatus> | undefined;
  private generation = 0;
  private disposed = false;

  constructor(private readonly options: PersonalSignerSupervisorOptions) {
    if (!safeAbsolutePath(options.userDataPath) || !safeAbsolutePath(options.command)) {
      throw new Error("invalid personal signer supervisor path");
    }
    this.directory = join(options.userDataPath, "signers", "personal");
    this.provisioningPath = join(this.directory, "provisioning.json");
    this.configPath = join(this.directory, "runtime-config.json");
    this.spawn = options.spawn ?? defaultSpawn;
    this.readyTimeoutMs = options.readyTimeoutMs ?? 5_000;
    this.stopTimeoutMs = options.stopTimeoutMs ?? 250;
  }

  status(): PersonalSignerStatus {
    return this.statusValue;
  }

  configure(runtime: PersonalSignerRuntimeSettings): Promise<PersonalSignerStatus> {
    if (this.disposed) return Promise.reject(new Error("personal signer supervisor disposed"));
    validateRuntime(runtime);
    const key = JSON.stringify(runtime);
    if (this.pendingKey === key && this.pending) return this.pending;
    if (this.activeKey === key) return Promise.resolve(this.statusValue);
    const generation = this.generation + 1;
    this.generation = generation;
    this.pendingKey = key;
    const pending = this.activate(runtime, key, generation).finally(() => {
      if (this.pending === pending) {
        this.pending = undefined;
        this.pendingKey = undefined;
      }
    });
    this.pending = pending;
    return pending;
  }

  noteConfigurationChange(runtime: PersonalSignerRuntimeSettings): void {
    void this.configure(runtime);
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    this.activeKey = undefined;
    await this.stopChild();
    this.statusValue = { state: "stopped", generation: this.generation };
  }

  private async activate(
    runtime: PersonalSignerRuntimeSettings,
    key: string,
    generation: number,
  ): Promise<PersonalSignerStatus> {
    let provisioned: ProvisionedSigner | undefined;
    try {
      provisioned = await this.readProvisioning();
    } catch (error) {
      const errorCode: PersonalSignerErrorCode = error instanceof Error && error.message === "permissions"
        ? "provisioning-permissions" : "provisioning-invalid";
      return this.finishFailure(generation, errorCode);
    }
    if (!provisioned) {
      await this.stopChild();
      // A stale runtime document contains paths and public metadata only. Do
      // not unlink it through an unverified missing-directory path: without
      // unlinkat that cleanup would reintroduce a parent-directory race.
      this.activeKey = undefined;
      this.statusValue = { state: "unconfigured" };
      return this.statusValue;
    }
    const { provisioning, directoryIdentity } = provisioned;
    if (this.disposed || generation !== this.generation) return { state: "stopped", generation };
    await this.stopChild();
    const document = {
      format_version: RUNTIME_FORMAT_VERSION,
      protocol_profile: runtime.protocol,
      listen_addr: provisioning.listen_addr,
      profile_path: provisioning.profile_path,
      onepassword_executable: provisioning.onepassword_executable,
      wrapped_package_reference: provisioning.wrapped_package_reference,
      device_key_id: provisioning.device_key_id,
      server_cert_path: provisioning.server_cert_path,
      server_key_path: provisioning.server_key_path,
      client_ca_cert_path: provisioning.client_ca_cert_path,
      coordinator_spki_sha256_hex: provisioning.coordinator_spki_sha256_hex,
      device_id: provisioning.device_id,
      device_generation: provisioning.device_generation,
      round_timeout_ms: runtime.roundTimeoutMs,
      session_timeout_ms: runtime.sessionTimeoutMs,
      max_frame_bytes: FIXED_MAX_FRAME_BYTES,
      max_connections: FIXED_MAX_CONNECTIONS,
    };
    try {
      await this.writeRuntimeConfig(`${JSON.stringify(document)}\n`, directoryIdentity);
    } catch {
      return this.finishFailure(generation, "config-write-failed");
    }
    if (this.disposed || generation !== this.generation) return { state: "stopped", generation };
    this.statusValue = { state: "starting", generation };
    let child: PersonalSignerChild;
    try {
      child = this.spawn(
        this.options.command,
        ["signer", "serve", "--config", this.configPath],
        { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: {} },
      );
    } catch {
      return this.finishFailure(generation, "spawn-failed");
    }
    this.child = child;
    const result = await this.awaitReady(child, generation);
    if (result.state === "ready") this.activeKey = key;
    return result;
  }

  private finishFailure(generation: number, errorCode: PersonalSignerErrorCode): PersonalSignerStatus {
    const result: PersonalSignerStatus = { state: "failed", errorCode, generation };
    if (generation === this.generation) this.statusValue = result;
    return result;
  }

  private async readProvisioning(): Promise<ProvisionedSigner | undefined> {
    const directoryIdentity = await this.snapshotPrivateDirectory();
    if (!directoryIdentity) return undefined;
    await this.options.hooks?.afterInitialDirectorySnapshot?.();
    await this.assertDirectoryIdentity(directoryIdentity);
    let file;
    try {
      await this.assertDirectoryIdentity(directoryIdentity);
      file = await open(this.provisioningPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      await this.options.hooks?.afterProvisioningOpen?.();
      await this.assertDirectoryIdentity(directoryIdentity);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("permissions");
      throw error;
    }
    try {
      const metadata = await file.stat();
      if (!metadata.isFile() || !privateMode(metadata.mode)
        || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
        throw new Error("permissions");
      }
      if (metadata.size < 2 || metadata.size > MAX_PROVISIONING_BYTES) throw new Error("invalid");
      const bytes = await file.readFile();
      if (bytes.length > MAX_PROVISIONING_BYTES) throw new Error("invalid");
      const provisioning = parseProvisioning(JSON.parse(bytes.toString("utf8")) as unknown);
      await this.assertDirectoryIdentity(directoryIdentity);
      return { provisioning, directoryIdentity };
    } finally {
      await file.close();
    }
  }

  private async snapshotPrivateDirectory(): Promise<DirectoryIdentity | undefined> {
    const root = parse(this.directory).root;
    const segments = this.directory.slice(root.length).split(sep).filter(Boolean);
    let current = root;
    let metadata;
    for (const segment of segments) {
      current = join(current, segment);
      try {
        metadata = await lstat(current);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
        throw error;
      }
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error("permissions");
    }
    if (!metadata || (metadata.mode & 0o777) !== 0o700
      || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
      throw new Error("permissions");
    }
    return { dev: metadata.dev, ino: metadata.ino };
  }

  private async assertDirectoryIdentity(expected: DirectoryIdentity): Promise<void> {
    const current = await this.snapshotPrivateDirectory();
    if (!current || !sameDirectory(current, expected)) throw new Error("permissions");
  }

  private async unlinkIfDirectoryMatches(path: string, identity: DirectoryIdentity): Promise<void> {
    try {
      await this.assertDirectoryIdentity(identity);
      await unlink(path);
    } catch {
      // Without openat/unlinkat Node cannot safely clean a path after its parent
      // directory was replaced. Fail closed and avoid unlinking an attacker's file.
    }
  }

  private async writeRuntimeConfig(contents: string, directoryIdentity: DirectoryIdentity): Promise<void> {
    const temporaryPath = join(this.directory, `.runtime-config.${randomUUID()}.tmp`);
    let temporary;
    let temporaryIdentity: DirectoryIdentity | undefined;
    let renamed = false;
    let committed = false;
    try {
      // Node does not expose portable openat/renameat. Rechecking the recorded
      // directory identity at every path operation is a fail-closed fallback,
      // not an equivalent replacement for descriptor-relative filesystem APIs.
      await this.assertDirectoryIdentity(directoryIdentity);
      temporary = await open(
        temporaryPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
      const temporaryMetadata = await temporary.stat();
      temporaryIdentity = { dev: temporaryMetadata.dev, ino: temporaryMetadata.ino };
      if (!temporaryMetadata.isFile() || !privateMode(temporaryMetadata.mode)
        || temporaryMetadata.dev !== directoryIdentity.dev
        || (typeof process.getuid === "function" && temporaryMetadata.uid !== process.getuid())) {
        throw new Error("invalid runtime config temporary file");
      }
      await this.options.hooks?.afterRuntimeConfigTemporaryFileCreated?.();
      await this.assertDirectoryIdentity(directoryIdentity);
      await temporary.writeFile(contents, "utf8");
      await temporary.sync();
      await this.assertDirectoryIdentity(directoryIdentity);
      await this.options.hooks?.beforeRuntimeConfigRename?.();
      await this.assertDirectoryIdentity(directoryIdentity);
      await rename(temporaryPath, this.configPath);
      renamed = true;
      await this.options.hooks?.afterRuntimeConfigRename?.();
      await this.assertDirectoryIdentity(directoryIdentity);
      const target = await open(this.configPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        const targetMetadata = await target.stat();
        if (!targetMetadata.isFile() || !privateMode(targetMetadata.mode)
          || !temporaryIdentity || targetMetadata.dev !== temporaryIdentity.dev || targetMetadata.ino !== temporaryIdentity.ino
          || targetMetadata.dev !== directoryIdentity.dev
          || (typeof process.getuid === "function" && targetMetadata.uid !== process.getuid())) {
          throw new Error("invalid runtime config target");
        }
        await this.assertDirectoryIdentity(directoryIdentity);
      } finally {
        await target.close();
      }
      const directory = await open(this.directory, fsConstants.O_RDONLY);
      try {
        const directoryMetadata = await directory.stat();
        if (!sameDirectory(directoryIdentity, { dev: directoryMetadata.dev, ino: directoryMetadata.ino })) {
          throw new Error("runtime config directory changed");
        }
        await this.assertDirectoryIdentity(directoryIdentity);
        await directory.sync();
        await this.assertDirectoryIdentity(directoryIdentity);
      } finally {
        await directory.close();
      }
      committed = true;
    } finally {
      if (!committed && temporary) {
        await temporary.truncate(0).catch(() => undefined);
        await temporary.sync().catch(() => undefined);
      }
      await temporary?.close().catch(() => undefined);
      if (!committed) {
        await this.unlinkIfDirectoryMatches(renamed ? this.configPath : temporaryPath, directoryIdentity);
      }
    }
  }

  private awaitReady(child: PersonalSignerChild, generation: number): Promise<PersonalSignerStatus> {
    return new Promise((resolve) => {
      let completed = false;
      let ready = false;
      let stdout = Buffer.alloc(0);
      let stderr = Buffer.alloc(0);
      const timer = setTimeout(() => fail("ready-timeout"), this.readyTimeoutMs);
      timer.unref();
      const finish = (result: PersonalSignerStatus): void => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        resolve(result);
      };
      const fail = (errorCode: PersonalSignerErrorCode): void => {
        if (completed) return;
        if (this.child === child) this.child = undefined;
        finish(this.finishFailure(generation, errorCode));
        child.kill("SIGTERM");
      };
      child.stderr.on("data", (chunk: Buffer | string) => {
        if (stderr.length >= MAX_STDERR_BYTES) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        stderr = Buffer.concat([stderr, bytes.subarray(0, MAX_STDERR_BYTES - stderr.length)]);
      });
      const onStdout = (chunk: Buffer | string): void => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (ready) {
          fail("ready-invalid");
          return;
        }
        if (stdout.length + bytes.length > MAX_READY_BYTES) {
          fail("ready-invalid");
          return;
        }
        stdout = Buffer.concat([stdout, bytes]);
        const newline = stdout.indexOf(0x0a);
        if (newline < 0) return;
        const tail = stdout.subarray(newline + 1);
        if (tail.length !== 0 || stdout.subarray(0, newline).includes(0x0a)) {
          fail("ready-invalid");
          return;
        }
        try {
          parseReady(JSON.parse(stdout.subarray(0, newline).toString("utf8")) as unknown);
        } catch {
          fail("ready-invalid");
          return;
        }
        ready = true;
        child.stdout.removeListener("data", onStdout);
        child.stdout.pause();
        const result: PersonalSignerStatus = { state: "ready", generation };
        if (generation === this.generation) this.statusValue = result;
        finish(result);
      };
      child.stdout.on("data", onStdout);
      child.on("error", () => fail("spawn-failed"));
      child.on("close", (code) => {
        if (this.child === child) this.child = undefined;
        if (!ready) {
          fail(code === 0 ? "process-failed" : mappedStderr(stderr.toString("utf8")));
          return;
        }
        if (!this.disposed && generation === this.generation) {
          this.activeKey = undefined;
          this.statusValue = { state: "failed", errorCode: mappedStderr(stderr.toString("utf8")), generation };
        }
      });
    });
  }

  private async stopChild(): Promise<void> {
    const child = this.child;
    this.child = undefined;
    if (!child) return;
    let closed = false;
    const close = new Promise<void>((resolve) => {
      const listener = (): void => {
        closed = true;
        child.removeListener("close", listener);
        resolve();
      };
      child.once("close", listener);
    });
    child.kill("SIGTERM");
    await Promise.race([close, timerPromise(this.stopTimeoutMs)]);
    if (!closed) {
      child.kill("SIGKILL");
      await Promise.race([close, timerPromise(this.stopTimeoutMs)]);
    }
  }
}
