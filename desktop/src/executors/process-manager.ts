import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { ExecutorCommand } from "./types.js";

const MAX_OUTPUT_BYTES = 1_000_000;
const TERMINATION_GRACE_MILLISECONDS = 250;

export interface ProcessResult {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: string;
}

export interface RunningProcess {
  readonly completion: Promise<ProcessResult>;
  interrupt(): boolean;
}

export interface ProcessHost {
  probe(command: ExecutorCommand, timeoutMilliseconds?: number): Promise<ProcessResult>;
  start(command: ExecutorCommand, environmentOverrides?: ExecutorEnvironmentOverrides): RunningProcess;
  dispose(): Promise<void>;
}

export interface ExecutorEnvironmentOverrides {
  readonly CATOMICALS_CORDIS_BRIDGE_URL: string;
  readonly CATOMICALS_CORDIS_SESSION_TOKEN: string;
}

interface CapturedStream {
  readonly chunks: Buffer[];
  totalBytes: number;
}

function normalizedSpawnError(error: unknown): string {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return error.code;
  }
  return "spawn-failed";
}

function selectedEnvironment(keys: readonly string[]): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const key of keys) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

function applyEnvironmentOverrides(
  environment: NodeJS.ProcessEnv,
  overrides: ExecutorEnvironmentOverrides | undefined,
): NodeJS.ProcessEnv {
  if (!overrides) return environment;
  const entries = Object.entries(overrides);
  const allowed = new Set(["CATOMICALS_CORDIS_BRIDGE_URL", "CATOMICALS_CORDIS_SESSION_TOKEN"]);
  if (entries.length !== allowed.size || entries.some(([key, value]) => (
    !allowed.has(key) || typeof value !== "string" || value === "" || value.includes("\0")
  ))) {
    throw new Error("invalid executor environment override");
  }
  return { ...environment, ...overrides };
}

export class NodeProcessHost implements ProcessHost {
  private readonly children = new Set<ChildProcessWithoutNullStreams>();

  start(command: ExecutorCommand, environmentOverrides?: ExecutorEnvironmentOverrides): RunningProcess {
    const child = spawn(command.executable, [...command.args], {
      cwd: command.cwd,
      env: applyEnvironmentOverrides(selectedEnvironment(command.environmentKeys), environmentOverrides),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdin.end();
    this.children.add(child);

    const stdout: CapturedStream = { chunks: [], totalBytes: 0 };
    const stderr: CapturedStream = { chunks: [], totalBytes: 0 };
    let overflow = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;
    let resolveCompletion!: (result: ProcessResult) => void;
    const completion = new Promise<ProcessResult>((resolve) => { resolveCompletion = resolve; });

    const interruptChild = (): boolean => {
      if (settled) return false;
      const signaled = child.kill("SIGTERM");
      killTimer ??= setTimeout(() => {
        if (!settled) child.kill("SIGKILL");
      }, TERMINATION_GRACE_MILLISECONDS);
      killTimer.unref();
      return signaled;
    };
    const stopForOutputLimit = (): void => {
      if (overflow) return;
      overflow = true;
      interruptChild();
    };
    const append = (stream: CapturedStream, chunk: Buffer): void => {
      if (stream.totalBytes >= MAX_OUTPUT_BYTES) {
        stopForOutputLimit();
        return;
      }
      const available = MAX_OUTPUT_BYTES - stream.totalBytes;
      if (available <= 0) {
        stopForOutputLimit();
        return;
      }
      if (chunk.length > available) stopForOutputLimit();
      const captured = chunk.subarray(0, available);
      if (captured.length === 0) return;
      stream.chunks.push(captured);
      stream.totalBytes += captured.length;
    };
    child.stdout.on("data", (chunk: Buffer) => { append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { append(stderr, chunk); });

    const finalize = (stream: CapturedStream): string => {
      if (stream.chunks.length === 0) return "";
      if (stream.chunks.length === 1) return stream.chunks[0]!.toString("utf8");
      return Buffer.concat(stream.chunks, stream.totalBytes).toString("utf8");
    };

    const finish = (result: ProcessResult): void => {
      if (settled) return;
      settled = true;
      if (killTimer) clearTimeout(killTimer);
      this.children.delete(child);
      resolveCompletion(result);
    };
    child.once("error", (error) => {
      finish({
        exitCode: null,
        signal: null,
        stdout: finalize(stdout),
        stderr: finalize(stderr),
        error: normalizedSpawnError(error),
      });
    });
    child.once("close", (exitCode, signal) => {
      finish({
        exitCode,
        signal,
        stdout: finalize(stdout),
        stderr: finalize(stderr),
        ...(overflow ? { error: "output-limit" } : {}),
      });
    });

    return {
      completion,
      interrupt: interruptChild,
    };
  }

  async probe(command: ExecutorCommand, timeoutMilliseconds = 3_000): Promise<ProcessResult> {
    const running = this.start(command);
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<ProcessResult>((resolve) => {
      timer = setTimeout(() => {
        running.interrupt();
        resolve({ exitCode: null, signal: "SIGTERM", stdout: "", stderr: "", error: "probe-timeout" });
      }, timeoutMilliseconds);
    });
    const result = await Promise.race([running.completion, timeout]);
    if (timer) clearTimeout(timer);
    return result;
  }

  async dispose(): Promise<void> {
    const children = [...this.children];
    for (const child of children) child.kill("SIGTERM");
    const forceTimer = setTimeout(() => {
      for (const child of children) {
        if (this.children.has(child)) child.kill("SIGKILL");
      }
    }, TERMINATION_GRACE_MILLISECONDS);
    await Promise.all(children.map((child) => new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else child.once("close", () => resolve());
    })));
    clearTimeout(forceTimer);
  }
}
