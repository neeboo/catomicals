import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { ExecutorCommand } from "./types.js";

const MAX_OUTPUT_BYTES = 1_000_000;

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
  start(command: ExecutorCommand): RunningProcess;
  dispose(): Promise<void>;
}

function normalizedSpawnError(error: unknown): string {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return error.code;
  }
  return "spawn-failed";
}

export class NodeProcessHost implements ProcessHost {
  private readonly children = new Set<ChildProcessWithoutNullStreams>();

  start(command: ExecutorCommand): RunningProcess {
    const child = spawn(command.executable, [...command.args], {
      cwd: command.cwd,
      env: process.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdin.end();
    this.children.add(child);

    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let overflow = false;
    let settled = false;
    let resolveCompletion!: (result: ProcessResult) => void;
    const completion = new Promise<ProcessResult>((resolve) => { resolveCompletion = resolve; });

    const append = (current: Buffer, chunk: Buffer): Buffer => {
      if (current.length >= MAX_OUTPUT_BYTES) return current;
      const available = MAX_OUTPUT_BYTES - current.length;
      if (chunk.length > available) overflow = true;
      return Buffer.concat([current, chunk.subarray(0, available)]);
    };
    child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });

    const finish = (result: ProcessResult): void => {
      if (settled) return;
      settled = true;
      this.children.delete(child);
      resolveCompletion(result);
    };
    child.once("error", (error) => {
      finish({
        exitCode: null,
        signal: null,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        error: normalizedSpawnError(error),
      });
    });
    child.once("close", (exitCode, signal) => {
      finish({
        exitCode,
        signal,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        ...(overflow ? { error: "output-limit" } : {}),
      });
    });

    return {
      completion,
      interrupt: (): boolean => settled ? false : child.kill("SIGTERM"),
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
    await Promise.all(children.map((child) => new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else child.once("close", () => resolve());
    })));
  }
}
