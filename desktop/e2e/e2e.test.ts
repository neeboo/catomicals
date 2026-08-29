/**
 * Electron/browser E2E for the session-backed chat shell. Builds the web
 * renderer and the desktop main process, then launches the real Electron app
 * twice against the same temp userData:
 *
 *   phase 1 — create two sessions, send/store wallet-safe messages through
 *             a deterministic DeepSeek CLI fixture (no network or broadcast),
 *             rename/archive/unarchive/recoverable delete/restore, cross-
 *             session content search opening the matched session, and a
 *             `catomicals://session/<id>` open-url deep link.
 *   phase 2 — restart/reopen: the launch-time deep link opens session A and
 *             the transcript is reconstructed from the persisted JSONL log;
 *             session list, rename, and cross-session search survive restart.
 */

import { execFileSync, spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// The electron package's Node entry is the binary path string.
import electron from "electron";

const desktopRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const projectRoot = dirname(desktopRoot);
const driverPath = join(desktopRoot, "e2e", "driver.mjs");
const electronBinary = electron as unknown as string;

interface PhaseResult {
  code: number;
  result: {
    phase: number;
    ok?: boolean;
    steps?: Array<{ name: string; ok: boolean; detail?: string }>;
    sessionA?: string;
    sessionB?: string;
    error?: string;
  } | null;
  stdout: string;
  stderr: string;
}

function runPhase(args: string[], userDataDir: string, executorBin: string): Promise<PhaseResult> {
  return new Promise((resolve, reject) => {
    // --no-sandbox/--disable-gpu keep the harness environment able to spawn
    // Electron's helper processes; the app's own renderer sandbox and all
    // main-process security checks are untouched.
    const child = spawn(electronBinary, ["--no-sandbox", "--disable-gpu", driverPath, `--user-data-dir=${userDataDir}`, ...args], {
      env: {
        ...process.env,
        CATOMICALS_E2E: "1",
        PATH: `${executorBin}:${process.env.PATH ?? ""}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`e2e phase timed out (args: ${args.join(" ")})`));
    }, 120_000);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const match = stdout.match(/E2E_RESULT (\{.*\})/);
      resolve({
        code: code ?? -1,
        result: match ? JSON.parse(match[1]) as PhaseResult["result"] : null,
        stdout,
        stderr,
      });
    });
  });
}

function installDeterministicDeepseek(userDataDir: string): string {
  const bin = join(userDataDir, "e2e-bin");
  mkdirSync(bin, { recursive: true });
  const command = join(bin, "dsh");
  writeFileSync(command, `#!/bin/sh
if [ "$*" = "--version" ]; then
  printf '%s\\n' 'dsh 0.1.1-e2e'
elif [ "$*" = "--profile headless --help" ]; then
  printf '%s\\n' 'Usage: dsh --profile headless' 'task'
elif [ "$*" = "--help" ]; then
  printf '%s\\n' 'Usage: dsh'
else
  printf '%s\\n' '## E2E agent' '' '已记录。'
fi
`, "utf8");
  chmodSync(command, 0o755);
  return bin;
}

function buildOnce(): void {
  execFileSync("pnpm", ["build"], { cwd: join(projectRoot, "web"), stdio: "inherit" });
  execFileSync("pnpm", ["build:electron"], { cwd: desktopRoot, stdio: "inherit" });
}

describe("chat shell session E2E", () => {
  it(
    "creates, stores, searches, manages, deep-links, and restores sessions across a restart",
    { timeout: 240_000 },
    async () => {
      buildOnce();
      const userDataDir = mkdtempSync(join(tmpdir(), "catomicals-e2e-"));
      const executorBin = installDeterministicDeepseek(userDataDir);
      try {
        const phase1 = await runPhase(["--phase=1"], userDataDir, executorBin);
        expect(phase1.code, `phase 1 exited ${phase1.code}\n${phase1.stderr}`).toBe(0);
        expect(phase1.result?.ok, phase1.stdout).toBe(true);
        expect(phase1.result?.sessionA).toBeTruthy();
        expect(phase1.result?.sessionB).toBeTruthy();
        expect(phase1.result?.sessionA).not.toBe(phase1.result?.sessionB);

        const steps1 = phase1.result?.steps ?? [];
        const byName = (name: string) => steps1.find((step) => step.name === name);
        expect(byName("create two sessions")?.ok).toBe(true);
        expect(byName("send and store message A with a terminal agent turn")?.ok).toBe(true);
        expect(byName("send and store message B")?.ok).toBe(true);
        expect(byName("cross-session search opens the matched session")?.ok).toBe(true);
        expect(byName("rename session")?.ok).toBe(true);
        expect(byName("archive/unarchive session")?.ok).toBe(true);
        expect(byName("recoverable delete + restore")?.ok).toBe(true);
        expect(byName("catomicals://session/<id> opens the exact session")?.ok).toBe(true);

        const phase2 = await runPhase(
          ["--phase=2", `--session-a=${phase1.result!.sessionA}`, `--session-b=${phase1.result!.sessionB}`, `catomicals://session/${phase1.result!.sessionA}`],
          userDataDir,
          executorBin,
        );
        expect(phase2.code, `phase 2 exited ${phase2.code}\n${phase2.stderr}`).toBe(0);
        expect(phase2.result?.ok, phase2.stdout).toBe(true);
        const steps2 = phase2.result?.steps ?? [];
        const byName2 = (name: string) => steps2.find((step) => step.name === name);
        expect(byName2("transcript restored after restart (launch deeplink)")?.ok).toBe(true);
        expect(byName2("session title persisted through restart")?.ok).toBe(true);
        expect(byName2("cross-session search after restart")?.ok).toBe(true);
      } finally {
        rmSync(userDataDir, { recursive: true, force: true });
      }
    },
  );
});
