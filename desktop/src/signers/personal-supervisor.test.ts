import { EventEmitter } from "node:events";
import { constants as fsConstants } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
  PersonalSignerSupervisor,
  type PersonalSignerChild,
  type PersonalSignerRuntimeSettings,
  type SpawnPersonalSigner,
} from "./personal-supervisor.js";

const runtime: PersonalSignerRuntimeSettings = {
  protocol: "frost-secp256k1-tr-v1",
  signingRounds: 2,
  roundTimeoutMs: 30_000,
  sessionTimeoutMs: 120_000,
};

const provisioning = {
  format_version: 1,
  listen_addr: "127.0.0.1:19787",
  profile_path: "/private/personal/profile.bin",
  onepassword_executable: "/usr/local/bin/op",
  wrapped_package_reference: "op://Private/Catomicals/package",
  device_key_id: "catomicals-personal-signer",
  server_cert_path: "/private/personal/server.pem",
  server_key_path: "/private/personal/server-key.pem",
  client_ca_cert_path: "/private/personal/client-ca.pem",
  coordinator_spki_sha256_hex: "11".repeat(32),
  device_id: "11111111-1111-4111-8111-111111111111",
  device_generation: 1,
};

class FakeChild extends EventEmitter implements PersonalSignerChild {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly kill = vi.fn((signal?: NodeJS.Signals) => {
    queueMicrotask(() => this.emit("close", signal === "SIGKILL" ? null : 0, signal ?? null));
    return true;
  });

  ready(): void {
    this.stdout.write(`${JSON.stringify({
      event: "personal_signer_status",
      state: "ready",
      signer_id: 2,
      signer_set_id: "22222222-2222-4222-8222-222222222222",
      epoch: 1,
      device_generation: 1,
      online: true,
      protocol_profile: "frost-secp256k1-tr-v1",
      signing_rounds: 2,
    })}\n`);
  }

  exit(code = 1): void {
    this.emit("close", code, null);
  }
}

async function fixture(options: { provisioned?: boolean; spawn?: SpawnPersonalSigner } = {}) {
  const root = await mkdtemp(join(tmpdir(), "catomicals-personal-signer-"));
  const signerDirectory = join(root, "signers", "personal");
  await mkdir(signerDirectory, { recursive: true, mode: 0o700 });
  await chmod(signerDirectory, 0o700);
  if (options.provisioned !== false) {
    await writeFile(join(signerDirectory, "provisioning.json"), JSON.stringify(provisioning), {
      mode: 0o600,
      flag: fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    });
  }
  const children: FakeChild[] = [];
  const spawn = options.spawn ?? vi.fn(() => {
    const child = new FakeChild();
    children.push(child);
    return child;
  });
  return {
    root,
    signerDirectory,
    configPath: join(signerDirectory, "runtime-config.json"),
    children,
    spawn,
    supervisor: new PersonalSignerSupervisor({
      userDataPath: root,
      command: "/workspace/target/debug/catomicals",
      spawn,
      readyTimeoutMs: 100,
      stopTimeoutMs: 10,
    }),
  };
}

describe("personal FROST signer supervisor", () => {
  it("stays unconfigured and does not write or spawn when host provisioning is absent", async () => {
    const context = await fixture({ provisioned: false });

    await expect(context.supervisor.configure(runtime)).resolves.toEqual({ state: "unconfigured" });

    await expect(readFile(context.configPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(context.spawn).not.toHaveBeenCalled();
  });

  it("atomically writes a private format-v2 runtime and starts only the exact signer command", async () => {
    const context = await fixture();
    const configured = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(1));
    context.children[0]!.ready();

    await expect(configured).resolves.toMatchObject({ state: "ready", generation: 1 });
    expect(context.spawn).toHaveBeenCalledWith(
      "/workspace/target/debug/catomicals",
      ["signer", "serve", "--config", context.configPath],
      { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: {} },
    );
    const document = JSON.parse(await readFile(context.configPath, "utf8")) as Record<string, unknown>;
    expect(document).toEqual({
      format_version: 2,
      protocol_profile: "frost-secp256k1-tr-v1",
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
      round_timeout_ms: 30_000,
      session_timeout_ms: 120_000,
      max_frame_bytes: 65_536,
      max_connections: 1,
    });
    expect((await stat(context.signerDirectory)).mode & 0o777).toBe(0o700);
    expect((await stat(context.configPath)).mode & 0o777).toBe(0o600);
    expect((await readFile(context.configPath, "utf8"))).not.toMatch(/signing_share|secret_share|private_key|package_content/i);
    expect((context.spawn as ReturnType<typeof vi.fn>).mock.calls[0]).not.toContain("op://Private/Catomicals/package");
  });

  it("rejects a world-readable provisioning file before reading or spawning", async () => {
    const context = await fixture();
    await chmod(join(context.signerDirectory, "provisioning.json"), 0o644);

    await expect(context.supervisor.configure(runtime)).resolves.toEqual({
      state: "failed",
      errorCode: "provisioning-permissions",
      generation: 1,
    });
    expect(context.spawn).not.toHaveBeenCalled();
  });

  it("rejects provisioning from a group-readable signer directory", async () => {
    const context = await fixture();
    await chmod(context.signerDirectory, 0o750);

    await expect(context.supervisor.configure(runtime)).resolves.toMatchObject({
      state: "failed",
      errorCode: "provisioning-permissions",
    });
    expect(context.spawn).not.toHaveBeenCalled();
  });

  it("accepts one bounded ready document and rejects oversized or additional stdout", async () => {
    const oversized = await fixture();
    const oversizedResult = oversized.supervisor.configure(runtime);
    await vi.waitFor(() => expect(oversized.children).toHaveLength(1));
    oversized.children[0]!.stdout.write("x".repeat(4_097));
    await expect(oversizedResult).resolves.toMatchObject({ state: "failed", errorCode: "ready-invalid" });

    const additional = await fixture();
    const additionalResult = additional.supervisor.configure(runtime);
    await vi.waitFor(() => expect(additional.children).toHaveLength(1));
    additional.children[0]!.stdout.write(`${JSON.stringify({
      event: "personal_signer_status",
      state: "ready",
      signer_id: 2,
      signer_set_id: "22222222-2222-4222-8222-222222222222",
      epoch: 1,
      device_generation: 1,
      online: true,
      protocol_profile: "frost-secp256k1-tr-v1",
      signing_rounds: 2,
    })}\nunexpected\n`);
    await expect(additionalResult).resolves.toMatchObject({ state: "failed", errorCode: "ready-invalid" });
  });

  it("detaches stdout immediately after the single ready document", async () => {
    const context = await fixture();
    const configured = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(1));
    context.children[0]!.ready();

    await expect(configured).resolves.toMatchObject({ state: "ready" });
    expect(context.children[0]!.stdout.listenerCount("data")).toBe(0);
  });

  it("maps stderr to fixed codes without returning or logging raw process output", async () => {
    const secret = "private-package-material-should-never-surface";
    const context = await fixture();
    const configured = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(1));
    context.children[0]!.stderr.write(`1Password signer package is unavailable: ${secret}`);
    context.children[0]!.exit(1);

    const result = await configured;
    expect(result).toEqual({ state: "failed", errorCode: "onepassword-unavailable", generation: 1 });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("starts each changed generation once, deduplicates identical settings, and never restarts a crashed child", async () => {
    const context = await fixture();
    const first = context.supervisor.configure(runtime);
    const duplicate = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(1));
    context.children[0]!.ready();
    await expect(first).resolves.toMatchObject({ state: "ready", generation: 1 });
    await expect(duplicate).resolves.toMatchObject({ state: "ready", generation: 1 });
    expect(context.spawn).toHaveBeenCalledTimes(1);

    context.children[0]!.exit(1);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(context.spawn).toHaveBeenCalledTimes(1);

    const retry = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(2));
    context.children[1]!.ready();
    await expect(retry).resolves.toMatchObject({ state: "ready", generation: 2 });
    expect(context.spawn).toHaveBeenCalledTimes(2);

    const second = context.supervisor.configure({ ...runtime, roundTimeoutMs: 45_000 });
    await vi.waitFor(() => expect(context.children).toHaveLength(3));
    context.children[2]!.ready();
    await expect(second).resolves.toMatchObject({ state: "ready", generation: 3 });
    expect(context.spawn).toHaveBeenCalledTimes(3);
  });

  it("interrupts the signer and removes listeners during desktop shutdown", async () => {
    const context = await fixture();
    const configured = context.supervisor.configure(runtime);
    await vi.waitFor(() => expect(context.children).toHaveLength(1));
    context.children[0]!.ready();
    await configured;

    await context.supervisor.dispose();

    expect(context.children[0]!.kill).toHaveBeenCalledWith("SIGTERM");
    await expect(context.supervisor.configure(runtime)).rejects.toThrow("disposed");
  });
});
