import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IdentityStore, type IdentityCipher, type IdentityProfile, type IdentitySession } from "./store";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function reversibleTestCipher(): IdentityCipher {
  return {
    encrypt: (value) => Buffer.from(`sealed:${value}`, "utf8"),
    decrypt: (value) => value.toString("utf8").replace(/^sealed:/, ""),
  };
}

const session: IdentitySession = {
  version: 1,
  provider: "local-device",
  accountId: "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
  sessionId: "c1f66ac1-3b46-4c93-afdb-38c301a97732",
  displayName: "本机用户",
  createdAt: 1_775_000_000_000,
  authenticatedAt: 1_775_000_000_000,
};

const profile: IdentityProfile = {
  version: 1,
  provider: "local-device",
  accountId: session.accountId,
  displayName: session.displayName,
  createdAt: session.createdAt,
};

describe("identity session persistence", () => {
  it("restores an encrypted local identity after constructing a fresh store", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const first = new IdentityStore(root, reversibleTestCipher());

    await first.write(session);

    const persisted = await readFile(first.path, "utf8");
    expect(persisted).not.toContain(session.accountId);
    expect(persisted).not.toContain(session.sessionId);
    expect(persisted).not.toContain(session.displayName);
    await expect(new IdentityStore(root, reversibleTestCipher()).read()).resolves.toEqual(session);
  });

  it("removes the durable session on logout", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const store = new IdentityStore(root, reversibleTestCipher());
    await store.write(session);

    await store.clear();

    await expect(store.read()).resolves.toBeNull();
  });

  it("keeps the encrypted device profile when the login session is cleared", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const store = new IdentityStore(root, reversibleTestCipher());
    await store.writeProfile(profile);
    await store.write(session);

    await store.clear();

    await expect(store.read()).resolves.toBeNull();
    await expect(new IdentityStore(root, reversibleTestCipher()).readProfile()).resolves.toEqual(profile);
    expect(await readFile(store.profilePath, "utf8")).not.toContain(profile.accountId);
  });

  it("fails closed when secure storage is unavailable", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const store = new IdentityStore(root);

    expect(store.available).toBe(false);
    await expect(store.write(session)).rejects.toThrow("secure storage unavailable");
    await expect(store.read()).resolves.toBeNull();
  });

  it("rejects oversized identity files before decrypting them", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const decrypt = vi.fn((value: Buffer) => value.toString("utf8"));
    const store = new IdentityStore(root, {
      encrypt: (value) => Buffer.from(value, "utf8"),
      decrypt,
    });
    await writeFile(store.path, JSON.stringify({ version: 1, ciphertext: "A".repeat(16 * 1024) }));

    await expect(store.read()).rejects.toThrow("identity data is corrupted");
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("removes its temporary file when the atomic rename fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-"));
    roots.push(root);
    const store = new IdentityStore(root, reversibleTestCipher());
    await mkdir(store.path);

    await expect(store.write(session)).rejects.toThrow();

    expect((await readdir(root)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});
