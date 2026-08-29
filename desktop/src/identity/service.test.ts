import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LocalDeviceIdentityProvider } from "./provider";
import { IdentityService } from "./service";
import { IdentityStore, type IdentityCipher } from "./store";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const cipher: IdentityCipher = {
  encrypt: (value) => Buffer.from(value, "utf8"),
  decrypt: (value) => value.toString("utf8"),
};

describe("identity service", () => {
  it("creates and restores a local-device session through a provider adapter", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const store = new IdentityStore(root, cipher);
    const provider = new LocalDeviceIdentityProvider({
      now: () => 1_775_000_000_000,
      randomId: (() => {
        const ids = ["a4f36bdd-66d9-4d87-a070-4e3ad531d12f", "c1f66ac1-3b46-4c93-afdb-38c301a97732"];
        return () => ids.shift()!;
      })(),
    });
    const service = new IdentityService(store, [provider]);

    await expect(service.state()).resolves.toEqual({ available: true, session: null });
    const created = await service.login({ provider: "local-device" });
    expect(created).toMatchObject({
      provider: "local-device",
      accountId: "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
      sessionId: "c1f66ac1-3b46-4c93-afdb-38c301a97732",
      displayName: "本机用户",
    });
    await expect(new IdentityService(new IdentityStore(root, cipher), [provider]).state())
      .resolves.toEqual({ available: true, session: created });
  });

  it("clears the active identity session on logout", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const service = new IdentityService(
      new IdentityStore(root, cipher),
      [new LocalDeviceIdentityProvider()],
    );
    await service.login({ provider: "local-device" });

    await service.logout();

    await expect(service.state()).resolves.toEqual({ available: true, session: null });
  });

  it("reuses the device account and rotates only the login session after logout", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const ids = [
      "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
      "c1f66ac1-3b46-4c93-afdb-38c301a97732",
      "ef5915ae-9384-4321-90d7-4542f5ddfabc",
    ];
    const service = new IdentityService(
      new IdentityStore(root, cipher),
      [new LocalDeviceIdentityProvider({ randomId: () => ids.shift()! })],
    );
    const first = await service.login({ provider: "local-device" });
    await service.logout();

    const second = await service.login({ provider: "local-device" });

    expect(second.accountId).toBe(first.accountId);
    expect(second.sessionId).not.toBe(first.sessionId);
  });

  it("serializes concurrent first logins onto one durable device account", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const ids = [
      "a4f36bdd-66d9-4d87-a070-4e3ad531d12f",
      "c1f66ac1-3b46-4c93-afdb-38c301a97732",
      "ef5915ae-9384-4321-90d7-4542f5ddfabc",
    ];
    const service = new IdentityService(
      new IdentityStore(root, cipher),
      [new LocalDeviceIdentityProvider({ randomId: () => ids.shift()! })],
    );

    const [first, second] = await Promise.all([
      service.login({ provider: "local-device" }),
      service.login({ provider: "local-device" }),
    ]);

    expect(second.accountId).toBe(first.accountId);
    expect(second.sessionId).not.toBe(first.sessionId);
    await expect(service.state()).resolves.toEqual({ available: true, session: second });
  });

  it("rejects providers that are not backed by a configured adapter", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const service = new IdentityService(new IdentityStore(root, cipher), []);

    await expect(service.login({ provider: "google" as never })).rejects.toThrow("identity provider unavailable");
  });

  it("reports damaged encrypted identity data as an explicit recoverable state", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const store = new IdentityStore(root, cipher);
    await writeFile(store.path, JSON.stringify({ version: 1, ciphertext: Buffer.from("/Users/private/not-json").toString("base64") }));
    const service = new IdentityService(store, [new LocalDeviceIdentityProvider()]);

    await expect(service.state()).resolves.toEqual({
      available: true,
      session: null,
      issue: "identity-data-corrupt",
    });
  });

  it("resets damaged identity data only through an explicit recovery action", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    const store = new IdentityStore(root, cipher);
    await writeFile(store.profilePath, "{broken:/Users/private/profile}");
    const service = new IdentityService(store, [new LocalDeviceIdentityProvider()]);
    const recover = (service as unknown as { recover(): Promise<void> }).recover;

    expect(recover).toBeTypeOf("function");
    await recover.call(service);

    await expect(service.state()).resolves.toEqual({ available: true, session: null });
  });

  it("rechecks protected storage availability for every state and login operation", async () => {
    const root = await mkdtemp(join(tmpdir(), "catomicals-identity-service-"));
    roots.push(root);
    let current: IdentityCipher | undefined;
    const store = new IdentityStore(root, { current: () => current });
    const service = new IdentityService(store, [new LocalDeviceIdentityProvider()]);

    await expect(service.state()).resolves.toEqual({ available: false, session: null });
    current = cipher;
    await expect(service.state()).resolves.toEqual({ available: true, session: null });
    await expect(service.login({ provider: "local-device" })).resolves.toMatchObject({ provider: "local-device" });
    current = undefined;
    await expect(service.state()).resolves.toEqual({ available: false, session: null });
    await expect(service.login({ provider: "local-device" })).rejects.toThrow("secure storage unavailable");
  });
});
