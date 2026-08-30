import { describe, expect, it, vi } from "vitest";
import { createBuiltinCordisHost } from "./builtins.js";
import type { CordisService } from "./health.js";
import { cordisAccess } from "./permissions.js";
import {
  applyStartupWalletEndpoint,
  resolveStartupWalletEndpoint,
} from "./startup-wallet-settings.js";
import { InMemoryCordisStateStore } from "./store.js";

const walletPluginId = "@catomicals/plugin-walletd";
const settingsReadAccess = cordisAccess("plugin.settings.read");

function walletHealth(healthyEndpoint: string): CordisService {
  return {
    name: "walletd.health",
    health: async ({ settings }) => settings.endpoint === healthyEndpoint
      ? { status: "healthy" }
      : { status: "unhealthy", message: "wallet offline" },
  };
}

describe("startup wallet settings", () => {
  it("accepts a loopback development endpoint and ignores startup overrides in packaged builds", () => {
    expect(resolveStartupWalletEndpoint({
      packaged: false,
      value: "http://127.0.0.1:18787",
    })).toBe("http://127.0.0.1:18787");
    expect(resolveStartupWalletEndpoint({
      packaged: true,
      value: "https://attacker.example",
    })).toBeUndefined();
  });

  it.each([
    "https://127.0.0.1:18787",
    "http://wallet.example:18787",
    "http://user:password@127.0.0.1:18787",
    "http://127.0.0.1:18787/api/v1",
    "http://127.0.0.1:18787/?token=secret",
  ])("rejects an invalid development wallet endpoint: %s", (value) => {
    expect(() => resolveStartupWalletEndpoint({ packaged: false, value })).toThrow("wallet");
  });

  it("does not create an intent when the persisted endpoint already matches", async () => {
    const host = createBuiltinCordisHost(
      new InMemoryCordisStateStore(),
      [walletHealth("http://127.0.0.1:18787")],
    );
    await host.initialize();
    const createIntent = vi.spyOn(host, "createSettingsIntent");

    await applyStartupWalletEndpoint(host, "http://127.0.0.1:18787");

    expect(createIntent).not.toHaveBeenCalled();
  });

  it("uses the host validation, intent, and desktop confirmation path while preserving managed mode", async () => {
    const host = createBuiltinCordisHost(
      new InMemoryCordisStateStore(),
      [walletHealth("http://127.0.0.1:28787")],
    );
    await host.initialize();
    const validate = vi.spyOn(host, "validateSettingsPatch");
    const createIntent = vi.spyOn(host, "createSettingsIntent");
    const confirmIntent = vi.spyOn(host, "confirmSettingsIntent");

    await applyStartupWalletEndpoint(host, "http://127.0.0.1:28787");

    expect(validate).toHaveBeenCalledOnce();
    expect(createIntent).toHaveBeenCalledWith(walletPluginId, {
      schemaVersion: 2,
      changes: [{ id: "endpoint", value: "http://127.0.0.1:28787" }],
    }, expect.any(Object));
    expect(confirmIntent).toHaveBeenCalledOnce();
    await expect(host.readPluginSettings(walletPluginId, settingsReadAccess)).resolves.toMatchObject({
      settings: {
        endpoint: "http://127.0.0.1:28787",
        processMode: "managed",
      },
    });
  });

  it("does not replace last-good settings when the candidate endpoint is unhealthy", async () => {
    const store = new InMemoryCordisStateStore();
    const host = createBuiltinCordisHost(store, [walletHealth("http://127.0.0.1:18787")]);
    await host.initialize();
    const before = await store.load(walletPluginId);

    await expect(applyStartupWalletEndpoint(host, "http://127.0.0.1:28787"))
      .rejects.toThrow("health");

    const after = await store.load(walletPluginId);
    expect(after?.lastGood).toEqual(before?.lastGood);
    expect(after?.lastGood.settings).toMatchObject({
      endpoint: "http://127.0.0.1:18787",
      processMode: "managed",
    });
  });
});
