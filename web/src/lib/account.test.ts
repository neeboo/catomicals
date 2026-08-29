import { describe, expect, it } from "vitest";
import { AUTH_PROVIDERS } from "./account";

describe("account provider registry", () => {
  it("keeps identity login separate from transaction authorization", () => {
    expect(AUTH_PROVIDERS.map((provider) => provider.id)).toEqual([
      "google",
      "apple",
      "email",
      "local-device",
    ]);
    expect(AUTH_PROVIDERS.every((provider) => provider.capabilities.includes("identity"))).toBe(true);
    expect(AUTH_PROVIDERS.every((provider) => !provider.capabilities.includes("transaction-signing"))).toBe(true);
  });

  it("marks remote providers unconfigured until their real services exist", () => {
    expect(AUTH_PROVIDERS.filter((provider) => provider.id !== "local-device")
      .every((provider) => provider.status === "unconfigured")).toBe(true);
  });

  it("offers a device-bound local identity without advertising wallet authorization Passkeys", () => {
    const localDevice = AUTH_PROVIDERS.find((provider) => provider.id === "local-device");

    expect(localDevice).toMatchObject({
      status: "ready",
      statusLabel: "由系统安全存储保护",
      capabilities: ["identity"],
      flow: "local-device",
    });
    expect(AUTH_PROVIDERS.some((provider) => provider.capabilities.includes("transaction-signing"))).toBe(false);
  });
});
