import { describe, expect, it } from "vitest";
import { AUTH_PROVIDERS } from "./account";

describe("account provider registry", () => {
  it("keeps identity login separate from transaction authorization", () => {
    expect(AUTH_PROVIDERS.map((provider) => provider.id)).toEqual([
      "google",
      "apple",
      "email",
      "passkey",
    ]);
    expect(AUTH_PROVIDERS.every((provider) => provider.capabilities.includes("identity"))).toBe(true);
    expect(AUTH_PROVIDERS.every((provider) => !provider.capabilities.includes("transaction-signing"))).toBe(true);
  });

  it("marks remote providers unconfigured until their real services exist", () => {
    expect(AUTH_PROVIDERS.filter((provider) => provider.id !== "passkey")
      .every((provider) => provider.status === "unconfigured")).toBe(true);
  });
});
