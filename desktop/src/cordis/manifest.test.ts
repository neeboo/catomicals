import { describe, expect, it } from "vitest";
import { createSignedFixture } from "./test-fixtures.js";
import { parsePluginManifest, verifyFixedPluginPackage } from "./manifest.js";

describe("fixed Cordis plugin manifests", () => {
  it("accepts a closed B0 manifest and verifies its package attestation", () => {
    const { registration, trust } = createSignedFixture();

    expect(verifyFixedPluginPackage(registration, trust).plugin_id).toBe(registration.id);
  });

  it("rejects unknown manifest fields", () => {
    const { registration } = createSignedFixture();

    expect(() => parsePluginManifest({ ...registration.manifest as object, installScript: "postinstall.sh" }))
      .toThrow("unexpected fields");
  });

  it("rejects package tampering and signatures outside the fixed trust entry", () => {
    const { registration, trust } = createSignedFixture();

    expect(() => verifyFixedPluginPackage({ ...registration, descriptor: registration.descriptor + "tampered" }, trust))
      .toThrow("package digest");
    expect(() => verifyFixedPluginPackage({ ...registration, signature: Buffer.alloc(64).toString("base64") }, trust))
      .toThrow("attestation");
  });

  it("binds catalog category and capabilities into the signed manifest", () => {
    const { registration, trust } = createSignedFixture({
      catalog: { category: "chain", capabilities: ["chain.rpc", "chain.address"] },
    });
    expect(verifyFixedPluginPackage(registration, trust).catalog).toEqual({
      category: "chain",
      capabilities: ["chain.rpc", "chain.address"],
    });

    const manifest = structuredClone(registration.manifest);
    manifest.catalog = { category: "agent", capabilities: ["agent.executor"] };
    expect(() => verifyFixedPluginPackage({ ...registration, manifest }, trust)).toThrow("attestation");
  });

  it("rejects unsafe wallet authority and secret scopes", () => {
    const { registration } = createSignedFixture();
    const manifest = {
      ...registration.manifest,
      permission_scopes: ["wallet.sign", "secret.read"],
    };

    expect(() => parsePluginManifest(manifest)).toThrow("permission scope");
  });
});
