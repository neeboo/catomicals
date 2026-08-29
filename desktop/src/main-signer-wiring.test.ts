import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("desktop personal signer wiring", () => {
  it("shows the renderer before starting the personal signer", async () => {
    const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");
    const windowReady = source.indexOf("await createWindow();");
    const signerStart = source.indexOf("void configurePersonalSigner();", windowReady);

    expect(source).toContain("new PersonalSignerSupervisor({");
    expect(windowReady).toBeGreaterThan(0);
    expect(signerStart).toBeGreaterThan(windowReady);
  });

  it("routes only confirmed signer settings to the signer supervisor and disposes it on shutdown", async () => {
    const source = await readFile(new URL("./main.ts", import.meta.url), "utf8");

    expect(source).toContain("applyRuntimeSettingsImpact(executorRegistry, review, personalSignerSettingsSink)");
    expect(source).toContain("cleanupSigner: () => personalSignerSupervisor?.dispose() ?? Promise.resolve()");
    expect(source).toContain("await runtimeConfig.signerRuntime()");
  });
});
