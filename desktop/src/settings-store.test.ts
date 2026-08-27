import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SettingsStore, parsePersistedSettings } from "./settings-store";
import { DESKTOP_ENDPOINTS } from "./runtime-security";

describe("desktop settings persistence", () => {
  it("rejects unknown persisted fields by falling back to safe defaults", () => {
    const parsed = parsePersistedSettings({
      defaultHarness: "claude-code",
      adapters: {},
      apiKey: "secret",
    });
    expect(parsed.defaultHarness).toBe("codex");
    expect(JSON.stringify(parsed)).not.toContain("secret");
  });

  it("takes the wallet endpoint from the shared desktop runtime contract", () => {
    expect(parsePersistedSettings(undefined).walletNodeUrl).toBe(DESKTOP_ENDPOINTS.walletNodeUrl);
    const source = readFileSync(new URL("./settings-store.ts", import.meta.url), "utf8");
    expect(source).not.toContain('walletNodeUrl: "http://127.0.0.1:18787"');
  });

  it("falls back to safe defaults when persisted URLs fail strict validation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-settings-"));
    const store = new SettingsStore(directory);
    try {
      const valid = parsePersistedSettings(undefined);
      await writeFile(store.path, JSON.stringify({
        ...valid,
        walletNodeUrl: "https://wallet.example",
        browserHome: "file:///etc/passwd",
      }));

      const recovered = await store.read();

      expect(recovered).toEqual(valid);
      await expect(store.write({ ...valid, walletNodeUrl: "https://wallet.example" }))
        .rejects.toThrow("wallet node");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
