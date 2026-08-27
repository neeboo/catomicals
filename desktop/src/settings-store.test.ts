import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SettingsStore, parsePersistedSettings } from "./settings-store";

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

  it("exposes legacy runtime fields once and persists only the UI preference after completion", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-settings-"));
    const store = new SettingsStore(directory);
    try {
      await writeFile(store.path, JSON.stringify({
        version: 1,
        defaultHarness: "deepseek",
        adapters: {
          codex: { command: "legacy-codex", defaultModel: "old", reasoningEffort: "high", workingDirectory: "/old" },
          deepseek: { command: "legacy-dsh", defaultModel: "", reasoningEffort: "high", workingDirectory: "/old" },
          "claude-code": { command: "legacy-claude", defaultModel: "old", reasoningEffort: "high", workingDirectory: "/old" },
        },
        mcpEnabled: false,
        walletNodeUrl: "http://127.0.0.1:18787",
        browserHome: "https://example.com",
      }));

      await expect(store.readLegacyRuntimeSettings()).resolves.toMatchObject({
        adapters: { codex: { command: "legacy-codex", defaultModel: "old" } },
        browserHome: "https://example.com",
        mcpEnabled: false,
      });
      await expect(store.read()).resolves.toEqual({ version: 2, defaultHarness: "deepseek" });
      expect(JSON.parse(await readFile(store.path, "utf8"))).toMatchObject({ version: 1, adapters: expect.any(Object) });

      await store.completeLegacyRuntimeMigration({ version: 2, defaultHarness: "deepseek" });

      expect(JSON.parse(await readFile(store.path, "utf8"))).toEqual({ version: 2, defaultHarness: "deepseek" });
      await expect(store.readLegacyRuntimeSettings()).resolves.toBeUndefined();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects runtime fields from current settings writes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-settings-"));
    const store = new SettingsStore(directory);
    try {
      const valid = { version: 2, defaultHarness: "codex" } as const;

      await expect(store.write({ ...valid, walletNodeUrl: "http://127.0.0.1:18787" }))
        .rejects.toThrow("fields");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
