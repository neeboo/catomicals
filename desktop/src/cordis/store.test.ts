import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { digestJson } from "./manifest.js";
import { FileCordisStateStore } from "./store.js";

describe("Cordis plugin state storage", () => {
  it("stores each last-good tree in a separate private namespace", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-cordis-"));
    const store = new FileCordisStateStore(directory);
    const pluginId = "@catomicals/plugin-walletd";
    const settings = { endpoint: "http://127.0.0.1:18787" };
    try {
      await store.save(pluginId, {
        storageVersion: 1,
        pluginId,
        lastGood: {
          pluginVersion: "1.0.0",
          settingsSchemaVersion: 1,
          migrationVersion: 0,
          settings,
          settingsDigest: digestJson(settings),
        },
      });

      expect(await store.load(pluginId)).toMatchObject({ pluginId, lastGood: { settings } });
      const files = await import("node:fs/promises").then(({ readdir }) => readdir(join(directory, "cordis", "plugins")));
      expect(files).toHaveLength(1);
      expect(files[0]).not.toContain("walletd");
      const mode = await import("node:fs/promises").then(({ stat }) => stat(join(directory, "cordis", "plugins", files[0]!)));
      expect(mode.mode & 0o777).toBe(0o600);
      expect(await readFile(join(directory, "cordis", "plugins", files[0]!), "utf8")).not.toContain("privateKey");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
