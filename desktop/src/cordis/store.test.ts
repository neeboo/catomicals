import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { digestJson } from "./manifest.js";
import { FileCordisStateStore } from "./store.js";

describe("Cordis plugin state storage", () => {
  it("makes the temporary file and directory durable before save returns", () => {
    const source = readFileSync(new URL("./store.ts", import.meta.url), "utf8");
    const saveStart = source.indexOf("async save(pluginId: string, state: StoredPluginState): Promise<void>", source.indexOf("export class FileCordisStateStore"));
    const fileSync = source.indexOf("file.sync()", saveStart);
    const rename = source.indexOf("rename(temporary, path)", saveStart);
    const directorySync = source.indexOf("directory.sync()", saveStart);

    expect(saveStart).toBeGreaterThan(0);
    expect(fileSync).toBeGreaterThan(saveStart);
    expect(rename).toBeGreaterThan(fileSync);
    expect(directorySync).toBeGreaterThan(rename);
  });

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

  it("uses collision-free temporary files for concurrent writers", async () => {
    const directory = await mkdtemp(join(tmpdir(), "catomicals-cordis-concurrent-"));
    const store = new FileCordisStateStore(directory);
    const pluginId = "@catomicals/plugin-walletd";
    try {
      const writes = Array.from({ length: 24 }, (_, index) => {
        const settings = { endpoint: `http://127.0.0.1:${18_000 + index}` };
        return store.save(pluginId, {
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
      });

      const results = await Promise.allSettled(writes);

      expect(results.every((result) => result.status === "fulfilled")).toBe(true);
      expect((await store.load(pluginId))?.lastGood.settings.endpoint).toMatch(/^http:\/\/127\.0\.0\.1:18\d{3}$/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
