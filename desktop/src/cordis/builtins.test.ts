import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createBuiltinCordisHost, FIXED_PLUGIN_IDS } from "./builtins.js";
import { InMemoryCordisStateStore } from "./store.js";

describe("built-in Cordis catalog", () => {
  it("loads the fixed signed first-party catalog", async () => {
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore());

    await host.initialize();

    expect(host.listPlugins()).toEqual(FIXED_PLUGIN_IDS.map((pluginId) => expect.objectContaining({ pluginId, status: "ready" })));
  });

  it("contains no dynamic package, code, shell, or secret-loading path", () => {
    const sources = ["builtins.ts", "host.ts", "manifest.ts", "settings.ts"]
      .map((file) => readFileSync(new URL(file, import.meta.url), "utf8"))
      .join("\n");

    expect(sources).not.toMatch(/child_process|\bspawn\s*\(|\bexec(?:File)?\s*\(|\beval\s*\(|new Function|import\s*\(/);
    expect(sources).not.toContain("privateKey");
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(createBuiltinCordisHost(new InMemoryCordisStateStore()))))
      .not.toEqual(expect.arrayContaining(["install", "loadPackage", "runShell", "readSecret", "approve", "sign", "broadcast"]));
  });
});
