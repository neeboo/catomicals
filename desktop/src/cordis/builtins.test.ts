import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createBuiltinCordisHost, FIXED_PLUGIN_IDS } from "./builtins.js";
import type { CordisService } from "./health.js";
import { cordisAccess } from "./permissions.js";
import { InMemoryCordisStateStore } from "./store.js";

describe("built-in Cordis catalog", () => {
  const catalogAccess = cordisAccess("plugin.catalog.read");
  const healthAccess = cordisAccess("plugin.health.read");

  it("isolates core plugins until their required services are registered", async () => {
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore());

    await host.initialize();

    expect(host.listPlugins(catalogAccess)).toEqual(FIXED_PLUGIN_IDS.map((pluginId, index) => expect.objectContaining({
      pluginId,
      status: index < 4 ? "isolated" : "ready",
      ...(index < 4 ? { errorCode: "missing_service" } : {}),
    })));
  });

  it("refreshes built-in health against registered backend services", async () => {
    const statuses = new Map<string, "healthy" | "unhealthy">([
      ["walletd.health", "healthy"],
      ["bitcoin.node.health", "healthy"],
      ["indexer.health", "healthy"],
      ["mcp.health", "healthy"],
    ]);
    const services: CordisService[] = [...statuses.keys()].map((name) => ({
      name,
      health: async () => ({ status: statuses.get(name) ?? "unhealthy" }),
    }));
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), services);

    await host.initialize();
    expect(host.listPlugins(catalogAccess)).toEqual(FIXED_PLUGIN_IDS.map((pluginId) => expect.objectContaining({
      pluginId,
      status: "ready",
    })));

    statuses.set("walletd.health", "unhealthy");
    expect(await host.readHealth("@catomicals/plugin-walletd", healthAccess)).toMatchObject({ status: "isolated", code: "health_failed" });
    statuses.set("walletd.health", "healthy");
    expect(await host.readHealth("@catomicals/plugin-walletd", healthAccess)).toMatchObject({ status: "healthy" });
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

  it("does not report optional executor, browser, or backup runtimes as healthy when unavailable", async () => {
    const services: CordisService[] = [
      "executor.codex.health", "executor.deepseek.health", "executor.claude.code.health", "browser.health", "backup.health",
    ].map((name) => ({ name, health: async () => ({ status: "degraded", message: "runtime unavailable" }) }));
    const host = createBuiltinCordisHost(new InMemoryCordisStateStore(), services);
    await host.initialize();

    await expect(host.readHealth("@catomicals/plugin-executor-codex", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
    await expect(host.readHealth("@catomicals/plugin-browser", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
    await expect(host.readHealth("@catomicals/plugin-backup", healthAccess))
      .resolves.toMatchObject({ status: "degraded", message: "runtime unavailable" });
  });
});
