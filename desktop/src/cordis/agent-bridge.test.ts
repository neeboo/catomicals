import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  CORDIS_AGENT_PERMISSION_SCOPES,
  cordisPatchToExternal,
  externalPatchToCordis,
  isLoopbackAddress,
  startCordisAgentBridge,
  type CordisAgentBridgeHost,
} from "./agent-bridge.js";

const pluginId = "@catomicals/plugin-mcp";
const protocolSessionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function host(): CordisAgentBridgeHost {
  return {
    listPlugins: vi.fn(() => [{ pluginId, pluginVersion: "1.0.0", status: "ready" }] as const),
    readManifest: vi.fn(() => ({ plugin_id: pluginId })),
    readSettingsSchema: vi.fn(() => ({ version: 1, fields: [] })),
    readHealth: vi.fn(async () => ({ status: "healthy", code: "ok", message: "healthy", checkedAt: "2026-08-28T00:00:00.000Z" })),
    validateSettingsPatch: vi.fn(() => ({ valid: true, settingsDigest: `sha256:${"a".repeat(64)}`, restartImpact: "none" })),
    createSettingsIntent: vi.fn(async () => ({ reviewId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" })),
  };
}

async function request(
  endpoint: string,
  token: string,
  route: string,
  body: string | object,
  init: RequestInit = {},
): Promise<Response> {
  return fetch(`${endpoint}/v1/cordis/${route}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...init.headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
    redirect: "manual",
    ...init,
  });
}

describe("Cordis private agent bridge", () => {
  it("listens on a random IPv4 loopback port and exposes exactly six POST routes", async () => {
    const bridgeHost = host();
    const bridge = await startCordisAgentBridge({ host: bridgeHost });
    const credential = bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    try {
      const routes: readonly [string, object, keyof CordisAgentBridgeHost][] = [
        ["list_plugins", {}, "listPlugins"],
        ["read_plugin_manifest", { plugin_id: pluginId }, "readManifest"],
        ["read_plugin_settings_schema", { plugin_id: pluginId }, "readSettingsSchema"],
        ["read_plugin_health", { plugin_id: pluginId }, "readHealth"],
        ["validate_plugin_settings_patch", {
          plugin_id: pluginId,
          patch: { schema_version: 1, changes: { enabled: true, retries: 3 } },
        }, "validateSettingsPatch"],
        ["create_plugin_settings_intent", {
          plugin_id: pluginId,
          patch: { schema_version: 1, changes: { enabled: false } },
        }, "createSettingsIntent"],
      ];

      expect(new URL(bridge.endpoint).hostname).toBe("127.0.0.1");
      expect(Number(new URL(bridge.endpoint).port)).toBeGreaterThan(0);

      for (const [route, body, method] of routes) {
        const response = await request(bridge.endpoint, credential.token, route, body);
        expect(response.status, route).toBe(200);
        expect(await response.json()).toMatchObject({ ok: true });
        expect(bridgeHost[method]).toHaveBeenCalledOnce();
      }
      expect(bridgeHost.validateSettingsPatch).toHaveBeenCalledWith(
        pluginId,
        {
          schemaVersion: 1,
          changes: [{ id: "enabled", value: true }, { id: "retries", value: 3 }],
        },
        expect.objectContaining({ scopes: CORDIS_AGENT_PERMISSION_SCOPES }),
      );

      const unavailable = await request(bridge.endpoint, credential.token, "apply_plugin_settings", {});
      expect(unavailable.status).toBe(404);
      expect(await unavailable.json()).toEqual({
        ok: false,
        error: { code: "route_not_found", message: "route not found" },
      });

      const getResponse = await fetch(`${bridge.endpoint}/v1/cordis/list_plugins`, {
        headers: { authorization: `Bearer ${credential.token}` },
        redirect: "manual",
      });
      expect(getResponse.status).toBe(405);
    } finally {
      await bridge.close();
    }
  });

  it("binds fixed permissions to the token and ignores no caller-declared authority", async () => {
    const bridgeHost = host();
    const bridge = await startCordisAgentBridge({ host: bridgeHost });
    const credential = bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    try {
      const response = await request(bridge.endpoint, credential.token, "list_plugins", {
        permission_scope: "plugin.settings_intent.create",
      });
      expect(response.status).toBe(400);
      expect(bridgeHost.listPlugins).not.toHaveBeenCalled();

      const valid = await request(bridge.endpoint, credential.token, "read_plugin_manifest", { plugin_id: pluginId });
      expect(valid.status).toBe(200);
      expect(bridgeHost.readManifest).toHaveBeenCalledWith(
        pluginId,
        expect.objectContaining({ scopes: CORDIS_AGENT_PERMISSION_SCOPES }),
      );
    } finally {
      await bridge.close();
    }
  });

  it("rejects invalid, expired, revoked, and cross-session credentials", async () => {
    let currentTime = Date.parse("2026-08-28T00:00:00.000Z");
    const bridgeHost = host();
    const bridge = await startCordisAgentBridge({
      host: bridgeHost,
      now: () => new Date(currentTime),
      tokenLifetimeMs: 1_000,
    });
    const first = bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    const second = bridge.issueSessionToken({
      executorSessionId: "executor-b",
      protocolSessionId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    });
    try {
      expect((await request(bridge.endpoint, "x".repeat(43), "list_plugins", {})).status).toBe(401);

      bridge.revokeSession({ executorSessionId: "executor-a", protocolSessionId });
      expect((await request(bridge.endpoint, first.token, "list_plugins", {})).status).toBe(401);
      expect((await request(bridge.endpoint, second.token, "list_plugins", {})).status).toBe(200);

      currentTime += 1_001;
      expect((await request(bridge.endpoint, second.token, "list_plugins", {})).status).toBe(401);
    } finally {
      await bridge.close();
    }
  });

  it("keeps only the newest credential for one executor protocol session", async () => {
    const bridge = await startCordisAgentBridge({ host: host() });
    const identity = { executorSessionId: "executor-a", protocolSessionId };
    const first = bridge.issueSessionToken(identity);
    const second = bridge.issueSessionToken(identity);
    try {
      expect((await request(bridge.endpoint, first.token, "list_plugins", {})).status).toBe(401);
      expect((await request(bridge.endpoint, second.token, "list_plugins", {})).status).toBe(200);
    } finally {
      await bridge.close();
    }
  });

  it("rejects browser credentials, oversized bodies, deep graphs, node floods, and prototype-pollution fields", async () => {
    const bridgeHost = host();
    const bridge = await startCordisAgentBridge({ host: bridgeHost });
    const credential = bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    try {
      const origin = await request(bridge.endpoint, credential.token, "list_plugins", {}, {
        headers: { origin: "https://example.com" },
      });
      expect(origin.status).toBe(403);

      const cookie = await request(bridge.endpoint, credential.token, "list_plugins", {}, {
        headers: { cookie: "session=browser" },
      });
      expect(cookie.status).toBe(403);

      const oversized = await request(
        bridge.endpoint,
        credential.token,
        "read_plugin_manifest",
        JSON.stringify({ plugin_id: pluginId, padding: "x".repeat(64 * 1024) }),
      );
      expect(oversized.status).toBe(413);

      const deep = await request(
        bridge.endpoint,
        credential.token,
        "list_plugins",
        JSON.stringify({ extra: { a: { b: { c: { d: { e: { f: { g: { h: { i: true } } } } } } } } } }),
      );
      expect(deep.status).toBe(400);

      const nodeFlood = await request(
        bridge.endpoint,
        credential.token,
        "list_plugins",
        JSON.stringify({ extra: Array.from({ length: 513 }, () => null) }),
      );
      expect(nodeFlood.status).toBe(400);

      const pollution = await request(
        bridge.endpoint,
        credential.token,
        "read_plugin_manifest",
        `{"plugin_id":"${pluginId}","__proto__":{"polluted":true}}`,
      );
      expect(pollution.status).toBe(400);
      expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
    } finally {
      await bridge.close();
    }
  });

  it("returns stable sanitized errors without credential or browser-facing response headers", async () => {
    const bridgeHost = host();
    vi.mocked(bridgeHost.readHealth).mockRejectedValueOnce(
      new Error("secret-token /Users/operator/private command --dangerous"),
    );
    const bridge = await startCordisAgentBridge({ host: bridgeHost });
    const credential = bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    try {
      const response = await request(bridge.endpoint, credential.token, "read_plugin_health", { plugin_id: pluginId });
      const serialized = JSON.stringify(await response.json());
      expect(response.status).toBe(502);
      expect(serialized).toBe(JSON.stringify({
        ok: false,
        error: { code: "cordis_request_failed", message: "Cordis request failed" },
      }));
      expect(serialized).not.toContain(credential.token);
      expect(serialized).not.toContain("/Users/");
      expect(serialized).not.toContain("command");
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(response.headers.get("location")).toBeNull();
    } finally {
      await bridge.close();
    }
  });

  it("closes idempotently and revokes all issued credentials", async () => {
    const bridge = await startCordisAgentBridge({ host: host() });
    bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId });
    await bridge.close();
    await expect(bridge.close()).resolves.toBeUndefined();
    expect(() => bridge.issueSessionToken({ executorSessionId: "executor-a", protocolSessionId })).toThrow("agent bridge closed");
  });

  it("keeps the bridge out of renderer IPC and never imports desktop Cordis authority", async () => {
    const directory = fileURLToPath(new URL(".", import.meta.url));
    const [source, preload, ipc, main] = await Promise.all([
      readFile(new URL("./agent-bridge.ts", import.meta.url), "utf8"),
      readFile(new URL("../preload.cts", import.meta.url), "utf8"),
      readFile(new URL("../ipc.ts", import.meta.url), "utf8"),
      readFile(new URL("../main.ts", import.meta.url), "utf8"),
    ]);
    expect(directory).toContain("/cordis/");
    expect(source).not.toContain("cordisDesktopAccess");
    expect(source).not.toContain("console.");
    expect(preload).not.toContain("agent-bridge");
    expect(ipc).not.toContain("agent-bridge");
    expect(main).not.toMatch(/IPC_CHANNELS\.[A-Za-z]*agent/i);
    const initialize = main.indexOf("await cordisHost.initialize()");
    const migration = main.indexOf("await runtimeMigration.migrate(cordisHost, legacyRuntimeSettings)");
    const startBridge = main.indexOf("await startCordisAgentBridge({ host: cordisHost })");
    const registerIpc = main.indexOf("registerIpc();", startBridge);
    const createWindow = main.indexOf("await createWindow();", startBridge);
    expect(initialize).toBeGreaterThan(-1);
    expect(migration).toBeGreaterThan(initialize);
    expect(startBridge).toBeGreaterThan(migration);
    expect(registerIpc).toBeGreaterThan(startBridge);
    expect(createWindow).toBeGreaterThan(registerIpc);
  });
});

describe("Cordis private bridge value conversion", () => {
  it("converts sparse snake_case patches to the internal array without losing values", () => {
    const external = {
      schema_version: 7,
      changes: {
        enabled: true,
        retries: 4,
        "endpoint.url": "http://127.0.0.1:18443",
        optional: null,
      },
    } as const;

    const internal = externalPatchToCordis(external);
    expect(internal).toEqual({
      schemaVersion: 7,
      changes: [
        { id: "enabled", value: true },
        { id: "retries", value: 4 },
        { id: "endpoint.url", value: "http://127.0.0.1:18443" },
        { id: "optional", value: null },
      ],
    });
    expect(cordisPatchToExternal(internal)).toEqual(external);
  });
});

describe("loopback address guard", () => {
  it("accepts IPv4 loopback forms and rejects public or absent peers", () => {
    expect(isLoopbackAddress("127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
    expect(isLoopbackAddress("192.168.1.10")).toBe(false);
    expect(isLoopbackAddress(undefined)).toBe(false);
  });
});
