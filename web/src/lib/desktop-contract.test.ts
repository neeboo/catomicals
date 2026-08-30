import { describe, expectTypeOf, it } from "vitest";
import type { ExecutorSession } from "./desktop";

describe("desktop executor session mirror", () => {
  it("exposes the runtime session identity and read-only MCP metadata", () => {
    const session = {
      sessionId: "local-session",
      protocolSessionId: "7fbcabf0-4fe8-4ce7-91d0-8678d65f79f6",
      nativeSessionId: "thread-native",
      provider: "codex",
      state: "idle",
      capabilities: {
        create: true,
        send: true,
        interrupt: true,
        status: true,
        dispose: true,
        resume: true,
        modelSelection: true,
        reasoningEffort: true,
        mcp: true,
        walletApproval: false,
        signing: false,
        broadcast: false,
      },
      mcp: {
        enabled: true,
        transport: "stdio",
        services: ["catomicals-config", "catomicals-wallet"],
        toolNames: ["read_plugin_manifest", "get_wallet_status"],
      },
      allowedScopes: ["plugin.manifest.read", "wallet.status.read"],
      model: "gpt-test",
      reasoningEffort: "high",
      workingDirectory: "/work",
      restartImpact: "none",
    } as const satisfies ExecutorSession;

    expectTypeOf(session.protocolSessionId).toEqualTypeOf<"7fbcabf0-4fe8-4ce7-91d0-8678d65f79f6">();
    expectTypeOf(session.capabilities.mcp).toEqualTypeOf<true>();
    expectTypeOf(session.mcp.enabled).toEqualTypeOf<true>();
    expectTypeOf(session.allowedScopes).toMatchTypeOf<readonly string[]>();
  });
});
