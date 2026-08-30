import { describe, expectTypeOf, it } from "vitest";
import type { ExecutorSendResult, ExecutorSession } from "./desktop";

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

  it("mirrors the typed final executor message while retaining raw output", () => {
    const result = {
      sessionId: "local-session",
      protocolSessionId: "7fbcabf0-4fe8-4ce7-91d0-8678d65f79f6",
      provider: "codex",
      state: "completed",
      capabilities: {
        create: true,
        send: true,
        interrupt: true,
        status: true,
        dispose: true,
        resume: true,
        modelSelection: true,
        reasoningEffort: true,
        mcp: false,
        walletApproval: false,
        signing: false,
        broadcast: false,
      },
      mcp: { enabled: false, transport: "stdio", services: [], toolNames: [] },
      allowedScopes: [],
      workingDirectory: "/work",
      restartImpact: "none",
      output: "done",
      message: {
        schema_version: 1,
        message_id: "36c0c2a6-1d23-4dd5-90ed-e75891a40ef1",
        session_id: "7fbcabf0-4fe8-4ce7-91d0-8678d65f79f6",
        role: "assistant",
        content_digest: `sha256:${"1".repeat(64)}`,
        created_at: "2026-08-30T12:00:00.000Z",
        parts: [{ type: "text", text: "done" }],
      },
    } as const satisfies ExecutorSendResult;

    expectTypeOf(result.message.parts[0]).toEqualTypeOf<{ readonly type: "text"; readonly text: "done" }>();
  });
});
