import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ALLOWED_INVOKE_CHANNELS,
  IPC_CHANNELS,
  isPrivateBrowserHost,
  parseBrowserUrl,
  parseDesktopSettingsUpdate,
  parseExecutorCreateRequest,
  parseExecutorProbeRequest,
  parseExecutorResumeRequest,
  parseExecutorSendRequest,
  parseExecutorSessionRequest,
  parseHarnessRequest,
  parseIpcArguments,
  parsePluginIdRequest,
  parsePluginSettingsReviewRequest,
  parsePluginSettingsPatchRequest,
  shouldBlockBrowserRequest,
} from "./ipc";

describe("Electron IPC contract", () => {
  it("exposes a fixed invoke allowlist", () => {
    expect(ALLOWED_INVOKE_CHANNELS).toEqual(Object.values(IPC_CHANNELS));
    expect(new Set(ALLOWED_INVOKE_CHANNELS).size).toBe(ALLOWED_INVOKE_CHANNELS.length);
  });

  it("keeps the sandbox preload self-contained and aligned with the IPC allowlist", () => {
    const source = readFileSync(new URL("./preload.cts", import.meta.url), "utf8");
    expect(source).not.toMatch(/from\s+["']\.\//);
    for (const channel of ALLOWED_INVOKE_CHANNELS) expect(source).toContain(`"${channel}"`);
    expect(source).not.toMatch(/\b(?:apply|promote|install)Plugin\b|\breadSecret\b|\bapprove\s*\(|\bbroadcast\s*\(|\bsignTransaction\b/);
    expect(source).toContain("readPluginSettings:");
    expect(source).toContain("readPluginSettingsReview:");
    expect(source).toContain("confirmPluginSettingsIntent:");
    expect(source).toContain("requestWallet:");
    expect(source).toContain("getMcpEnabled:");
    expect(source).not.toContain("getRuntimeConfig:");
    expect(source).not.toContain("permissionScopes");
  });

  it("accepts only read, validate, and intent creation plugin requests", () => {
    expect(parsePluginIdRequest({ pluginId: "@catomicals/plugin-walletd" }))
      .toEqual({ pluginId: "@catomicals/plugin-walletd" });
    expect(parsePluginSettingsPatchRequest({
      pluginId: "@catomicals/plugin-browser",
      patch: { schemaVersion: 1, changes: [{ id: "home", value: "https://example.com" }] },
    })).toEqual({
      pluginId: "@catomicals/plugin-browser",
      patch: { schemaVersion: 1, changes: [{ id: "home", value: "https://example.com" }] },
    });
    expect(() => parsePluginIdRequest({ pluginId: "@catomicals/plugin-walletd", action: "sign" })).toThrow("fields");
    expect(() => parsePluginIdRequest({
      pluginId: "@catomicals/plugin-walletd",
      permissionScopes: ["plugin.settings_intent.create"],
    })).toThrow("fields");
    expect(() => parsePluginSettingsPatchRequest({
      pluginId: "@catomicals/plugin-walletd",
      patch: { schemaVersion: 1, changes: [{ id: "enabled", value: false }] },
      permissionScopes: ["plugin.settings_intent.create"],
    })).toThrow("fields");
    expect(() => parsePluginSettingsPatchRequest({
      pluginId: "@catomicals/plugin-walletd",
      patch: { schemaVersion: 1, changes: [{ id: "credential", value: { plaintext: "secret" } }] },
    })).toThrow("primitive");
  });

  it("accepts only a closed review identifier and rejects prototype or size abuse", () => {
    expect(parsePluginSettingsReviewRequest({ reviewId: "review-1" })).toEqual({ reviewId: "review-1" });
    expect(() => parsePluginSettingsReviewRequest({ reviewId: "review-1", pluginId: "attacker" })).toThrow("fields");
    expect(() => parsePluginSettingsReviewRequest({ reviewId: "../review" })).toThrow("review");

    const polluted = Object.create({ permissionScopes: ["plugin.settings_intent.create"] }) as Record<string, unknown>;
    polluted.pluginId = "@catomicals/plugin-walletd";
    expect(() => parsePluginIdRequest(polluted)).toThrow("plain object");

    expect(() => parsePluginSettingsPatchRequest({
      pluginId: "@catomicals/plugin-walletd",
      patch: { schemaVersion: 1, changes: [{ id: "endpoint", value: "x".repeat(70_000) }] },
    })).toThrow("too large");
  });

  it("permits only http and https browser navigation", () => {
    expect(parseBrowserUrl("https://mempool.space/signet")).toBe("https://mempool.space/signet");
    expect(() => parseBrowserUrl("javascript:alert(1)")).toThrow("http");
    expect(() => parseBrowserUrl("file:///etc/passwd")).toThrow("http");
  });

  it("blocks local addresses even when IPv4 is embedded in IPv6", () => {
    expect(isPrivateBrowserHost("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateBrowserHost("::ffff:192.168.1.4")).toBe(true);
  });

  it("blocks every non-web browser request scheme", () => {
    expect(shouldBlockBrowserRequest("file:///etc/passwd")).toBe(true);
    expect(shouldBlockBrowserRequest("devtools://devtools/bundled/inspector.html")).toBe(true);
    expect(shouldBlockBrowserRequest("mailto:test@example.com")).toBe(true);
  });

  it("allows harness chat prompts but no transaction or signing authority", () => {
    expect(parseHarnessRequest({ harnessId: "codex", sessionId: "wallet-main", prompt: "检查交易" }))
      .toEqual({ harnessId: "codex", sessionId: "wallet-main", prompt: "检查交易" });
    expect(() => parseHarnessRequest({ harnessId: "codex", prompt: "批准", privateKey: "secret" }))
      .toThrow("fields");
    expect(() => parseHarnessRequest({ harnessId: "codex", sessionId: "wallet-main", prompt: "签名", intentId: "x" }))
      .toThrow("fields");
  });

  it("accepts only typed executor lifecycle requests", () => {
    expect(parseExecutorProbeRequest({ provider: "codex" })).toEqual({ provider: "codex" });
    expect(parseExecutorCreateRequest({ provider: "claude-code", sessionId: "wallet-main" }))
      .toEqual({ provider: "claude-code", sessionId: "wallet-main" });
    expect(() => parseExecutorCreateRequest({
      provider: "claude-code",
      sessionId: "wallet-main",
      protocolSessionId: "8f744d1f-1b9a-4bd6-9d30-54c8ba7f739c",
    })).toThrow("fields");
    expect(parseExecutorResumeRequest({ provider: "codex", sessionId: "wallet-main", nativeSessionId: "native-1" }))
      .toEqual({ provider: "codex", sessionId: "wallet-main", nativeSessionId: "native-1" });
    expect(parseExecutorSendRequest({ sessionId: "wallet-main", prompt: "inspect" }))
      .toEqual({ sessionId: "wallet-main", prompt: "inspect" });
    expect(parseExecutorSessionRequest({ sessionId: "wallet-main" })).toEqual({ sessionId: "wallet-main" });
  });

  it("keeps process configuration and wallet authority out of executor IPC", () => {
    expect(() => parseExecutorCreateRequest({
      provider: "codex",
      sessionId: "wallet-main",
      command: "sh",
      args: ["-c", "rm -rf /"],
    })).toThrow("fields");
    expect(() => parseExecutorSendRequest({
      sessionId: "wallet-main",
      prompt: "approve",
      permissionScope: "wallet.sign",
    })).toThrow("fields");
    expect(() => parseExecutorResumeRequest({
      provider: "codex",
      sessionId: "wallet-main",
      nativeSessionId: "bad\nvalue",
    })).toThrow("native session");
    expect(() => parseExecutorResumeRequest({
      provider: "codex",
      sessionId: "wallet-main",
      nativeSessionId: "--last",
    })).toThrow("native session");
    expect(() => parseExecutorSendRequest({ sessionId: "wallet-main", prompt: "bad\0prompt" }))
      .toThrow("prompt");
  });

  it("rejects extra IPC arguments", () => {
    expect(parseIpcArguments([], 0)).toEqual([]);
    expect(parseIpcArguments(["browser"], 1)).toEqual(["browser"]);
    expect(() => parseIpcArguments(["browser", "extra"], 1)).toThrow("argument count");
  });

  it("rejects unknown or malformed settings update fields", () => {
    const valid = {
      version: 2,
      defaultHarness: "codex",
    };
    expect(parseDesktopSettingsUpdate(valid)).toEqual(valid);
    expect(() => parseDesktopSettingsUpdate({ ...valid, apiKey: "secret" })).toThrow("fields");
    expect(() => parseDesktopSettingsUpdate({ ...valid, walletNodeUrl: "http://127.0.0.1:18787" }))
      .toThrow("fields");
  });
});
