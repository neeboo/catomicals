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
  });

  it("rejects extra IPC arguments", () => {
    expect(parseIpcArguments([], 0)).toEqual([]);
    expect(parseIpcArguments(["browser"], 1)).toEqual(["browser"]);
    expect(() => parseIpcArguments(["browser", "extra"], 1)).toThrow("argument count");
  });

  it("rejects unknown or malformed settings update fields", () => {
    const valid = {
      version: 1,
      defaultHarness: "codex",
      adapters: {
        codex: { command: "codex", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
        deepseek: { command: "deepseek-harness", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
        "claude-code": { command: "claude", defaultModel: "", reasoningEffort: "high", workingDirectory: "" },
      },
      mcpEnabled: true,
      walletNodeUrl: "http://127.0.0.1:18787",
      browserHome: "https://mempool.space/signet",
    };
    expect(parseDesktopSettingsUpdate(valid)).toEqual(valid);
    expect(() => parseDesktopSettingsUpdate({ ...valid, apiKey: "secret" })).toThrow("fields");
    expect(() => parseDesktopSettingsUpdate({ ...valid, walletNodeUrl: "https://wallet.example" })).toThrow("wallet node");
    expect(() => parseDesktopSettingsUpdate({
      ...valid,
      adapters: { ...valid.adapters, codex: { ...valid.adapters.codex, shell: true } },
    })).toThrow("fields");
  });
});
