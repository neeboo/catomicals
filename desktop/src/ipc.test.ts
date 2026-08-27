import { describe, expect, it } from "vitest";
import {
  ALLOWED_INVOKE_CHANNELS,
  IPC_CHANNELS,
  parseBrowserUrl,
  parseHarnessRequest,
} from "./ipc";

describe("Electron IPC contract", () => {
  it("exposes a fixed invoke allowlist", () => {
    expect(ALLOWED_INVOKE_CHANNELS).toEqual(Object.values(IPC_CHANNELS));
    expect(new Set(ALLOWED_INVOKE_CHANNELS).size).toBe(ALLOWED_INVOKE_CHANNELS.length);
  });

  it("permits only http and https browser navigation", () => {
    expect(parseBrowserUrl("https://mempool.space/signet")).toBe("https://mempool.space/signet");
    expect(() => parseBrowserUrl("javascript:alert(1)")).toThrow("http");
    expect(() => parseBrowserUrl("file:///etc/passwd")).toThrow("http");
  });

  it("allows harness chat prompts but no transaction or signing authority", () => {
    expect(parseHarnessRequest({ harnessId: "codex", sessionId: "wallet-main", prompt: "检查交易" }))
      .toEqual({ harnessId: "codex", sessionId: "wallet-main", prompt: "检查交易" });
    expect(() => parseHarnessRequest({ harnessId: "codex", prompt: "批准", privateKey: "secret" }))
      .toThrow("fields");
    expect(() => parseHarnessRequest({ harnessId: "codex", sessionId: "wallet-main", prompt: "签名", intentId: "x" }))
      .toThrow("fields");
  });
});
