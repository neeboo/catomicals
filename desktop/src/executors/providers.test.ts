import { describe, expect, it } from "vitest";
import { codexAdapter } from "./codex";
import { deepseekAdapter } from "./deepseek";
import { claudeCodeAdapter } from "./claude-code";

const profile = {
  command: "/Applications/Agent Tools/bin/agent",
  defaultModel: "model-x",
  reasoningEffort: "high" as const,
  workingDirectory: "/tmp/work tree",
};

describe("executor provider command contracts", () => {
  it("builds Codex invocations as fixed argument arrays with read-only authority", () => {
    const prompt = "review; rm -rf / $(whoami)";
    const command = codexAdapter.buildSendCommand({ profile, prompt });

    expect(command).toEqual({
      executable: profile.command,
      args: [
        "--ask-for-approval", "never",
        "--sandbox", "read-only",
        "--cd", profile.workingDirectory,
        "--model", profile.defaultModel,
        "--config", 'model_reasoning_effort="high"',
        "exec", "--ignore-user-config", "--json", "--color", "never",
        prompt,
      ],
      cwd: profile.workingDirectory,
    });
    expect(command.args).toContain(prompt);
    expect(command).not.toHaveProperty("shell");
  });

  it("builds native resume forms without broadening authority", () => {
    const codex = codexAdapter.buildSendCommand({ profile, nativeSessionId: "thread-1", prompt: "next" }).args;
    expect(codex).toContain("thread-1");
    expect(codex.indexOf("--color")).toBeLessThan(codex.indexOf("resume"));

    const claude = claudeCodeAdapter.buildSendCommand({ profile, nativeSessionId: "session-1", prompt: "next" });
    expect(claude.args).toEqual(expect.arrayContaining([
      "--safe-mode", "--permission-mode", "plan", "--tools", "", "--resume", "session-1", "next",
    ]));
    expect(claude.args).not.toContain("--dangerously-skip-permissions");
  });

  it("reports only provider capabilities implemented by the host", () => {
    expect(codexAdapter.capabilities).toMatchObject({ resume: true, modelSelection: true, mcp: false });
    expect(claudeCodeAdapter.capabilities).toMatchObject({ resume: true, modelSelection: true, mcp: false });
    expect(deepseekAdapter.capabilities).toMatchObject({ resume: false, modelSelection: false, mcp: false });
    expect(deepseekAdapter.buildSendCommand({ profile, prompt: "hello" })).toEqual({
      executable: profile.command,
      args: ["--profile", "headless", "hello"],
      cwd: profile.workingDirectory,
    });
  });

  it("extracts only explicit native session identifiers", () => {
    expect(codexAdapter.extractNativeSessionId([
      '{"type":"thread.started","thread_id":"codex-thread"}',
      '{"type":"item.completed"}',
    ].join("\n"))).toBe("codex-thread");
    expect(claudeCodeAdapter.extractNativeSessionId([
      '{"type":"system","subtype":"init","session_id":"claude-session"}',
      '{"type":"result","result":"done"}',
    ].join("\n"))).toBe("claude-session");
    expect(deepseekAdapter.extractNativeSessionId("session maybe abc")).toBeUndefined();
  });
});
