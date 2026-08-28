import { describe, expect, it } from "vitest";
import { codexAdapter } from "./codex";
import { deepseekAdapter } from "./deepseek";
import { claudeCodeAdapter } from "./claude-code";
import {
  CORDIS_MCP_PUBLIC_TOOL_NAMES,
  CORDIS_MCP_TOOL_NAMES,
  WALLET_MCP_PUBLIC_TOOL_NAMES,
  WALLET_MCP_TOOL_NAMES,
} from "./types";

const profile = {
  command: "/Applications/Agent Tools/bin/agent",
  defaultModel: "model-x",
  reasoningEffort: "high" as const,
  workingDirectory: "/tmp/work tree",
};

const mcp = {
  command: "catomicals",
  walletUrl: "http://127.0.0.1:18787",
  deepseekPatchPath: "/private/tmp/catomicals-cordis/cordis.patch.yml",
};

describe("executor provider command contracts", () => {
  it("builds Codex invocations as fixed argument arrays with read-only authority", () => {
    const prompt = "review; rm -rf / $(whoami)";
    const command = codexAdapter.buildSendCommand({ profile, prompt });

    expect(command).toMatchObject({
      executable: profile.command,
      args: [
        "--ask-for-approval", "never",
        "--sandbox", "read-only",
        "--cd", profile.workingDirectory,
        "--model", profile.defaultModel,
        "--config", 'model_reasoning_effort="high"',
        "exec", "--ignore-user-config", "--json", "--color", "never", "--",
        prompt,
      ],
      cwd: profile.workingDirectory,
    });
    expect(command.args).toContain(prompt);
    expect(command.args.at(-2)).toBe("--");
    expect(command).not.toHaveProperty("shell");
  });

  it("builds native resume forms without broadening authority", () => {
    const codex = codexAdapter.buildSendCommand({ profile, nativeSessionId: "thread-1", prompt: "next" }).args;
    expect(codex).toContain("thread-1");
    expect(codex.indexOf("--color")).toBeLessThan(codex.indexOf("resume"));

    const claude = claudeCodeAdapter.buildSendCommand({ profile, nativeSessionId: "session-1", prompt: "next" });
    expect(claude.args).toEqual(expect.arrayContaining([
      "--verbose", "--safe-mode", "--permission-mode", "plan", "--tools", "", "--resume", "session-1", "next",
    ]));
    expect(claude.args).not.toContain("--dangerously-skip-permissions");
    expect(claude.args.at(-2)).toBe("--");
  });

  it("reports only provider capabilities implemented by the host", () => {
    expect(codexAdapter.capabilities).toMatchObject({ resume: true, modelSelection: true, mcp: false });
    expect(claudeCodeAdapter.capabilities).toMatchObject({ resume: true, modelSelection: true, mcp: false });
    expect(deepseekAdapter.capabilities).toMatchObject({ resume: false, modelSelection: false, mcp: false });
    expect(deepseekAdapter.buildSendCommand({ profile, prompt: "hello" })).toMatchObject({
      executable: profile.command,
      args: ["--profile", "headless", "--", "hello"],
      cwd: profile.workingDirectory,
    });
  });

  it("attaches Cordis configuration and wallet tools through each provider's native mechanism", () => {
    const codex = codexAdapter.buildSendCommand({ profile, prompt: "inspect", mcp });
    expect(codex.args).toEqual(expect.arrayContaining([
      "--config", 'mcp_servers.catomicals.command="catomicals"',
      "--config", `mcp_servers.catomicals.args=${JSON.stringify(["mcp", "cordis-serve"])}`,
      "--config", `mcp_servers.catomicals.env_vars=${JSON.stringify([
        "CATOMICALS_CORDIS_BRIDGE_URL", "CATOMICALS_CORDIS_SESSION_TOKEN",
      ])}`,
      "--config", `mcp_servers.catomicals.enabled_tools=${JSON.stringify(CORDIS_MCP_TOOL_NAMES)}`,
      "--config", 'mcp_servers.catomicals_wallet.command="catomicals"',
      "--config", `mcp_servers.catomicals_wallet.args=${JSON.stringify([
        "mcp", "serve", "--wallet-url", "http://127.0.0.1:18787",
      ])}`,
      "--config", `mcp_servers.catomicals_wallet.enabled_tools=${JSON.stringify(WALLET_MCP_TOOL_NAMES)}`,
      "exec", "--ignore-user-config",
    ]));

    const deepseek = deepseekAdapter.buildSendCommand({ profile, prompt: "inspect", mcp });
    expect(deepseek.args).toEqual([
      "--profile", "headless", "--patch", mcp.deepseekPatchPath, "--", "inspect",
    ]);

    const claude = claudeCodeAdapter.buildSendCommand({ profile, prompt: "inspect", mcp });
    const mcpConfigIndex = claude.args.indexOf("--mcp-config");
    expect(mcpConfigIndex).toBeGreaterThan(-1);
    expect(JSON.parse(claude.args[mcpConfigIndex + 1]!)).toEqual({
      mcpServers: {
        catomicals: { command: "catomicals", args: ["mcp", "cordis-serve"] },
        catomicals_wallet: {
          command: "catomicals",
          args: ["mcp", "serve", "--wallet-url", "http://127.0.0.1:18787"],
        },
      },
    });
    expect(claude.args).toEqual(expect.arrayContaining([
      "--strict-mcp-config",
      "--setting-sources", "",
      "--tools", "",
      "--allowedTools", [...CORDIS_MCP_PUBLIC_TOOL_NAMES, ...WALLET_MCP_PUBLIC_TOOL_NAMES].join(","),
    ]));
    expect(claude.args).not.toContain("--safe-mode");
    expect(claude.args).not.toContain("--dangerously-skip-permissions");
  });

  it("probes provider MCP configuration offline through each native assembly path", () => {
    expect(codexAdapter.buildCapabilityProbeCommand(profile).args).toEqual(["exec", "--help"]);
    expect(deepseekAdapter.buildCapabilityProbeCommand(profile).args).toEqual(["--profile", "headless", "--help"]);
    expect(claudeCodeAdapter.buildCapabilityProbeCommand(profile).args).toEqual(["--help"]);
    expect(codexAdapter.buildMcpCapabilityProbeCommand(profile).args).toEqual(["exec", "--help"]);
    expect(deepseekAdapter.buildMcpCapabilityProbeCommand(profile).args).toEqual(["--help"]);
    expect(claudeCodeAdapter.buildMcpCapabilityProbeCommand(profile).args).toEqual(["--help"]);
    const codexAssemblyProbe = codexAdapter.buildMcpAssemblyProbeCommand(profile, mcp);
    expect(codexAssemblyProbe.args).toEqual(expect.arrayContaining([
      "exec", "--ignore-user-config", "--version",
    ]));
    expect(codexAssemblyProbe.args).not.toContain("get");
    expect(deepseekAdapter.buildMcpAssemblyProbeCommand(profile, mcp).args).toEqual([
      "--profile", "headless", "--patch", mcp.deepseekPatchPath, "--dump-config",
    ]);
    expect(claudeCodeAdapter.buildMcpAssemblyProbeCommand(profile, mcp).args).toEqual(expect.arrayContaining([
      "--mcp-config", expect.any(String), "--strict-mcp-config", "--version",
    ]));
    expect(claudeCodeAdapter.acceptsCapabilityProbe("--print --verbose --output-format --input-format --safe-mode --permission-mode --tools --resume"))
      .toBe(true);
    expect(claudeCodeAdapter.acceptsCapabilityProbe("--print --output-format"))
      .toBe(false);
    expect(codexAdapter.acceptsMcpCapabilityProbe("--config --ignore-user-config")).toBe(true);
    expect(deepseekAdapter.acceptsMcpCapabilityProbe("--patch")) .toBe(true);
    expect(claudeCodeAdapter.acceptsMcpCapabilityProbe("--mcp-config --strict-mcp-config --setting-sources --tools --allowedTools"))
      .toBe(true);
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
