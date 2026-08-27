import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand, ExecutorMcpConfiguration } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, CORDIS_MCP_PUBLIC_TOOL_NAMES, commandWorkingDirectory, containsProbeTokens, executorEnvironmentKeys, jsonLineSessionId } from "./types.js";

const environmentKeys = executorEnvironmentKeys(["CLAUDE_CONFIG_DIR", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"]);

function mcpConfigArgs(command: string): string[] {
  return [
    "--setting-sources", "",
    "--mcp-config", JSON.stringify({
      mcpServers: {
        catomicals: { command, args: ["mcp", "cordis-serve"] },
      },
    }),
    "--strict-mcp-config",
  ];
}

function mcpToolArgs(): string[] {
  return [
    "--tools", "",
    "--allowedTools", CORDIS_MCP_PUBLIC_TOOL_NAMES.join(","),
  ];
}

export const claudeCodeAdapter: ExecutorAdapter = Object.freeze({
  id: "claude-code",
  capabilities: Object.freeze({
    ...CHAT_ONLY_CAPABILITIES,
    resume: true,
    modelSelection: true,
    reasoningEffort: true,
  }),
  buildProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--version"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildCapabilityProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildMcpCapabilityProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildMcpAssemblyProbeCommand: (
    profile: HarnessSettings,
    mcp: ExecutorMcpConfiguration,
  ): ExecutorCommand => ({
    executable: profile.command,
    args: [...mcpConfigArgs(mcp.command), ...mcpToolArgs(), "--version"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  acceptsCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["--print", "--verbose", "--output-format", "--input-format", "--safe-mode", "--permission-mode", "--tools", "--resume"],
  ),
  acceptsMcpCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["--mcp-config", "--strict-mcp-config", "--setting-sources", "--tools", "--allowedTools"],
  ),
  buildSendCommand: ({ profile, nativeSessionId, prompt, mcp }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: [
      "--print",
      "--verbose",
      "--output-format", "stream-json",
      "--input-format", "text",
      ...(mcp ? mcpConfigArgs(mcp.command) : ["--safe-mode"]),
      "--permission-mode", "plan",
      ...(mcp ? mcpToolArgs() : ["--tools", ""]),
      ...(profile.defaultModel ? ["--model", profile.defaultModel] : []),
      "--effort", profile.reasoningEffort,
      ...(nativeSessionId ? ["--resume", nativeSessionId] : []),
      "--",
      prompt,
    ],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  extractNativeSessionId: (stdout: string): string | undefined => jsonLineSessionId(
    stdout,
    (record) => record.type === "system" && record.subtype === "init" ? record.session_id : undefined,
  ),
});
