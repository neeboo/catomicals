import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, CORDIS_MCP_TOOL_NAMES, commandWorkingDirectory, containsProbeTokens, executorEnvironmentKeys, jsonLineSessionId } from "./types.js";

const environmentKeys = executorEnvironmentKeys(["CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL"]);

function commonArgs(profile: Parameters<ExecutorAdapter["buildProbeCommand"]>[0]): string[] {
  const args = ["--ask-for-approval", "never", "--sandbox", "read-only"];
  if (profile.workingDirectory) args.push("--cd", profile.workingDirectory);
  if (profile.defaultModel) args.push("--model", profile.defaultModel);
  args.push("--config", `model_reasoning_effort=${JSON.stringify(profile.reasoningEffort)}`);
  return args;
}

function mcpArgs(command: string): string[] {
  return [
    "--config", `mcp_servers.catomicals.command=${JSON.stringify(command)}`,
    "--config", `mcp_servers.catomicals.args=${JSON.stringify(["mcp", "cordis-serve"])}`,
    "--config", `mcp_servers.catomicals.env_vars=${JSON.stringify([
      "CATOMICALS_CORDIS_BRIDGE_URL", "CATOMICALS_CORDIS_SESSION_TOKEN",
    ])}`,
    "--config", `mcp_servers.catomicals.enabled_tools=${JSON.stringify(CORDIS_MCP_TOOL_NAMES)}`,
    "--config", "mcp_servers.catomicals.required=true",
  ];
}

export const codexAdapter: ExecutorAdapter = Object.freeze({
  id: "codex",
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
    args: ["exec", "--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildMcpCapabilityProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["exec", "--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  acceptsCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["--json", "--ignore-user-config", "--color", "--sandbox"],
  ),
  acceptsMcpCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["--config", "--ignore-user-config"],
  ),
  buildSendCommand: ({ profile, nativeSessionId, prompt, mcp }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: [
      ...commonArgs(profile),
      ...(mcp ? mcpArgs(mcp.command) : []),
      "exec",
      "--ignore-user-config",
      "--json",
      "--color",
      "never",
      ...(nativeSessionId ? ["resume", nativeSessionId] : []),
      "--",
      prompt,
    ],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  extractNativeSessionId: (stdout: string): string | undefined => jsonLineSessionId(
    stdout,
    (record) => record.type === "thread.started" ? record.thread_id : undefined,
  ),
});
