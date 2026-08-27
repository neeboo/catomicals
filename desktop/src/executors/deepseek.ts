import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, commandWorkingDirectory, containsProbeTokens, executorEnvironmentKeys } from "./types.js";

const environmentKeys = executorEnvironmentKeys([
  "DSH_HOME", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
]);

export const deepseekAdapter: ExecutorAdapter = Object.freeze({
  id: "deepseek",
  capabilities: Object.freeze({
    ...CHAT_ONLY_CAPABILITIES,
    resume: false,
    modelSelection: false,
    reasoningEffort: false,
  }),
  buildProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--version"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildCapabilityProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--profile", "headless", "--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  buildMcpCapabilityProbeCommand: (profile: HarnessSettings): ExecutorCommand => ({
    executable: profile.command,
    args: ["--help"],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  acceptsCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["Usage: dsh --profile headless", "task"],
  ),
  acceptsMcpCapabilityProbe: (stdout: string): boolean => containsProbeTokens(stdout, ["--patch"]),
  buildSendCommand: ({ profile, prompt, mcp }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: [
      "--profile", "headless",
      ...(mcp?.deepseekPatchPath ? ["--patch", mcp.deepseekPatchPath] : []),
      "--", prompt,
    ],
    cwd: commandWorkingDirectory(profile),
    environmentKeys,
  }),
  extractNativeSessionId: (): undefined => undefined,
});
