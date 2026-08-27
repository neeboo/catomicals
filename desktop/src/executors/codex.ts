import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, commandWorkingDirectory, containsProbeTokens, executorEnvironmentKeys, jsonLineSessionId } from "./types.js";

const environmentKeys = executorEnvironmentKeys(["CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL"]);

function commonArgs(profile: Parameters<ExecutorAdapter["buildProbeCommand"]>[0]): string[] {
  const args = ["--ask-for-approval", "never", "--sandbox", "read-only"];
  if (profile.workingDirectory) args.push("--cd", profile.workingDirectory);
  if (profile.defaultModel) args.push("--model", profile.defaultModel);
  args.push("--config", `model_reasoning_effort=${JSON.stringify(profile.reasoningEffort)}`);
  return args;
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
  acceptsCapabilityProbe: (stdout: string): boolean => containsProbeTokens(
    stdout,
    ["--json", "--ignore-user-config", "--color", "--sandbox"],
  ),
  buildSendCommand: ({ profile, nativeSessionId, prompt }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: [
      ...commonArgs(profile),
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
