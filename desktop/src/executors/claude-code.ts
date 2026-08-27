import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, commandWorkingDirectory, jsonLineSessionId } from "./types.js";

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
  }),
  buildSendCommand: ({ profile, nativeSessionId, prompt }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: [
      "--print",
      "--output-format", "stream-json",
      "--input-format", "text",
      "--safe-mode",
      "--permission-mode", "plan",
      "--tools", "",
      ...(profile.defaultModel ? ["--model", profile.defaultModel] : []),
      "--effort", profile.reasoningEffort,
      ...(nativeSessionId ? ["--resume", nativeSessionId] : []),
      prompt,
    ],
    cwd: commandWorkingDirectory(profile),
  }),
  extractNativeSessionId: (stdout: string): string | undefined => jsonLineSessionId(
    stdout,
    (record) => record.type === "system" && record.subtype === "init" ? record.session_id : undefined,
  ),
});
