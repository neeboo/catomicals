import type { HarnessSettings } from "../contracts.js";
import type { BuildSendCommandInput, ExecutorAdapter, ExecutorCommand } from "./types.js";
import { CHAT_ONLY_CAPABILITIES, commandWorkingDirectory } from "./types.js";

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
  }),
  buildSendCommand: ({ profile, prompt }: BuildSendCommandInput): ExecutorCommand => ({
    executable: profile.command,
    args: ["--profile", "headless", prompt],
    cwd: commandWorkingDirectory(profile),
  }),
  extractNativeSessionId: (): undefined => undefined,
});
