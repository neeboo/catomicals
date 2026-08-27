import type { CordisRestartImpact, HarnessId } from "./contracts.js";
import type { LegacyDesktopRuntimeSettings } from "./settings-store.js";

interface ExecutorConfigurationSink {
  noteConfigurationChange(provider: HarnessId, restartImpact: CordisRestartImpact): void;
}

interface ConfirmedSettingsImpact {
  readonly pluginId: string;
  readonly restartImpact: CordisRestartImpact;
}

const executorPlugins: Readonly<Record<string, HarnessId>> = Object.freeze({
  "@catomicals/plugin-executor-codex": "codex",
  "@catomicals/plugin-executor-deepseek": "deepseek",
  "@catomicals/plugin-executor-claude-code": "claude-code",
});

export function applyRuntimeSettingsImpact(
  registry: ExecutorConfigurationSink,
  review: ConfirmedSettingsImpact,
): void {
  const provider = executorPlugins[review.pluginId];
  if (provider) registry.noteConfigurationChange(provider, review.restartImpact);
}

function executorCandidate(profile: LegacyDesktopRuntimeSettings["adapters"][HarnessId]): Readonly<Record<string, string>> {
  return {
    command: profile.command,
    defaultModel: profile.defaultModel,
    reasoningEffort: profile.reasoningEffort,
    workingDirectory: profile.workingDirectory,
  };
}

export function legacyRuntimeCandidates(
  legacy: LegacyDesktopRuntimeSettings,
): ReadonlyArray<readonly [string, Readonly<Record<string, string | boolean>>]> {
  return [
    ["@catomicals/plugin-executor-codex", executorCandidate(legacy.adapters.codex)],
    ["@catomicals/plugin-executor-deepseek", executorCandidate(legacy.adapters.deepseek)],
    ["@catomicals/plugin-executor-claude-code", executorCandidate(legacy.adapters["claude-code"])],
    ["@catomicals/plugin-browser", { home: legacy.browserHome }],
    ["@catomicals/plugin-walletd", { endpoint: legacy.walletNodeUrl }],
    ["@catomicals/plugin-mcp", { enabled: legacy.mcpEnabled }],
  ];
}
