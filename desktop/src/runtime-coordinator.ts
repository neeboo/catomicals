import type { CordisRestartImpact, HarnessId } from "./contracts.js";
import type { LegacyDesktopRuntimeSettings } from "./settings-store.js";
import { cordisAccess, cordisDesktopAccess, type CordisAccessContext, type CordisDesktopAccessContext } from "./cordis/permissions.js";

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

interface LegacyMigrationHost {
  readPluginSettings(pluginId: unknown, access: CordisAccessContext): Promise<{ settings: Readonly<Record<string, string | boolean | number | null>> }>;
  createSettingsIntent(
    pluginId: unknown,
    patch: unknown,
    access: CordisAccessContext,
  ): Promise<{ reviewId: string }>;
  confirmSettingsIntent(reviewId: unknown, access: CordisDesktopAccessContext): Promise<unknown>;
}

const migrationAccess = cordisAccess("plugin.settings.read", "plugin.settings_intent.create");

function executorCandidate(profile: LegacyDesktopRuntimeSettings["adapters"][HarnessId]): Readonly<Record<string, string>> {
  return {
    command: profile.command,
    defaultModel: profile.defaultModel,
    reasoningEffort: profile.reasoningEffort,
    workingDirectory: profile.workingDirectory,
  };
}

export async function migrateLegacyRuntimeSettings(
  host: LegacyMigrationHost,
  legacy: LegacyDesktopRuntimeSettings,
): Promise<void> {
  const candidates: ReadonlyArray<readonly [string, Readonly<Record<string, string | boolean>>]> = [
    ["@catomicals/plugin-executor-codex", executorCandidate(legacy.adapters.codex)],
    ["@catomicals/plugin-executor-deepseek", executorCandidate(legacy.adapters.deepseek)],
    ["@catomicals/plugin-executor-claude-code", executorCandidate(legacy.adapters["claude-code"])],
    ["@catomicals/plugin-browser", { home: legacy.browserHome }],
    ["@catomicals/plugin-walletd", { endpoint: legacy.walletNodeUrl }],
    ["@catomicals/plugin-mcp", { enabled: legacy.mcpEnabled }],
  ];
  for (const [pluginId, candidate] of candidates) {
    const current = await host.readPluginSettings(pluginId, migrationAccess);
    const changes = Object.entries(candidate).flatMap(([id, value]) => Object.is(current.settings[id], value)
      ? []
      : [{ id, value }]);
    if (changes.length === 0) continue;
    const intent = await host.createSettingsIntent(pluginId, { schemaVersion: 1, changes }, migrationAccess);
    await host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess);
  }
}
