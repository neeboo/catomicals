import type { CordisHost, PluginSettingsView } from "./host.js";
import { cordisAccess, cordisDesktopAccess } from "./permissions.js";
import { parseLoopbackWalletEndpoint } from "./runtime-config.js";

const walletPluginId = "@catomicals/plugin-walletd";
const startupSettingsAccess = cordisAccess(
  "plugin.settings.read",
  "plugin.settings.validate",
  "plugin.settings_intent.create",
);

interface StartupWalletEndpointOptions {
  readonly packaged: boolean;
  readonly value: string | undefined;
}

export function resolveStartupWalletEndpoint({
  packaged,
  value,
}: StartupWalletEndpointOptions): string | undefined {
  if (packaged || value === undefined) return undefined;
  return parseLoopbackWalletEndpoint(value);
}

export async function applyStartupWalletEndpoint(
  host: CordisHost,
  endpoint: string,
): Promise<PluginSettingsView> {
  const normalizedEndpoint = parseLoopbackWalletEndpoint(endpoint);
  const current = await host.readPluginSettings(walletPluginId, startupSettingsAccess);
  if (current.settings.endpoint === normalizedEndpoint) return current;

  const patch = {
    schemaVersion: current.settingsSchemaVersion,
    changes: [{ id: "endpoint", value: normalizedEndpoint }],
  } as const;
  const validation = host.validateSettingsPatch(walletPluginId, patch, startupSettingsAccess);
  if (!validation.valid) throw new Error(validation.error ?? "invalid startup wallet settings");
  const intent = await host.createSettingsIntent(walletPluginId, patch, startupSettingsAccess);
  return host.confirmSettingsIntent(intent.reviewId, cordisDesktopAccess);
}
