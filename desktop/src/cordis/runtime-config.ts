import type { HarnessId, HarnessSettings } from "../contracts.js";
import { HARNESS_IDS, REASONING_EFFORTS } from "../contracts.js";
import { parseBrowserUrl } from "../browser-security.js";
import type { PluginSettingsView } from "./host.js";
import { cordisAccess, type CordisAccessContext } from "./permissions.js";

const runtimeSettingsAccess = cordisAccess("plugin.settings.read");

const executorPluginIds: Readonly<Record<HarnessId, string>> = Object.freeze({
  codex: "@catomicals/plugin-executor-codex",
  deepseek: "@catomicals/plugin-executor-deepseek",
  "claude-code": "@catomicals/plugin-executor-claude-code",
});

interface CordisSettingsReader {
  readPluginSettings(pluginId: unknown, access: CordisAccessContext): Promise<PluginSettingsView>;
}

function plainText(value: unknown, field: string, maximum: number, allowEmpty = true): string {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.trim() === "") || /[\0\r\n]/.test(value)) {
    throw new Error(`invalid Cordis ${field}`);
  }
  return value;
}

export function parseExecutorRuntimeProfile(value: Readonly<Record<string, unknown>>): HarnessSettings {
  const effort = value.reasoningEffort;
  if (typeof effort !== "string" || !REASONING_EFFORTS.includes(effort as HarnessSettings["reasoningEffort"])) {
    throw new Error("invalid Cordis reasoning effort");
  }
  return {
    command: plainText(value.command, "executor command", 256, false),
    defaultModel: plainText(value.defaultModel, "default model", 256),
    reasoningEffort: effort as HarnessSettings["reasoningEffort"],
    workingDirectory: plainText(value.workingDirectory, "working directory", 1024),
  };
}

export function parseLoopbackWalletEndpoint(value: unknown): string {
  if (typeof value !== "string" || value.length > 512) throw new Error("invalid wallet loopback endpoint");
  const url = new URL(value);
  const hostname = url.hostname.toLowerCase();
  if (url.protocol !== "http:"
    || !["localhost", "127.0.0.1", "[::1]"].includes(hostname)
    || url.username || url.password
    || (url.pathname !== "/" && url.pathname !== "")
    || url.search || url.hash) {
    throw new Error("wallet endpoint must be an unauthenticated loopback HTTP origin");
  }
  return url.origin;
}

export class CordisRuntimeConfig {
  constructor(private readonly reader: CordisSettingsReader) {}

  async executor(provider: HarnessId): Promise<HarnessSettings> {
    if (!HARNESS_IDS.includes(provider)) throw new Error("invalid executor provider");
    const view = await this.reader.readPluginSettings(executorPluginIds[provider], runtimeSettingsAccess);
    return parseExecutorRuntimeProfile(view.settings);
  }

  async browserHome(): Promise<string> {
    const view = await this.reader.readPluginSettings("@catomicals/plugin-browser", runtimeSettingsAccess);
    return parseBrowserUrl(view.settings.home);
  }

  async walletEndpoint(): Promise<string> {
    const view = await this.reader.readPluginSettings("@catomicals/plugin-walletd", runtimeSettingsAccess);
    return parseLoopbackWalletEndpoint(view.settings.endpoint);
  }

  async mcpEnabled(): Promise<boolean> {
    const view = await this.reader.readPluginSettings("@catomicals/plugin-mcp", runtimeSettingsAccess);
    if (typeof view.settings.enabled !== "boolean") throw new Error("invalid Cordis MCP setting");
    return view.settings.enabled;
  }

}
