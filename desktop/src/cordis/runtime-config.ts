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

interface RuntimeReadinessGate {
  assertRuntimeReady(): void;
}

export interface GenerativeUiSettings {
  readonly enabled: boolean;
  readonly preference: "prefer" | "automatic" | "off";
  readonly maxBlocks: 1 | 2;
  readonly referenceRepository: string;
  readonly customInstructions: string;
}

export interface WalletRuntimeConfiguration {
  readonly endpoint: string;
  readonly processMode: "managed" | "external";
}

export interface SignerRuntimeConfiguration {
  readonly protocol: "frost-secp256k1-tr-v1";
  readonly signingRounds: 2;
  readonly roundTimeoutMs: number;
  readonly sessionTimeoutMs: number;
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

export function parseGenerativeUiSettings(value: Readonly<Record<string, unknown>>): GenerativeUiSettings {
  if (typeof value.enabled !== "boolean") throw new Error("invalid Cordis generative UI enabled setting");
  if (value.preference !== "prefer" && value.preference !== "automatic" && value.preference !== "off") {
    throw new Error("invalid Cordis generative UI preference");
  }
  if (value.maxBlocks !== 1 && value.maxBlocks !== 2) throw new Error("invalid Cordis generative UI block limit");
  return {
    enabled: value.enabled,
    preference: value.preference,
    maxBlocks: value.maxBlocks,
    referenceRepository: plainText(value.referenceRepository, "generative UI reference repository", 1024),
    customInstructions: plainText(value.customInstructions, "generative UI custom instructions", 4096),
  };
}

function positiveIntegerSetting(value: unknown, field: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`invalid Cordis ${field}`);
  }
  return value as number;
}

export function parseSignerRuntimeConfiguration(value: Readonly<Record<string, unknown>>): SignerRuntimeConfiguration {
  if (value.signerProtocol !== "frost-secp256k1-tr-v1") throw new Error("invalid Cordis signer protocol");
  if (value.signingRounds !== 2) throw new Error("invalid Cordis signer rounds");
  const roundTimeoutMs = positiveIntegerSetting(value.roundTimeoutMs, "signer round timeout", 1_000, 120_000);
  const sessionTimeoutMs = positiveIntegerSetting(value.sessionTimeoutMs, "signer session timeout", 1_000, 900_000);
  if (sessionTimeoutMs < roundTimeoutMs * 2) throw new Error("invalid Cordis signer session timeout");
  return {
    protocol: "frost-secp256k1-tr-v1",
    signingRounds: 2,
    roundTimeoutMs,
    sessionTimeoutMs,
  };
}

export class CordisRuntimeConfig {
  constructor(
    private readonly reader: CordisSettingsReader,
    private readonly readiness?: RuntimeReadinessGate,
  ) {}

  private assertReady(): void {
    this.readiness?.assertRuntimeReady();
  }

  async executor(provider: HarnessId): Promise<HarnessSettings> {
    this.assertReady();
    if (!HARNESS_IDS.includes(provider)) throw new Error("invalid executor provider");
    const view = await this.reader.readPluginSettings(executorPluginIds[provider], runtimeSettingsAccess);
    return parseExecutorRuntimeProfile(view.settings);
  }

  async browserHome(): Promise<string> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-browser", runtimeSettingsAccess);
    return parseBrowserUrl(view.settings.home);
  }

  async walletEndpoint(): Promise<string> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-walletd", runtimeSettingsAccess);
    return parseLoopbackWalletEndpoint(view.settings.endpoint);
  }

  async mcpEnabled(): Promise<boolean> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-mcp", runtimeSettingsAccess);
    if (typeof view.settings.enabled !== "boolean") throw new Error("invalid Cordis MCP setting");
    return view.settings.enabled;
  }

  async walletRuntime(): Promise<WalletRuntimeConfiguration> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-walletd", runtimeSettingsAccess);
    if (view.settings.processMode !== "managed" && view.settings.processMode !== "external") {
      throw new Error("invalid Cordis wallet process mode");
    }
    return {
      endpoint: parseLoopbackWalletEndpoint(view.settings.endpoint),
      processMode: view.settings.processMode,
    };
  }

  async signerRuntime(): Promise<SignerRuntimeConfiguration> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-walletd", runtimeSettingsAccess);
    return parseSignerRuntimeConfiguration(view.settings);
  }

  async generativeUi(): Promise<GenerativeUiSettings> {
    this.assertReady();
    const view = await this.reader.readPluginSettings("@catomicals/plugin-generative-ui", runtimeSettingsAccess);
    return parseGenerativeUiSettings(view.settings);
  }

}
