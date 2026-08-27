import { CordisHost } from "./host.js";
import {
  canonicalJson,
  digestBytes,
  digestJson,
  type FixedPluginRegistration,
  type PluginManifest,
  type TrustedPlugin,
} from "./manifest.js";
import type { CordisPermissionScope } from "./permissions.js";
import type { CordisSettingsField, CordisSettingsSchema } from "./settings.js";
import type { CordisStateStore } from "./store.js";

export const FIXED_PLUGIN_IDS = [
  "@catomicals/plugin-walletd",
  "@catomicals/plugin-bitcoin-node",
  "@catomicals/plugin-indexer",
  "@catomicals/plugin-mcp",
  "@catomicals/plugin-executor-codex",
  "@catomicals/plugin-executor-deepseek",
  "@catomicals/plugin-executor-claude-code",
  "@catomicals/plugin-backup",
  "@catomicals/plugin-browser",
] as const;

type FixedPluginId = (typeof FIXED_PLUGIN_IDS)[number];

interface BuiltinSpec {
  readonly id: FixedPluginId;
  readonly manifestId: string;
  readonly namespace: string;
  readonly fields: readonly CordisSettingsField[];
  readonly permissions: readonly CordisPermissionScope[];
  readonly optionalServices: readonly string[];
}

const stringField = (
  id: string,
  label: string,
  defaultValue: string,
  restart: "none" | "plugin" | "desktop" = "plugin",
): CordisSettingsField => ({ id, label, type: "string", required: true, default: defaultValue, restart, maxLength: 1024 });

const enabledField: CordisSettingsField = {
  id: "enabled",
  label: "Enabled",
  type: "boolean",
  required: true,
  default: true,
  restart: "plugin",
};

const executorFields = (command: string): readonly CordisSettingsField[] => [
  stringField("command", "Command", command),
  stringField("defaultModel", "Default model", "", "none"),
  {
    id: "reasoningEffort",
    label: "Reasoning effort",
    type: "string",
    required: true,
    default: "high",
    choices: ["low", "medium", "high", "xhigh"],
    restart: "none",
  },
  stringField("workingDirectory", "Working directory", "", "none"),
];

const specs: readonly BuiltinSpec[] = [
  {
    id: "@catomicals/plugin-walletd",
    manifestId: "00000000-0000-4000-8000-000000000001",
    namespace: "walletd",
    fields: [
      stringField("endpoint", "Wallet node endpoint", "http://127.0.0.1:18787"),
      { id: "processMode", label: "Process mode", type: "string", required: true, default: "managed", choices: ["managed", "external"], restart: "plugin" },
    ],
    permissions: ["wallet.status.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["walletd.health"],
  },
  {
    id: "@catomicals/plugin-bitcoin-node",
    manifestId: "00000000-0000-4000-8000-000000000002",
    namespace: "bitcoin.node",
    fields: [
      { id: "profile", label: "Node profile", type: "string", required: true, default: "inquisition", choices: ["inquisition", "external"], restart: "plugin" },
      stringField("endpoint", "Node gateway endpoint", "http://127.0.0.1:18443"),
    ],
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["bitcoin.node.health"],
  },
  {
    id: "@catomicals/plugin-indexer",
    manifestId: "00000000-0000-4000-8000-000000000003",
    namespace: "indexer",
    fields: [enabledField, stringField("databasePath", "Database path", "")],
    permissions: ["indexer.query.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["indexer.health"],
  },
  {
    id: "@catomicals/plugin-mcp",
    manifestId: "00000000-0000-4000-8000-000000000004",
    namespace: "mcp",
    fields: [enabledField, { id: "transport", label: "Transport", type: "string", required: true, default: "stdio", choices: ["stdio", "http-oauth"], restart: "plugin" }],
    permissions: ["plugin.catalog.read", "plugin.manifest.read", "plugin.settings_schema.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["mcp.health"],
  },
  {
    id: "@catomicals/plugin-executor-codex",
    manifestId: "00000000-0000-4000-8000-000000000005",
    namespace: "executor.codex",
    fields: executorFields("codex"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.codex.health"],
  },
  {
    id: "@catomicals/plugin-executor-deepseek",
    manifestId: "00000000-0000-4000-8000-000000000006",
    namespace: "executor.deepseek",
    fields: executorFields("dsh"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.deepseek.health"],
  },
  {
    id: "@catomicals/plugin-executor-claude-code",
    manifestId: "00000000-0000-4000-8000-000000000007",
    namespace: "executor.claude.code",
    fields: executorFields("claude"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.claude.code.health"],
  },
  {
    id: "@catomicals/plugin-backup",
    manifestId: "00000000-0000-4000-8000-000000000008",
    namespace: "backup",
    fields: [
      stringField("directory", "Backup directory", ""),
      { id: "retention", label: "Retention count", type: "integer", required: true, default: 7, minimum: 1, maximum: 365, restart: "none" },
      stringField("schedule", "Schedule", "manual", "none"),
    ],
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["backup.health"],
  },
  {
    id: "@catomicals/plugin-browser",
    manifestId: "00000000-0000-4000-8000-000000000009",
    namespace: "browser",
    fields: [stringField("home", "Browser home", "https://mempool.space/signet", "none")],
    permissions: ["browser.open.public", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["browser.health"],
  },
];

const publisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu37oOwTVXgyPnMlEtvLNpsamINKH+dT0GFAM+Q8V9hg=
-----END PUBLIC KEY-----
`;

const signatures: Readonly<Record<FixedPluginId, string>> = {
  "@catomicals/plugin-walletd": "MT6NVX7QKsKsQvdRx0ESFpRViZGFXaUGn6BsFQhGOLzsbCbFOzo7QrV5ohEJPZOnqsJv1IpEWenlE8tlVmOBCA==",
  "@catomicals/plugin-bitcoin-node": "E6c8aKRnL7u8J4hswhC99aflaHJMb0dVUWU3UqflaJ1nxw931Ap4tud+9lmIrKGDBbnnNta7g2A4975P7ToQBQ==",
  "@catomicals/plugin-indexer": "DW5NR3WyN1ZNB7o5zMmN2maELhIoTZZmHlKJe7seIrbHFSv49zAiHUQOpIHQQ4EMbCXanLM/dDhh/NjrsDEjDQ==",
  "@catomicals/plugin-mcp": "Fw8aHidAJvwJ47qT053r+6x8rw6xYgKl5GqK9p1OfwNnp8rVBVLL/UWvOpi4u2wbQ76sozKFrRZWJsUJoPvIBw==",
  "@catomicals/plugin-executor-codex": "W08x0Wn5mNspFXfRtIaYXso2NEbKJEV/Wf1UjJoXh8E9hiZvm7NxNcit+bSMEFBkbrh3N738r/PaHQdV/D11Bw==",
  "@catomicals/plugin-executor-deepseek": "FwpGmwgTrZ3SuFezTwrmIWsXj/z/H+J07u53WetUOZnxSMDFzBUskVdp8Qz7nykuJygW+8u8jA+eyv/QcB/QBA==",
  "@catomicals/plugin-executor-claude-code": "IFFUONaJ78ZM8Sl26Awk92wLkKFcEPE9JEWZG2tdXooHtJJbD+dmZFDeYY9K1VnedvgGak4dGE34M02tqWNxDw==",
  "@catomicals/plugin-backup": "mqi0LgFv4t9v4Hv6kYghCAXYO4bEnt439EQ7UYA710RFQCizPq28vOXrsjWjXO12nnQ/kJsQ8XGsvyHXjjSGAA==",
  "@catomicals/plugin-browser": "5dSb3wptZmVaO4LwMlfM5w7Wz/fwfNWGVhW5lkQ1uxLIEDhL3pgy82AbDGW8eF/LG1q4UnJDmux4cg9Dw1RdCg==",
};

function buildPackage(spec: BuiltinSpec): { registration: FixedPluginRegistration; trust: TrustedPlugin } {
  const pluginVersion = "1.0.0";
  const descriptor = canonicalJson({
    pluginId: spec.id,
    pluginVersion,
    implementation: "catomicals-cordis-declarative-v1",
  });
  const schema: CordisSettingsSchema = { version: 1, fields: spec.fields };
  const signature = signatures[spec.id];
  const manifest: PluginManifest = {
    schema_version: 1,
    manifest_id: spec.manifestId,
    plugin_id: spec.id,
    plugin_version: pluginVersion,
    runtime_api: 1,
    publisher: { publisher_id: "catomicals-core", key_id: "desktop-release-2026-01" },
    package_digest: digestBytes(Buffer.from(descriptor)),
    package_attestation: {
      algorithm: "ed25519",
      attestation_digest: digestBytes(Buffer.from(signature, "base64")),
    },
    entries: { host: "dist/cordis/builtins.js", client: "dist/cordis/client.js" },
    inject: { required: [], optional: [...spec.optionalServices] },
    permission_scopes: [...spec.permissions],
    settings: {
      namespace: spec.namespace,
      mode: "intent_only",
      schema_version: schema.version,
      schema_digest: digestJson(schema),
    },
    ui_surfaces: [{ surface_id: "settings", placement: "settings", client_entry: "dist/cordis/client.js" }],
    migration: { namespace: spec.namespace, current: 0 },
  };
  return {
    registration: { id: spec.id, manifest, descriptor, signature, settingsSchema: schema },
    trust: {
      pluginId: spec.id,
      pluginVersion,
      publisherId: manifest.publisher.publisher_id,
      keyId: manifest.publisher.key_id,
      packageDigest: manifest.package_digest,
      publicKey: publisherKey,
    },
  };
}

export function builtinPackages(): readonly { registration: FixedPluginRegistration; trust: TrustedPlugin }[] {
  return specs.map(buildPackage);
}

export function createBuiltinCordisHost(stateStore: CordisStateStore): CordisHost {
  const packages = builtinPackages();
  return new CordisHost({
    registrations: packages.map((item) => item.registration),
    trust: packages.map((item) => item.trust),
    stateStore,
  });
}
