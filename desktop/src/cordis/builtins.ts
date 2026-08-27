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
import type { CordisService } from "./health.js";

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
  readonly healthService?: string;
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
    optionalServices: [],
    healthService: "walletd.health",
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
    optionalServices: [],
    healthService: "bitcoin.node.health",
  },
  {
    id: "@catomicals/plugin-indexer",
    manifestId: "00000000-0000-4000-8000-000000000003",
    namespace: "indexer",
    fields: [enabledField, stringField("databasePath", "Database path", "")],
    permissions: ["indexer.query.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "indexer.health",
  },
  {
    id: "@catomicals/plugin-mcp",
    manifestId: "00000000-0000-4000-8000-000000000004",
    namespace: "mcp",
    fields: [enabledField, { id: "transport", label: "Transport", type: "string", required: true, default: "stdio", choices: ["stdio", "http-oauth"], restart: "plugin" }],
    permissions: ["plugin.catalog.read", "plugin.manifest.read", "plugin.settings_schema.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "mcp.health",
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
MCowBQYDK2VwAyEAAuOmye98y8meOUYy4hElYiZWS+EjxGdo0yEFckoSr6c=
-----END PUBLIC KEY-----
`;

const signatures: Readonly<Record<FixedPluginId, string>> = {
  "@catomicals/plugin-walletd": "pxzcT6kKVWAnMNpV2RuLaemMS2V88zGuBOmH/eljTHfVdMB31nq3a5SJVtj91bEN0uyEnT+nc2FA28SogSLIBg==",
  "@catomicals/plugin-bitcoin-node": "VY5hARKPHleP2lp8IdzVfDOTcJsSIWPiQFWy+gbLUPMNCvNlYhMdIF0+flXyp9ahvgW/nnWE4iCMh7nUrcE/CA==",
  "@catomicals/plugin-indexer": "pf13XONnjLr6lMviG2Zc1FLeqZvCrpyH1KBY5KW7jNnZAGKWSUoekcPqEFn+hnAx2J1ev/15Z66JFG63L9+hBQ==",
  "@catomicals/plugin-mcp": "P5zN21UDwA13G0wxwMFVJJGoTi5j64i2+TSyyQe1/Um7CBmSCTD2wHL5Q4zisG+53EsP8UJAoKD7aO3u12mjAQ==",
  "@catomicals/plugin-executor-codex": "3EI9BpAEI4kC0O38NGw24mkrViu+0BT758aFNgNVr/aLq+r/Qx1D9Q+O7S8VO9ogd2vZZYae0wX/RqmzmBYYCg==",
  "@catomicals/plugin-executor-deepseek": "xk22MUF7Et9m7ndhpTrTkUSkbSS7iZpMOlvbkjoFFFbaCyEKuoueE4eg1DXCe+ifMjpIgW2KiJzW2djwae83BQ==",
  "@catomicals/plugin-executor-claude-code": "WNumnEftigsNX1cDfBZQ6gW494i50HdLnb1ksCA46xl/tvl3iBHONk0oyjMOb6mKAwpTq/0R5vGSxpGlyPrABA==",
  "@catomicals/plugin-backup": "/U14tKVGV0MLPvutu3f1yAhSkRubTgbxgrR04UN3cqjDZHwN1MyKmYf2NXBI1NZBH9MYNQpdSi1s34HzSrLCAA==",
  "@catomicals/plugin-browser": "NS1k69Ra8Yw89KpWJ6GbXWTOjP5zbQW8LnRH0bfdKGgapHn4XcZ5YM93sXMBkwZYeS52L1eW5/tUIUq7xvH8Cw==",
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
    inject: { required: spec.healthService ? [spec.healthService] : [], optional: [...spec.optionalServices] },
    permission_scopes: [...spec.permissions],
    settings: {
      namespace: spec.namespace,
      mode: "intent_only",
      schema_version: schema.version,
      schema_digest: digestJson(schema),
    },
    ui_surfaces: [{ surface_id: "settings", placement: "settings", client_entry: "dist/cordis/client.js" }],
    migration: { namespace: spec.namespace, current: 0 },
    ...(spec.healthService ? { health_service: spec.healthService } : {}),
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

export function createBuiltinCordisHost(stateStore: CordisStateStore, services: readonly CordisService[] = []): CordisHost {
  const packages = builtinPackages();
  return new CordisHost({
    registrations: packages.map((item) => item.registration),
    trust: packages.map((item) => item.trust),
    stateStore,
    services,
  });
}
