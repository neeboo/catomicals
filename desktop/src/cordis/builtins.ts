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
  "@catomicals/plugin-generative-ui",
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
  readonly runtimeHealthService?: string;
  readonly publisherKey?: string;
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
      stringField("endpoint", "Node gateway endpoint", "http://127.0.0.1:18787"),
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
    runtimeHealthService: "indexer.health",
  },
  {
    id: "@catomicals/plugin-mcp",
    manifestId: "00000000-0000-4000-8000-000000000004",
    namespace: "mcp",
    fields: [enabledField, { id: "transport", label: "Transport", type: "string", required: true, default: "stdio", choices: ["stdio", "http-oauth"], restart: "plugin" }],
    permissions: ["plugin.catalog.read", "plugin.manifest.read", "plugin.settings_schema.read", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    healthService: "mcp.health",
    runtimeHealthService: "mcp.health",
  },
  {
    id: "@catomicals/plugin-executor-codex",
    manifestId: "00000000-0000-4000-8000-000000000005",
    namespace: "executor.codex",
    fields: executorFields("codex"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.codex.health"],
    runtimeHealthService: "executor.codex.health",
  },
  {
    id: "@catomicals/plugin-executor-deepseek",
    manifestId: "00000000-0000-4000-8000-000000000006",
    namespace: "executor.deepseek",
    fields: executorFields("dsh"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.deepseek.health"],
    runtimeHealthService: "executor.deepseek.health",
  },
  {
    id: "@catomicals/plugin-executor-claude-code",
    manifestId: "00000000-0000-4000-8000-000000000007",
    namespace: "executor.claude.code",
    fields: executorFields("claude"),
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["executor.claude.code.health"],
    runtimeHealthService: "executor.claude.code.health",
  },
  {
    id: "@catomicals/plugin-generative-ui",
    manifestId: "00000000-0000-4000-8000-00000000000a",
    namespace: "generative.ui",
    fields: [
      { ...enabledField, restart: "none" },
      {
        id: "preference",
        label: "组件输出偏好",
        type: "string",
        required: true,
        default: "prefer",
        choices: ["prefer", "automatic", "off"],
        restart: "none",
      },
      {
        id: "maxBlocks",
        label: "每条回复最多组件数",
        type: "integer",
        required: true,
        default: 2,
        minimum: 1,
        maximum: 2,
        restart: "none",
      },
      {
        id: "referenceRepository",
        label: "界面参考仓库",
        type: "string",
        required: true,
        default: "/Users/ghostcorn/dev/deepseek-harness",
        restart: "none",
        maxLength: 1024,
      },
      {
        id: "customInstructions",
        label: "追加生成规范",
        type: "string",
        required: true,
        default: "",
        restart: "none",
        maxLength: 4096,
        control: "textarea",
      },
    ],
    permissions: ["plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: [],
    publisherKey: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4C3L9i1clPkZH/NsjZgdZh5O0j3aDUODfT7jE2bp9JE=
-----END PUBLIC KEY-----
`,
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
    runtimeHealthService: "backup.health",
  },
  {
    id: "@catomicals/plugin-browser",
    manifestId: "00000000-0000-4000-8000-000000000009",
    namespace: "browser",
    fields: [stringField("home", "Browser home", "https://mempool.space/signet", "none")],
    permissions: ["browser.open.public", "plugin.health.read", "plugin.settings.validate", "plugin.settings_intent.create"],
    optionalServices: ["browser.health"],
    runtimeHealthService: "browser.health",
  },
];

const publisherKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7W8WSsvBKb6whyJYKFp9VhqZGvJ5PEkhin0FvWkXsGM=
-----END PUBLIC KEY-----
`;

const signatures: Readonly<Record<FixedPluginId, string>> = {
  "@catomicals/plugin-walletd": "CKjtmFYRMTve9CtgtIKJrd5Kipg8hOzzRBik4Bu7KY3QJcBg/etOxePNZsnF261B9rmY9CCftP7I1aN4FHAuBA==",
  "@catomicals/plugin-bitcoin-node": "j4iASKyUbus0IJKpIIpktQZ9PwjYUFbtvjX04sc9M44p2FWuyzkSiGZTZmlo+GmjQztw5wtNBmYouQxqujDCAA==",
  "@catomicals/plugin-indexer": "PX/DVyyIGs5mMmujB+xioUlltEqSlVVhz+eSgGqHZ950zxsBOQW/WJsbaYZGdra2jcWdn2MVJ02sp7TtjsXNCQ==",
  "@catomicals/plugin-mcp": "g6WKVIlkn9sPNGSNeSpMRl6ZxdimTqTFtSqc3yG+AlPuEWQl4uXoSsxAORQBL/zwnJ0Q5odSVRGWn+jHWfcfAA==",
  "@catomicals/plugin-executor-codex": "yUzds6wig0/SA5RUwl7txdMt0k9tfAMQn4ChkcI1cfk+mh/Hu48BQgBHoKXjHLyt8yxPPrI40JengRfABWA7Bw==",
  "@catomicals/plugin-executor-deepseek": "/uG1bryz/mtAv80mjLOTaBnJJCYoyg7Rc13EfwTE0lPUz3ykEgHeEgsxpcIidqcocf4N6e5YKE68yBdCb7nPAw==",
  "@catomicals/plugin-executor-claude-code": "nNLF86vlSDvlZXqYYy9otQGoXaMiE5FUvom0GlMesC7sZMg/pqvi4t9/A86vxcl1Cp73M25pVrxm2cKeVsmEAQ==",
  "@catomicals/plugin-generative-ui": "SuuuJb84JBq0xUryuifWXv3Lm/EU8SI9QLIjaEsxwW6MhpvzO8bbW9NAm9vpHNBaF8JgR5P3HXkyeR3+PNFdAg==",
  "@catomicals/plugin-backup": "azpzHPFLpkcsPpO0TWz5SWbeVMudtJnzPzDY4+RZTJDX6gUqRLQo9TyZm1O8IWSu4ukLOnb9TQ0NSFJY+KfZDw==",
  "@catomicals/plugin-browser": "GL04RzqgDeWiDG8yBHAGJr4ph8xIe0CJjfQEPIAj2PILfYo7OYRfLjvzA526cwplrU8CW+4IHUUGxTr4ELHDCg==",
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
    registration: {
      id: spec.id,
      manifest,
      descriptor,
      signature,
      settingsSchema: schema,
      ...(spec.runtimeHealthService ? {
        healthCheck: async ({ services }) => {
          const snapshot = services.get(spec.runtimeHealthService!);
          return snapshot
            ? { status: snapshot.status, ...(snapshot.message ? { message: snapshot.message } : {}) }
            : { status: "degraded" as const, message: `${spec.runtimeHealthService} unavailable` };
        },
      } : {}),
    },
    trust: {
      pluginId: spec.id,
      pluginVersion,
      publisherId: manifest.publisher.publisher_id,
      keyId: manifest.publisher.key_id,
      packageDigest: manifest.package_digest,
      publicKey: spec.publisherKey ?? publisherKey,
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
